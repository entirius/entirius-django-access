# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Token API secrets: ``key_hash`` in no response, the raw value only in its own create/rotate response (never cached,
never logged, never audited), forbidden fields and mixed scopes refused, secret tokens expire within 365 days, only
access managers reach the API, and the OpenAPI document holds no token-like string."""

import json
import logging
import re
from datetime import timedelta

import pytest
from drf_spectacular.generators import SchemaGenerator
from rest_framework.test import APIClient

from django_access.models import ApiToken, Application, AuditEntry
from django_access.openapi import add_api_key_security
from tests.helpers import TOKEN_API_URL as URL
from tests.helpers import TOKEN_ENDPOINTS as ENDPOINTS
from tests.helpers import call_token_api as call

pytestmark = pytest.mark.django_db

SECRET_SCOPE = "checkout.erase"
TOKEN_LIKE = re.compile(r"ent_api_[A-Za-z0-9_-]{43}")
SHOWN_ONCE = ("create", "rotate")
FORBIDDEN_TOKEN_FIELDS = [
    {"legacy": True},
    {"legacy_source": "settings.AGREEMENTS_API_KEY"},
    {"key_hash": "0" * 64},
    {"prefix": "ent_api_mine"},
    {"last_four": "mine"},
    {"revoked_at": None},
    {"revoked_by": 1},
    {"last_used_at": None},
    {"application": 1},
]
FORBIDDEN_APPLICATION_FIELDS = [{"id": 99}, {"created_by": 1}, {"created_at": "2026-01-01T00:00:00Z"}, {"tokens": []}]


def keys_at_any_depth(value) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {key for item in value.values() for key in keys_at_any_depth(item)}
    if isinstance(value, list):
        return {key for item in value for key in keys_at_any_depth(item)}
    return set()


def tokens_url(application: Application) -> str:
    return f"{URL}applications/{application.pk}/tokens/"


def secret_body(clock, days: int | None = 30, **extra) -> dict:
    expiry = {} if days is None else {"expires_at": (clock.now + timedelta(days=days)).isoformat()}
    return {"name": "erase", "scopes": [SECRET_SCOPE], **expiry, **extra}


@pytest.fixture
def flow(admin_api, application, clock, caplog):
    """Every token/application endpoint, the 400 and 409 bodies included: ``[(label, response)]`` and the raws."""
    caplog.set_level(logging.DEBUG)
    seen = []

    def record(label: str, response):
        seen.append((label, response))
        return response.json()

    record("app create", admin_api.post(URL + "applications/", {"name": "Integration"}, format="json"))
    created = record("create", admin_api.post(tokens_url(application), secret_body(clock), format="json"))
    for label, path in [("apps", "applications/"), ("app", f"applications/{application.pk}/")]:
        record(label, admin_api.get(URL + path))
    record("app patch", admin_api.patch(f"{URL}applications/{application.pk}/", {"description": "x"}, format="json"))
    record("list", admin_api.get(tokens_url(application)))
    rotated = record("rotate", admin_api.post(f"{URL}tokens/{created['id']}/rotate/", {}, format="json"))
    record("list again", admin_api.get(tokens_url(application)))
    for label in ("revoke", "revoke again"):
        record(label, admin_api.post(f"{URL}tokens/{rotated['id']}/revoke/"))
    record("409", admin_api.post(f"{URL}tokens/{rotated['id']}/rotate/", {}, format="json"))
    mixed = {"scopes": ["checkout.storefront", SECRET_SCOPE]}
    record("400", admin_api.post(tokens_url(application), secret_body(clock, **mixed), format="json"))
    record("400 expiry", admin_api.post(tokens_url(application), secret_body(clock, days=None), format="json"))
    return seen, created["raw"], rotated["raw"]


def test_flow_answers_as_expected(flow):
    seen, _, _ = flow
    statuses = [response.status_code for _, response in seen]
    assert statuses == [201, 201, 200, 200, 200, 200, 201, 200, 200, 200, 409, 400, 400]


def test_no_response_carries_key_hash(flow):
    seen, _, _ = flow
    hashes = list(ApiToken.objects.values_list("key_hash", flat=True))
    for label, response in seen:
        assert "key_hash" not in keys_at_any_depth(response.json()), label
        assert not any(value in response.content.decode() for value in hashes), label


def test_raw_only_in_create_and_rotate(flow):
    seen, _, _ = flow
    carrying = [label for label, response in seen if "raw" in keys_at_any_depth(response.json())]
    assert carrying == list(SHOWN_ONCE)


def test_raw_value_never_appears_again(flow):
    seen, created_raw, rotated_raw = flow
    labels = [label for label, _ in seen]
    for raw, shown_in in [(created_raw, "create"), (rotated_raw, "rotate")]:
        later = seen[labels.index(shown_in) + 1 :]
        assert not [label for label, response in later if raw in response.content.decode()]


def test_raw_value_in_no_log_record_or_audit_row(flow, caplog):
    _, *raws = flow
    records = caplog.get_records("setup") + caplog.get_records("call")  # the flow runs in fixture setup
    assert not [record.name for record in records if any(raw in record.getMessage() for raw in raws)]
    rows = [str(row) for row in AuditEntry.objects.values()]
    assert rows and not any(raw in row for row in rows for raw in raws)


def test_create_and_rotate_are_never_cached(flow):
    seen, _, _ = flow
    for label, response in seen:
        if label in SHOWN_ONCE:
            assert (response["Cache-Control"], response["Pragma"]) == ("no-store", "no-cache"), label


@pytest.mark.parametrize("extra", FORBIDDEN_TOKEN_FIELDS)
def test_token_create_refuses_forbidden_fields(admin_api, application, extra):
    body = {"scopes": ["checkout.storefront"], **extra}
    response = admin_api.post(tokens_url(application), body, format="json")
    assert response.status_code == 400 and not ApiToken.objects.exists()


@pytest.mark.parametrize("extra", FORBIDDEN_TOKEN_FIELDS)
def test_token_rotate_refuses_forbidden_fields(admin_api, issue, extra):
    token, _ = issue()
    response = admin_api.post(f"{URL}tokens/{token.pk}/rotate/", extra, format="json")
    assert response.status_code == 400 and ApiToken.objects.count() == 1


@pytest.mark.parametrize("extra", FORBIDDEN_APPLICATION_FIELDS)
def test_application_patch_refuses_forbidden_fields(admin_api, application, extra):
    response = admin_api.patch(f"{URL}applications/{application.pk}/", {"name": "New", **extra}, format="json")
    assert response.status_code == 400
    application.refresh_from_db()
    assert application.name == "storefront"


def test_mixed_scopes_are_refused(admin_api, application, clock):
    body = secret_body(clock, scopes=["checkout.storefront", SECRET_SCOPE])
    response = admin_api.post(tokens_url(application), body, format="json")
    assert response.status_code == 400 and not ApiToken.objects.exists()


def assert_expiry_issue(response, issue: str) -> None:
    assert response.status_code == 400
    detail = response.json()["details"][0]
    assert (detail["field"], detail["issue"]) == ("expires_at", issue)


@pytest.mark.parametrize(("days", "issue"), [(None, "EXPIRY_REQUIRED"), (366, "EXPIRY_TOO_LONG")])
def test_secret_token_expiry_is_enforced(admin_api, application, clock, days, issue):
    assert_expiry_issue(admin_api.post(tokens_url(application), secret_body(clock, days), format="json"), issue)
    assert not ApiToken.objects.exists()


def test_secret_token_at_365_days_is_issued(admin_api, application, clock):
    assert admin_api.post(tokens_url(application), secret_body(clock, 365), format="json").status_code == 201


def test_secret_rotation_beyond_365_days_is_refused(admin_api, issue, clock):
    token, _ = issue([SECRET_SCOPE], expires_at=clock.now + timedelta(days=30))
    body = {"expires_at": (clock.now + timedelta(days=366)).isoformat()}
    assert_expiry_issue(admin_api.post(f"{URL}tokens/{token.pk}/rotate/", body, format="json"), "EXPIRY_TOO_LONG")


@pytest.fixture
def ids(issue, application):
    token, _ = issue()
    return {"application": application.pk, "token": token.pk}


@pytest.mark.parametrize(("method", "path", "body"), ENDPOINTS)
@pytest.mark.parametrize("name", ["viewer", "editor", "manager"])
def test_roles_without_access_manage_are_refused(person, api_as, ids, name, method, path, body):
    response = call(api_as(person(name)), method, path, body, ids)
    assert response.status_code == 403 and response.json()["details"][0]["issue"] == "ACCESS_DENIED"


@pytest.mark.parametrize(("method", "path", "body"), ENDPOINTS)
def test_customer_is_staff_only(person, api_as, ids, method, path, body):
    response = call(api_as(person("customer")), method, path, body, ids)
    assert response.status_code == 403 and response.json()["details"][0]["issue"] == "STAFF_ONLY"


@pytest.mark.parametrize(("method", "path", "body"), ENDPOINTS)
def test_a_token_never_opens_the_api(issue, clock, ids, method, path, body):
    _, public_raw = issue()
    _, secret_raw = issue([SECRET_SCOPE], expires_at=clock.now + timedelta(days=30))
    client = APIClient()
    client.credentials(HTTP_X_API_KEY=public_raw, HTTP_X_API_ADMIN_KEY=secret_raw)
    assert call(client, method, path, body, ids).status_code == 401


def test_openapi_document_holds_no_token_like_string():
    schema = SchemaGenerator(urlconf="django_access.urls").get_schema(request=None, public=True)
    document = json.dumps(add_api_key_security(schema, generator=None, request=None, public=True))
    assert not TOKEN_LIKE.search(document)
    assert "key_hash" not in document
