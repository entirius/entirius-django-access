# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Token API v2: applications and tokens over the admin API — auth matrix, CRUD, rotate overlap, revoke, catalogue."""

from datetime import datetime, timedelta

import pytest
from django.db.models import QuerySet
from django.utils import timezone

from django_access.catalogue import registry
from django_access.exceptions import AccessConflict
from django_access.models import ApiToken, Application, AuditAction, AuditEntry
from django_access.services import tokens
from tests.helpers import TOKEN_API_URL, TOKEN_ENDPOINTS, call_token_api

pytestmark = pytest.mark.django_db

URL = TOKEN_API_URL
OK = {"get": 200, "post": 201, "patch": 200}
ENDPOINTS = TOKEN_ENDPOINTS
REFUSED = {"anonymous": 401, "customer": 403, "staff": 403, "viewer": 403, "manager": 403}


@pytest.fixture
def ids(issue, application):
    token, _ = issue()
    return {"application": application.pk, "token": token.pk}


call = call_token_api


def expected(name: str, method: str, path: str) -> int:
    return REFUSED.get(name, 200 if path.endswith(("revoke/", "expiry/")) else OK[method])


def in_days(days: int) -> str:
    return (timezone.now() + timedelta(days=days)).isoformat()


@pytest.mark.parametrize(("method", "path", "body"), ENDPOINTS)
@pytest.mark.parametrize("name", [*REFUSED, "administrator", "superuser"])
def test_auth_matrix(name, method, path, body, ids, person, api_as):
    client = api_as(None if name == "anonymous" else person(name))
    response = call(client, method, path, body, ids)
    assert response.status_code == expected(name, method, path), response.content


def test_application_create_list_detail_and_patch(admin_api):
    created = admin_api.post(URL + "applications/", {"name": "Widget", "description": "Forms"}, format="json")
    assert created.status_code == 201
    body = created.json()
    assert set(body) == {"id", "name", "description", "is_active", "created_at"} and body["is_active"] is True
    listed = admin_api.get(URL + "applications/").json()
    assert [row["name"] for row in listed["results"]] == ["Widget"]
    patched = admin_api.patch(f"{URL}applications/{body['id']}/", {"is_active": False}, format="json")
    assert patched.status_code == 200 and patched.json()["is_active"] is False
    detail = admin_api.get(f"{URL}applications/{body['id']}/").json()
    assert detail == {**body, "is_active": False}
    assert AuditEntry.objects.filter(action=AuditAction.APPLICATION_UPDATE).get().detail["changes"] == {
        "is_active": {"from": True, "to": False}
    }


def test_application_has_no_delete(admin_api, application):
    response = admin_api.delete(f"{URL}applications/{application.pk}/")
    assert response.status_code == 405 and Application.objects.filter(pk=application.pk).exists()


@pytest.mark.parametrize("method", ["post", "patch"])
def test_duplicate_application_name_is_409(admin_api, application, method):
    other = Application.objects.create(name="other")
    path = "applications/" if method == "post" else f"applications/{other.pk}/"
    response = getattr(admin_api, method)(URL + path, {"name": application.name}, format="json")
    assert response.status_code == 409 and response.json()["error"] == "CONFLICT"


@pytest.mark.parametrize("body", [{}, {"name": None}, {"is_active": None}, {"name": ""}])
def test_application_patch_refuses_empty_or_null(admin_api, application, body):
    response = admin_api.patch(f"{URL}applications/{application.pk}/", body, format="json")
    assert response.status_code == 400


def test_token_create_and_list(admin_api, application):
    body = {"name": "Shop", "scopes": ["checkout.storefront"], "channel_idx": "emporium"}
    created = admin_api.post(f"{URL}applications/{application.pk}/tokens/", body, format="json")
    assert created.status_code == 201
    token = created.json()
    assert token["raw"].startswith(tokens.TOKEN_PREFIX) and token["raw"][:12] == token["prefix"]
    assert token["raw"][-4:] == token["last_four"]
    assert (token["state"], token["channel_idx"], token["legacy"]) == ("active", "emporium", False)
    rows = admin_api.get(f"{URL}applications/{application.pk}/tokens/").json()["results"]
    assert [row["id"] for row in rows] == [token["id"]] and "raw" not in rows[0]
    assert {key: value for key, value in token.items() if key != "raw"} == rows[0]


def test_token_list_shows_states(admin_api, issue, system, clock):
    revoked, _ = issue(name="revoked")
    tokens.revoke_token(revoked, actor=system)
    issue(name="expired", expires_at=clock.now + timedelta(hours=1))
    issue(name="active")
    clock.advance(hours=2)
    application = revoked.application_id
    rows = admin_api.get(f"{URL}applications/{application}/tokens/").json()["results"]
    assert {row["name"]: row["state"] for row in rows} == {
        "revoked": "revoked",
        "expired": "expired",
        "active": "active",
    }


def test_token_list_of_unknown_application_is_404(admin_api):
    assert admin_api.get(f"{URL}applications/999/tokens/").status_code == 404


@pytest.mark.parametrize(
    "body",
    [
        {"scopes": []},
        {"scopes": ["nope.nope"]},
        {"scopes": ["checkout.storefront"], "expires_at": "2020-01-01T00:00:00Z"},
        {"scopes": ["checkout.storefront"], "expires_at": "2099-01-01T00:00:00"},
        {"scopes": ["checkout.storefront"], "channel_idx": ""},
    ],
)
def test_token_create_refusals(admin_api, application, body):
    response = admin_api.post(f"{URL}applications/{application.pk}/tokens/", body, format="json")
    assert response.status_code == 400 and not ApiToken.objects.exists()


def test_rotate_keeps_the_old_token_for_the_overlap(admin_api, issue, key_request, clock):
    old, old_raw = issue(channel_idx="emporium", name="shop")
    response = admin_api.post(f"{URL}tokens/{old.pk}/rotate/", {"overlap_hours": 2}, format="json")
    assert response.status_code == 201
    new = response.json()
    assert (new["name"], new["channel_idx"], new["scopes"]) == ("shop", "emporium", ["checkout.storefront"])
    old.refresh_from_db()
    assert old.expires_at == clock.now + timedelta(hours=2)
    assert tokens.verify_api_key(key_request(HTTP_X_API_KEY=old_raw), "checkout.storefront") is not None
    clock.advance(hours=2)
    assert tokens.verify_api_key(key_request(HTTP_X_API_KEY=old_raw), "checkout.storefront") is None
    assert tokens.verify_api_key(key_request(HTTP_X_API_KEY=new["raw"]), "checkout.storefront").pk == new["id"]


def test_rotate_defaults_to_24_hours(admin_api, issue, clock):
    old, _ = issue()
    assert admin_api.post(f"{URL}tokens/{old.pk}/rotate/", {}, format="json").status_code == 201
    old.refresh_from_db()
    assert old.expires_at == clock.now + timedelta(hours=24)


@pytest.mark.parametrize("hours", [-1, 169, "x"])
def test_rotate_overlap_bounds(admin_api, issue, hours):
    old, _ = issue()
    response = admin_api.post(f"{URL}tokens/{old.pk}/rotate/", {"overlap_hours": hours}, format="json")
    assert response.status_code == 400 and ApiToken.objects.count() == 1


def test_rotate_with_an_explicit_expiry(admin_api, issue):
    old, _ = issue()
    submitted = in_days(30)
    response = admin_api.post(f"{URL}tokens/{old.pk}/rotate/", {"expires_at": submitted}, format="json")
    assert response.status_code == 201
    expected = datetime.fromisoformat(submitted)
    assert datetime.fromisoformat(response.json()["expires_at"]) == expected
    assert ApiToken.objects.get(pk=response.json()["id"]).expires_at == expected


def test_rotate_of_a_revoked_token_is_409(admin_api, issue, system):
    old, _ = issue()
    tokens.revoke_token(old, actor=system)
    response = admin_api.post(f"{URL}tokens/{old.pk}/rotate/", {}, format="json")
    assert response.status_code == 409 and ApiToken.objects.count() == 1


def test_revoke_stops_the_token_and_is_idempotent(admin_api, issue, key_request):
    token, raw = issue()
    first = admin_api.post(f"{URL}tokens/{token.pk}/revoke/")
    assert first.status_code == 200 and first.json()["state"] == "revoked"
    assert tokens.verify_api_key(key_request(HTTP_X_API_KEY=raw), "checkout.storefront") is None
    second = admin_api.post(f"{URL}tokens/{token.pk}/revoke/")
    assert second.status_code == 200 and second.json() == first.json()
    assert AuditEntry.objects.filter(action=AuditAction.TOKEN_REVOKE).count() == 1


@pytest.mark.parametrize("action", ["rotate", "revoke"])
def test_unknown_token_is_404(admin_api, action):
    assert admin_api.post(f"{URL}tokens/999/{action}/", {}, format="json").status_code == 404


def test_audit_rows_carry_the_actor_and_address(admin_api, application):
    admin_api.post(f"{URL}applications/{application.pk}/tokens/", {"scopes": ["checkout.storefront"]}, format="json")
    row = AuditEntry.objects.get(action=AuditAction.TOKEN_CREATE)
    assert row.actor is not None and row.ip == "127.0.0.1"


def test_catalogue_lists_the_token_scopes(admin_api):
    scopes = admin_api.get(URL + "catalogue/").json()["scopes"]
    assert [scope["key"] for scope in scopes] == [scope.key for scope in registry.scopes()]
    storefront = next(scope for scope in scopes if scope["key"] == "checkout.storefront")
    assert storefront["publishable"] is True and storefront["module"] == "django_checkout"
    assert set(storefront) == {"key", "label", "module", "publishable", "routes"} and storefront["routes"]


def test_racing_duplicate_application_name_is_a_conflict(application, system, monkeypatch):
    """Two requests pass the ``exists()`` check together; the unique index answers the second as a conflict."""
    other = Application.objects.create(name="other")
    monkeypatch.setattr(QuerySet, "exists", lambda self: False)
    with pytest.raises(AccessConflict):
        tokens.create_application(application.name, actor=system)
    with pytest.raises(AccessConflict):
        tokens.update_application(other, {"name": application.name}, actor=system)
