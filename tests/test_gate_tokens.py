# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""The gate on an exchanged JWT: the token's scopes decide, its state applies at once, and every mode enforces it."""

import pytest
from django.test import override_settings
from rest_framework_simplejwt.tokens import AccessToken

from django_access.services import tokens
from tests import gate_urls
from tests import token_gate_urls as urls
from tests.helpers import bearer

pytestmark = [pytest.mark.django_db, pytest.mark.urls("tests.token_gate_urls")]

MODES = ["enforce", "observe", "off"]


@pytest.fixture
def jwt_of(client):
    """``jwt_of(raw)`` → the Authorization header of the JWT the key buys."""

    def make(raw: str) -> dict:
        response = client.post(urls.EXCHANGE, HTTP_X_API_KEY=raw)
        assert response.status_code == 200, response.content
        return {"HTTP_AUTHORIZATION": f"Bearer {response.json()['access']}"}

    return make


def issue_of(issue, scopes):
    token, raw = issue(scopes)
    return token, raw


def issue_code(response) -> str | None:
    details = response.json().get("details") or [{}]
    return details[0].get("issue")


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(
    ("scopes", "method", "path", "status"),
    [
        (["pim.products:read"], "get", urls.PRODUCTS, 200),
        (["pim.products:read"], "post", urls.PRODUCTS, 403),
        (["pim.products:write"], "post", urls.PRODUCTS, 200),
        (["pim.products:write"], "get", urls.PRODUCTS, 200),
        (["pim.products:write"], "get", urls.SCHEMA, 403),
        (["pim.products:write", "pim.schema:read"], "get", urls.SCHEMA, 200),
        (["pim.products:write"], "delete", urls.PRODUCT_DELETE, 403),
        (["pim.products:write", "pim.product_delete:write"], "delete", urls.PRODUCT_DELETE, 200),
        (["pim.products:read"], "get", gate_urls.BASELINE, 200),
        (["pim.products:read"], "get", gate_urls.UNMAPPED, 403),
        (["pim.products:read"], "get", "/admin/", 403),
    ],
)
def test_the_tokens_scopes_decide_in_every_mode(client, issue, jwt_of, mode, scopes, method, path, status):
    _, raw = issue(scopes)
    headers = jwt_of(raw)
    with override_settings(ACCESS_GATE_MODE=mode):
        response = getattr(client, method)(path, **headers)
    assert response.status_code == status


def test_refusal_names_the_permission(client, issue, jwt_of):
    _, raw = issue(["pim.products:read"])
    response = client.post(urls.PRODUCTS, **jwt_of(raw))
    detail = response.json()["details"][0]
    assert (detail["issue"], detail["description"]) == ("ACCESS_DENIED", "needs pim.products:write")


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("change", ["revoke", "deactivate", "expire"])
def test_a_dead_token_stops_its_live_jwt_at_once(client, issue, application, system, jwt_of, mode, change):
    token, raw = issue(["pim.products:read"])
    issue(["pim.products:read"])  # a second live token keeps the service account staff
    headers = jwt_of(raw)
    assert client.get(urls.PRODUCTS, **headers).status_code == 200
    if change == "revoke":
        tokens.revoke_token(token, actor=system)
    elif change == "deactivate":
        tokens.update_application(application, {"is_active": False}, actor=system)
    else:
        tokens.rotate_token(token, actor=system, overlap_hours=0)
    with override_settings(ACCESS_GATE_MODE=mode):
        response = client.get(urls.PRODUCTS, **headers)
    assert response.status_code == 403
    assert issue_code(response) == "TOKEN_INACTIVE"


def test_revoking_the_last_token_refuses_too(client, issue, system, jwt_of):
    token, raw = issue(["pim.products:read"])
    headers = jwt_of(raw)
    tokens.revoke_token(token, actor=system)
    response = client.get(urls.PRODUCTS, **headers)
    assert (response.status_code, issue_code(response)) == (403, "TOKEN_INACTIVE")


def forged(user, token_id) -> dict:
    jwt = AccessToken.for_user(user)
    jwt[tokens.EXCHANGE_CLAIM] = token_id
    return {"HTTP_AUTHORIZATION": f"Bearer {jwt}"}


@pytest.mark.parametrize("claim", ["other_users_token", "missing_token", "not_an_int"])
def test_a_claim_that_does_not_belong_to_the_user_is_refused(client, issue, person, claim):
    token, _ = issue(["pim.products:read"])
    user = person("superuser")
    token_id = {"other_users_token": token.pk, "missing_token": 999_999, "not_an_int": "1"}[claim]
    response = client.get(urls.PRODUCTS, **forged(user, token_id))
    assert (response.status_code, issue_code(response)) == (403, "TOKEN_INACTIVE")


def test_the_superuser_bypass_never_applies_to_an_exchanged_jwt(client, issue, application, jwt_of):
    _, raw = issue(["pim.products:read"])
    headers = jwt_of(raw)
    application.refresh_from_db()
    application.service_user.is_superuser = True
    application.service_user.save()
    assert client.post(urls.PRODUCTS, **headers).status_code == 403


@pytest.mark.parametrize("mode", ["observe", "off"])
def test_staff_jwts_keep_the_mode(client, person, mode):
    headers = bearer(person("viewer"))
    with override_settings(ACCESS_GATE_MODE=mode):
        assert client.post(urls.PRODUCTS, **headers).status_code == 200


def test_the_service_account_without_a_claim_holds_nothing(client, issue, application):
    issue(["pim.products:write"])
    application.refresh_from_db()
    response = client.get(urls.PRODUCTS, **bearer(application.service_user))
    assert (response.status_code, issue_code(response)) == (403, "ACCESS_DENIED")


def test_outside_the_admin_set_the_gate_does_nothing(client, issue, jwt_of, system):
    token, raw = issue(["pim.products:read"])
    headers = jwt_of(raw)
    tokens.revoke_token(token, actor=system)
    assert client.get(gate_urls.PUBLIC, **headers).status_code == 200


def test_off_mode_skips_a_malformed_bearer(client):
    with override_settings(ACCESS_GATE_MODE="off"):
        assert client.get(urls.PRODUCTS, HTTP_AUTHORIZATION="Bearer").status_code == 401
