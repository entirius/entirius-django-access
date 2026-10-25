# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""``POST token/exchange``: the body, the claim and lifetime, one 401 for every refusal, throttles, last-used, logs."""

import logging
from datetime import timedelta

import pytest
from django.core.cache import cache
from django.test import override_settings
from rest_framework_simplejwt.tokens import AccessToken

from django_access.models import AuditEntry
from django_access.services import tokens
from tests import token_gate_urls as urls

pytestmark = [pytest.mark.django_db, pytest.mark.urls("tests.token_gate_urls")]

ADMIN = ["pim.products:write"]


def exchange(client, raw: str | None, header: str = "HTTP_X_API_KEY"):
    extra = {header: raw} if raw is not None else {}
    return client.post(urls.EXCHANGE, **extra)


def test_exchange_returns_a_short_lived_jwt_of_the_service_user(client, issue, application):
    token, raw = issue(ADMIN)
    response = exchange(client, raw)
    assert response.status_code == 200
    assert response["Cache-Control"] == "no-store"
    body = response.json()
    assert set(body) == {"access", "token_type", "expires_in"}
    assert (body["token_type"], body["expires_in"]) == ("Bearer", 300)
    jwt = AccessToken(body["access"])
    application.refresh_from_db()
    assert jwt["user_id"] == str(application.service_user_id)
    assert jwt[tokens.EXCHANGE_CLAIM] == token.pk
    assert 290 <= jwt["exp"] - jwt["iat"] <= 300


def test_the_alias_header_works(client, issue):
    _, raw = issue(ADMIN)
    assert exchange(client, raw, "HTTP_X_API_ADMIN_KEY").status_code == 200


@override_settings(ACCESS_TOKEN_EXCHANGE_TTL_S=900)
def test_the_lifetime_is_a_setting(client, issue):
    _, raw = issue(ADMIN)
    body = exchange(client, raw).json()
    jwt = AccessToken(body["access"])
    assert body["expires_in"] == 900
    assert 890 <= jwt["exp"] - jwt["iat"] <= 900


def refusal(response) -> dict:
    assert response.status_code == 401
    body = response.json()
    body.pop("debug_id")
    return body


EXPECTED_401 = {
    "error": "AUTHENTICATION_REQUIRED",
    "message": "Authentication credentials were not provided or are invalid.",
    "details": [
        {
            "field": None,
            "location": "header",
            "issue": "INVALID_API_KEY",
            "description": "An active application key with an admin scope is required in X-API-KEY.",
        }
    ],
}


@pytest.mark.parametrize("cause", ["missing", "unknown", "revoked", "expired", "inactive", "key_route_only"])
def test_every_refusal_is_the_same_401(client, issue, application, system, clock, cause):
    token, raw = issue(["vault.api"] if cause == "key_route_only" else ADMIN, expires_at=clock.now + timedelta(hours=1))
    if cause == "missing":
        raw = None
    elif cause == "unknown":
        raw = raw[:-4] + "zzzz"
    elif cause == "revoked":
        tokens.revoke_token(token, actor=system)
    elif cause == "expired":
        clock.advance(hours=2)
    elif cause == "inactive":
        tokens.update_application(application, {"is_active": False}, actor=system)
    response = exchange(client, raw)
    assert response["WWW-Authenticate"] == 'ApiKey realm="api", header="X-API-KEY"'
    assert refusal(response) == EXPECTED_401


def test_a_superuser_service_account_is_refused(client, issue, application):
    _, raw = issue(ADMIN)
    application.refresh_from_db()
    application.service_user.is_superuser = True
    application.service_user.save()
    assert refusal(exchange(client, raw)) == EXPECTED_401


def test_exchange_updates_last_used_and_writes_no_audit_row(client, issue):
    token, raw = issue(ADMIN)
    rows = AuditEntry.objects.count()
    exchange(client, raw)
    token.refresh_from_db()
    assert token.last_used_at is not None
    assert AuditEntry.objects.count() == rows


def test_exchange_logs_ids_never_the_key_or_the_jwt(client, issue, caplog):
    token, raw = issue(ADMIN)
    with caplog.at_level(logging.INFO, logger="django_access.tokens"):
        jwt = exchange(client, raw).json()["access"]
    assert f"token={token.pk}" in caplog.text
    assert raw not in caplog.text and jwt not in caplog.text and token.key_hash not in caplog.text


def test_get_is_not_allowed(client, issue):
    _, raw = issue(ADMIN)
    assert client.get(urls.EXCHANGE, HTTP_X_API_KEY=raw).status_code == 405


@pytest.fixture
def throttled():
    cache.clear()
    yield
    cache.clear()


def test_exchange_is_throttled_per_key(client, issue, throttled, monkeypatch):
    from django_access.api import exchange as view_module

    monkeypatch.setattr(view_module.KeyThrottle, "default_rate", "2/min")
    _, raw = issue(ADMIN)
    _, other = issue(ADMIN)
    assert [exchange(client, raw).status_code for _ in range(3)] == [200, 200, 429]
    assert exchange(client, other).status_code == 200


def test_exchange_is_throttled_per_address(client, throttled, monkeypatch):
    from django_access.api import exchange as view_module

    monkeypatch.setattr(view_module.AddressThrottle, "default_rate", "2/min")
    codes = [exchange(client, f"ent_api_unknown{n}").status_code for n in range(3)]
    assert codes == [401, 401, 429]


def test_a_key_less_flood_hits_the_address_throttle(client, throttled, monkeypatch):
    from django_access.api import exchange as view_module

    monkeypatch.setattr(view_module.AddressThrottle, "default_rate", "2/min")
    assert [exchange(client, None).status_code for _ in range(3)] == [401, 401, 429]


def test_the_setting_overrides_the_default_rate(client, issue, throttled, monkeypatch):
    from django_access.api import exchange as view_module

    rates = {"access_token_exchange": "1/min", "access_token_exchange_address": "100/min"}
    monkeypatch.setattr(view_module.KeyThrottle, "THROTTLE_RATES", rates)
    _, raw = issue(ADMIN)
    assert [exchange(client, raw).status_code for _ in range(2)] == [200, 429]


@pytest.mark.parametrize("configured", ["missing", "nonsense", None])
@pytest.mark.parametrize(("name", "default"), [("KeyThrottle", "30/min"), ("AddressThrottle", "120/min")])
def test_a_missing_or_malformed_rate_falls_back_to_the_default(monkeypatch, configured, name, default):
    from django_access.api import exchange as view_module

    throttle = getattr(view_module, name)
    rates = {} if configured == "missing" else {throttle.scope: configured}
    monkeypatch.setattr(throttle, "THROTTLE_RATES", rates)
    assert throttle().get_rate() == default
