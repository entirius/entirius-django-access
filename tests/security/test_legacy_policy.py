# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Legacy key lifetime (D28): no automatic expiry, the migration clearing it, a per-token expiry a team sets or clears
(service, API, CLI; audited), and the usage report — never a secret in any output."""

import importlib
import json
from datetime import timedelta
from io import StringIO

import pytest
from django.apps import apps
from django.core.management import call_command
from django.core.management.base import CommandError
from django.utils import timezone

from django_access.exceptions import AccessConflict, TokenExpiryError
from django_access.models import ApiToken, AuditAction, AuditEntry
from django_access.services import legacy, tokens
from django_access.services.tokens import hash_key, verify_api_key

RETURNS, STOREFRONT = "django_returns.APIKey", "django_checkout.APIKey"
URL = "/api/access/v2/admin/tokens/{}/expiry/"
MIGRATION = importlib.import_module("django_access.migrations.0004_legacy_tokens_without_expiry")


def days(n: int):
    return timezone.now() + timedelta(days=n)


def imported(legacy_row, model: str = RETURNS, **fields) -> tuple[ApiToken, str]:
    """A legacy token (secret ``returns.api`` by default) and its legacy value."""
    row = legacy_row(model, **fields)
    legacy.import_legacy_keys()
    return ApiToken.objects.get(key_hash=hash_key(row.key)), row.key


def expiry_rows() -> list[dict]:
    return list(AuditEntry.objects.filter(action=AuditAction.TOKEN_EXPIRY).values_list("detail", flat=True))


def test_a_legacy_token_still_verifies_ten_years_on(legacy_row, key_request, clock):
    _, value = imported(legacy_row)
    clock.advance(days=3653)
    assert verify_api_key(key_request(HTTP_X_API_KEY=value), "returns.api") is not None


def test_the_migration_clears_automatic_expiries_and_keeps_team_set_ones(legacy_row, system):
    automatic, _ = imported(legacy_row)
    team, _ = imported(legacy_row, STOREFRONT, channel="emporium")
    rotated, _ = imported(legacy_row, "django_vault.APIKey")
    tokens.rotate_token(rotated, actor=system, overlap_hours=24)
    issued, _ = tokens.issue_token(automatic.application, scopes=["vault.api"], expires_at=days(30), actor=system)
    tokens.set_token_expiry(team, expires_at=days(60), actor=system)
    ApiToken.objects.filter(pk=automatic.pk).update(expires_at=days(90))
    MIGRATION.clear_automatic_expiry(apps, None)
    MIGRATION.clear_automatic_expiry(apps, None)
    expiries = dict(ApiToken.objects.values_list("pk", "expires_at"))
    assert expiries[automatic.pk] is None
    assert expiries[team.pk] is not None and expiries[issued.pk] is not None
    assert expiries[rotated.pk] is not None  # the overlap cutoff of a rotation is a team's choice too


@pytest.mark.parametrize("expires_at", [days(3650), None])
def test_a_legacy_secret_token_takes_any_future_date_or_none(legacy_row, system, expires_at):
    token, _ = imported(legacy_row)
    assert tokens.set_token_expiry(token, expires_at=expires_at, actor=system).expires_at == expires_at
    [detail] = expiry_rows()
    assert detail == {
        "token_id": token.pk,
        "legacy": True,
        "from": None,
        "to": expires_at.isoformat() if expires_at else None,
    }


@pytest.mark.parametrize(
    ("expires_at", "code"),
    [(None, TokenExpiryError.EXPIRY_REQUIRED), (days(400), TokenExpiryError.EXPIRY_TOO_LONG)],
)
def test_an_issued_secret_token_keeps_d21(issue, system, expires_at, code):
    token, _ = issue(["vault.api"], expires_at=days(30))
    with pytest.raises(TokenExpiryError) as raised:
        tokens.set_token_expiry(token, expires_at=expires_at, actor=system)
    assert raised.value.code == code and expiry_rows() == []


def test_an_issued_publishable_token_may_clear_its_expiry(issue, system):
    token, _ = issue(expires_at=days(30))
    assert tokens.set_token_expiry(token, expires_at=None, actor=system).expires_at is None


def test_a_past_expiry_is_refused(legacy_row, system):
    token, _ = imported(legacy_row)
    with pytest.raises(TokenExpiryError) as raised:
        tokens.set_token_expiry(token, expires_at=days(-1), actor=system)
    assert raised.value.code == TokenExpiryError.EXPIRY_IN_PAST and expiry_rows() == []


def test_a_revoked_token_is_refused(legacy_row, system):
    token, _ = imported(legacy_row)
    tokens.revoke_token(token, actor=system)
    with pytest.raises(AccessConflict):
        tokens.set_token_expiry(token, expires_at=None, actor=system)
    assert expiry_rows() == []


def test_api_sets_and_clears_without_secret_material(legacy_row, admin_api):
    token, value = imported(legacy_row)
    later = days(30).isoformat()
    set_ = admin_api.post(URL.format(token.pk), {"expires_at": later}, format="json")
    cleared = admin_api.post(URL.format(token.pk), {"expires_at": None}, format="json")
    assert (set_.status_code, cleared.status_code) == (200, 200)
    assert set_.json()["expires_at"] is not None and cleared.json()["expires_at"] is None
    body = set_.content.decode() + cleared.content.decode()
    assert value not in body and token.key_hash not in body and len(expiry_rows()) == 2


@pytest.mark.parametrize(
    ("body", "issue"),
    [({"expires_at": "2000-01-01T00:00:00Z"}, "EXPIRY_IN_PAST"), ({"expires_at": None, "legacy": False}, None)],
)
def test_api_400(legacy_row, admin_api, body, issue):
    token, value = imported(legacy_row)
    response = admin_api.post(URL.format(token.pk), body, format="json")
    assert response.status_code == 400 and value not in response.content.decode()
    if issue:
        assert [detail["issue"] for detail in response.json()["details"]] == [issue]


def test_api_400_for_an_issued_secret_token_without_expiry(issue, admin_api):
    token, _ = issue(["vault.api"], expires_at=days(30))
    response = admin_api.post(URL.format(token.pk), {"expires_at": None}, format="json")
    assert [detail["issue"] for detail in response.json()["details"]] == ["EXPIRY_REQUIRED"]


@pytest.mark.parametrize("name", ["staff", "manager"])
def test_api_403_without_access_manage(legacy_row, person, api_as, name):
    token, _ = imported(legacy_row)
    response = api_as(person(name)).post(URL.format(token.pk), {"expires_at": None}, format="json")
    assert response.status_code == 403 and expiry_rows() == []


def test_cli_expire_at_and_clear(legacy_row):
    token, value = imported(legacy_row)
    out = StringIO()
    call_command("access_token", "expire", str(token.pk), "--at", days(10).date().isoformat(), stdout=out)
    assert ApiToken.objects.get(pk=token.pk).expires_at is not None
    call_command("access_token", "expire", str(token.pk), "--clear", stdout=out)
    assert ApiToken.objects.get(pk=token.pk).expires_at is None
    assert value not in out.getvalue() and len(expiry_rows()) == 2


def test_cli_expire_refuses_a_past_date(legacy_row):
    token, _ = imported(legacy_row)
    with pytest.raises(CommandError, match="must be in the future"):
        call_command("access_token", "expire", str(token.pk), "--at", "2000-01-01", stdout=StringIO())


def test_report_rows_and_json_hold_no_secret(legacy_row, settings, tmp_path):
    settings.AGREEMENTS_API_KEY = "s" * 12  # short: shows no character
    returns, value = imported(legacy_row)
    ApiToken.objects.filter(pk=returns.pk).update(last_used_at=timezone.now())
    out, report = StringIO(), tmp_path / "legacy.json"
    call_command("access_legacy_report", "--json", str(report), stdout=out)
    rows = json.loads(report.read_text())
    assert [row["source"] for row in rows] == [returns.legacy_source, "settings.AGREEMENTS_API_KEY"]
    agreements = rows[1]
    assert (agreements["last_used_at"], agreements["expires_at"], agreements["state"]) == ("never", "none", "active")
    assert agreements["display"] == "legacy…" and rows[0]["last_used_at"] != "never"
    text = out.getvalue() + report.read_text()
    hashes = ApiToken.objects.values_list("key_hash", flat=True)
    assert not any(secret in text for secret in [value, "s" * 12, *hashes])


def test_report_filters_by_module(legacy_row, settings):
    settings.AGREEMENTS_API_KEY = "a" * 40
    imported(legacy_row)
    out = StringIO()
    call_command("access_legacy_report", "--module", "django_agreements", stdout=out)
    lines = out.getvalue().splitlines()
    assert len(lines) == 3 and "settings.AGREEMENTS_API_KEY" in lines[1] and lines[2] == "1 legacy token(s)"
