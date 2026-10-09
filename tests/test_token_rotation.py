# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Token age and the rotation recommendation (D31): ``age_days`` and ``rotation_due`` in the service, the API, the CLI
and the legacy report; ``token_rotation_days`` in the catalogue. Nothing is refused because of age."""

import json
from datetime import timedelta
from io import StringIO

import pytest
from django.core.management import call_command

from django_access.models import ApiToken
from django_access.services import legacy, tokens
from django_access.services.tokens import hash_key, rotation_due, token_age_days

pytestmark = pytest.mark.django_db

URL = "/api/access/v2/admin/"


@pytest.mark.parametrize(("age", "due"), [(364, False), (365, True), (3650, True)])
def test_rotation_is_due_from_the_setting_on(issue, clock, key_request, age, due):
    token, raw = issue()
    clock.advance(days=age)
    assert (token_age_days(token, clock.now), rotation_due(token, clock.now)) == (age, due)
    assert tokens.verify_api_key(key_request(HTTP_X_API_KEY=raw), "checkout.storefront") == token


def test_the_setting_moves_the_boundary_and_zero_disables_it(issue, clock, settings):
    token, _ = issue()
    clock.advance(days=30)
    settings.ACCESS_TOKEN_ROTATION_DAYS = 30
    assert rotation_due(token, clock.now)
    settings.ACCESS_TOKEN_ROTATION_DAYS = 0
    assert not rotation_due(token, clock.now)
    settings.ACCESS_TOKEN_ROTATION_DAYS = -1
    assert not rotation_due(token, clock.now)


def test_a_revoked_or_expired_token_is_never_due(issue, system, clock):
    expiring, _ = issue(expires_at=clock.now + timedelta(days=400))
    revoked = tokens.revoke_token(issue()[0], actor=system)
    clock.advance(days=500)
    assert not rotation_due(expiring, clock.now) and not rotation_due(revoked, clock.now)


def test_api_create_and_list_show_age_and_rotation(admin_api, application, clock):
    created = admin_api.post(f"{URL}applications/{application.pk}/tokens/", {"scopes": ["vault.api"]}, format="json")
    assert (created.json()["age_days"], created.json()["rotation_due"]) == (0, False)
    clock.advance(days=365)
    [row] = admin_api.get(f"{URL}applications/{application.pk}/tokens/").json()["results"]
    assert (row["age_days"], row["rotation_due"]) == (365, True)


def test_api_expiry_answer_shows_age_and_rotation(admin_api, issue, clock):
    token, _ = issue()
    clock.advance(days=400)
    answer = admin_api.post(f"{URL}tokens/{token.pk}/expiry/", {"expires_at": None}, format="json").json()
    assert (answer["age_days"], answer["rotation_due"]) == (400, True)


def test_catalogue_carries_the_rotation_days(admin_api, settings):
    settings.ACCESS_TOKEN_ROTATION_DAYS = 90
    assert admin_api.get(f"{URL}catalogue/").json()["token_rotation_days"] == 90


def test_cli_list_prints_age_and_rotation_due(issue, clock):
    issue(name="old")
    clock.advance(days=365)
    issue(name="new")
    out = StringIO()
    call_command("access_token", "list", stdout=out)
    old_row, new_row = out.getvalue().splitlines()
    assert "\tage=365d\t" in old_row and old_row.endswith("\trotation due")
    assert "\tage=0d\t" in new_row and "rotation due" not in new_row


def test_legacy_report_shows_age_and_rotation_due(legacy_row, clock, tmp_path):
    row = legacy_row("django_returns.APIKey")
    legacy.import_legacy_keys()
    clock.advance(days=366)
    out, report = StringIO(), tmp_path / "legacy.json"
    call_command("access_legacy_report", "--json", str(report), stdout=out)
    [entry] = json.loads(report.read_text())
    assert (entry["age_days"], entry["rotation_due"]) == (366, True)
    header, line, _ = out.getvalue().splitlines()
    assert header.endswith("\tage_days\trotation_due") and line.endswith("\t366\trotation due")
    assert ApiToken.objects.get(key_hash=hash_key(row.key)).legacy
