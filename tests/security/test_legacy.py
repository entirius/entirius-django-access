# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Legacy keys: short and mixed secrets, ``--check``, the purge on demand, an expiry a team set, and no secret in any
output."""

import logging
import secrets
from datetime import timedelta
from io import StringIO

import pytest
from django.apps import apps
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import IntegrityError
from django.utils import timezone

from django_access.models import ApiToken, AuditAction, AuditEntry
from django_access.services import legacy
from django_access.services.tokens import hash_key, revoke_token, verify_api_key

STOREFRONT, RETURNS = "django_checkout.APIKey", "django_returns.APIKey"


def run(command: str, *args: str) -> tuple[str, CommandError | None]:
    out = StringIO()
    try:
        call_command(command, *args, stdout=out)
    except CommandError as exc:
        return out.getvalue(), exc
    return out.getvalue(), None


def token_of(value: str) -> ApiToken:
    return ApiToken.objects.get(key_hash=hash_key(value))


def rows(model: str) -> int:
    return apps.get_model(model).objects.count()


def purge_rows() -> list[AuditEntry]:
    return list(AuditEntry.objects.filter(action=AuditAction.LEGACY_PURGE))


def back(days: int):
    return timezone.now() - timedelta(days=days)


def test_a_short_secret_shows_no_character(legacy_row, key_request):
    value = secrets.token_hex(10)  # 20 characters, as a human might have typed
    row = legacy_row(STOREFRONT, channel="emporium", key=value)
    report = legacy.import_legacy_keys()
    token = token_of(value)
    assert (token.prefix, token.last_four, token.display) == ("legacy", "", "legacy…")
    assert report.sources[STOREFRONT].short == [f"{STOREFRONT}#{row.pk}"]
    assert verify_api_key(key_request(HTTP_X_API_KEY=value), "checkout.storefront", "emporium") == token


def test_the_checkout_fixture_shape_keeps_the_normal_display(legacy_row):
    value = secrets.token_urlsafe(28)[:37]  # 37 characters, not hex
    legacy_row(STOREFRONT, channel="emporium", key=value)
    assert legacy.import_legacy_keys().total("short") == 0
    assert (token_of(value).prefix, token_of(value).last_four) == (value[:6], value[-4:])


@pytest.fixture
def mixed(legacy_row):
    """One secret in the storefront (publishable) and in returns (secret)."""
    shop = legacy_row(STOREFRONT, channel="emporium")
    erase = legacy_row(RETURNS, key=shop.key)
    return shop, [f"{STOREFRONT}#{shop.pk}", f"{RETURNS}#{erase.pk}"]


def test_a_mixed_secret_gets_no_token_and_fails_check(mixed):
    shop, refs = mixed
    report = legacy.import_legacy_keys()
    assert not ApiToken.objects.filter(key_hash=hash_key(shop.key)).exists()
    assert report.mixed == [refs]
    assert report.sources[STOREFRONT].mixed == refs[:1]
    out, error = run("access_import_legacy_keys", "--check")
    assert error is not None and "1 mixed" in str(error)
    assert f"MIXED legacy secret in {', '.join(refs)} — not imported, rotate before deploying" in out


def test_check_passes_after_a_clean_import(legacy_row):
    legacy_row(STOREFRONT, channel="emporium")
    legacy_row("django_contact_forms.APIKey")  # no channel: authenticates nothing today, never counts
    legacy.import_legacy_keys()
    out, error = run("access_import_legacy_keys", "--check")
    assert error is None and "Legacy keys OK" in out


def test_check_fails_on_one_unimported_row_and_writes_nothing(legacy_row):
    legacy_row(STOREFRONT, channel="emporium")
    legacy.import_legacy_keys()
    late = legacy_row(RETURNS)
    out, error = run("access_import_legacy_keys", "--check")
    assert error is not None and "1 not imported" in str(error)
    assert f"  missing: {RETURNS}#{late.pk}" in out
    assert ApiToken.objects.count() == 1


@pytest.mark.parametrize(
    ("model", "fields"),
    [(STOREFRONT, {"channel": "outlet"}), ("django_contact_forms.APIKey", {"channel": "emporium"})],
)
def test_a_row_the_existing_token_does_not_serve_is_stale_and_fails_check(legacy_row, model, fields):
    """The secret is copied to another channel or another source after the import: the token is never widened."""
    first = legacy_row(STOREFRONT, channel="emporium")
    legacy.import_legacy_keys()
    late = legacy_row(model, key=first.key, **fields)
    report = legacy.import_legacy_keys()
    assert f"{model}#{late.pk}" in report.sources[model].stale
    assert token_of(first.key).scopes == ["checkout.storefront"] and token_of(first.key).channel_idx == "emporium"
    _, error = run("access_import_legacy_keys", "--check")
    assert error is not None and "stale" in str(error)


def test_check_fails_on_a_failing_source(legacy_row, monkeypatch):
    legacy.import_legacy_keys()
    monkeypatch.setattr(legacy, "_rows", lambda model, source: 1 / 0)
    out, error = run("access_import_legacy_keys", "--check")
    assert error is not None and "FAILED" in out


def test_check_fails_on_an_unimported_agreements_setting(settings, db):
    settings.AGREEMENTS_API_KEY = secrets.token_hex(32)
    _, error = run("access_import_legacy_keys", "--check")
    assert error is not None


def used(value: str, days_ago: int) -> None:
    ApiToken.objects.filter(key_hash=hash_key(value)).update(last_used_at=back(days_ago))


def test_purge_without_yes_only_lists(legacy_row):
    row = legacy_row(STOREFRONT, channel="emporium")
    legacy.import_legacy_keys()
    out, error = run("access_purge_legacy_keys")
    assert error is None and rows(STOREFRONT) == 1 and purge_rows() == []
    assert out.startswith("Listing only") and f"  deleted: {STOREFRONT}#{row.pk}" in out


def test_purge_with_yes_deletes_without_a_time_gate(legacy_row):
    row = legacy_row(STOREFRONT, channel="emporium")
    legacy_row(RETURNS)
    legacy.import_legacy_keys()
    out, error = run("access_purge_legacy_keys", "--yes")
    assert error is None and rows(STOREFRONT) == rows(RETURNS) == 0
    assert f"  deleted: {STOREFRONT}#{row.pk}" in out
    [entry] = purge_rows()
    assert entry.detail["deleted"] == 2 and row.key not in str(entry.detail)


def test_a_recently_used_key_is_refused_without_force(legacy_row):
    row = legacy_row(STOREFRONT, channel="emporium")
    legacy.import_legacy_keys()
    used(row.key, 3)
    out, error = run("access_purge_legacy_keys", "--yes")
    assert error is not None and rows(STOREFRONT) == 1 and purge_rows() == []
    assert f"  refused: {STOREFRONT}#{row.pk} (last used {token_of(row.key).last_used_at.isoformat()})" in out
    assert run("access_purge_legacy_keys", "--yes", "--recent-days", "2")[1] is None and rows(STOREFRONT) == 0


def test_force_deletes_a_recently_used_key(legacy_row):
    row = legacy_row(RETURNS)
    legacy.import_legacy_keys()
    used(row.key, 0)
    _, error = run("access_purge_legacy_keys", "--yes", "--force")
    assert error is None and rows(RETURNS) == 0 and purge_rows()[0].detail["force"] is True


def test_a_revoked_key_used_recently_is_not_in_use(legacy_row, system):
    row = legacy_row(RETURNS)
    legacy.import_legacy_keys()
    used(row.key, 0)
    revoke_token(token_of(row.key), actor=system)
    _, error = run("access_purge_legacy_keys", "--yes")
    assert error is None and rows(RETURNS) == 0


def test_a_second_purge_is_a_no_op(legacy_row, system):
    legacy_row(RETURNS)
    legacy.import_legacy_keys()
    legacy.purge_legacy_sources(actor=system)
    report = legacy.purge_legacy_sources(actor=system)
    assert report.ids(legacy.DELETED) == [] and len(purge_rows()) == 1


def test_force_deletes_never_imported_rows(legacy_row, mixed):
    legacy_row(RETURNS)
    legacy_row("django_contact_forms.APIKey")  # null channel, never imported
    legacy.import_legacy_keys()
    _, error = run("access_purge_legacy_keys", "--yes", "--force")
    assert error is None
    assert rows(STOREFRONT) == rows(RETURNS) == rows("django_contact_forms.APIKey") == 0


def test_never_imported_rows_are_kept_without_force(mixed):
    legacy.import_legacy_keys()
    out, error = run("access_purge_legacy_keys", "--yes")
    assert error is None and rows(STOREFRONT) == rows(RETURNS) == 1
    assert "not_imported 1" in out


def test_dry_run_is_an_alias_of_listing(legacy_row):
    legacy_row(RETURNS)
    legacy.import_legacy_keys()
    out, _ = run("access_purge_legacy_keys", "--dry-run", "--yes", "--force")
    assert out.startswith("Listing only") and rows(RETURNS) == 1 and purge_rows() == []


def test_the_agreements_setting_is_named_unless_in_use(settings, db):
    settings.AGREEMENTS_API_KEY = secrets.token_hex(32)
    legacy.import_legacy_keys()
    used(settings.AGREEMENTS_API_KEY, 1)
    assert "remove AGREEMENTS_API_KEY" not in run("access_purge_legacy_keys", "--yes")[0]
    used(settings.AGREEMENTS_API_KEY, 31)
    assert "remove AGREEMENTS_API_KEY from settings_local" in run("access_purge_legacy_keys", "--yes")[0]


def test_an_expired_legacy_token_is_refused_and_never_revived(legacy_row, key_request):
    row = legacy_row(STOREFRONT, channel="emporium")
    legacy.import_legacy_keys()
    ApiToken.objects.update(expires_at=back(1))
    expiry = token_of(row.key).expires_at
    request = key_request(HTTP_X_API_KEY=row.key)
    assert verify_api_key(request, "checkout.storefront", "emporium") is None
    legacy.import_legacy_keys()
    assert token_of(row.key).expires_at == expiry
    assert verify_api_key(request, "checkout.storefront", "emporium") is None


@pytest.fixture
def everything(legacy_row, settings, monkeypatch, caplog):
    """Import, re-run, a source failing with a hash in its message, ``--report`` and ``--check``; every secret seen."""
    caplog.set_level(logging.DEBUG)
    settings.AGREEMENTS_API_KEY = secrets.token_hex(32)
    values = [legacy_row(STOREFRONT, channel="emporium").key, legacy_row(RETURNS).key, settings.AGREEMENTS_API_KEY]
    values.append(legacy_row("django_vault.APIKey", key=secrets.token_hex(8)).key)
    legacy.import_legacy_keys()
    legacy.import_legacy_keys()
    hashes = list(ApiToken.objects.values_list("key_hash", flat=True))
    rows_of = legacy._rows

    def failing(model, source):
        if source.model == RETURNS:
            raise IntegrityError(f"duplicate key value (key_hash)=({hashes[0]}) {values[1]}")
        return rows_of(model, source)

    monkeypatch.setattr(legacy, "_rows", failing)
    legacy.import_legacy_keys()
    output = run("access_import_legacy_keys", "--report")[0] + run("access_import_legacy_keys", "--check")[0]
    return [*values, *hashes], output


def test_no_log_record_holds_a_value_or_a_hash(everything, caplog):
    secrets_seen, _ = everything
    records = caplog.get_records("setup") + caplog.get_records("call")
    assert any("IntegrityError" in record.getMessage() for record in records)
    assert not [r.name for r in records if any(secret in r.getMessage() for secret in secrets_seen)]


def test_no_output_or_audit_row_holds_a_value_or_a_hash(everything):
    secrets_seen, output = everything
    audit = str(list(AuditEntry.objects.values()))
    assert not any(secret in output or secret in audit for secret in secrets_seen)
    assert len(secrets_seen) == 8
