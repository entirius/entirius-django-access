# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
from datetime import timedelta
from io import StringIO

import pytest
from django.core.management import call_command
from django.utils import timezone

from django_access.models import ApiToken, AuditAction, AuditEntry
from django_access.services import legacy
from django_access.services.tokens import hash_key

SOURCES = [
    ("django_accounts.APIAdminKey", {"channel": "emporium"}, "accounts.erase", "emporium"),
    ("django_checkout.APIAdminKey", {"channel": "emporium"}, "checkout.erase", "emporium"),
    ("django_checkout.APIKey", {"channel": "emporium"}, "checkout.storefront", "emporium"),
    ("django_contact_forms.APIKey", {"channel": "emporium"}, "contact_forms.submit", "emporium"),
    ("django_contact_forms.APIKey", {"channel": "emporium", "scope": "booking"}, "contact_forms.booking", "emporium"),
    ("django_returns.APIKey", {}, "returns.api", None),
    ("django_reviews.APIKey", {}, "reviews.moderate", None),
    ("django_vault.APIKey", {}, "vault.api", None),
]


def token_of(value: str) -> ApiToken:
    return ApiToken.objects.select_related("application").get(key_hash=hash_key(value))


def import_runs() -> int:
    return AuditEntry.objects.filter(action=AuditAction.LEGACY_IMPORT).count()


@pytest.mark.parametrize(("model", "fields", "scope", "channel"), SOURCES)
def test_every_source_is_imported_with_the_same_secret(legacy_row, model, fields, scope, channel):
    row = legacy_row(model, **fields)
    now = timezone.now()
    report = legacy.import_legacy_keys(now=now)
    token = token_of(row.key)
    assert (token.scopes, token.channel_idx, token.legacy) == ([scope], channel, True)
    assert token.legacy_source == f"{model}#{row.pk}"
    assert (token.prefix, token.last_four) == (row.key[:6], row.key[-4:])
    assert token.expires_at == now + timedelta(days=90)
    assert token.application.name == f"Legacy keys: {model.split('.')[0]}"
    assert report.sources[model].imported == [f"{model}#{row.pk}"]


def test_one_application_per_module(legacy_row):
    legacy_row("django_checkout.APIKey", channel="emporium")
    legacy_row("django_checkout.APIAdminKey", channel="emporium")
    legacy.import_legacy_keys()
    assert set(ApiToken.objects.values_list("application__name", flat=True)) == {"Legacy keys: django_checkout"}


def test_ttl_follows_the_setting(legacy_row, settings):
    settings.ACCESS_LEGACY_KEY_TTL_DAYS = 7
    row = legacy_row("django_vault.APIKey")
    now = timezone.now()
    legacy.import_legacy_keys(now=now)
    assert token_of(row.key).expires_at == now + timedelta(days=7)


def test_rerun_is_idempotent_and_never_extends_the_expiry(legacy_row):
    row = legacy_row("django_checkout.APIKey", channel="emporium")
    first = timezone.now() - timedelta(days=30)
    legacy.import_legacy_keys(now=first)
    report = legacy.import_legacy_keys()
    assert ApiToken.objects.count() == 1
    assert token_of(row.key).expires_at == first + timedelta(days=90)
    assert report.sources["django_checkout.APIKey"].present == [f"django_checkout.APIKey#{row.pk}"]
    assert import_runs() == 1


def test_a_secret_shared_by_two_channels_becomes_one_unpinned_token(legacy_row):
    one = legacy_row("django_checkout.APIKey", channel="emporium")
    two = legacy_row("django_checkout.APIKey", channel="outlet", key=one.key)
    report = legacy.import_legacy_keys()
    token = token_of(one.key)
    assert (ApiToken.objects.count(), token.channel_idx, token.scopes) == (1, None, ["checkout.storefront"])
    refs = [f"django_checkout.APIKey#{one.pk}", f"django_checkout.APIKey#{two.pk}"]
    assert report.sources["django_checkout.APIKey"].unpinned == refs
    assert token.legacy_source == ",".join(refs)


def test_a_secret_in_two_secret_sources_holds_both_scopes(legacy_row):
    row = legacy_row("django_returns.APIKey")
    legacy_row("django_vault.APIKey", key=row.key)
    legacy.import_legacy_keys()
    assert token_of(row.key).scopes == ["returns.api", "vault.api"]


@pytest.mark.parametrize("model", ["django_contact_forms.APIKey", "django_checkout.APIKey"])
def test_a_row_without_a_channel_is_skipped_and_reported(legacy_row, model):
    row = legacy_row(model)
    report = legacy.import_legacy_keys()
    assert not ApiToken.objects.exists()
    assert report.sources[model].skipped == [f"{model}#{row.pk}"]


@pytest.mark.parametrize(
    ("model", "fields"),
    [("django_vault.APIKey", {"key": ""}), ("django_contact_forms.APIKey", {"channel": "emporium", "scope": "other"})],
)
def test_an_empty_value_or_an_unknown_scope_is_skipped(legacy_row, model, fields):
    row = legacy_row(model, **fields)
    assert legacy.import_legacy_keys().sources[model].skipped == [f"{model}#{row.pk}"]
    assert not ApiToken.objects.exists()


def test_the_agreements_setting_is_imported_when_set(settings, db):
    settings.AGREEMENTS_API_KEY = "a" * 40
    report = legacy.import_legacy_keys()
    token = token_of("a" * 40)
    assert (token.scopes, token.legacy_source) == (["agreements.subscribe"], "settings.AGREEMENTS_API_KEY")
    assert token.application.name == "Legacy keys: django_agreements"
    assert report.sources["settings.AGREEMENTS_API_KEY"].imported == ["settings.AGREEMENTS_API_KEY"]


def test_an_unset_agreements_setting_imports_nothing(settings, db):
    settings.AGREEMENTS_API_KEY = ""
    assert "settings.AGREEMENTS_API_KEY" not in legacy.import_legacy_keys().sources
    assert not ApiToken.objects.exists()


def test_a_failing_source_does_not_stop_the_others(legacy_row, monkeypatch, caplog):
    vault = legacy_row("django_vault.APIKey")
    legacy_row("django_returns.APIKey")
    rows = legacy._rows

    def broken(model, source):
        if source.model == "django_returns.APIKey":
            raise RuntimeError("boom")
        return rows(model, source)

    monkeypatch.setattr(legacy, "_rows", broken)
    report = legacy.import_legacy_keys()
    assert token_of(vault.key).scopes == ["vault.api"]
    assert report.failed == ["django_returns.APIKey"]
    assert "django_returns.APIKey (RuntimeError)" in caplog.text
    assert "boom" not in caplog.text


def test_dry_run_writes_nothing(legacy_row):
    row = legacy_row("django_vault.APIKey")
    report = legacy.import_legacy_keys(dry_run=True)
    assert report.sources["django_vault.APIKey"].imported == [f"django_vault.APIKey#{row.pk}"]
    assert not ApiToken.objects.exists()
    assert import_runs() == 0


def test_one_audit_row_per_run_that_imported(legacy_row):
    legacy.import_legacy_keys()
    assert import_runs() == 0
    row = legacy_row("django_vault.APIKey")
    legacy.import_legacy_keys()
    entry = AuditEntry.objects.get(action=AuditAction.LEGACY_IMPORT)
    assert entry.actor_label == "system"
    assert entry.detail == {"django_vault.APIKey": {"imported": [f"django_vault.APIKey#{row.pk}"]}}


@pytest.mark.django_db(transaction=True)
def test_migrate_imports_the_legacy_keys(legacy_row):
    row = legacy_row("django_reviews.APIKey")
    call_command("migrate", verbosity=0)
    assert token_of(row.key).scopes == ["reviews.moderate"]


@pytest.mark.django_db(transaction=True)
def test_migrate_never_fails_because_of_the_import(legacy_row, monkeypatch, caplog):
    monkeypatch.setattr(legacy, "import_legacy_keys", lambda: 1 / 0)
    call_command("migrate", verbosity=0)
    assert "Legacy key import failed (ZeroDivisionError)" in caplog.text


def test_command_prints_counts_and_with_report_the_ids(legacy_row):
    row = legacy_row("django_vault.APIKey")
    out = StringIO()
    call_command("access_import_legacy_keys", "--report", stdout=out)
    lines = out.getvalue().splitlines()
    assert "django_returns.APIKey: imported 0, present 0, skipped 0, unpinned 0, short 0, mixed 0, stale 0" in lines
    vault = lines.index("django_vault.APIKey: imported 1, present 0, skipped 0, unpinned 0, short 0, mixed 0, stale 0")
    assert lines[vault + 1] == f"  imported: django_vault.APIKey#{row.pk}"
    assert row.key not in out.getvalue()


def test_command_dry_run_writes_nothing(legacy_row):
    legacy_row("django_vault.APIKey")
    call_command("access_import_legacy_keys", "--dry-run", stdout=StringIO())
    assert not ApiToken.objects.exists()
