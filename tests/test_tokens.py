# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
import hashlib
import re
from datetime import timedelta

import pytest
from django.db import IntegrityError, connection
from django.test.utils import CaptureQueriesContext

from django_access.exceptions import AccessConflict
from django_access.models import ApiToken, Application, AuditEntry
from django_access.services import tokens
from django_access.services.access_service import Actor

pytestmark = pytest.mark.django_db

STOREFRONT = "checkout.storefront"
RAW_FORMAT = re.compile(r"ent_api_[A-Za-z0-9_-]{43}")


def updates(queries) -> int:
    return sum(query["sql"].startswith("UPDATE") for query in queries.captured_queries)


def test_raw_value_format_and_display_fields(issue):
    token, raw = issue()
    assert RAW_FORMAT.fullmatch(raw)
    assert (token.prefix, token.last_four) == (raw[:12], raw[-4:])
    assert token.key_hash == hashlib.sha256(raw.encode()).hexdigest()


def test_only_the_hash_is_stored(issue):
    token, raw = issue()
    row = ApiToken.objects.filter(pk=token.pk).values().get()
    leaked = any(raw in str(value) for value in row.values())
    assert not leaked, "the raw value is stored in the token row"
    assert row["key_hash"] == tokens.hash_key(raw)


def test_hash_is_unique(issue, application):
    token, _ = issue()
    with pytest.raises(IntegrityError):
        ApiToken.objects.create(application=application, prefix="x", key_hash=token.key_hash, scopes=[STOREFRONT])


def test_two_issues_never_share_a_value(issue):
    (first, _), (second, _) = issue(), issue()
    assert first.key_hash != second.key_hash


def test_scopes_are_validated_and_normalised(issue):
    token, _ = issue([STOREFRONT, "contact_forms.submit", STOREFRONT])
    assert token.scopes == ["checkout.storefront", "contact_forms.submit"]
    for scopes in ([], ["nope.scope"]):
        with pytest.raises(ValueError):
            issue(scopes)


def test_valid_token_is_returned_and_attached(issue, key_request):
    token, raw = issue()
    request = key_request(HTTP_X_API_KEY=raw)
    assert tokens.verify_api_key(request, STOREFRONT) == token
    assert request.access_token == token


@pytest.mark.parametrize("header", ["HTTP_X_API_KEY", "HTTP_X_API_ADMIN_KEY"])
def test_both_headers_are_accepted(issue, key_request, header):
    token, raw = issue()
    assert tokens.verify_api_key(key_request(**{header: raw}), STOREFRONT) == token


def test_x_api_key_wins_over_the_alias(issue, key_request):
    (first, first_raw), (_, second_raw) = issue(), issue()
    both = key_request(HTTP_X_API_KEY=first_raw, HTTP_X_API_ADMIN_KEY=second_raw)
    assert tokens.verify_api_key(both, STOREFRONT) == first
    unknown_first = key_request(HTTP_X_API_KEY="ent_api_unknown", HTTP_X_API_ADMIN_KEY=second_raw)
    assert tokens.verify_api_key(unknown_first, STOREFRONT) is None


def test_missing_header_is_refused(key_request):
    assert tokens.verify_api_key(key_request(), STOREFRONT) is None


def test_refusals(issue, key_request, application, system, clock):
    expired, expired_raw = issue(expires_at=clock.now + timedelta(hours=1))
    revoked, revoked_raw = issue()
    tokens.revoke_token(revoked, actor=system)
    _, valid_raw = issue()
    clock.advance(hours=1)
    assert tokens.verify_api_key(key_request(HTTP_X_API_KEY=expired_raw), STOREFRONT) is None
    assert tokens.verify_api_key(key_request(HTTP_X_API_KEY=revoked_raw), STOREFRONT) is None
    assert tokens.verify_api_key(key_request(HTTP_X_API_KEY=valid_raw), "contact_forms.submit") is None
    assert tokens.verify_api_key(key_request(HTTP_X_API_KEY="ent_api_unknown"), STOREFRONT) is None
    Application.objects.filter(pk=application.pk).update(is_active=False)
    assert tokens.verify_api_key(key_request(HTTP_X_API_KEY=valid_raw), STOREFRONT) is None


def test_empty_scopes_grant_nothing(issue, key_request):
    """Default-deny: django-ai-auth answered True for an empty tool set; a token row without scopes allows nothing."""
    token, raw = issue()
    ApiToken.objects.filter(pk=token.pk).update(scopes=[])
    assert tokens.verify_api_key(key_request(HTTP_X_API_KEY=raw), STOREFRONT) is None


def test_pinned_token_passes_on_its_own_channel_only(issue, key_request):
    pinned, raw = issue(channel_idx="emporium")
    assert tokens.verify_api_key(key_request(HTTP_X_API_KEY=raw), STOREFRONT, "emporium") == pinned
    assert tokens.verify_api_key(key_request(HTTP_X_API_KEY=raw), STOREFRONT, "other") is None


def test_pinned_token_is_refused_where_no_channel_is_passed(issue, key_request):
    """Fail-closed: a pin that cannot be checked is a refusal."""
    _, raw = issue(channel_idx="emporium")
    assert tokens.verify_api_key(key_request(HTTP_X_API_KEY=raw), STOREFRONT) is None
    assert tokens.verify_api_key(key_request(HTTP_X_API_KEY=raw), STOREFRONT, None) is None


def test_unpinned_token_passes_on_every_channel_and_without_one(issue, key_request):
    unpinned, raw = issue()
    for channel_idx in ("emporium", "other", None):
        assert tokens.verify_api_key(key_request(HTTP_X_API_KEY=raw), STOREFRONT, channel_idx) == unpinned


def test_last_used_is_written_once_per_interval(issue, key_request, clock, settings):
    settings.ACCESS_TOKEN_LAST_USED_INTERVAL_S = 300
    token, raw = issue()
    with CaptureQueriesContext(connection) as queries:
        tokens.verify_api_key(key_request(HTTP_X_API_KEY=raw), STOREFRONT)
        tokens.verify_api_key(key_request(HTTP_X_API_KEY=raw), STOREFRONT)
    assert updates(queries) == 1
    first_use = clock.now
    token.refresh_from_db()
    assert token.last_used_at == first_use
    clock.advance(seconds=301)
    tokens.verify_api_key(key_request(HTTP_X_API_KEY=raw), STOREFRONT)
    token.refresh_from_db()
    assert token.last_used_at == first_use + timedelta(seconds=301)


def test_rotate_copies_the_token_and_shortens_the_old_one(issue, system, clock):
    token, raw = issue(channel_idx="emporium", name="shop", expires_at=clock.now + timedelta(days=10))
    ApiToken.objects.filter(pk=token.pk).update(legacy=True, legacy_source="checkout.APIKey#1")
    successor, new_raw = tokens.rotate_token(token, actor=system, overlap_hours=24)
    token.refresh_from_db()
    assert (successor.application_id, successor.scopes, successor.channel_idx, successor.name) == (
        token.application_id,
        token.scopes,
        "emporium",
        "shop",
    )
    assert (successor.legacy, successor.legacy_source) == (False, "")
    assert token.expires_at == clock.now + timedelta(hours=24)
    assert successor.expires_at is None  # D31: a successor inherits no expiry
    assert RAW_FORMAT.fullmatch(new_raw) and tokens.hash_key(new_raw) != tokens.hash_key(raw)


def test_rotate_of_an_expired_token_yields_a_live_successor(issue, system, clock, key_request):
    """Documented in ``docs/gotchas.md``: rotate refuses revoked tokens only; the expired one stays expired."""
    token, _ = issue(expires_at=clock.now + timedelta(days=1))
    clock.advance(days=2)
    successor, raw = tokens.rotate_token(token, actor=system, overlap_hours=24)
    token.refresh_from_db()
    assert token.expires_at < clock.now
    assert tokens.verify_api_key(key_request(HTTP_X_API_KEY=raw), STOREFRONT) == successor


def test_rotate_keeps_an_earlier_expiry(issue, system, clock):
    token, _ = issue(expires_at=clock.now + timedelta(hours=2))
    tokens.rotate_token(token, actor=system, overlap_hours=24)
    token.refresh_from_db()
    assert token.expires_at == clock.now + timedelta(hours=2)


def test_rotate_of_a_publishable_token_without_expiry(issue, system, clock):
    token, _ = issue()
    successor, _ = tokens.rotate_token(token, actor=system)
    assert successor.expires_at is None


def test_revoke(issue, make_user, clock):
    user = make_user()
    token, _ = issue()
    tokens.revoke_token(token, actor=Actor(user))
    token.refresh_from_db()
    assert (token.revoked_at, token.revoked_by) == (clock.now, user)
    with pytest.raises(AccessConflict):
        tokens.revoke_token(token, actor=Actor(user))


def test_create_application_refuses_a_duplicate(system):
    tokens.create_application("widget", actor=system)
    with pytest.raises(AccessConflict):
        tokens.create_application("widget", actor=system)


def test_mutations_write_audit_rows(make_user):
    actor = Actor(make_user(), ip="10.0.0.2")
    application = tokens.create_application("widget", actor=actor)
    token, _ = tokens.issue_token(application, scopes=["contact_forms.submit"], name="form", actor=actor)
    successor, _ = tokens.rotate_token(token, actor=actor)
    tokens.revoke_token(successor, actor=actor)
    rows = list(AuditEntry.objects.order_by("id"))
    assert [row.action for row in rows] == ["application.create", "token.create", "token.rotate", "token.revoke"]
    assert [row.target_id for row in rows[1:]] == [str(token.pk), str(successor.pk), str(successor.pk)]
    assert set(rows[1].detail) == {
        "token_id",
        "name",
        "application_id",
        "scopes",
        "channel_idx",
        "expires_at",
        "prefix",
        "last_four",
    }
    token.refresh_from_db()
    assert (rows[2].detail["replaces"], rows[2].detail["replaces_expires_at"]) == (
        token.pk,
        token.expires_at.isoformat(),
    )
    assert {(row.actor, row.ip) for row in rows} == {(actor.user, "10.0.0.2")}


@pytest.mark.parametrize("hours", [-1, 365 * 24 + 1])
def test_rotate_bounds_the_overlap(issue, system, hours):
    token, _ = issue()
    with pytest.raises(ValueError):
        tokens.rotate_token(token, actor=system, overlap_hours=hours)
    assert ApiToken.objects.count() == 1


def test_rotate_revalidates_stored_scopes(issue, system, clock):
    """A row edited outside the service (mixed groups) is not carried into a fresh successor."""
    token, _ = issue(expires_at=clock.now + timedelta(days=30))
    ApiToken.objects.filter(pk=token.pk).update(scopes=[STOREFRONT, "vault.api"])
    with pytest.raises(ValueError):
        tokens.rotate_token(token, actor=system)
    assert ApiToken.objects.count() == 1
