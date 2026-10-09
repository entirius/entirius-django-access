# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Token lifecycle under a frozen clock: every state change applies on the very next verify (nothing is cached)."""

from datetime import timedelta
from io import StringIO

import pytest
from django.core.management import CommandError, call_command

from django_access.exceptions import AccessConflict, TokenExpiryError
from django_access.models import ApiToken, Application
from django_access.services import tokens

pytestmark = pytest.mark.django_db

STOREFRONT = "checkout.storefront"
VAULT = "vault.api"


@pytest.fixture
def verify(key_request):
    return lambda raw, scope=STOREFRONT: tokens.verify_api_key(key_request(HTTP_X_API_KEY=raw), scope)


def test_issue_verify_rotate_revoke(issue, verify, system, clock):
    token, raw = issue()
    assert verify(raw) == token
    successor, new_raw = tokens.rotate_token(token, actor=system, overlap_hours=24)
    clock.advance(hours=24, seconds=-1)
    assert (verify(raw), verify(new_raw)) == (token, successor)
    clock.advance(seconds=1)
    assert (verify(raw), verify(new_raw)) == (None, successor)
    tokens.revoke_token(successor, actor=system)
    assert verify(new_raw) is None


def test_rotate_without_overlap_refuses_the_old_token_at_once(issue, verify, system, clock):
    token, raw = issue()
    successor, new_raw = tokens.rotate_token(token, actor=system, overlap_hours=0)
    assert (verify(raw), verify(new_raw)) == (None, successor)


def test_deactivated_application_refuses_every_token(issue, verify, application):
    raws = [issue()[1], issue(["contact_forms.submit"])[1]]
    assert all(verify(raw, scope) for raw, scope in zip(raws, [STOREFRONT, "contact_forms.submit"], strict=True))
    Application.objects.filter(pk=application.pk).update(is_active=False)
    assert [verify(raw, scope) for raw, scope in zip(raws, [STOREFRONT, "contact_forms.submit"], strict=True)] == [
        None,
        None,
    ]


def test_expiry_boundary_is_inclusive(issue, verify, clock):
    token, raw = issue(expires_at=clock.now + timedelta(minutes=5))
    clock.advance(minutes=5, microseconds=-1)
    assert verify(raw) == token
    clock.advance(microseconds=1)
    assert verify(raw) is None


def test_rotate_of_a_revoked_token_is_refused(issue, system):
    token, _ = issue()
    tokens.revoke_token(token, actor=system)
    with pytest.raises(AccessConflict):
        tokens.rotate_token(token, actor=system)
    assert ApiToken.objects.count() == 1


@pytest.mark.parametrize("scopes", [[], [STOREFRONT, VAULT], ["contact_forms.booking", "checkout.erase"]])
def test_empty_and_mixed_scope_sets_are_refused(issue, clock, scopes):
    with pytest.raises(ValueError):
        issue(scopes, expires_at=clock.now + timedelta(days=30))
    assert not ApiToken.objects.exists()


@pytest.mark.parametrize("days", [None, 3650])
def test_secret_token_needs_no_expiry_and_has_no_maximum(issue, clock, days):
    """D31: no lifetime cap — an old token is flagged ``rotation_due`` instead."""
    expires_at = clock.now + timedelta(days=days) if days else None
    token, _ = issue([VAULT], expires_at=expires_at)
    assert token.expires_at == expires_at


def test_a_past_expiry_is_refused_at_issue(issue, clock):
    with pytest.raises(TokenExpiryError) as refused:
        issue([VAULT], expires_at=clock.now)
    assert refused.value.code == "EXPIRY_IN_PAST" and not ApiToken.objects.exists()


def test_secret_rotation_inherits_no_expiry(issue, system, clock):
    token, _ = issue(["returns.api"], expires_at=clock.now + timedelta(days=365))
    clock.advance(days=300)
    successor, _ = tokens.rotate_token(token, actor=system)
    assert successor.expires_at is None
    later = clock.now + timedelta(days=3650)
    assert tokens.rotate_token(successor, actor=system, expires_at=later)[0].expires_at == later


def test_rotation_refuses_a_past_expiry(issue, system, clock):
    token, _ = issue([VAULT])
    with pytest.raises(TokenExpiryError) as refused:
        tokens.rotate_token(token, actor=system, expires_at=clock.now - timedelta(seconds=1))
    assert refused.value.code == "EXPIRY_IN_PAST" and ApiToken.objects.count() == 1


def test_publishable_token_may_live_without_expiry(issue):
    token, _ = issue(["agreements.subscribe"])
    assert token.expires_at is None


def test_cli_issues_a_secret_scope_without_expiry():
    args = ["create", "--application", "erase", "--create-application", "--scope", "checkout.erase"]
    call_command("access_token", *args, stdout=StringIO(), stderr=StringIO())
    assert ApiToken.objects.get().expires_at is None


def test_cli_refuses_a_non_positive_lifetime_and_creates_nothing():
    args = ["create", "--application", "erase", "--create-application", "--scope", "checkout.erase"]
    with pytest.raises(CommandError):
        call_command("access_token", *args, "--expires-days", "0", stdout=StringIO(), stderr=StringIO())
    assert not ApiToken.objects.exists() and not Application.objects.exists()
