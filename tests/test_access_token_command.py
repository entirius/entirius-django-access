# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
import re
from datetime import timedelta
from io import StringIO

import pytest
from django.core.management import CommandError, call_command

from django_access.models import ApiToken, Application
from django_access.services import tokens

pytestmark = pytest.mark.django_db

RAW_FORMAT = re.compile(r"ent_api_[A-Za-z0-9_-]{43}")


def run(*args: str) -> tuple[str, str]:
    out, err = StringIO(), StringIO()
    call_command("access_token", *args, stdout=out, stderr=err)
    return out.getvalue(), err.getvalue()


def create(*extra: str) -> tuple[str, str]:
    return run("create", "--application", "shop", "--create-application", "--scope", "checkout.storefront", *extra)


def test_create_prints_the_raw_value_once_alone_on_stdout():
    out, err = create("--channel", "emporium", "--name", "pwa")
    lines = out.splitlines()
    assert len(lines) == 1 and RAW_FORMAT.fullmatch(lines[0])
    token = ApiToken.objects.get(key_hash=tokens.hash_key(lines[0]))
    assert (token.application.name, token.channel_idx, token.name, token.expires_at) == (
        "shop",
        "emporium",
        "pwa",
        None,
    )
    leaked = lines[0] in err
    assert not leaked, "the raw value reached stderr"
    assert token.display in err


def test_create_with_expiry_days(clock):
    out, _ = run(
        "create", "--application", "ops", "--create-application", "--scope", "vault.api", "--expires-days", "30"
    )
    token = ApiToken.objects.get(key_hash=tokens.hash_key(out.strip()))
    assert token.expires_at == clock.now + timedelta(days=30)


def test_create_needs_an_existing_application_or_the_flag():
    with pytest.raises(CommandError, match="--create-application"):
        run("create", "--application", "shop", "--scope", "checkout.storefront")
    assert not ApiToken.objects.exists()


@pytest.mark.parametrize("days", ["0", "-3", "x"])
def test_expires_days_must_be_positive(days):
    with pytest.raises(CommandError):
        create("--expires-days", days)
    assert not Application.objects.exists()


def test_create_refuses_unknown_scopes_and_creates_nothing():
    with pytest.raises(CommandError, match="Unknown token scopes"):
        run("create", "--application", "shop", "--create-application", "--scope", "nope.scope")
    assert not Application.objects.exists()


def test_rotate_prints_the_new_raw_value_once():
    old_raw = create()[0].strip()
    old = ApiToken.objects.get()
    out, _ = run("rotate", str(old.pk), "--overlap-hours", "0")
    lines = out.splitlines()
    assert len(lines) == 1 and RAW_FORMAT.fullmatch(lines[0])
    assert tokens.hash_key(lines[0]) != tokens.hash_key(old_raw)
    assert ApiToken.objects.count() == 2


def test_revoke_and_list():
    raw = create()[0].strip()
    token = ApiToken.objects.get()
    out, _ = run("revoke", str(token.pk))
    assert "revoked" in out
    listing, _ = run("list", "--application", "shop")
    leaked = raw in listing or token.key_hash in listing
    assert not leaked, "list printed a secret"
    assert token.display in listing and "revoked" in listing and "checkout.storefront" in listing
    assert run("list", "--application", "other")[0] == ""


def test_unknown_token_id():
    with pytest.raises(CommandError, match="No token 999"):
        run("revoke", "999")
