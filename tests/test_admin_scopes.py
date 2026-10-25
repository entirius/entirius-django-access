# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Admin scopes on tokens: ``<area>:read|write`` from the staff catalogue, never ``access.manage``, never pinned."""

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError

from django_access.models import Application

pytestmark = pytest.mark.django_db


@pytest.mark.parametrize(
    "scopes",
    [["pim.products:write"], ["pim.schema:read"], ["pim.products:write", "vault.api"], ["pim.product_delete:write"]],
)
def test_admin_scopes_from_the_catalogue_are_accepted(issue, scopes):
    token, _ = issue(scopes)
    assert token.scopes == sorted(scopes)


def test_read_and_write_of_one_area_are_kept_and_deduplicated(issue):
    token, _ = issue(["pim.products:write", "pim.products:read", "pim.products:write"])
    assert token.scopes == ["pim.products:read", "pim.products:write"]


@pytest.mark.parametrize(
    "scope",
    ["pim.nothing:read", "pim.products:delete", "pim.product_delete:read", "pim.products", "staff.baseline:read"],
)
def test_unknown_admin_scopes_are_refused(issue, scope):
    with pytest.raises(ValueError, match="Unknown token scopes"):
        issue([scope])


@pytest.mark.parametrize("scope", ["access.manage:read", "access.manage:write"])
def test_access_manage_is_never_a_token_scope(issue, scope):
    with pytest.raises(ValueError, match="access.manage"):
        issue([scope])


def test_admin_scopes_never_share_a_token_with_publishable_ones(issue):
    with pytest.raises(ValueError, match="Publishable and secret"):
        issue(["pim.products:read", "checkout.storefront"])


def test_admin_scopes_cannot_be_pinned(issue):
    with pytest.raises(ValueError, match="cannot be pinned"):
        issue(["pim.products:read"], channel_idx="emporium")


def test_key_route_tokens_keep_their_pin(issue):
    token, _ = issue(["vault.api"], channel_idx="emporium")
    assert token.channel_idx == "emporium"


def test_cli_issues_an_admin_scoped_key(capsys):
    call_command(
        "access_token",
        "create",
        "--application",
        "erp-bridge",
        "--create-application",
        "--scope",
        "pim.products:write",
        "--scope",
        "pim.schema:read",
    )
    raw = capsys.readouterr().out.strip()
    application = Application.objects.get(name="erp-bridge")
    assert raw.startswith("ent_api_")
    assert application.tokens.get().scopes == ["pim.products:write", "pim.schema:read"]
    assert application.service_user.is_staff


def test_cli_refuses_an_unknown_admin_scope():
    with pytest.raises(CommandError, match="Unknown token scopes"):
        call_command("access_token", "create", "--application", "x", "--create-application", "--scope", "pim.x:read")
