# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Secret hygiene: after a full lifecycle no log record, audit row, CLI listing or admin page holds a raw value or hash."""

import logging
from io import StringIO

import pytest
from django.contrib import admin
from django.core.management import call_command
from django.urls import path, reverse

from django_access.models import ApiToken, AuditEntry
from django_access.services import tokens

pytestmark = pytest.mark.django_db

urlpatterns = [path("admin/", admin.site.urls)]


def contains_any(text: str, secrets: list[str]) -> bool:
    return any(secret in text for secret in secrets)


@pytest.fixture
def lifecycle(issue, key_request, system, caplog):
    """Issue, verify, rotate, verify, revoke, list; returns every secret seen and the ``list`` output."""
    caplog.set_level(logging.DEBUG)
    token, raw = issue(channel_idx="emporium", name="shop")
    tokens.verify_api_key(key_request(HTTP_X_API_KEY=raw), "checkout.storefront", "emporium")
    successor, new_raw = tokens.rotate_token(token, actor=system)
    tokens.verify_api_key(key_request(HTTP_X_API_ADMIN_KEY=new_raw), "checkout.storefront")
    tokens.verify_api_key(key_request(HTTP_X_API_KEY=raw + "tampered"), "checkout.storefront")
    tokens.revoke_token(successor, actor=system)
    listing = StringIO()
    call_command("access_token", "list", stdout=listing)
    hashes = list(ApiToken.objects.values_list("key_hash", flat=True))
    return [raw, new_raw, *hashes], listing.getvalue()


def test_no_log_record_holds_a_secret(lifecycle, caplog):
    secrets, _ = lifecycle
    records = caplog.get_records("setup") + caplog.get_records("call")  # the lifecycle runs in fixture setup
    leaked = [record.name for record in records if contains_any(record.getMessage(), secrets)]
    assert not leaked, f"secret in log records of {leaked}"


def test_no_audit_field_holds_a_secret(lifecycle):
    secrets, _ = lifecycle
    rows = [str(row) for row in AuditEntry.objects.values()]
    assert len(rows) == 3
    leaked = any(contains_any(row, secrets) for row in rows)
    assert not leaked, "secret in an audit row"


def test_cli_list_holds_no_secret(lifecycle):
    secrets, listing = lifecycle
    leaked = contains_any(listing, secrets)
    assert not leaked, "secret in access_token list"
    assert listing.count("\n") == 2


@pytest.mark.urls(__name__)
def test_admin_pages_render_without_key_hash(lifecycle, client, make_user):
    secrets, _ = lifecycle
    client.force_login(make_user(is_superuser=True))
    token = ApiToken.objects.first()
    pages = [
        reverse("admin:django_access_apitoken_changelist"),
        reverse("admin:django_access_apitoken_change", args=[token.pk]),
    ]
    for url in pages:
        response = client.get(url)
        body = response.content.decode()
        assert response.status_code == 200, url
        leaked = contains_any(body, secrets) or "key_hash" in body or "Key hash" in body
        assert not leaked, f"key material on {url}"
        assert token.prefix in body, url


@pytest.mark.urls(__name__)
def test_admin_offers_no_add(client, make_user):
    client.force_login(make_user(is_superuser=True))
    assert client.get(reverse("admin:django_access_apitoken_add")).status_code == 403
