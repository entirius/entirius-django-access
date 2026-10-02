# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Audit integrity: every mutation endpoint leaves one row with actor, client address and target; the address follows
DRF's ``NUM_PROXIES`` rule, so a client-sent ``X-Forwarded-For`` never forges it."""

import pytest
from django.conf import settings
from django.test import RequestFactory, override_settings
from rest_framework.request import Request

from django_access.api.admin.views._base import client_ip
from django_access.models import AuditAction, AuditEntry
from django_access.services import access_service
from django_access.services.access_service import RoleInput
from django_access.services.permissions import VIEWER

URL = "/api/access/v2/admin/"
VISITOR, CDN, PROXY = "203.0.113.7", "198.51.100.20", "10.0.0.5"
SPOOFED = "6.6.6.6"


def proxies(count: int | None) -> override_settings:
    return override_settings(REST_FRAMEWORK={**settings.REST_FRAMEWORK, "NUM_PROXIES": count})


def ip_of(remote: str, forwarded: str | None = None) -> str | None:
    headers = {"REMOTE_ADDR": remote}
    if forwarded is not None:
        headers["HTTP_X_FORWARDED_FOR"] = forwarded
    return client_ip(Request(RequestFactory().get("/", **headers)))


def test_unset_num_proxies_takes_remote_addr_only():
    assert ip_of(PROXY, f"{SPOOFED}, {VISITOR}") == PROXY
    assert ip_of(PROXY) == PROXY


@proxies(1)
def test_one_proxy_takes_the_rightmost_forwarded_entry():
    assert ip_of(PROXY, f"{SPOOFED}, {CDN}, {VISITOR}") == VISITOR
    assert ip_of(PROXY, VISITOR) == VISITOR
    assert ip_of(PROXY) == PROXY


@proxies(2)
def test_two_proxies_count_from_the_right():
    assert ip_of(PROXY, f"{SPOOFED}, {VISITOR}, {CDN}") == VISITOR
    assert ip_of(PROXY, VISITOR) == PROXY  # fewer entries than proxies: the client wrote them all


@proxies(0)
def test_zero_proxies_take_remote_addr():
    assert ip_of(PROXY, SPOOFED) == PROXY


@proxies(1)
def test_an_empty_header_takes_remote_addr():
    assert ip_of(PROXY, "") == PROXY


@proxies(1)
def test_a_malformed_address_is_stored_as_none():
    assert ip_of(PROXY, "not-an-ip") is None
    assert ip_of("") is None


@pytest.fixture
def custom(db, system):
    return access_service.create_role(RoleInput("stock", "Stock", permissions=["qms.stock:read"]), system)


def mutations(custom, make_user, group, role, system) -> list[tuple]:
    grant = access_service.grant_role(role(VIEWER), group=group, actor=system)
    return [
        ("post", "roles/", {"key": "warehouse", "name": "W"}, AuditAction.ROLE_CREATE, "django_access.role"),
        ("patch", f"roles/{custom.pk}/", {"name": "S2"}, AuditAction.ROLE_UPDATE, "django_access.role"),
        (
            "post",
            "grants/",
            {"role": "stock", "user_id": make_user().pk},
            AuditAction.GRANT_CREATE,
            "django_access.grant",
        ),
        ("delete", f"grants/{grant.pk}/", None, AuditAction.GRANT_DELETE, "django_access.grant"),
        ("delete", f"roles/{custom.pk}/", None, AuditAction.ROLE_DELETE, "django_access.role"),
    ]


@pytest.mark.django_db
@pytest.mark.parametrize("num_proxies", [None, 1])
def test_every_mutation_leaves_one_row_with_actor_address_and_target(
    num_proxies, custom, make_user, group, role, system, person, api_as
):
    administrator = person("administrator")
    client = api_as(administrator)
    with proxies(num_proxies):
        for method, path, body, action, target_type in mutations(custom, make_user, group, role, system):
            before = AuditEntry.objects.count()
            forwarded = {"HTTP_X_FORWARDED_FOR": f"{SPOOFED}, {CDN}, {VISITOR}", "REMOTE_ADDR": PROXY}
            response = getattr(client, method)(URL + path, body, format="json", **forwarded)
            assert response.status_code in (200, 201, 204), response.content
            assert AuditEntry.objects.count() == before + 1
            entry = AuditEntry.objects.order_by("-pk").first()
            assert (entry.action, entry.target_type, entry.actor_id) == (action, target_type, administrator.pk)
            assert entry.ip == (VISITOR if num_proxies == 1 else PROXY) and entry.target_id
