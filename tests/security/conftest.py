# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Principals of the security suite (every secret generated here) and the recorded view runs."""

import secrets
from datetime import timedelta

import pytest
from django.utils import timezone
from rest_framework_simplejwt.tokens import AccessToken

from django_access.catalogue import registry
from django_access.models import AuditAction, AuditEntry
from django_access.services import access_service
from django_access.services.permissions import ADMINISTRATOR, EDITOR, MANAGER, VIEWER
from tests.security import urls


def bearer(user, **lifetime) -> dict:
    token = AccessToken.for_user(user)
    if lifetime:
        token.set_exp(lifetime=timedelta(**lifetime))
    return {"HTTP_AUTHORIZATION": f"Bearer {token}"}


def bypass_rows() -> list[dict]:
    """The ``detail`` of every ``gate.bypass`` row, oldest first."""
    rows = AuditEntry.objects.filter(action=AuditAction.GATE_BYPASS).order_by("pk")
    return list(rows.values_list("detail", flat=True))


@pytest.fixture(autouse=True)
def ran():
    """The ``(path, method)`` of every view that ran during the test."""
    urls.RAN.clear()
    yield urls.RAN
    urls.RAN.clear()


@pytest.fixture
def principal(client, make_user, role, group, system, issue):
    """``principal(name)`` → the request headers of that principal (the session superuser logs ``client`` in)."""

    def granted(role_key: str) -> dict:
        user = make_user()
        access_service.grant_role(role(role_key), user=user, actor=system)
        return bearer(user)

    def inactive() -> dict:
        user = make_user()
        access_service.grant_role(role(MANAGER), user=user, actor=system)
        headers = bearer(user)
        user.is_active = False
        user.save()
        return headers

    def deleted() -> dict:
        user = make_user(is_superuser=True)
        headers = bearer(user)
        user.delete()
        return headers

    def via_group() -> dict:
        user = make_user()
        user.groups.add(group)
        access_service.grant_role(role(ADMINISTRATOR), group=group, actor=system)
        return bearer(user)

    def every_scope() -> dict:
        """Every token scope: a publishable token and a secret one (one token never mixes the two groups)."""
        public = [scope.key for scope in registry.scopes() if scope.publishable]
        secret = [scope.key for scope in registry.scopes() if not scope.publishable]
        _, public_raw = issue(public)
        _, secret_raw = issue(secret, expires_at=timezone.now() + timedelta(days=30))
        return {"HTTP_X_API_KEY": public_raw, "HTTP_X_API_ADMIN_KEY": secret_raw}

    def session_superuser() -> dict:
        client.force_login(make_user(is_superuser=True))
        return {}

    builders = {
        "anonymous": dict,
        "malformed_header": lambda: {"HTTP_AUTHORIZATION": f"Bearer {secrets.token_hex(8)} {secrets.token_hex(8)}"},
        "expired_jwt": lambda: bearer(make_user(is_superuser=True), minutes=-1),
        "deleted_user_jwt": deleted,
        "customer": lambda: bearer(make_user(is_staff=False)),
        "inactive_staff": inactive,
        "staff_no_role": lambda: bearer(make_user()),
        "viewer": lambda: granted(VIEWER),
        "editor": lambda: granted(EDITOR),
        "manager": lambda: granted(MANAGER),
        "administrator": lambda: granted(ADMINISTRATOR),
        "administrator_group": via_group,
        "superuser": lambda: bearer(make_user(is_superuser=True)),
        "superuser_not_staff": lambda: bearer(make_user(is_superuser=True, is_staff=False)),
        "token_every_scope": every_scope,
        "session_superuser": session_superuser,
    }
    return lambda name: builders[name]()
