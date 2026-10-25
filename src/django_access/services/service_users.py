# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""The service user of an application: the account its admin-scoped tokens act as on admin routes.

One per application, created with its first admin-scoped token: username ``access-app-<pk>``, unusable password,
never a superuser, no grants — its permissions are the scopes of the token it presents (``services.gate``). It is staff
and active while the application is active and holds a live admin-scoped token; every token and application mutation
recomputes that in its own transaction. Applications are never deleted, so the row stays for the modules' foreign keys.
"""

from django.contrib.auth import get_user_model
from django.db.models import Q
from django.utils import timezone

from django_access.exceptions import AccessConflict
from django_access.models import Application

USERNAME_PREFIX = "access-app-"
ADMIN_SCOPE_MARK = ":"  # admin scopes are permission keys (<area>:<level>); key-route scopes carry no colon


def admin_scopes(scopes: list[str]) -> list[str]:
    return [scope for scope in scopes if ADMIN_SCOPE_MARK in scope]


def _holds_live_admin_token(application: Application) -> bool:
    live = application.tokens.filter(Q(expires_at__isnull=True) | Q(expires_at__gt=timezone.now()), revoked_at=None)
    return any(admin_scopes(scopes) for scopes in live.values_list("scopes", flat=True))


def _create(application: Application):
    username = f"{USERNAME_PREFIX}{application.pk}"
    users = get_user_model().objects
    if users.filter(username=username).exists():
        raise AccessConflict(f"A user {username!r} already exists and is not this application's service account")
    user = users.create_user(username=username, is_staff=False, is_active=False)  # no password → unusable
    application.service_user = user
    application.save(update_fields=["service_user"])
    return user


def sync_service_user(application: Application):
    """Create the service user when the first live admin token appears; set ``is_staff`` / ``is_active``."""
    live = application.is_active and _holds_live_admin_token(application)
    user = application.service_user
    if user is None:
        if not live:
            return None
        user = _create(application)
    if (user.is_staff, user.is_active) != (live, live):
        user.is_staff = user.is_active = live
        user.save(update_fields=["is_staff", "is_active"])
    return user


def is_service_user(user) -> bool:
    return Application.objects.filter(service_user_id=user.pk).exists()


def service_users():
    return get_user_model().objects.filter(access_application__isnull=False)
