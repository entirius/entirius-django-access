# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
import itertools
from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.cache import cache
from django.test import RequestFactory
from django.utils import timezone

from django_access.catalogue import registry
from django_access.models import Application, Role
from django_access.services import route_map, tokens
from django_access.services.access_service import Actor
from django_access.services.permissions import ADMINISTRATOR

_names = itertools.count()


@pytest.fixture(autouse=True)
def clean_state():
    registry.reset()
    route_map.reset()
    cache.clear()
    yield
    cache.clear()


@pytest.fixture
def make_user(db):
    def make(**flags):
        defaults = {"is_staff": True, "is_active": True}
        return get_user_model().objects.create_user(username=f"user{next(_names)}", **{**defaults, **flags})

    return make


@pytest.fixture
def role(db):
    return lambda key: Role.objects.get(key=key)


@pytest.fixture
def group(db):
    return Group.objects.create(name="editors")


@pytest.fixture
def system():
    return Actor()


@pytest.fixture
def admin_grant(make_user, role, system):
    """An active staff Administrator — the only access manager of the database."""
    from django_access.services import access_service

    return access_service.grant_role(role(ADMINISTRATOR), user=make_user(), actor=system)


@pytest.fixture
def application(db):
    return Application.objects.create(name="storefront")


@pytest.fixture
def issue(application, system):
    """``issue(scopes, **kwargs)`` → ``(token, raw)``; a publishable storefront token by default."""

    def make(scopes=("checkout.storefront",), **kwargs):
        kwargs.setdefault("application", application)
        return tokens.issue_token(kwargs.pop("application"), scopes=list(scopes), actor=system, **kwargs)

    return make


@pytest.fixture
def key_request():
    """``key_request(HTTP_X_API_KEY=…, HTTP_X_API_ADMIN_KEY=…)`` → a GET request carrying those headers."""
    factory = RequestFactory()
    return lambda **headers: factory.get("/", **headers)


class Clock:
    def __init__(self) -> None:
        self.now = timezone.now()

    def advance(self, **delta) -> None:
        self.now += timedelta(**delta)


@pytest.fixture
def clock(monkeypatch):
    """A frozen ``timezone.now`` for the services and ``auto_now_add``; ``clock.advance(hours=…)`` moves it."""
    frozen = Clock()
    monkeypatch.setattr(timezone, "now", lambda: frozen.now)
    return frozen
