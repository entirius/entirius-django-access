# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
import itertools
import secrets
from datetime import timedelta

import pytest
from django.apps import apps
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.cache import cache
from django.test import RequestFactory
from django.utils import timezone
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import AccessToken

from django_access.catalogue import registry
from django_access.models import Application, Role
from django_access.services import route_map, tokens
from django_access.services.access_service import Actor
from django_access.services.permissions import ADMINISTRATOR, EDITOR, MANAGER, VIEWER

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
        defaults = {"username": f"user{next(_names)}", "is_staff": True, "is_active": True}
        return get_user_model().objects.create_user(**{**defaults, **flags})

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


@pytest.fixture
def legacy_row(db):
    """``legacy_row("django_checkout.APIKey", channel="emporium", key=…, **fields)`` → a row of a fake legacy module;
    a fresh 64-hex secret by default (the shape ``generate_key()`` produces)."""

    def make(model: str, *, channel: str | None = None, key: str | None = None, **fields):
        cls = apps.get_model(model)
        if channel is not None:
            fields["channel"], _ = cls._meta.get_field("channel").related_model.objects.get_or_create(idx=channel)
        return cls.objects.create(key=secrets.token_hex(32) if key is None else key, **fields)

    return make


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


@pytest.fixture
def person(make_user, role, system):
    """``person(name)`` → a fresh user of that kind: customer, staff (no role), a built-in role holder, superuser."""
    from django_access.services import access_service

    def granted(role_key: str):
        user = make_user()
        access_service.grant_role(role(role_key), user=user, actor=system)
        return user

    builders = {
        "customer": lambda: make_user(is_staff=False),
        "staff": make_user,
        "viewer": lambda: granted(VIEWER),
        "editor": lambda: granted(EDITOR),
        "manager": lambda: granted(MANAGER),
        "administrator": lambda: granted(ADMINISTRATOR),
        "superuser": lambda: make_user(is_superuser=True),
        "superuser_not_staff": lambda: make_user(is_superuser=True, is_staff=False),
    }
    return lambda name: builders[name]()


@pytest.fixture
def api_as():
    """``api_as(user)`` → an ``APIClient`` sending the user's Bearer JWT; ``api_as(None)`` → anonymous."""

    def make(user=None) -> APIClient:
        client = APIClient()
        if user is not None:
            client.credentials(HTTP_AUTHORIZATION=f"Bearer {AccessToken.for_user(user)}")
        return client

    return make


@pytest.fixture
def admin_api(person, api_as):
    """An Administrator (not a superuser) — the access manager of the database."""
    return api_as(person("administrator"))
