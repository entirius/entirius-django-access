# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
import itertools

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.cache import cache

from django_access.catalogue import registry
from django_access.models import Role
from django_access.services import route_map
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
