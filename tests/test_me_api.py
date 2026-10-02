# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""``GET me`` for every principal type: anonymous, customer, a role holder, a superuser."""

import pytest
from django.test import override_settings

from django_access.catalogue import registry
from django_access.catalogue.areas import READ, WRITE

pytestmark = pytest.mark.django_db

URL = "/api/access/v2/me/"


def test_anonymous_is_401(api_as):
    assert api_as(None).get(URL).status_code == 401


@override_settings(ACCESS_GATE_MODE="observe")
def test_customer_learns_nothing(person, api_as):
    customer = person("customer")
    body = api_as(customer).get(URL).json()
    assert body["user"]["id"] == customer.pk and body["user"]["is_staff"] is False
    assert body["gate_mode"] is None and body["permissions"] == {} and body["roles"] == []
    assert body["manages_access"] is False


def test_viewer_reads(person, api_as):
    body = api_as(person("viewer")).get(URL).json()
    assert body["permissions"]["pim.products"] == READ and "access.manage" not in body["permissions"]
    assert body["roles"] == [{"key": "viewer", "name": "Viewer"}]
    assert body["gate_mode"] == "enforce" and body["manages_access"] is False


def test_administrator_manages_access(person, api_as):
    body = api_as(person("administrator")).get(URL).json()
    assert body["manages_access"] is True and body["permissions"]["access.manage"] == WRITE


def test_superuser_gets_every_area_at_its_top_level(person, api_as):
    body = api_as(person("superuser")).get(URL).json()
    expected = {area.key: WRITE if WRITE in area.levels else READ for area in registry.areas()}
    assert body["permissions"] == expected
    assert body["permissions"]["lookup.search"] == READ and body["permissions"]["content.publish"] == WRITE
    assert body["manages_access"] is True and body["user"]["is_superuser"] is True and body["roles"] == []


def test_identity_fields(person, api_as, make_user):
    user = make_user(email="a@example.test", first_name="Ann", last_name="Lee")
    assert api_as(user).get(URL).json()["user"] == {
        "id": user.pk,
        "username": user.username,
        "email": "a@example.test",
        "first_name": "Ann",
        "last_name": "Lee",
        "is_staff": True,
        "is_superuser": False,
    }
