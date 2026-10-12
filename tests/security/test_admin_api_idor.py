# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""IDOR / enumeration: the staff directory never confirms that a non-staff account exists, a grant to one never echoes
it, and 404/409 bodies name no internal class."""

import pytest

from django_access.models import Grant
from django_access.services.permissions import ADMINISTRATOR, VIEWER

pytestmark = pytest.mark.django_db

URL = "/api/access/v2/admin/"
INTERNAL_NAMES = ("AccessConflict", "AccessLockout", "DoesNotExist", "NotStaff", "Traceback", "django_access")


def without_debug_id(response) -> dict:
    return {key: value for key, value in response.json().items() if key != "debug_id"}


@pytest.fixture
def unknown(admin_api):
    response = admin_api.get(f"{URL}staff/999999/")
    assert response.status_code == 404
    return without_debug_id(response)


@pytest.mark.parametrize(
    "flags", [{"is_staff": False}, {"is_staff": True, "is_active": False}, {"is_staff": False, "is_superuser": True}]
)
def test_staff_detail_of_a_non_staff_user_is_an_unknown_id(admin_api, make_user, unknown, flags):
    user = make_user(email="private@example.test", **flags)
    response = admin_api.get(f"{URL}staff/{user.pk}/")
    assert response.status_code == 404 and without_debug_id(response) == unknown
    assert user.username not in response.content.decode()


def test_staff_list_never_shows_customers(admin_api, make_user):
    customer = make_user(is_staff=False, username="customer-x")
    rows = admin_api.get(URL + "staff/?search=customer").json()["results"]
    assert rows == [] and customer.username not in admin_api.get(URL + "staff/").content.decode()


@pytest.mark.parametrize("flags", [{"is_staff": False}, {"is_active": False}])
def test_grant_to_a_non_staff_user_is_400_like_an_unknown_id(admin_api, make_user, flags):
    user = make_user(username="hidden-person", email="hidden@example.test", **flags)
    response, unknown_id = (
        admin_api.post(URL + "grants/", {"role": VIEWER, "user_id": user_id}, format="json")
        for user_id in (user.pk, 999999)
    )
    assert response.status_code == unknown_id.status_code == 400
    assert without_debug_id(response) == without_debug_id(unknown_id)
    assert "hidden" not in response.content.decode()
    assert not Grant.objects.filter(user=user).exists()


def test_conflict_and_not_found_bodies_name_no_internal_class(admin_api, role):
    responses = [
        admin_api.delete(f"{URL}grants/{Grant.objects.get(role__key=ADMINISTRATOR).pk}/"),
        admin_api.patch(f"{URL}roles/{role(VIEWER).pk}/", {"name": "x"}, format="json"),
        admin_api.get(f"{URL}roles/999999/"),
    ]
    assert [response.status_code for response in responses] == [409, 409, 404]
    for response in responses:
        assert not any(name in response.content.decode() for name in INTERNAL_NAMES)
