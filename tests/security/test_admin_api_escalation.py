# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Escalation through the admin API: ``access.manage`` is never part of a custom role (Q2), forbidden and unknown
fields are refused (mass assignment), a Manager writes nothing, built-in roles never change."""

import pytest

from django_access.catalogue.areas import ACCESS_MANAGE
from django_access.models import AuditEntry, Grant, Role, RolePermission
from django_access.services import access_service
from django_access.services.access_service import RoleInput
from django_access.services.permissions import ADMINISTRATOR, MANAGER, VIEWER

pytestmark = pytest.mark.django_db

URL = "/api/access/v2/admin/"
RESERVED = {
    "field": "permissions",
    "location": "body",
    "issue": "ACCESS_MANAGE_RESERVED",
    "description": "access.manage belongs to the built-in Administrator role only",
}
MANAGE_KEYS = [f"{ACCESS_MANAGE}:read", f"{ACCESS_MANAGE}:write"]


@pytest.fixture
def custom(system):
    return access_service.create_role(RoleInput("stock", "Stock", permissions=["qms.stock:read"]), system)


def state() -> tuple:
    return Role.objects.count(), RolePermission.objects.count(), AuditEntry.objects.count()


def assert_reserved(response) -> None:
    assert response.status_code == 400
    body = response.json()
    assert body["error"] == "VALIDATION_ERROR" and body["details"] == [RESERVED]


@pytest.mark.parametrize("key", MANAGE_KEYS)
def test_create_with_access_manage_is_reserved(admin_api, key):
    before = state()
    body = {"key": "sneaky", "name": "Sneaky", "permissions": ["qms.stock:read", key]}
    assert_reserved(admin_api.post(URL + "roles/", body, format="json"))
    assert state() == before


@pytest.mark.parametrize("key", MANAGE_KEYS)
def test_patch_adding_access_manage_is_reserved(admin_api, custom, key):
    before = state()
    assert_reserved(admin_api.patch(f"{URL}roles/{custom.pk}/", {"permissions": [key]}, format="json"))
    assert state() == before
    assert list(custom.permissions.values_list("permission", flat=True)) == ["qms.stock:read"]


def test_catalogue_marks_only_access_manage_unassignable(admin_api):
    areas = [area for module in admin_api.get(URL + "catalogue/").json()["modules"] for area in module["areas"]]
    assert [area["key"] for area in areas if not area["assignable"]] == [ACCESS_MANAGE]
    assert len(areas) == 49


def test_administrator_still_carries_access_manage(admin_api, role):
    body = admin_api.get(f"{URL}roles/{role(ADMINISTRATOR).pk}/").json()
    assert body["permissions"][ACCESS_MANAGE] == "write"


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("post", "roles/", {"key": "mine", "name": "Mine"}),
        ("patch", "roles/{role}/", {"name": "Mine"}),
        ("delete", "roles/{role}/", None),
        ("post", "grants/", {"role": ADMINISTRATOR, "user_id": "{me}"}),
        ("delete", "grants/{grant}/", None),
    ],
)
def test_manager_writes_nothing(person, api_as, custom, system, method, path, body):
    manager = person("manager")
    grant = access_service.grant_role(custom, user=manager, actor=system)
    ids = {"role": custom.pk, "grant": grant.pk, "me": manager.pk}
    payload = body and {key: int(ids["me"]) if value == "{me}" else value for key, value in body.items()}
    before = state(), Grant.objects.count()
    response = getattr(api_as(manager), method)(URL + path.format(**ids), payload, format="json")
    assert response.status_code == 403 and (state(), Grant.objects.count()) == before


@pytest.mark.parametrize(("method", "body"), [("patch", {"description": "x"}), ("delete", None)])
@pytest.mark.parametrize("key", [ADMINISTRATOR, MANAGER, VIEWER])
def test_builtin_roles_are_409(admin_api, role, key, method, body):
    response = getattr(admin_api, method)(f"{URL}roles/{role(key).pk}/", body, format="json")
    assert response.status_code == 409 and response.json()["error"] == "CONFLICT"
    assert Role.objects.filter(key=key, builtin=True).exists()


@pytest.mark.parametrize(
    "extra", [{"builtin": True}, {"id": 1}, {"created_by": 1}, {"created_at": "2026-01-01T00:00:00Z"}, {"owner": 1}]
)
def test_create_refuses_forbidden_fields(admin_api, extra):
    before = state()
    response = admin_api.post(URL + "roles/", {"key": "mass", "name": "Mass", **extra}, format="json")
    assert response.status_code == 400 and state() == before


@pytest.mark.parametrize("extra", [{"builtin": True}, {"key": "renamed"}, {"id": 1}, {"created_by": 1}])
def test_patch_refuses_forbidden_fields(admin_api, custom, extra):
    response = admin_api.patch(f"{URL}roles/{custom.pk}/", {"name": "New", **extra}, format="json")
    assert response.status_code == 400
    custom.refresh_from_db()
    assert (custom.key, custom.name, custom.builtin) == ("stock", "Stock", False)


@pytest.mark.parametrize("key", [ADMINISTRATOR, MANAGER, "editor", VIEWER])
def test_role_key_of_a_builtin_is_409(admin_api, key):
    response = admin_api.post(URL + "roles/", {"key": key, "name": "Impostor"}, format="json")
    assert response.status_code == 409
    assert Role.objects.get(key=key).builtin is True


@pytest.mark.parametrize("key", ["A", "1abc", "a", "a" * 51, "a b", "a/b"])
def test_role_key_must_be_a_slug(admin_api, key):
    assert admin_api.post(URL + "roles/", {"key": key, "name": "X"}, format="json").status_code == 400


@pytest.mark.parametrize(
    "body",
    [{"name": "n" * 101}, {"description": "d" * 1001}, {"permissions": ["qms.stock:read"] * 99}],
)
def test_role_length_limits(admin_api, body):
    assert admin_api.post(URL + "roles/", {"key": "limits", "name": "L", **body}, format="json").status_code == 400


@pytest.mark.parametrize("holders", [{"user_id": 1, "group_id": 1}, {}])
def test_grant_needs_exactly_one_holder(admin_api, holders):
    before = Grant.objects.count()
    assert admin_api.post(URL + "grants/", {"role": VIEWER, **holders}, format="json").status_code == 400
    assert Grant.objects.count() == before


def test_grant_refuses_extra_fields(admin_api, make_user):
    body = {"role": VIEWER, "user_id": make_user().pk, "created_by": 1}
    assert admin_api.post(URL + "grants/", body, format="json").status_code == 400
