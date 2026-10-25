# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""``pim.attribute_values``: attribute values apart from the PIM schema — the routes, the built-in roles, migration
0007 for custom roles, and an admin scope on a token."""

import importlib

import pytest

from django_access.catalogue import registry
from django_access.models import Role, RolePermission
from django_access.services import access_service
from django_access.services.access_service import RoleInput
from django_access.services.permissions import builtin_permissions, effective_permissions
from django_access.services.route_map import classify, required_permission, walk
from tests import attribute_values_urls as urls

pytestmark = [pytest.mark.django_db, pytest.mark.urls("tests.attribute_values_urls")]

AREA = "pim.attribute_values"
migration = importlib.import_module("django_access.migrations.0007_attribute_values_area")


def routes() -> dict:
    return dict(walk("tests.attribute_values_urls"))


@pytest.mark.parametrize("root", urls.PIM_ROOTS)
@pytest.mark.parametrize("suffix", urls.VALUE_ROUTES)
@pytest.mark.parametrize(("method", "level"), [("GET", "read"), ("POST", "write"), ("DELETE", "write")])
def test_attribute_value_routes_need_the_area(root, suffix, method, level):
    route = root + suffix
    assert required_permission(classify(route, routes()[route]), method) == f"{AREA}:{level}"


@pytest.mark.parametrize("root", urls.PIM_ROOTS)
@pytest.mark.parametrize("suffix", urls.SCHEMA_ROUTES)
def test_schema_routes_stay_schema(root, suffix):
    route = root + suffix
    assert required_permission(classify(route, routes()[route]), "GET") == "pim.schema:read"


def test_the_area_is_in_the_catalogue():
    area = registry.area(AREA)
    assert (area.module, area.levels, area.label) == ("django_pim", ("read", "write"), "Attribute values")


@pytest.mark.parametrize(
    ("role_key", "level"), [("administrator", "write"), ("manager", "write"), ("editor", "write"), ("viewer", "read")]
)
def test_builtin_roles_keep_their_rights(role_key, level):
    permissions = builtin_permissions(role_key)
    assert permissions[AREA] == level == ("read" if role_key == "viewer" else permissions["pim.schema"])


def custom_role(*permissions: str) -> Role:
    role = Role.objects.create(key="catalogue", name="Catalogue")
    RolePermission.objects.bulk_create(RolePermission(role=role, permission=key) for key in permissions)
    return role


@pytest.mark.parametrize("level", ["read", "write"])
def test_migration_gives_custom_schema_roles_the_same_level(level):
    from django.apps import apps

    role = custom_role(f"pim.schema:{level}", "pim.products:write")
    migration.add_attribute_values(apps, None)
    migration.add_attribute_values(apps, None)  # idempotent
    held = set(role.permissions.values_list("permission", flat=True))
    assert held == {f"pim.schema:{level}", "pim.products:write", f"{AREA}:{level}"}


def test_migration_leaves_roles_without_schema_alone():
    from django.apps import apps

    role = custom_role("pim.products:write")
    migration.add_attribute_values(apps, None)
    assert list(role.permissions.values_list("permission", flat=True)) == ["pim.products:write"]


def test_migration_reverse_removes_the_area():
    from django.apps import apps

    role = custom_role("pim.schema:write", f"{AREA}:write")
    migration.remove_attribute_values(apps, None)
    assert list(role.permissions.values_list("permission", flat=True)) == ["pim.schema:write"]


def test_a_custom_role_may_hold_the_area_alone(make_user, system):
    role = access_service.create_role(RoleInput("values", "Values", permissions=[f"{AREA}:write"]), system)
    user = make_user()
    access_service.grant_role(role, user=user, actor=system)
    assert effective_permissions(user) == {AREA: "write"}


def test_an_integration_token_may_hold_it(issue):
    token, _ = issue(["pim.products:write", f"{AREA}:write"])
    assert f"{AREA}:write" in token.scopes
