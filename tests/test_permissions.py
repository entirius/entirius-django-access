# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
import pytest
from django.core.cache import cache

from django_access.catalogue import registry
from django_access.catalogue.areas import STAFF_BASELINE
from django_access.services import access_service
from django_access.services.access_service import RoleInput
from django_access.services.permissions import (
    VERSION_KEY,
    builtin_permissions,
    effective_permissions,
    has_permission,
)
from django_access.signals import ACCESS_FLAGS

pytestmark = pytest.mark.django_db


def test_editor_is_computed_from_the_catalogue():
    editor = builtin_permissions("editor")
    assert editor["faq.faq"] == "write"
    assert editor["content.publish"] == "write"
    assert editor["checkout.orders"] == "read"
    assert "access.manage" not in editor
    assert "platform.devtools" not in editor  # write-only area: nothing to read


def test_builtin_roles_cover_the_catalogue():
    every = {item.key for item in registry.areas()}
    administrator, manager, viewer = (builtin_permissions(key) for key in ("administrator", "manager", "viewer"))
    assert set(administrator) == every
    assert administrator["access.manage"] == "write"
    assert administrator["lookup.search"] == "read"  # read-only area: its top level
    assert set(manager) == every - {"access.manage"}
    assert set(viewer.values()) == {"read"}
    assert "access.manage" not in viewer and "content.publish" not in viewer


def test_editor_role(make_user, role, system):
    user = make_user()
    access_service.grant_role(role("editor"), user=user, actor=system)
    assert has_permission(user, "faq.faq:write")
    assert has_permission(user, "checkout.orders:read")
    assert not has_permission(user, "checkout.orders:write")
    assert not has_permission(user, "access.manage:read")


def test_group_grant_and_union(make_user, role, group, system):
    user = make_user()
    user.groups.add(group)
    access_service.grant_role(role("viewer"), group=group, actor=system)
    custom = access_service.create_role(RoleInput("orders", "Orders", permissions=["checkout.orders:write"]), system)
    access_service.grant_role(custom, user=user, actor=system)
    permissions = effective_permissions(user)
    assert permissions["checkout.orders"] == "write"
    assert permissions["faq.faq"] == "read"


def test_staff_without_grant_has_only_the_baseline(make_user):
    user = make_user()
    assert effective_permissions(user) == {}
    assert has_permission(user, STAFF_BASELINE)


@pytest.mark.parametrize(
    "flags", [{"is_staff": False}, {"is_active": False}, {"is_active": False, "is_superuser": True}]
)
def test_non_staff_and_inactive_get_nothing(flags, make_user, role, system):
    user = make_user()
    access_service.grant_role(role("administrator"), user=make_user(), actor=system)
    access_service.grant_role(role("manager"), user=user, actor=system)
    for name, value in flags.items():
        setattr(user, name, value)
    user.save()
    assert effective_permissions(user) == {}
    assert not has_permission(user, STAFF_BASELINE)


def test_superuser_gets_every_area(make_user):
    user = make_user(is_superuser=True)
    permissions = effective_permissions(user)
    assert set(permissions) == {item.key for item in registry.areas()}
    assert permissions["access.manage"] == "write"
    assert has_permission(user, "platform.devtools:write")


def test_cache_bumps_on_grant(make_user, role, system, django_capture_on_commit_callbacks):
    user = make_user()
    assert effective_permissions(user) == {}
    with django_capture_on_commit_callbacks(execute=True):
        access_service.grant_role(role("viewer"), user=user, actor=system)
    assert effective_permissions(user)["faq.faq"] == "read"


def test_cache_bumps_on_group_membership(make_user, role, group, system, django_capture_on_commit_callbacks):
    user = make_user()
    with django_capture_on_commit_callbacks(execute=True):
        access_service.grant_role(role("viewer"), group=group, actor=system)
    assert effective_permissions(user) == {}
    with django_capture_on_commit_callbacks(execute=True):
        user.groups.add(group)
    assert effective_permissions(user)["faq.faq"] == "read"
    with django_capture_on_commit_callbacks(execute=True):
        group.user_set.remove(user)
    assert effective_permissions(user) == {}


@pytest.mark.parametrize("partial", [False, True])
@pytest.mark.parametrize(
    ("flag", "start", "end"),
    [("is_staff", {"is_staff": False}, True), ("is_superuser", {}, True), ("is_active", {}, False)],
)
def test_cache_bumps_on_each_access_flag(flag, start, end, partial, make_user, django_capture_on_commit_callbacks):
    assert flag in ACCESS_FLAGS
    user = make_user(**start)
    before = cache.get_or_set(VERSION_KEY, "initial", timeout=None)
    with django_capture_on_commit_callbacks(execute=True):
        setattr(user, flag, end)
        user.save(update_fields=[flag]) if partial else user.save()
    assert cache.get(VERSION_KEY) != before


def test_cache_bumps_on_groups_clear(make_user, role, group, system, django_capture_on_commit_callbacks):
    user = make_user()
    with django_capture_on_commit_callbacks(execute=True):
        access_service.grant_role(role("viewer"), group=group, actor=system)
        user.groups.add(group)
    assert effective_permissions(user)["faq.faq"] == "read"
    with django_capture_on_commit_callbacks(execute=True):
        user.groups.clear()
    assert effective_permissions(user) == {}


def test_cascaded_grant_delete_bumps(make_user, role, group, system, django_capture_on_commit_callbacks):
    """A group deleted outside ``access_service``: its grants cascade and the members lose the role at once."""
    user = make_user()
    with django_capture_on_commit_callbacks(execute=True):
        access_service.grant_role(role("viewer"), group=group, actor=system)
        user.groups.add(group)
    assert effective_permissions(user)["faq.faq"] == "read"
    with django_capture_on_commit_callbacks(execute=True):
        group.delete()
    assert effective_permissions(user) == {}


def test_customer_save_runs_no_flag_query(make_user, django_assert_num_queries):
    customer = make_user(is_staff=False)
    customer.first_name = "Ada"
    with django_assert_num_queries(1):  # the UPDATE alone
        customer.save()


def test_cached_answer_survives_until_commit(make_user, role, system, django_capture_on_commit_callbacks):
    user = make_user()
    grant = access_service.grant_role(role("viewer"), user=user, actor=system)
    assert effective_permissions(user)["faq.faq"] == "read"
    with django_capture_on_commit_callbacks(execute=True):
        access_service.revoke_grant(grant, system)
        assert effective_permissions(user)["faq.faq"] == "read"  # the bump waits for the commit
    assert effective_permissions(user) == {}


def test_unknown_permission_key_fails_loudly(make_user):
    with pytest.raises(ValueError):
        has_permission(make_user(is_superuser=True), "faq.faq:wrtie")


def test_unrelated_user_save_does_not_bump(make_user, django_capture_on_commit_callbacks):
    user = make_user()
    with django_capture_on_commit_callbacks() as callbacks:
        user.first_name = "Ada"
        user.save()
        user.save(update_fields=["last_login"])
    assert callbacks == []
