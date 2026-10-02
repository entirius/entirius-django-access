# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
from types import SimpleNamespace

import pytest

from django_access.catalogue import registry
from django_access.exceptions import AccessConflict, AccessLockout, ReservedPermission
from django_access.models import Application, AuditEntry, Grant, Role
from django_access.services import access_service, tokens
from django_access.services.access_service import Actor, RoleInput

pytestmark = pytest.mark.django_db


def actions() -> list[str]:
    return list(AuditEntry.objects.order_by("id").values_list("action", flat=True))


def test_every_mutation_writes_its_audit_row(admin_grant, make_user, group):
    actor = Actor(admin_grant.user, ip="10.0.0.1")
    custom = access_service.create_role(RoleInput("faq", "FAQ", permissions=["faq.faq:read"]), actor)
    access_service.update_role(custom, {"name": "FAQ editors", "permissions": ["faq.faq:write"]}, actor)
    grant = access_service.grant_role(custom, group=group, actor=actor)
    access_service.revoke_grant(grant, actor)
    role_id = custom.pk
    access_service.delete_role(custom, actor)
    assert actions() == ["grant.create", "role.create", "role.update", "grant.create", "grant.delete", "role.delete"]
    update = AuditEntry.objects.get(action="role.update")
    assert update.detail["changes"]["permissions"] == {"from": ["faq.faq:read"], "to": ["faq.faq:write"]}
    assert (update.actor, update.actor_label, update.ip) == (admin_grant.user, admin_grant.user.username, "10.0.0.1")
    deleted = AuditEntry.objects.get(action="role.delete")
    assert (deleted.target_type, deleted.target_id) == ("django_access.role", str(role_id))


def test_custom_role_rejects_unknown_keys(system):
    for keys in (["nope.area:read"], ["lookup.search:write"], ["faq.faq"]):
        with pytest.raises(ValueError):
            access_service.create_role(RoleInput("bad", "Bad", permissions=keys), system)
    assert not Role.objects.filter(key="bad").exists()


def test_builtin_roles_are_locked(role, system):
    with pytest.raises(AccessConflict):
        access_service.update_role(role("viewer"), {"name": "Reader"}, system)
    with pytest.raises(AccessConflict):
        access_service.delete_role(role("viewer"), system)


@pytest.mark.parametrize("updates", [{"key": "renamed"}, {"builtin": True}, {"name": "Ok", "key": "renamed"}])
def test_update_role_whitelists_fields(updates, admin_grant, system):
    custom = access_service.create_role(RoleInput("faq", "FAQ"), system)
    rows = AuditEntry.objects.count()
    with pytest.raises(ValueError, match="not editable via update_role"):
        access_service.update_role(custom, updates, system)
    stored = Role.objects.get(pk=custom.pk)
    assert (stored.key, stored.name, stored.builtin) == ("faq", "FAQ", False)
    assert AuditEntry.objects.count() == rows


@pytest.mark.parametrize("updates", [{"created_by": None}, {"id": 99}, {"name": "Ok", "created_at": None}])
def test_update_application_whitelists_fields(updates, application, system):
    rows = AuditEntry.objects.count()
    with pytest.raises(ValueError, match="not editable via update_application"):
        tokens.update_application(application, updates, actor=system)
    assert Application.objects.get().name == application.name == "storefront"
    assert AuditEntry.objects.count() == rows


def test_duplicates_conflict(admin_grant, system):
    with pytest.raises(AccessConflict):
        access_service.create_role(RoleInput("viewer", "Viewer"), system)
    with pytest.raises(AccessConflict):
        access_service.grant_role(admin_grant.role, user=admin_grant.user, actor=system)


def test_grant_needs_exactly_one_holder(role, system):
    with pytest.raises(ValueError):
        access_service.grant_role(role("viewer"), actor=system)


def test_revoking_the_last_administrator_is_refused(admin_grant, system):
    grant_id = admin_grant.pk
    with pytest.raises(AccessLockout):
        access_service.revoke_grant(admin_grant, system)
    assert Grant.objects.filter(pk=grant_id).exists()
    assert actions() == ["grant.create"]


def test_lockout_holds_for_a_group_administrator(make_user, role, group, system):
    make_user().groups.add(group)
    grant = access_service.grant_role(role("administrator"), group=group, actor=system)
    grant_id = grant.pk
    with pytest.raises(AccessLockout):
        access_service.revoke_grant(grant, system)
    assert Grant.objects.filter(pk=grant_id).exists()


@pytest.mark.parametrize("key", ["access.manage:read", "access.manage:write"])
def test_custom_role_cannot_be_created_with_access_manage(key, system):
    with pytest.raises(ReservedPermission) as raised:
        access_service.create_role(RoleInput("keeper", "Keeper", permissions=["faq.faq:read", key]), system)
    assert raised.value.keys == [key]
    assert isinstance(raised.value, ValueError)
    assert not Role.objects.filter(key="keeper").exists()
    assert not AuditEntry.objects.exists()


@pytest.mark.parametrize("key", ["access.manage:read", "access.manage:write"])
def test_custom_role_cannot_gain_access_manage(key, admin_grant, system):
    custom = access_service.create_role(RoleInput("faq", "FAQ", permissions=["faq.faq:read"]), system)
    with pytest.raises(ReservedPermission):
        access_service.update_role(custom, {"name": "Keeper", "permissions": [key]}, system)
    custom.refresh_from_db()
    assert custom.name == "FAQ"
    assert list(custom.permissions.values_list("permission", flat=True)) == ["faq.faq:read"]
    assert actions() == ["grant.create", "role.create"]


def test_custom_role_areas_exclude_access_manage():
    keys = {item.key for item in registry.custom_role_areas()}
    assert "access.manage" not in keys
    assert keys == {item.key for item in registry.areas()} - {"access.manage"}


def test_administrator_still_holds_access_manage(admin_grant):
    from django_access.services.permissions import manages_access

    assert manages_access(admin_grant.user)


@pytest.mark.parametrize("flags", [{"is_staff": False}, {"is_active": False}])
def test_grant_target_must_be_active_staff(flags, make_user, role, system):
    with pytest.raises(ValueError, match="active staff"):
        access_service.grant_role(role("viewer"), user=make_user(**flags), actor=system)
    assert not Grant.objects.exists()
    assert not AuditEntry.objects.exists()


def test_group_administrators_count(make_user, role, group, system):
    user = make_user()
    user.groups.add(group)
    access_service.grant_role(role("administrator"), group=group, actor=system)
    assert access_service.has_access_manager()


def test_a_database_without_managers_may_still_change(make_user, role, system):
    grant = access_service.grant_role(role("viewer"), user=make_user(), actor=system)
    access_service.revoke_grant(grant, system)
    assert not access_service.has_access_manager()


def test_revoke_allowed_with_an_active_superuser(admin_grant, make_user, system):
    make_user(is_superuser=True)
    access_service.revoke_grant(admin_grant, system)
    assert not Grant.objects.exists()


@pytest.mark.parametrize("flags", [{"is_active": False}, {"is_staff": False}])
def test_unusable_superuser_does_not_count(flags, admin_grant, make_user, system):
    make_user(is_superuser=True, **flags)
    with pytest.raises(AccessLockout):
        access_service.revoke_grant(admin_grant, system)


def test_a_long_username_is_cut_to_the_audit_label():
    user = SimpleNamespace(get_username=lambda: "u" * 200)
    assert Actor(user).label == "u" * 150
