# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
import pytest

from django_access.exceptions import AccessConflict, AccessLockout
from django_access.models import AuditEntry, Grant, Role
from django_access.services import access_service
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


def test_update_role_whitelists_fields(admin_grant, system):
    custom = access_service.create_role(RoleInput("faq", "FAQ"), system)
    with pytest.raises(ValueError):
        access_service.update_role(custom, {"builtin": True}, system)


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


def test_lockout_holds_for_a_custom_manager_role(make_user, system):
    manager = access_service.create_role(RoleInput("keeper", "Keeper", permissions=["access.manage:write"]), system)
    grant = access_service.grant_role(manager, user=make_user(), actor=system)
    with pytest.raises(AccessLockout):
        access_service.update_role(manager, {"permissions": ["access.manage:read"]}, system)
    with pytest.raises(AccessLockout):
        access_service.delete_role(manager, system)
    assert Grant.objects.filter(pk=grant.pk).exists()


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


def test_inactive_superuser_does_not_count(admin_grant, make_user, system):
    make_user(is_superuser=True, is_active=False)
    with pytest.raises(AccessLockout):
        access_service.revoke_grant(admin_grant, system)
