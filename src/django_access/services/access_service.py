# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""The only writer of roles and grants: each mutation runs in one transaction with its audit row and the lockout guard.

The guard wraps every change that can take access away (update, delete, revoke): when an access manager existed before
and none is left after, it raises ``AccessLockout`` and the whole transaction rolls back. Creating a role or a grant
cannot take access away, so it skips the two guard queries.
"""

from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.db import models, transaction
from django.db.models import Q

from django_access.catalogue import registry
from django_access.exceptions import AccessConflict, AccessLockout
from django_access.models import AuditAction, AuditEntry, Grant, Role, RolePermission
from django_access.services.permissions import ADMINISTRATOR, MANAGE_ACCESS_PERMISSION, bump_version

SYSTEM_LABEL = "system"
_EDITABLE_ROLE_FIELDS = frozenset({"name", "description", "permissions"})


@dataclass(frozen=True)
class Actor:
    """Who makes a change: a user (None = the system) and the request's IP when there is one."""

    user: Any = None
    ip: str | None = None

    @property
    def label(self) -> str:
        return self.user.get_username() if self.user else SYSTEM_LABEL


@dataclass(frozen=True)
class RoleInput:
    key: str
    name: str
    description: str = ""
    permissions: list[str] = field(default_factory=list)


def record_audit(action: str, actor: Actor, target: models.Model, detail: dict | None = None) -> AuditEntry:
    return AuditEntry.objects.create(
        actor=actor.user,
        actor_label=actor.label,
        action=action,
        target_type=target._meta.label_lower,
        target_id=str(target.pk),
        target_label=str(target)[:255],
        detail=detail or {},
        ip=actor.ip,
    )


def _validated(permissions: list[str]) -> list[str]:
    """Deduplicated, sorted keys; ``ValueError`` for any key the catalogue does not offer."""
    for key in permissions:
        registry.parse_perm(key)
    return sorted(set(permissions))


def _set_permissions(role: Role, permissions: list[str]) -> None:
    role.permissions.all().delete()
    RolePermission.objects.bulk_create(RolePermission(role=role, permission=key) for key in permissions)


def _refuse_builtin(role: Role) -> None:
    if role.builtin:
        raise AccessConflict(f"Built-in role {role.key!r} cannot be changed")


def has_access_manager() -> bool:
    """Whether an active superuser or an active staff user holding access.manage:write exists."""
    users = get_user_model().objects.filter(is_active=True)
    if users.filter(is_superuser=True).exists():
        return True
    managing_roles = Role.objects.filter(
        Q(key=ADMINISTRATOR, builtin=True) | Q(permissions__permission=MANAGE_ACCESS_PERMISSION)
    )
    holders = Q(access_grants__role__in=managing_roles) | Q(groups__access_grants__role__in=managing_roles)
    return users.filter(holders, is_staff=True).exists()


@contextmanager
def _lockout_guard():
    """Refuse a change that takes away the last access manager (a database without one may still change).

    Guarded changes serialise on the Administrator row, so two concurrent revokes cannot each see the other manager.
    """
    Role.objects.select_for_update().filter(key=ADMINISTRATOR, builtin=True).first()
    had_manager = has_access_manager()
    yield
    if had_manager and not has_access_manager():
        raise AccessLockout("Nobody active would be left to manage access")


def _finish(action: str, actor: Actor, target: models.Model, detail: dict) -> None:
    record_audit(action, actor, target, detail)
    bump_version()


@transaction.atomic
def create_role(data: RoleInput, actor: Actor) -> Role:
    permissions = _validated(data.permissions)
    if Role.objects.filter(key=data.key).exists():
        raise AccessConflict(f"Role {data.key!r} already exists")
    role = Role.objects.create(key=data.key, name=data.name, description=data.description)
    _set_permissions(role, permissions)
    _finish(AuditAction.ROLE_CREATE, actor, role, {"key": role.key, "name": role.name, "permissions": permissions})
    return role


def _role_state(role: Role) -> dict:
    permissions = list(role.permissions.values_list("permission", flat=True))
    return {"name": role.name, "description": role.description, "permissions": permissions}


def _apply(role: Role, updates: dict[str, Any]) -> None:
    if invalid := set(updates) - _EDITABLE_ROLE_FIELDS:
        raise ValueError(f"Fields not editable via update_role: {sorted(invalid)}")
    if "permissions" in updates:
        _set_permissions(role, _validated(updates["permissions"]))
    for name in updates.keys() - {"permissions"}:
        setattr(role, name, updates[name])
    role.save()


@transaction.atomic
def update_role(role: Role, updates: dict[str, Any], actor: Actor) -> Role:
    """Change a custom role's ``name``, ``description`` or ``permissions`` (replaces the whole set)."""
    _refuse_builtin(role)
    before = _role_state(role)
    with _lockout_guard():
        _apply(role, updates)
    after = _role_state(role)
    changes = {name: {"from": before[name], "to": after[name]} for name in before if before[name] != after[name]}
    _finish(AuditAction.ROLE_UPDATE, actor, role, {"key": role.key, "changes": changes})
    return role


@transaction.atomic
def delete_role(role: Role, actor: Actor) -> None:
    """Delete a custom role together with its grants."""
    _refuse_builtin(role)
    detail = {"key": role.key, "name": role.name, "grants": role.grants.count()}
    target = Role(pk=role.pk, key=role.key, name=role.name)
    with _lockout_guard():
        role.delete()
    _finish(AuditAction.ROLE_DELETE, actor, target, detail)


def _holder_detail(grant: Grant) -> dict:
    return {"role": grant.role.key, "user_id": grant.user_id, "group_id": grant.group_id}


@transaction.atomic
def grant_role(role: Role, *, user=None, group: Group | None = None, actor: Actor) -> Grant:
    """Grant the role to exactly one user or one group."""
    if (user is None) == (group is None):
        raise ValueError("Grant a role to exactly one of user or group")
    if Grant.objects.filter(role=role, user=user, group=group).exists():
        raise AccessConflict(f"Role {role.key!r} is already granted")
    grant = Grant.objects.create(role=role, user=user, group=group, created_by=actor.user)
    _finish(AuditAction.GRANT_CREATE, actor, grant, _holder_detail(grant))
    return grant


@transaction.atomic
def revoke_grant(grant: Grant, actor: Actor) -> None:
    detail = _holder_detail(grant)
    target = Grant(pk=grant.pk, role=grant.role, user_id=grant.user_id, group_id=grant.group_id)
    with _lockout_guard():
        grant.delete()
    _finish(AuditAction.GRANT_DELETE, actor, target, detail)
