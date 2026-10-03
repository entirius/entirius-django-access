# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Read side of the admin API and ``me``: the catalogue, roles, grants, the staff directory, groups and the audit log.

Writes stay in ``access_service``. The staff directory lists only active staff users and never confirms that any other
account exists: a lookup of a customer, an inactive user or an unknown id fails the same way.
"""

from dataclasses import dataclass
from datetime import datetime

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.db.models import Count, Prefetch, Q, QuerySet

from django_access.catalogue import registry
from django_access.models import AuditEntry, Grant, Role
from django_access.services import gate, permissions, tokens

GRANT_RELATED = ("role", "user", "group")


class NotStaff(LookupError):
    """No active staff user with this id — the same answer for a customer, an inactive user and an unknown id."""


@dataclass(frozen=True)
class AuditFilter:
    action: str | None = None
    actor_id: int | None = None
    since: datetime | None = None
    until: datetime | None = None


def catalogue() -> dict:
    """Areas grouped by module (``assignable`` false for ``access.manage``), the built-in roles' permissions, the
    token scopes and the rotation recommendation in days."""
    assignable = {item.key for item in registry.custom_role_areas()}
    by_module: dict[str, list[dict]] = {}
    for item in registry.areas():
        by_module.setdefault(item.module, []).append({**_area(item), "assignable": item.key in assignable})
    modules = [{"module": module, "areas": areas} for module, areas in by_module.items()]
    roles = [
        {"key": key, "name": name, "description": text, "permissions": permissions.builtin_permissions(key)}
        for key, (name, text) in permissions.BUILTIN_ROLES.items()
    ]
    scopes = [_scope(scope) for scope in registry.scopes()]
    return {"modules": modules, "roles": roles, "scopes": scopes, "token_rotation_days": tokens.rotation_days()}


def _area(item) -> dict:
    return {"key": item.key, "label": item.label, "levels": list(item.levels), "sensitive": list(item.sensitive)}


def _scope(scope) -> dict:
    return {
        "key": scope.key,
        "label": scope.label,
        "module": scope.module,
        "publishable": scope.publishable,
        "routes": list(scope.routes),
    }


def roles() -> QuerySet[Role]:
    return Role.objects.annotate(grant_count=Count("grants")).order_by("-builtin", "name", "pk")


def grants(role_key: str | None = None, user_id: int | None = None, group_id: int | None = None) -> QuerySet[Grant]:
    filters = {"role__key": role_key, "user_id": user_id, "group_id": group_id}
    rows = Grant.objects.select_related(*GRANT_RELATED)
    return rows.filter(**{name: value for name, value in filters.items() if value is not None})


def grant_target(role_key: str, user_id: int | None, group_id: int | None) -> tuple[Role, object, Group | None]:
    """``(role, user, group)`` of a grant request; ``ValueError`` for an unknown role or group, and for any user who is
    not active staff — without saying which (the API never confirms that a customer account exists)."""
    role = Role.objects.filter(key=role_key).first()
    if role is None:
        raise ValueError("Unknown role")
    if group_id is not None:
        group = Group.objects.filter(pk=group_id).first()
        if group is None:
            raise ValueError("Unknown group")
        return role, None, group
    user = _active_staff().filter(pk=user_id).first()
    if user is None:
        raise ValueError("Grant target must be an active staff user")
    return role, user, None


def _active_staff() -> QuerySet:
    return get_user_model().objects.filter(is_active=True, is_staff=True)


def staff_users(search: str = "") -> QuerySet:
    users = _active_staff().prefetch_related(
        Prefetch("access_grants", queryset=Grant.objects.select_related("role")),
        Prefetch("groups__access_grants", queryset=Grant.objects.select_related("role", "group")),
    )
    if search:
        fields = ("username", "email", "first_name", "last_name")
        users = users.filter(Q(*(Q(**{f"{name}__icontains": search}) for name in fields), _connector=Q.OR))
    return users.order_by("username", "pk")


def staff_user(user_id: int):
    user = staff_users().filter(pk=user_id).first()
    if user is None:
        raise NotStaff(user_id)
    return user


def staff_roles(user) -> list[dict]:
    """Roles of a ``staff_users()`` row: direct grants, then grants through each group (from the prefetch)."""
    direct = [{"role": grant.role, "via_group": None} for grant in user.access_grants.all()]
    via = [
        {"role": grant.role, "via_group": group.name}
        for group in user.groups.all()
        for grant in group.access_grants.all()
    ]
    return direct + via


def user_grants(user) -> QuerySet[Grant]:
    return Grant.objects.select_related(*GRANT_RELATED).filter(Q(user=user) | Q(group__in=user.groups.all()))


def groups() -> QuerySet[Group]:
    rows = Group.objects.annotate(member_count=Count("user", distinct=True)).order_by("name", "pk")
    return rows.prefetch_related(Prefetch("access_grants", queryset=Grant.objects.select_related(*GRANT_RELATED)))


def audit_entries(where: AuditFilter) -> QuerySet[AuditEntry]:
    filters = {
        "action": where.action,
        "actor_id": where.actor_id,
        "created_at__gte": where.since,
        "created_at__lte": where.until,
    }
    return AuditEntry.objects.filter(**{name: value for name, value in filters.items() if value is not None})


def me(user) -> dict:
    """What ``user`` may do; a non-staff user learns nothing about the gate, roles or areas."""
    staff = user.is_staff or user.is_superuser
    held = list(permissions.granted_roles(user)) if staff else []
    return {
        "gate_mode": gate.mode() if staff else None,
        "manages_access": permissions.manages_access(user),
        "roles": [{"key": role.key, "name": role.name} for role in held],
        "permissions": permissions.effective_permissions(user) if staff else {},
    }
