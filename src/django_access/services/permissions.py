# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Effective permissions of a user: the staff baseline plus the union of roles granted directly or through a group.

Built-in roles are computed from the catalogue at run time, so a new area joins them without a migration. Results are
cached per user under a global version that every access change bumps (``bump_version``), never trusted after it.
"""

import uuid
import zlib

from django.core.cache import cache
from django.db import transaction
from django.db.models import Q, QuerySet

from django_access.catalogue import registry
from django_access.catalogue.areas import ACCESS_MANAGE, READ, STAFF_BASELINE, WRITE, Area
from django_access.models import Role

ADMINISTRATOR = "administrator"
MANAGER = "manager"
EDITOR = "editor"
VIEWER = "viewer"
BUILTIN_ROLES = {
    ADMINISTRATOR: ("Administrator", "Everything, including access management."),
    MANAGER: ("Manager", "Everything except access management."),
    EDITOR: ("Editor", "Writes content, catalogue, FAQ and e-mail templates; reads the rest."),
    VIEWER: ("Viewer", "Reads everything except access management."),
}
MANAGE_ACCESS_PERMISSION = f"{ACCESS_MANAGE}:{WRITE}"
EDITOR_WRITE_AREAS = frozenset(
    {"pim.products", "pim.categories", "pim.schema", "pim.quality", "faq.faq", "email.templates"}
)
EDITOR_WRITE_PREFIX = "content."
LEVEL_RANK = {READ: 1, WRITE: 2}
VERSION_KEY = "access:perms:version"


def _offered(area: Area, wanted: str | None) -> str | None:
    """The level the area offers for ``wanted``: write falls back to read on a read-only area."""
    if wanted in area.levels:
        return wanted
    return READ if wanted == WRITE and READ in area.levels else None


def _builtin_wanted(role_key: str, area_key: str) -> str | None:
    if area_key == ACCESS_MANAGE:
        return WRITE if role_key == ADMINISTRATOR else None
    if role_key in (ADMINISTRATOR, MANAGER):
        return WRITE
    if role_key == EDITOR and (area_key in EDITOR_WRITE_AREAS or area_key.startswith(EDITOR_WRITE_PREFIX)):
        return WRITE
    return READ


def builtin_permissions(role_key: str) -> dict[str, str]:
    """``{area: level}`` of a built-in role, from the current catalogue."""
    levels = ((item.key, _offered(item, _builtin_wanted(role_key, item.key))) for item in registry.areas())
    return {key: level for key, level in levels if level}


def _custom_permissions(role: Role) -> dict[str, str]:
    known = {item.key for item in registry.areas()}
    pairs = (row.permission.rpartition(":")[::2] for row in role.permissions.all())
    return _union({area_key: level} for area_key, level in pairs if area_key in known)


def role_permissions(role: Role) -> dict[str, str]:
    return builtin_permissions(role.key) if role.builtin else _custom_permissions(role)


def _union(permission_sets) -> dict[str, str]:
    merged: dict[str, str] = {}
    for permissions in permission_sets:
        for area_key, level in permissions.items():
            if LEVEL_RANK[level] > LEVEL_RANK.get(merged.get(area_key), 0):
                merged[area_key] = level
    return merged


def granted_roles(user) -> QuerySet[Role]:
    """Roles granted to the user directly or through one of their groups."""
    held = Q(grants__user=user) | Q(grants__group__in=user.groups.all())
    return Role.objects.filter(held).distinct().prefetch_related("permissions")


def _every_area() -> dict[str, str]:
    return {item.key: level for item in registry.areas() if (level := _offered(item, WRITE))}


def _compute(user) -> dict[str, str]:
    return _union(role_permissions(role) for role in granted_roles(user))


def effective_permissions(user) -> dict[str, str]:
    """``{area: "read" | "write"}``: superuser → every area; inactive or non-staff → ``{}``; staff → granted roles."""
    if not getattr(user, "is_active", False):
        return {}
    if user.is_superuser:
        return _every_area()
    if not user.is_staff:
        return {}
    key = f"access:perms:{_version()}:{user.pk}"
    permissions = cache.get(key)
    if permissions is None:
        permissions = _compute(user)
        cache.set(key, permissions)
    return permissions


def has_permission(user, permission: str) -> bool:
    """Whether the user holds ``<area>:<level>`` (write implies read); ``staff.baseline`` = any active staff.

    ``ValueError`` for a key the catalogue does not offer — a typo must fail loudly, not match a held write.
    """
    if permission == STAFF_BASELINE:
        return bool(getattr(user, "is_active", False) and user.is_staff)
    area_key = registry.parse_perm(permission)[0].key
    held = effective_permissions(user).get(area_key)
    return held is not None and registry.implies(f"{area_key}:{held}", permission)


def manages_access(user) -> bool:
    return has_permission(user, MANAGE_ACCESS_PERMISSION)


def _version() -> str:
    """The bumped version plus a catalogue fingerprint: a deploy that changes areas never reads older answers."""
    areas = ";".join(f"{item.key}={','.join(item.levels)}" for item in registry.areas())
    return f"{cache.get_or_set(VERSION_KEY, uuid.uuid4().hex, timeout=None)}-{zlib.crc32(areas.encode()):08x}"


def bump_version() -> None:
    """Invalidate every cached answer once the current transaction commits (immediately outside one)."""
    transaction.on_commit(lambda: cache.set(VERSION_KEY, uuid.uuid4().hex, timeout=None))
