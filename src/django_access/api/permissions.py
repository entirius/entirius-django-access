# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Permission classes of the access API: the staff baseline and ``access.manage`` — checked in the view as well, so the
API stays closed when the gate runs in ``observe`` or ``off``."""

from rest_framework.permissions import SAFE_METHODS, BasePermission, IsAdminUser

from django_access.catalogue.areas import ACCESS_MANAGE, READ, STAFF_BASELINE, WRITE
from django_access.services import permissions


class IsStaffUser(IsAdminUser):
    """An active staff user — a superuser only with ``is_staff`` (the route map reads the ``IsAdminUser`` base: admin,
    self-authenticating)."""

    def has_permission(self, request, view) -> bool:
        return permissions.has_permission(request.user, STAFF_BASELINE)


class HasAreaPermission(BasePermission):
    """``access.manage:read`` for safe methods, ``access.manage:write`` for every other."""

    def has_permission(self, request, view) -> bool:
        level = READ if request.method in SAFE_METHODS else WRITE
        return permissions.has_permission(request.user, f"{ACCESS_MANAGE}:{level}")
