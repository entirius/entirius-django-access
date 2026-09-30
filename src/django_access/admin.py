# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Read-only admin: every access change goes through ``access_service`` (audit + lockout guard)."""

from django.contrib import admin

from django_access.models import AuditEntry, Grant, Role


class ReadOnlyAdmin(admin.ModelAdmin):
    def has_add_permission(self, request) -> bool:
        return False

    def has_change_permission(self, request, obj=None) -> bool:
        return False

    def has_delete_permission(self, request, obj=None) -> bool:
        return False


@admin.register(Role)
class RoleAdmin(ReadOnlyAdmin):
    list_display = ("key", "name", "builtin", "updated_at")
    search_fields = ("key", "name")


@admin.register(Grant)
class GrantAdmin(ReadOnlyAdmin):
    list_display = ("role", "user", "group", "created_at", "created_by")
    list_select_related = ("role", "user", "group", "created_by")


@admin.register(AuditEntry)
class AuditEntryAdmin(ReadOnlyAdmin):
    list_display = ("created_at", "action", "actor_label", "target_type", "target_label")
    list_filter = ("action",)
    search_fields = ("actor_label", "target_label")
