# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Read-only admin: every access change goes through ``access_service`` / ``tokens`` (audit + lockout guard).

Tokens have no add path (the admin could never show a raw value) and ``key_hash`` is on no list, form or page.
"""

from django.contrib import admin

from django_access.models import ApiToken, Application, AuditEntry, Grant, Role


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


@admin.register(Application)
class ApplicationAdmin(ReadOnlyAdmin):
    list_display = ("name", "is_active", "created_at", "created_by")
    search_fields = ("name",)


@admin.register(ApiToken)
class ApiTokenAdmin(ReadOnlyAdmin):
    fields = (
        "application",
        "name",
        "prefix",
        "last_four",
        "scopes",
        "channel_idx",
        "expires_at",
        "last_used_at",
        "revoked_at",
        "revoked_by",
        "created_at",
        "created_by",
        "legacy",
        "legacy_source",
    )
    readonly_fields = fields
    list_display = ("__str__", "application", "channel_idx", "expires_at", "last_used_at", "revoked_at", "legacy")
    list_filter = ("legacy",)
    list_select_related = ("application",)
    search_fields = ("name", "prefix", "application__name")
