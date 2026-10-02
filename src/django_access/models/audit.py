# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
from django.conf import settings
from django.db import models


class AuditAction:
    """Audit action names (README contract); ``action`` stays a free string so later plans add theirs."""

    ROLE_CREATE = "role.create"
    ROLE_UPDATE = "role.update"
    ROLE_DELETE = "role.delete"
    GRANT_CREATE = "grant.create"
    GRANT_DELETE = "grant.delete"
    GRANT_MIGRATE = "grant.migrate"
    APPLICATION_CREATE = "application.create"
    APPLICATION_UPDATE = "application.update"
    TOKEN_CREATE = "token.create"  # noqa: S105 — an audit action name
    TOKEN_ROTATE = "token.rotate"  # noqa: S105 — an audit action name
    TOKEN_REVOKE = "token.revoke"  # noqa: S105 — an audit action name
    GATE_BYPASS = "gate.bypass"


class AuditEntry(models.Model):
    """Append-only record of an access change; labels are copied so the row survives its actor and target."""

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )
    actor_label = models.CharField(max_length=150)
    action = models.CharField(max_length=64, db_index=True)
    target_type = models.CharField(max_length=64)
    target_id = models.CharField(max_length=64)
    target_label = models.CharField(max_length=255)
    detail = models.JSONField(default=dict, blank=True)
    ip = models.GenericIPAddressField(null=True, blank=True)

    class Meta:
        verbose_name_plural = "audit entries"
        ordering = ["-created_at", "-id"]

    def __str__(self) -> str:
        return f"{self.action} {self.target_type}#{self.target_id} by {self.actor_label}"
