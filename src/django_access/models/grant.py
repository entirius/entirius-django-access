# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
from django.conf import settings
from django.db import models
from django.db.models import Q


class Grant(models.Model):
    """A role held by one user or by every member of one ``auth.Group`` — exactly one of the two."""

    role = models.ForeignKey("django_access.Role", on_delete=models.CASCADE, related_name="grants")
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, blank=True, related_name="access_grants"
    )
    group = models.ForeignKey(
        "auth.Group", on_delete=models.CASCADE, null=True, blank=True, related_name="access_grants"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=Q(user__isnull=False, group__isnull=True) | Q(user__isnull=True, group__isnull=False),
                name="django_access_grant_user_xor_group",
            ),
            models.UniqueConstraint(fields=["role", "user"], name="django_access_grant_role_user"),
            models.UniqueConstraint(fields=["role", "group"], name="django_access_grant_role_group"),
        ]
        ordering = ["-created_at", "-id"]

    def __str__(self) -> str:
        holder = f"user {self.user_id}" if self.user_id else f"group {self.group_id}"
        return f"{self.role.key} → {holder}"
