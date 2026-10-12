# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
from django.db import models


class Role(models.Model):
    """A named set of permissions; built-in roles hold no rows, their permissions come from the catalogue."""

    key = models.SlugField(max_length=64, unique=True)
    name = models.CharField(max_length=128)
    description = models.TextField(blank=True, default="")
    builtin = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-builtin", "name", "id"]

    def __str__(self) -> str:
        return self.name


class RolePermission(models.Model):
    """One validated permission key (``<area>:<level>``) of a custom role."""

    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name="permissions")
    permission = models.CharField(max_length=128)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["role", "permission"], name="django_access_role_permission")]
        ordering = ["permission"]

    def __str__(self) -> str:
        return f"{self.role.key}: {self.permission}"
