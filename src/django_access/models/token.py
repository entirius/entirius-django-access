# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
from django.conf import settings
from django.db import models


class ApiToken(models.Model):
    """A hashed application token: only the SHA-256 of the raw value is stored, `prefix` and `last_four` identify it."""

    application = models.ForeignKey("django_access.Application", on_delete=models.CASCADE, related_name="tokens")
    name = models.CharField(max_length=128, blank=True, default="")
    prefix = models.CharField(max_length=12)
    last_four = models.CharField(max_length=4, blank=True, default="")
    key_hash = models.CharField(max_length=64, unique=True)
    scopes = models.JSONField(default=list)
    channel_idx = models.CharField(max_length=64, null=True, blank=True)  # noqa: DJ001 — null = unpinned (contract)
    expires_at = models.DateTimeField(null=True, blank=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )
    legacy = models.BooleanField(default=False)
    legacy_source = models.CharField(max_length=255, blank=True, default="")

    class Meta:
        ordering = ["-created_at", "-id"]

    def __str__(self) -> str:
        return f"{self.name or 'token'} ({self.display})"

    @property
    def display(self) -> str:
        """`prefix…last_four` — the only form a token is ever shown in after it was issued."""
        return f"{self.prefix}…{self.last_four}"
