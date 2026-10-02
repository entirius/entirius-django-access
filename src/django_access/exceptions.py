# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Refusals of the access service: conflicts mean HTTP 409 at the admin API (plan 06); reserved permissions (plan 06)
and expiry errors (plan 07) 400."""


class AccessConflict(Exception):
    """The change contradicts the current state: a built-in role, a duplicate key or grant."""


class AccessLockout(AccessConflict):
    """The change would leave no active user able to manage access."""


class ReservedPermission(ValueError):
    """A custom role asked for ``access.manage``: only the built-in Administrator role carries it."""

    ACCESS_MANAGE_RESERVED = "ACCESS_MANAGE_RESERVED"

    def __init__(self, keys: list[str]) -> None:
        super().__init__(f"Reserved for the built-in Administrator role: {', '.join(keys)}")
        self.keys = keys


class TokenExpiryError(ValueError):
    """A secret-scope token without an expiry, or with one beyond the maximum lifetime."""

    EXPIRY_REQUIRED = "EXPIRY_REQUIRED"
    EXPIRY_TOO_LONG = "EXPIRY_TOO_LONG"

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
