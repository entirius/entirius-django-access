# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Refusals of the access service; both mean HTTP 409 at the admin API (plan 06)."""


class AccessConflict(Exception):
    """The change contradicts the current state: a built-in role, a duplicate key or grant."""


class AccessLockout(AccessConflict):
    """The change would leave no active user able to manage access."""
