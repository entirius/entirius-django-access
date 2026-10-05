# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""A failed-login counter for every password login of the service (``api/token/``, the customer token route).

Only failed attempts count, per username + address and per address; a success clears the first counter and is never
counted. The address is DRF's ``get_ident`` (``NUM_PROXIES``). Cache keys carry hashes only — no username or address
is stored. Settings: ``AUTH_TOKEN_FAILURE_WINDOW_S`` (900), ``AUTH_TOKEN_MAX_FAILURES_PER_USER_IP`` (10),
``AUTH_TOKEN_MAX_FAILURES_PER_IP`` (100).
"""

import hashlib
from collections.abc import Mapping

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from rest_framework.exceptions import Throttled
from rest_framework.throttling import BaseThrottle


def failure_window_s() -> int:
    return getattr(settings, "AUTH_TOKEN_FAILURE_WINDOW_S", 900)


def _limits() -> tuple[int, int]:
    return (
        getattr(settings, "AUTH_TOKEN_MAX_FAILURES_PER_USER_IP", 10),
        getattr(settings, "AUTH_TOKEN_MAX_FAILURES_PER_IP", 100),
    )


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def login_username(request) -> str:
    """The username of a login body, stripped like SimpleJWT's ``CharField``: " admin" logs into "admin", so it must
    hit the same counter."""
    data = request.data if isinstance(request.data, Mapping) else {}
    return str(data.get(get_user_model().USERNAME_FIELD, "")).strip()


def failure_keys(request, username: str) -> tuple[str, str]:
    """(per username + address, per address) counter keys; ``username`` as the login serializer sees it."""
    ident = BaseThrottle().get_ident(request)
    per_user_ip = _digest(f"{username}\x00{ident}")
    return f"auth:fail:ui:{per_user_ip}", f"auth:fail:ip:{_digest(ident)}"


def refuse_when_blocked(request, username: str) -> None:
    """``Throttled`` when either counter has reached its limit — checked before the password is."""
    keys = failure_keys(request, username)
    counts = cache.get_many(keys)
    if any(counts.get(key, 0) >= limit for key, limit in zip(keys, _limits(), strict=True)):
        raise Throttled(wait=failure_window_s())


def _count(key: str) -> None:
    window = failure_window_s()
    if cache.add(key, 1, timeout=window):
        return
    try:
        cache.incr(key)
    except ValueError:  # expired between add and incr
        cache.add(key, 1, timeout=window)


def record_failure(request, username: str) -> None:
    for key in failure_keys(request, username):
        _count(key)


def clear(request, username: str) -> None:
    """A successful login clears its username + address counter; the per-address one runs out with its window."""
    cache.delete(failure_keys(request, username)[0])
