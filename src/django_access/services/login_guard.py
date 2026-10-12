# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""A failed-login counter for every password login of the service (``api/token/``, the customer token route, the
Django admin form through ``guarded_admin_login``).

Only failed attempts count, per username + address, per address and per username from any address; a success clears
the first counter and is never counted. The address is DRF's ``get_ident`` (``NUM_PROXIES``). Cache keys carry hashes
only — no username or address is stored. Settings: ``AUTH_TOKEN_FAILURE_WINDOW_S`` (900, the first two counters),
``AUTH_TOKEN_MAX_FAILURES_PER_USER_IP`` (10), ``AUTH_TOKEN_MAX_FAILURES_PER_IP`` (100),
``AUTH_TOKEN_MAX_FAILURES_PER_USER`` (50) and ``AUTH_TOKEN_USER_FAILURE_WINDOW_S`` (3600). The per-username counter
slows guesses spread over many addresses; its price: anyone who knows a username can hold it at 429 for up to its window.
"""

import functools
import hashlib
import math
import unicodedata
from collections.abc import Callable, Mapping

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.http import HttpResponse
from rest_framework.exceptions import Throttled
from rest_framework.throttling import BaseThrottle

ADMIN_LOGIN_REFUSED = "Too many failed login attempts. Try again later."


def failure_window_s() -> int:
    return getattr(settings, "AUTH_TOKEN_FAILURE_WINDOW_S", 900)


def _limits() -> tuple[int, int, int]:
    return (
        getattr(settings, "AUTH_TOKEN_MAX_FAILURES_PER_USER_IP", 10),
        getattr(settings, "AUTH_TOKEN_MAX_FAILURES_PER_IP", 100),
        getattr(settings, "AUTH_TOKEN_MAX_FAILURES_PER_USER", 50),
    )


def _windows() -> tuple[int, int, int]:
    window = failure_window_s()
    return window, window, getattr(settings, "AUTH_TOKEN_USER_FAILURE_WINDOW_S", 3600)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def login_username(request) -> str:
    """The username of a login body, stripped like SimpleJWT's ``CharField``: " admin" logs into "admin", so it must
    hit the same counter."""
    data = request.data if isinstance(request.data, Mapping) else {}
    return str(data.get(get_user_model().USERNAME_FIELD, "")).strip()


def failure_keys(request, username: str) -> tuple[str, str, str]:
    """(per username + address, per address, per username) counter keys; ``username`` as the login serializer sees
    it."""
    ident = BaseThrottle().get_ident(request)
    per_user_ip = _digest(f"{username}\x00{ident}")
    return f"auth:fail:ui:{per_user_ip}", f"auth:fail:ip:{_digest(ident)}", f"auth:fail:u:{_digest(username)}"


def refuse_when_blocked(request, username: str) -> None:
    """``Throttled`` when any counter has reached its limit — checked before the password is. ``wait`` is the window of
    the blocking counter, the longest when several block."""
    keys = failure_keys(request, username)
    counts = cache.get_many(keys)
    rules = zip(keys, _limits(), _windows(), strict=True)
    if waits := [window for key, limit, window in rules if counts.get(key, 0) >= limit]:
        raise Throttled(wait=max(waits))


def _count(key: str, window: int) -> None:
    """The window runs from the first failure."""
    if cache.add(key, 1, timeout=window):
        return
    try:
        cache.incr(key)
    except ValueError:  # expired between add and incr
        cache.add(key, 1, timeout=window)


def record_failure(request, username: str) -> None:
    for key, window in zip(failure_keys(request, username), _windows(), strict=True):
        _count(key, window)


def clear(request, username: str) -> None:
    """A successful login clears its username + address counter; the per-address and per-username ones run out with
    their windows."""
    cache.delete(failure_keys(request, username)[0])


def _form_username(request) -> str:
    """The username as the admin login form reads it (stripped, NFKC): a look-alike spelling hits the same counter."""
    return unicodedata.normalize("NFKC", str(request.POST.get("username", "")).strip())


def _refusal(exc: Throttled) -> HttpResponse:
    headers = {"Retry-After": str(math.ceil(exc.wait))}
    return HttpResponse(ADMIN_LOGIN_REFUSED, status=429, content_type="text/plain", headers=headers)


def _count_form_attempt(request, username: str, response) -> None:
    """The login form answers a wrong password by showing itself again (200) and a login by a redirect; anything
    else (a failed CSRF check) never read the password. Only a login as ``username`` clears its counter: a backend
    that signs somebody else in (a session or header credential) proved nothing about that account."""
    if response.status_code == 200:
        record_failure(request, username)
    elif 300 <= response.status_code < 400 and request.user.get_username() == username:
        clear(request, username)


def guarded_admin_login(view: Callable) -> Callable:
    """``AdminSite.login`` behind the counters of ``api/token/``: same keys, limits and windows, so a login blocked on
    one is blocked on the other. A blocked POST answers 429 with ``Retry-After`` before the password is checked."""

    @functools.wraps(view)
    def guarded(request, *args, **kwargs):
        if request.method != "POST":
            return view(request, *args, **kwargs)
        username = _form_username(request)
        try:
            refuse_when_blocked(request, username)
        except Throttled as exc:
            return _refusal(exc)
        response = view(request, *args, **kwargs)
        _count_form_attempt(request, username, response)
        return response

    guarded.admin_site = view.__self__  # the route map's mark of an admin-site view; a bound ``AdminSite.login`` only
    return guarded
