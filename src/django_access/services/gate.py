# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""The admin gate's decision for a resolved request, its refusal bodies and the superuser bypass audit row.

Outside the admin set nothing runs but one memoized ``classify()``. Inside it, the principal is what the view's own
authenticators would see — SimpleJWT ``JWTAuthentication`` and DRF ``SessionAuthentication`` only; the API-key headers
are never read, so a token never opens an admin route. Anonymous callers reach only views that authenticate them
themselves (``RouteInfo.self_auth``); everyone else is answered here.
"""

import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass

from django.conf import settings
from django.http import HttpRequest, JsonResponse
from django_utils.api.v2_errors import ErrorDetail, ErrorResponse
from rest_framework.authentication import SessionAuthentication
from rest_framework.exceptions import AuthenticationFailed, PermissionDenied
from rest_framework.permissions import SAFE_METHODS
from rest_framework_simplejwt.authentication import JWTAuthentication

from django_access.catalogue import registry
from django_access.catalogue.areas import STAFF_BASELINE, WRITE
from django_access.models import AuditAction, AuditEntry
from django_access.services import permissions, route_map
from django_access.services.access_service import Actor
from django_access.services.route_map import RouteInfo

logger = logging.getLogger("django_access.gate")

ENFORCE, OBSERVE, OFF = "enforce", "observe", "off"
MODES = (ENFORCE, OBSERVE, OFF)  # a tuple: an unhashable setting value must not raise
MODE_SETTING = "ACCESS_GATE_MODE"
ACCESS_DENIED, STAFF_ONLY, UNMAPPED_ROUTE = "ACCESS_DENIED", "STAFF_ONLY", "UNMAPPED_ROUTE"
NOT_AUTHENTICATED = "NOT_AUTHENTICATED"
JWT_AUTH = "rest_framework_simplejwt.authentication.JWTAuthentication"
SESSION_AUTH = "rest_framework.authentication.SessionAuthentication"
WWW_AUTHENTICATE = 'Bearer realm="api"'
# The v2 exception handler's texts, pinned here (django-utils keeps them private); a test compares them with its output.
AUTHENTICATION_MESSAGE = "Authentication credentials were not provided or are invalid."
PERMISSION_MESSAGE = "You do not have permission to perform this action."
INTERNAL_MESSAGE = "An internal error occurred."
_DESCRIPTIONS = {
    STAFF_ONLY: "A staff account is required.",
    UNMAPPED_ROUTE: "This admin route has no access area.",
    NOT_AUTHENTICATED: AUTHENTICATION_MESSAGE,
}
# The v2 exception handler's codes and texts, so clients and BDD steps read a gate refusal like a view's.
_ENVELOPES = {
    401: ("AUTHENTICATION_REQUIRED", AUTHENTICATION_MESSAGE, "header"),
    403: ("PERMISSION_DENIED", PERMISSION_MESSAGE, "path"),
}
_reported_modes: set[str] = set()


@dataclass(frozen=True)
class Decision:
    allow: bool
    status: int = 200
    issue: str | None = None
    needed: str | None = None
    bypass: bool = False


ALLOW = Decision(allow=True)


def mode() -> str:
    """The configured mode; any value but the three is enforced (logged once per process, ``E010`` at boot)."""
    value = getattr(settings, MODE_SETTING, ENFORCE)
    if value in MODES:
        return value
    if repr(value) not in _reported_modes:
        _reported_modes.add(repr(value))
        logger.error("Invalid %s %r: enforcing", MODE_SETTING, value)
    return ENFORCE


def decide(request: HttpRequest, view_func: Callable) -> Decision:
    """The gate's answer for a resolved request; ``ALLOW`` without any work outside the admin set."""
    info = route_map.classify(request.resolver_match.route, view_func)
    if not info.admin:
        return ALLOW
    user = principal(request, info, view_func)
    if user is None:
        return ALLOW if info.self_auth else Decision(False, 401, NOT_AUTHENTICATED)
    if not user.is_active:  # whatever the view's authenticator settings, an inactive account is never let through
        return Decision(False, 401, NOT_AUTHENTICATED)
    # Django serves HEAD with the GET handler, so HEAD needs what GET needs (a GET PII export is a write).
    method = "GET" if request.method == "HEAD" else request.method
    needed = route_map.required_permission(info, method)
    if user.is_superuser:  # without is_staff too: the view's IsAdminUser / IsStaffUser refuses them (bypass row kept)
        return Decision(True, needed=needed, bypass=_is_write(needed, method))
    if not user.is_staff:
        return Decision(False, 403, STAFF_ONLY, needed)
    return _staff_decision(user, info, needed)


def _is_write(needed: str | None, method: str) -> bool:
    """A superuser write worth a bypass row: a write permission, or any unsafe method on a route without an area."""
    if needed is None:
        return method not in SAFE_METHODS
    return needed.endswith(f":{WRITE}")


def _staff_decision(user, info: RouteInfo, needed: str | None) -> Decision:
    if needed is None:
        logger.error("Admin route without an access area: %s", info.route)
        return Decision(False, 403, UNMAPPED_ROUTE)
    if needed == STAFF_BASELINE:
        return ALLOW
    if not _offered(needed) or not permissions.has_permission(user, needed):
        return Decision(False, 403, ACCESS_DENIED, needed)
    return Decision(True, needed=needed)


def _offered(needed: str) -> bool:
    """Whether the area offers the level (a write on a read-only area does not; ``has_permission`` would raise)."""
    try:
        registry.parse_perm(needed)
    except ValueError:
        return False
    return True


def principal(request: HttpRequest, info: RouteInfo, view_func: Callable):
    """The user the view's own authenticators would see, or ``None``; cached on the request."""
    if not hasattr(request, "_access_principal"):
        request._access_principal = _authenticate(request, info, view_func)
    return request._access_principal


def _authenticate(request: HttpRequest, info: RouteInfo, view_func: Callable):
    """DRF view: its JWT/session authenticators in order, as DRF runs them — the first user wins, a rejected credential
    ends the walk. Other views: a valid Bearer JWT, else the session. Authenticators the gate does not run are
    skipped — their views are not ``self_auth``."""
    if not hasattr(view_func, "cls"):
        return _valid_jwt_user(request) or _session_user(request)
    runners = {JWT_AUTH: _jwt_user, SESSION_AUTH: _drf_session_user}
    try:
        users = (runners[dotted](request) for dotted in info.auth if dotted in runners)
        return next((user for user in users if user is not None), None)
    except AuthenticationFailed:  # InvalidToken is a subclass
        return None


def _jwt_user(request: HttpRequest):
    """``JWTAuthentication`` reads only ``request.META``: no DRF ``Request`` wrapper, the body stays unread."""
    result = JWTAuthentication().authenticate(request)
    return result[0] if result else None


def _valid_jwt_user(request: HttpRequest):
    try:
        return _jwt_user(request)
    except AuthenticationFailed:
        return None


def _session_user(request: HttpRequest):
    user = getattr(request, "user", None)
    return user if user is not None and user.is_authenticated else None


def _drf_session_user(request: HttpRequest):
    """The session as DRF ``SessionAuthentication`` takes it: only with a passing CSRF check, so a cross-site request
    riding a session decides nothing and leaves no bypass row."""
    user = _session_user(request)
    if user is None:
        return None
    try:
        SessionAuthentication().enforce_csrf(request)
    except PermissionDenied:
        return None
    return user


def refusal(decision: Decision) -> JsonResponse:
    """The v2 envelope of a 401/403 refusal; the 401 carries ``WWW-Authenticate``. Names no area for ``STAFF_ONLY``."""
    error, message, location = _ENVELOPES[decision.status]
    description = _DESCRIPTIONS.get(decision.issue) or f"needs {decision.needed}"
    detail = ErrorDetail(field=None, location=location, issue=decision.issue, description=description)
    body = ErrorResponse(error=error, message=message, debug_id=new_debug_id(), details=[detail])
    response = JsonResponse(body.model_dump(), status=decision.status)
    if decision.status == 401:
        response["WWW-Authenticate"] = WWW_AUTHENTICATE
    return response


def internal_error(debug_id: str) -> JsonResponse:
    body = ErrorResponse(error="INTERNAL_ERROR", message=INTERNAL_MESSAGE, debug_id=debug_id)
    return JsonResponse(body.model_dump(), status=500)


def new_debug_id() -> str:
    return uuid.uuid4().hex[:8]


def log_refusal(request: HttpRequest, decision: Decision) -> None:
    """``observe``: what enforce would have refused — never headers, cookies or the query string."""
    user = getattr(request, "_access_principal", None)
    logger.warning(
        "Gate would refuse: user=%s method=%s route=%s needed=%s issue=%s",
        getattr(user, "pk", None),
        request.method,
        request.resolver_match.route,
        decision.needed,
        decision.issue,
    )


def record_bypass(request: HttpRequest, decision: Decision, status: int) -> None:
    """One ``gate.bypass`` row for a superuser write, after the response, with its status."""
    user = request._access_principal
    route = request.resolver_match.route
    AuditEntry.objects.create(
        actor=user,
        actor_label=Actor(user).label,
        action=AuditAction.GATE_BYPASS,
        target_type="route",
        target_id="",
        target_label=route[:255],
        detail={"method": request.method, "route": route, "needed": decision.needed, "status": status},
    )
