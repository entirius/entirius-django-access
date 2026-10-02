# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""The README contract as an oracle: what every principal gets on every route class, per method and mode.

Outcomes: ``RAN`` the view ran (200); ``view401``/``view403`` the view refused on its own (v2 envelope, no details);
``gate401`` the gate's 401; an issue code = the gate's 403 with that issue. In ``observe`` and ``off`` the gate never
refuses: the answer is what the view itself gives.
"""

from dataclasses import dataclass, field

from tests.security import urls

RAN, VIEW401, VIEW403, GATE401 = "ran", "view401", "view403", "gate401"
ACCESS_DENIED, STAFF_ONLY, UNMAPPED_ROUTE = "ACCESS_DENIED", "STAFF_ONLY", "UNMAPPED_ROUTE"
VALID, INVALID = "valid", "invalid"
METHODS = ("GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE")
SAFE = ("GET", "HEAD", "OPTIONS")
WRITES = ("POST", "PUT", "PATCH", "DELETE")
MODES = ("enforce", "observe", "off")
READ, WRITE = "read", "write"
BASELINE = "staff.baseline"
JWT, JWT_SESSION, SESSION_BASIC, NONE = "jwt", "jwt+session", "session+basic", "none"

# Test areas: agreements.definitions, faq.faq, agreements.consents, pim.products (read/write), lookup.search (read
# only), platform.devtools and returns.attachments (write only). Built-in roles per the contract (§ Module).
_RW = ("agreements.definitions", "faq.faq", "agreements.consents", "pim.products")
_EDITOR_WRITES = ("faq.faq", "pim.products")
VIEWER_HELD = {**dict.fromkeys(_RW, READ), "lookup.search": READ}
EDITOR_HELD = {**VIEWER_HELD, **dict.fromkeys(_EDITOR_WRITES, WRITE)}
_WRITE_ONLY = ("platform.devtools", "returns.attachments")
MANAGER_HELD = {**dict.fromkeys((*_RW, *_WRITE_ONLY), WRITE), "lookup.search": READ}


@dataclass(frozen=True)
class Principal:
    jwt: str | None = None  # what SimpleJWT makes of the Authorization header (inactive/deleted/expired = INVALID)
    session: bool = False  # a logged-in session cookie, no header
    staff: bool = False
    superuser: bool = False
    held: dict[str, str] = field(default_factory=dict)


PRINCIPALS = {
    "anonymous": Principal(),
    "malformed_header": Principal(jwt=INVALID),
    "expired_jwt": Principal(jwt=INVALID, staff=True, superuser=True),
    "deleted_user_jwt": Principal(jwt=INVALID, staff=True, superuser=True),
    "customer": Principal(jwt=VALID),
    "inactive_staff": Principal(jwt=INVALID, staff=True, held=MANAGER_HELD),
    "staff_no_role": Principal(jwt=VALID, staff=True),
    "viewer": Principal(jwt=VALID, staff=True, held=VIEWER_HELD),
    "editor": Principal(jwt=VALID, staff=True, held=EDITOR_HELD),
    "manager": Principal(jwt=VALID, staff=True, held=MANAGER_HELD),
    "administrator": Principal(jwt=VALID, staff=True, held=MANAGER_HELD),
    "administrator_group": Principal(jwt=VALID, staff=True, held=MANAGER_HELD),
    "superuser": Principal(jwt=VALID, staff=True, superuser=True),
    "superuser_not_staff": Principal(jwt=VALID, superuser=True),
    "token_every_scope": Principal(),
    "session_superuser": Principal(session=True, staff=True, superuser=True),
}


@dataclass(frozen=True)
class Route:
    path: str
    auth: str
    permission: str  # "admin" (IsAdminUser), "user" (IsAuthenticated), "any" (AllowAny), "none" (no DRF)
    admin: bool = True
    self_auth: bool = False
    area: str | None = None
    levels: tuple[str, ...] = (READ, WRITE)
    overrides: dict[str, str] = field(default_factory=dict)


ROUTES = {
    "rw_read": Route(urls.RW_READ, JWT, "admin", self_auth=True, area="agreements.definitions"),
    "rw_write": Route(urls.RW_WRITE, JWT_SESSION, "admin", self_auth=True, area="faq.faq"),
    "read_only": Route(urls.READ_ONLY, JWT, "admin", self_auth=True, area="lookup.search", levels=(READ,)),
    "write_only": Route(urls.WRITE_ONLY, JWT, "admin", self_auth=True, area="platform.devtools", levels=(WRITE,)),
    # A GET PII export is a write; HEAD runs the same GET handler, so it needs what GET needs.
    "pii_export": Route(
        urls.EXPORT, JWT, "admin", self_auth=True, area="agreements.consents", overrides={"GET": WRITE, "HEAD": WRITE}
    ),
    "baseline": Route(urls.BASELINE, JWT, "admin", self_auth=True, area=BASELINE),
    "default_auth": Route(urls.DEFAULT_AUTH, SESSION_BASIC, "admin", area="pim.products"),
    "allow_any": Route(urls.ALLOW_ANY, JWT, "any", area="faq.faq"),
    "function": Route(urls.FUNCTION, NONE, "none", area="pim.products"),
    # A function-view PII download serves every method alike; its area is write-only, so every method needs write.
    "pii_download": Route(
        urls.PII_DOWNLOAD, NONE, "none", area="returns.attachments", levels=(WRITE,), overrides={"GET": WRITE}
    ),
    "unmapped": Route(urls.UNMAPPED, JWT, "admin", self_auth=True),
    "public": Route(urls.PUBLIC, SESSION_BASIC, "any", admin=False),
    "customer": Route(urls.CUSTOMER, JWT, "user", admin=False),
    "key": Route(urls.KEY, SESSION_BASIC, "any", admin=False),
}


def gate_sees_user(who: Principal, route: Route) -> bool:
    """Whether the gate finds a principal: only the JWT and session authenticators, as the view would run them."""
    if route.auth == JWT:
        return who.jwt == VALID
    if route.auth == JWT_SESSION:
        return who.jwt == VALID or (who.jwt is None and who.session)
    if route.auth == SESSION_BASIC:
        return who.session
    return who.jwt == VALID or who.session


def view_answer(who: Principal, route: Route) -> str:
    """What the view answers on its own (no gate)."""
    if route.auth == NONE:
        return RAN
    user = _view_user(who, route)
    if user == INVALID:
        return VIEW401
    if user is None:
        if route.permission == "any":
            return RAN
        return VIEW403 if route.auth == SESSION_BASIC else VIEW401  # SessionAuthentication sends no challenge
    return VIEW403 if route.permission == "admin" and not who.staff else RAN


def _view_user(who: Principal, route: Route) -> str | None:
    if route.auth in (JWT, JWT_SESSION) and who.jwt is not None:
        return who.jwt
    return VALID if who.session and route.auth != JWT else None


def needed_level(route: Route, method: str) -> str:
    level = route.overrides.get(method) or (READ if method in SAFE else WRITE)
    return level if level in route.levels else WRITE


def expected(who: Principal, route: Route, method: str, mode: str) -> str:
    if mode != "enforce" or not route.admin:
        return view_answer(who, route)
    if not gate_sees_user(who, route):
        return view_answer(who, route) if route.self_auth else GATE401
    if not who.staff:  # a superuser without is_staff too (D11)
        return STAFF_ONLY
    if who.superuser:
        return view_answer(who, route)
    if route.area is None:
        return UNMAPPED_ROUTE
    if route.area == BASELINE:
        return view_answer(who, route)
    level = needed_level(route, method)
    held = who.held.get(route.area)
    return view_answer(who, route) if held in (WRITE, level) else ACCESS_DENIED


def expects_bypass_row(who: Principal, route: Route, method: str, mode: str) -> bool:
    """One ``gate.bypass`` row: a staff superuser the gate sees, on a write of a mapped area or an unsafe method on an
    unmapped route, in every mode but ``off``."""
    if mode == "off" or not route.admin or not (who.superuser and who.staff) or not gate_sees_user(who, route):
        return False
    if route.area is None:
        return method not in SAFE
    return route.area != BASELINE and needed_level(route, method) == WRITE


CASES = [(who, route, method) for who in PRINCIPALS for route in ROUTES for method in METHODS]

_STATUS = {RAN: 200, VIEW401: 401, VIEW403: 403, GATE401: 401}
_ISSUES = {VIEW401: [], VIEW403: [], GATE401: ["NOT_AUTHENTICATED"]}


def assert_answer(response, outcome: str, ran: list, path: str, method: str) -> None:
    """Status, the recorded view run and, when there is a body, the refusal's issue."""
    assert response.status_code == _STATUS.get(outcome, 403)
    assert ran == ([(path, method)] if outcome == RAN else [])
    if outcome == RAN or method == "HEAD":  # a HEAD response has no body
        return
    assert [item["issue"] for item in response.json()["details"]] == _ISSUES.get(outcome, [outcome])
