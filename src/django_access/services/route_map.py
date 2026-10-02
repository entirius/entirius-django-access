# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Route map: for a resolved route, its owning module, whether it is an admin route, its area, the level each HTTP
method needs and whether the view authenticates the caller itself. Pure — imports no models, so the route audit runs in
a service that has not installed the app yet.

The route key is the exact string Django puts in ``ResolverMatch.route``; ``walk()`` rebuilds it for every pattern.
Admin set = path test ∪ view-permission test ∪ the exceptions in ``catalogue.defaults``. A route rule applies only to
the routes of its own module; framework routes (Django admin, DRF router roots, OpenAPI) match ``FRAMEWORK_RULES`` only.
Area precedence: the view's ``access_area`` → the owner's ``AppConfig`` rules → the access defaults (``area_source``);
the view's ``access_levels`` win per method over ``METHOD_OVERRIDES``; ``AREA_OVERRIDES`` still apply on top.
"""

import functools
import json
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import TextIO

from django.urls import URLPattern, URLResolver, get_resolver
from rest_framework.views import APIView

from django_access.catalogue import registry
from django_access.catalogue.areas import READ, STAFF_BASELINE, WRITE
from django_access.catalogue.defaults import (
    ADMIN_ROUTES,
    AREA_OVERRIDES,
    FRAMEWORK_RULES,
    METHOD_OVERRIDES,
    NOT_ADMIN_ROUTES,
    SELF_AUTH_ROUTES,
    RouteRule,
)
from django_access.catalogue.scopes import route_regex

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
ADMIN_PERMISSION_NAMES = frozenset({"IsAdminUser", "IsSuperUser"})
AUTH_PERMISSION_NAMES = ADMIN_PERMISSION_NAMES | {"IsAuthenticated"}
ADMIN_SITE_NAMES = frozenset({"AdminSite"})
# A view overriding one of these may authenticate or authorise differently from its declared classes.
OVERRIDE_BREAKS_SELF_AUTH = ("get_authenticators", "get_permissions", "check_permissions")
# Exactly these classes, never subclasses: the gate runs only them, a lenient subclass authenticates users it never sees.
SELF_AUTH_CLASSES = frozenset(
    {
        "rest_framework_simplejwt.authentication.JWTAuthentication",
        "rest_framework.authentication.SessionAuthentication",
    }
)
ADMIN_PATH_RE = re.compile(r"(?:^|/)admin/|^api-admin/")
DJANGO = "django"
FRAMEWORK_PACKAGES = frozenset({"rest_framework", DJANGO, "drf_spectacular"})
AUDIENCE_KEY, AUDIENCE_WEBHOOK, AUDIENCE_CUSTOMER, AUDIENCE_PUBLIC = "key", "webhook", "customer", "public"
# Where a route's area comes from (``RouteInfo.area_source``; None = no area).
VIEW, APP, DEFAULT, FRAMEWORK = "view", "app", "default", "framework"
AREA_SOURCES = (VIEW, APP, DEFAULT, FRAMEWORK)
AREA_ATTR, LEVELS_ATTR = "access_area", "access_levels"
RULES_DECLARATION = "access_route_rules"

_cache: dict[str, "RouteInfo"] = {}


@dataclass(frozen=True)
class RouteInfo:
    route: str
    owner: str
    admin: bool
    area: str | None
    method_levels: dict[str, str] = field(default_factory=dict)
    method_areas: dict[str, str] = field(default_factory=dict)
    self_auth: bool = False
    auth: tuple[str, ...] = ()
    area_source: str | None = None


def reset() -> None:
    """Forget classified routes and the catalogue they were classified against."""
    registry.reset()
    _cache.clear()
    _scope_patterns.cache_clear()


def walk(urlconf: str | None = None) -> Iterator[tuple[str, Callable]]:
    """Every ``(route, callback)`` of the urlconf, in resolver order, the route built as ``ResolverMatch.route``."""
    yield from _walk(get_resolver(urlconf).url_patterns)


def _walk(patterns: list) -> Iterator[tuple[str, Callable]]:
    for pattern in patterns:
        if isinstance(pattern, URLPattern):
            yield str(pattern.pattern), pattern.callback
        elif isinstance(pattern, URLResolver):
            prefix = str(pattern.pattern)
            for route, callback in _walk(pattern.url_patterns):
                yield (prefix + route.removeprefix("^") if prefix else route), callback


def classify(route: str, callback: Callable) -> RouteInfo:
    """The route's ``RouteInfo``, memoized by route string (one string resolves to one view)."""
    if route not in _cache:
        _cache[route] = _classify(route, callback)
    return _cache[route]


def _classify(route: str, callback: Callable) -> RouteInfo:
    path = route.removeprefix("^")
    owner, rule, source = _owner_and_rule(path, callback)
    if (view_area := view_attribute(callback, AREA_ATTR)) is not None:
        area, source = view_area, VIEW
    else:
        area, source = (rule.area, source) if rule else (None, None)
    return RouteInfo(
        route=route,
        owner=owner,
        admin=_is_admin(path, callback),
        area=area,
        method_levels={**_per_method(METHOD_OVERRIDES, "level", path), **_view_levels(callback)},
        method_areas=_per_method(AREA_OVERRIDES, "area", path),
        self_auth=_self_auth(path, callback),
        auth=tuple(_dotted(item) for item in _authentication_classes(callback)),
        area_source=source,
    )


def view_attribute(callback: Callable, name: str) -> object:
    """``name`` set on the callback (a decorated function view), else on its DRF ``cls`` / Django ``view_class``."""
    holders = (callback, getattr(callback, "cls", None), getattr(callback, "view_class", None))
    return next((value for holder in holders if (value := getattr(holder, name, None)) is not None), None)


def _view_levels(callback: Callable) -> dict[str, str]:
    """The view's ``access_levels`` by upper-case method; a malformed value is left to check ``E008``."""
    levels = view_attribute(callback, LEVELS_ATTR)
    if not isinstance(levels, dict):
        return {}
    return {str(method).upper(): level for method, level in levels.items()}


def _owner_and_rule(path: str, callback: Callable) -> tuple[str, RouteRule | None, str]:
    """The owner, its first matching rule and the rule's source; a framework route takes the module of its
    ``FRAMEWORK_RULES`` match."""
    owner = DJANGO if _is_django_admin_site(path, callback) else _owner(callback)
    if owner in FRAMEWORK_PACKAGES:
        rule = _first_match(FRAMEWORK_RULES, path)
        return (rule.module if rule else owner), rule, FRAMEWORK
    source = APP if owner in registry.declaring_labels(RULES_DECLARATION) else DEFAULT
    return owner, _first_match((item for item in registry.route_rules() if item.module == owner), path), source


def _first_match(rules, path: str) -> RouteRule | None:
    return next((item for item in rules if item.matches(path)), None)


def _per_method(overrides: tuple, attr: str, path: str) -> dict[str, str]:
    """``attr`` per overridden method; the first matching override wins, as for route rules."""
    values: dict[str, str] = {}
    for item in overrides:
        if item.matches(path):
            values.setdefault(item.method, getattr(item, attr))
    return values


def _owner(callback: Callable) -> str:
    view = getattr(callback, "cls", None) or getattr(callback, "view_class", None) or callback
    return view.__module__.split(".")[0]


def _is_django_admin_site(path: str, callback: Callable) -> bool:
    """A non-DRF view under ``SELF_AUTH_ROUTES``: the Django admin site, also for the views modules add to it (their
    ``admin_view`` wrapper copies the module's ``__module__``)."""
    return not hasattr(callback, "cls") and any(re.match(pattern, path) for pattern in SELF_AUTH_ROUTES)


def _is_admin_site_view(callback: Callable) -> bool:
    """A view the admin site marks itself (``get_urls`` wrappers) or its login page (a bound ``AdminSite`` method).

    A module's view wrapped by ``admin_site.admin_view()`` carries no mark: it cannot be told from an unwrapped view, so
    it is not self-authenticating — the gate answers its anonymous callers.
    """
    if hasattr(callback, "admin_site") or hasattr(callback, "model_admin"):
        return True
    return _named(type(getattr(callback, "__self__", None)), ADMIN_SITE_NAMES)


def _is_admin(path: str, callback: Callable) -> bool:
    if any(re.match(pattern, path) for pattern in NOT_ADMIN_ROUTES):
        return False
    if any(re.match(pattern, path) for pattern in ADMIN_ROUTES):
        return True
    return bool(ADMIN_PATH_RE.search(path)) or any(_is_admin_class(item) for item in _permission_classes(callback))


def _declared(callback: Callable, name: str) -> tuple:
    """A DRF view's ``name`` classes as DRF resolves them: ``as_view`` initkwargs, else the class attribute (the DRF
    default when the view declares none)."""
    initkwargs = getattr(callback, "initkwargs", None) or {}
    return tuple(initkwargs.get(name, getattr(callback.cls, name)))


def _authentication_classes(callback: Callable) -> tuple:
    if not hasattr(callback, "cls"):
        return ()
    return _declared(callback, "authentication_classes")


def _permission_classes(callback: Callable) -> tuple:
    if not hasattr(callback, "cls"):
        return ()
    return _declared(callback, "permission_classes")


def _dotted(item: type) -> str:
    return f"{item.__module__}.{item.__qualname__}"


def _self_auth(path: str, callback: Callable) -> bool:
    """Whether the view itself answers an anonymous caller (DRF: exactly JWT/Session + a permission requiring a user)."""
    view = getattr(callback, "cls", None)
    if view is None:
        return _is_django_admin_site(path, callback) and _is_admin_site_view(callback)
    if any(getattr(view, name) is not getattr(APIView, name) for name in OVERRIDE_BREAKS_SELF_AUTH):
        return False
    authenticators = _authentication_classes(callback)
    return (
        bool(authenticators)
        and all(_dotted(item) in SELF_AUTH_CLASSES for item in authenticators)
        and any(_requires_auth(item) for item in _permission_classes(callback))
    )


def _named(item: object, names: frozenset[str]) -> bool:
    return isinstance(item, type) and any(base.__name__ in names for base in item.__mro__)


def _is_admin_class(item: object) -> bool:
    """An admin permission class, or a DRF ``&``/``|`` composite holding one; ``~X`` (NOT) never is."""
    if hasattr(item, "op2_class"):
        return _is_admin_class(item.op1_class) or _is_admin_class(item.op2_class)
    if hasattr(item, "op1_class"):
        return False
    return _named(item, ADMIN_PERMISSION_NAMES)


def _requires_auth(item: object) -> bool:
    """A permission that refuses anonymous callers: ``A & B`` when either side does, ``A | B`` when both, ``~A`` never."""
    if hasattr(item, "op2_class"):
        sides = (_requires_auth(item.op1_class), _requires_auth(item.op2_class))
        return all(sides) if item.operator_class.__name__ == "OR" else any(sides)
    if hasattr(item, "op1_class"):
        return False
    return _named(item, AUTH_PERMISSION_NAMES)


def required_permission(info: RouteInfo, method: str) -> str | None:
    """``<area>:<level>`` the method needs, ``"staff.baseline"``, or ``None`` when the route has no area.

    An area override replaces the route's area for its method (deleting a SKU is not editing it). A level the area
    does not offer becomes write: a write-only area needs write for every method, and a write on a read-only area
    needs a key no role holds — refused, never an error.
    """
    if info.area is None or info.area == STAFF_BASELINE:
        return info.area
    method = method.upper()
    area = info.method_areas.get(method, info.area)
    level = info.method_levels.get(method) or (READ if method in SAFE_METHODS else WRITE)
    if level not in _levels(area):
        level = WRITE
    return f"{area}:{level}"


def _levels(area_key: str) -> tuple[str, ...]:
    try:
        return registry.area(area_key).levels
    except KeyError:
        return ()


def audit_routes(out: TextIO, json_path: str | None = None) -> int:
    """Print the per-module summary, every unmapped admin route and every foreign rule match; 1 when any exists."""
    entries = unique_entries()
    infos = [info for info, _ in entries]
    summary = _summary(infos)
    unmapped = unmapped_admin(infos)
    foreign = foreign_rule_matches(infos)
    _print_audit(out, summary, unmapped, foreign)
    _print_sources(out, infos)
    if json_path:
        _write_json(json_path, entries, summary, unmapped, foreign)
    return 1 if unmapped or foreign else 0


def audit_unmapped(out: TextIO, json_path: str | None = None) -> int:
    """The upgrade preflight: every admin route without an area with its owner and methods; 1 when any exists."""
    entries = unique_entries()
    infos = [info for info, _ in entries]
    unmapped = [(info, callback) for info, callback in entries if info.admin and info.area is None]
    for info, callback in unmapped:
        out.write(f"UNMAPPED {info.route}\towner={info.owner}\tmethods={','.join(handler_methods(callback))}\n")
    if not unmapped:
        out.write("no unmapped admin routes\n")
    if json_path:
        _write_json(json_path, entries, _summary(infos), unmapped_admin(infos), foreign_rule_matches(infos))
    return 1 if unmapped else 0


def unmapped_admin(infos: list[RouteInfo]) -> list[str]:
    return [info.route for info in infos if info.admin and info.area is None]


def handler_methods(callback: Callable) -> list[str]:
    """The HTTP methods the view handles (``OPTIONS`` left out — every view answers it); ``*`` for a function view."""
    if actions := getattr(callback, "actions", None):
        return sorted(method.upper() for method in actions)
    view = getattr(callback, "cls", None) or getattr(callback, "view_class", None)
    if view is None:
        return ["*"]
    return sorted(name.upper() for name in view.http_method_names if name != "options" and hasattr(view, name))


def unique_entries(urlconf: str | None = None) -> list[tuple[RouteInfo, Callable]]:
    """One ``(info, callback)`` per route string, the first one the resolver would match."""
    seen: dict[str, tuple[RouteInfo, Callable]] = {}
    for route, callback in walk(urlconf):
        seen.setdefault(route, (classify(route, callback), callback))
    return list(seen.values())


def foreign_rule_matches(infos: list[RouteInfo]) -> list[dict[str, str]]:
    """Every rule of another module whose pattern matches a route — owner scoping ignores it, the audit reports it."""
    return [
        {"route": info.route, "owner": info.owner, "rule_module": rule.module, "pattern": rule.pattern}
        for info in infos
        for rule in registry.route_rules()
        if rule.module != info.owner and rule.matches(info.route.removeprefix("^"))
    ]


def _summary(infos: list[RouteInfo]) -> dict[str, dict[str, int]]:
    summary: dict[str, dict[str, int]] = {}
    for info in infos:
        row = summary.setdefault(info.owner, {"routes": 0, "admin": 0, "mapped": 0, "unmapped": 0})
        row["routes"] += 1
        if info.admin:
            row["admin"] += 1
            row["mapped" if info.area else "unmapped"] += 1
    return dict(sorted(summary.items()))


def _print_audit(out: TextIO, summary: dict[str, dict[str, int]], unmapped: list[str], foreign: list[dict]) -> None:
    out.write(f"{'module':<32} {'routes':>7} {'admin':>7} {'mapped':>7} {'unmapped':>9}\n")
    for owner, row in summary.items():
        out.write(f"{owner:<32} {row['routes']:>7} {row['admin']:>7} {row['mapped']:>7} {row['unmapped']:>9}\n")
    totals = {key: sum(row[key] for row in summary.values()) for key in ("routes", "admin", "mapped", "unmapped")}
    out.write(f"{'TOTAL':<32} {totals['routes']:>7} {totals['admin']:>7} {totals['mapped']:>7} {len(unmapped):>9}\n")
    for route in unmapped:
        out.write(f"UNMAPPED admin route: {route}\n")
    for item in foreign:
        out.write(
            f"FOREIGN rule {item['rule_module']} {item['pattern']!r} matches {item['owner']} route {item['route']}\n"
        )
    out.write(f"route audit: {'FAILED' if unmapped or foreign else 'OK'}\n")


def _print_sources(out: TextIO, infos: list[RouteInfo]) -> None:
    counts = {source: sum(info.admin and info.area_source == source for info in infos) for source in AREA_SOURCES}
    out.write("admin area sources: " + ", ".join(f"{source} {count}" for source, count in counts.items()) + "\n")


def _write_json(path: str, entries: list, summary: dict, unmapped: list[str], foreign: list[dict]) -> None:
    infos = [info for info, _ in entries]
    report = {
        "routes": len(infos),
        "admin_routes": sum(info.admin for info in infos),
        "unmapped_admin": unmapped,
        "foreign_rule_matches": foreign,
        "admin_not_self_auth": [info.route for info in infos if info.admin and not info.self_auth],
        "modules": summary,
        "admin": [_admin_entry(info) for info in infos if info.admin],
        "non_admin": [_non_admin_entry(info, callback) for info, callback in entries if not info.admin],
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)


def _admin_entry(info: RouteInfo) -> dict:
    return {
        "route": info.route,
        "owner": info.owner,
        "area": info.area,
        "area_source": info.area_source,
        "method_areas": info.method_areas,
        "self_auth": info.self_auth,
        "auth": info.auth,
    }


def _non_admin_entry(info: RouteInfo, callback: Callable) -> dict:
    permissions = _permission_classes(callback)
    return {
        "route": info.route,
        "owner": info.owner,
        "auth": info.auth,
        "permissions": [_permission_name(item) for item in permissions],
        "audience": _audience(info.route.removeprefix("^"), permissions),
    }


def _permission_name(item: object) -> str:
    """A permission class name; DRF composites as ``(A AND B)``, ``(A OR B)``, ``(NOT A)``."""
    if hasattr(item, "op2_class"):
        operator = item.operator_class.__name__
        return f"({_permission_name(item.op1_class)} {operator} {_permission_name(item.op2_class)})"
    if hasattr(item, "op1_class"):
        return f"(NOT {_permission_name(item.op1_class)})"
    return getattr(item, "__name__", type(item).__name__)


def _audience(path: str, permissions: tuple) -> str:
    """Who a non-admin route serves: token-scope route → key, webhook, an authentication-requiring permission → customer."""
    if any(pattern.fullmatch(path.removesuffix("$")) for pattern in _scope_patterns()):
        return AUDIENCE_KEY
    if "webhook" in path:
        return AUDIENCE_WEBHOOK
    return AUDIENCE_CUSTOMER if any(_requires_auth(item) for item in permissions) else AUDIENCE_PUBLIC


@functools.cache
def _scope_patterns() -> tuple[re.Pattern, ...]:
    """The token scopes' doc patterns (``/api/x/{channel_idx}/carts/**``) as regexes over route strings."""
    return tuple(re.compile(route_regex(route.lstrip("/"))) for scope in registry.scopes() for route in scope.routes)
