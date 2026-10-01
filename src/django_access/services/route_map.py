# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Route map: for a resolved route, its owning module, whether it is an admin route, its area and the level each HTTP
method needs. Pure — imports no models, so the route audit runs in a service that has not installed the app yet.

The route key is the exact string Django puts in ``ResolverMatch.route``; ``walk()`` rebuilds it for every pattern.
Admin set = path test ∪ view-permission test ∪ the exceptions in ``catalogue.defaults``.
"""

import json
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import TextIO

from django.urls import URLPattern, URLResolver, get_resolver

from django_access.catalogue import registry
from django_access.catalogue.areas import READ, STAFF_BASELINE, WRITE
from django_access.catalogue.defaults import ADMIN_ROUTES, METHOD_OVERRIDES, NOT_ADMIN_ROUTES

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
ADMIN_PERMISSION_NAMES = frozenset({"IsAdminUser", "IsSuperUser"})
ADMIN_PATH_RE = re.compile(r"(?:^|/)admin/|^api-admin/")
# Framework views (DRF router roots) own no module: the matching route rule names it.
FRAMEWORK_PACKAGES = frozenset({"rest_framework", "django"})

_cache: dict[str, "RouteInfo"] = {}


@dataclass(frozen=True)
class RouteInfo:
    route: str
    owner: str
    admin: bool
    area: str | None
    method_levels: dict[str, str] = field(default_factory=dict)


def reset() -> None:
    """Forget classified routes and the catalogue they were classified against."""
    registry.reset()
    _cache.clear()


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
    rule = next((item for item in registry.route_rules() if item.matches(path)), None)
    owner = _owner(callback)
    if owner in FRAMEWORK_PACKAGES and rule is not None:
        owner = rule.module
    return RouteInfo(
        route=route,
        owner=owner,
        admin=_is_admin(path, callback),
        area=rule.area if rule else None,
        method_levels=_method_levels(path),
    )


def _method_levels(path: str) -> dict[str, str]:
    """Level per overridden method; the first matching override wins, as for route rules."""
    levels: dict[str, str] = {}
    for item in METHOD_OVERRIDES:
        if item.matches(path):
            levels.setdefault(item.method, item.level)
    return levels


def _owner(callback: Callable) -> str:
    view = getattr(callback, "cls", None) or getattr(callback, "view_class", None) or callback
    return view.__module__.split(".")[0]


def _is_admin(path: str, callback: Callable) -> bool:
    if any(re.match(pattern, path) for pattern in NOT_ADMIN_ROUTES):
        return False
    if any(re.match(pattern, path) for pattern in ADMIN_ROUTES):
        return True
    return bool(ADMIN_PATH_RE.search(path)) or _has_admin_permission(callback)


def _has_admin_permission(callback: Callable) -> bool:
    view = getattr(callback, "cls", None) or getattr(callback, "view_class", None)
    classes = getattr(view, "permission_classes", None) or ()
    return any(_is_admin_class(item) for item in classes)


def _is_admin_class(item: object) -> bool:
    """An admin permission class, or a DRF ``&``/``|`` composite holding one; ``~X`` (NOT) never is."""
    if hasattr(item, "op2_class"):
        return _is_admin_class(item.op1_class) or _is_admin_class(item.op2_class)
    if hasattr(item, "op1_class"):
        return False
    return isinstance(item, type) and any(base.__name__ in ADMIN_PERMISSION_NAMES for base in item.__mro__)


def required_permission(info: RouteInfo, method: str) -> str | None:
    """``<area>:<level>`` the method needs, ``"staff.baseline"``, or ``None`` when the route has no area.

    A level the area does not offer becomes write: a write-only area needs write for every method, and a write on a
    read-only area needs a key no role holds — refused, never an error.
    """
    if info.area is None or info.area == STAFF_BASELINE:
        return info.area
    method = method.upper()
    level = info.method_levels.get(method) or (READ if method in SAFE_METHODS else WRITE)
    if level not in _levels(info.area):
        level = WRITE
    return f"{info.area}:{level}"


def _levels(area_key: str) -> tuple[str, ...]:
    try:
        return registry.area(area_key).levels
    except KeyError:
        return ()


def audit_routes(out: TextIO, json_path: str | None = None) -> int:
    """Print routes / admin / mapped / unmapped per module and every unmapped admin route; 1 when any is unmapped."""
    infos = _unique_infos()
    summary = _summary(infos)
    unmapped = [info.route for info in infos if info.admin and info.area is None]
    _print_audit(out, summary, unmapped)
    if json_path:
        _write_json(json_path, infos, summary, unmapped)
    return 1 if unmapped else 0


def _unique_infos() -> list[RouteInfo]:
    """One info per route string, the first one the resolver would match."""
    seen: dict[str, RouteInfo] = {}
    for route, callback in walk():
        seen.setdefault(route, classify(route, callback))
    return list(seen.values())


def _summary(infos: list[RouteInfo]) -> dict[str, dict[str, int]]:
    summary: dict[str, dict[str, int]] = {}
    for info in infos:
        row = summary.setdefault(info.owner, {"routes": 0, "admin": 0, "mapped": 0, "unmapped": 0})
        row["routes"] += 1
        if info.admin:
            row["admin"] += 1
            row["mapped" if info.area else "unmapped"] += 1
    return dict(sorted(summary.items()))


def _print_audit(out: TextIO, summary: dict[str, dict[str, int]], unmapped: list[str]) -> None:
    out.write(f"{'module':<32} {'routes':>7} {'admin':>7} {'mapped':>7} {'unmapped':>9}\n")
    for owner, row in summary.items():
        out.write(f"{owner:<32} {row['routes']:>7} {row['admin']:>7} {row['mapped']:>7} {row['unmapped']:>9}\n")
    totals = {key: sum(row[key] for row in summary.values()) for key in ("routes", "admin", "mapped", "unmapped")}
    out.write(f"{'TOTAL':<32} {totals['routes']:>7} {totals['admin']:>7} {totals['mapped']:>7} {len(unmapped):>9}\n")
    for route in unmapped:
        out.write(f"UNMAPPED admin route: {route}\n")
    out.write(f"route audit: {'FAILED' if unmapped else 'OK'}\n")


def _write_json(path: str, infos: list[RouteInfo], summary: dict, unmapped: list[str]) -> None:
    report = {
        "routes": len(infos),
        "admin_routes": sum(info.admin for info in infos),
        "unmapped_admin": unmapped,
        "modules": summary,
        "admin": [{"route": i.route, "owner": i.owner, "area": i.area} for i in infos if i.admin],
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
