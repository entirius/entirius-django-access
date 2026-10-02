# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Test helper for modules that own admin routes: prove every one of them is covered by the module's own rules.

Plain ``AssertionError`` — no pytest needed. Works in a module's standalone test settings: the route map is built from
the given urlconf (default ``ROOT_URLCONF``) with ``django_access`` in ``INSTALLED_APPS``.
"""

from collections.abc import Callable

from django.apps import apps

from django_access.catalogue import registry
from django_access.catalogue.areas import STAFF_BASELINE
from django_access.services import route_map

UNMAPPED, FOREIGN_RULE, UNKNOWN_AREA, DEFAULTS = "unmapped", "foreign_rule", "unknown_area", "defaults"


def assert_routes_covered(app_label: str, *, urlconf: str | None = None, require_own: bool = False) -> None:
    """Fail when an admin route ``app_label`` owns has no area, an unknown area, or matches another module's rule.

    ``require_own=True`` also fails while the app declares no ``access_areas`` / ``access_route_rules`` of its own
    (it still lives on the access defaults). An app label that is not installed raises ``LookupError``.
    """
    config = apps.get_app_config(app_label)
    route_map.reset()
    problems = [problem for info, callback in _owned_admin(app_label, urlconf) for problem in _problems(info, callback)]
    if require_own and any(getattr(config, name, None) is None for name in registry.OWN_DECLARATIONS):
        problems.append(f"{app_label}: {DEFAULTS} (declare {' and '.join(registry.OWN_DECLARATIONS)} on its AppConfig)")
    if problems:
        raise AssertionError(f"{app_label}: admin routes not covered by its own rules:\n" + "\n".join(problems))


def _owned_admin(app_label: str, urlconf: str | None) -> list[tuple[route_map.RouteInfo, Callable]]:
    entries = route_map.unique_entries(urlconf)
    return [(info, callback) for info, callback in entries if info.owner == app_label and info.admin]


def _problems(info: route_map.RouteInfo, callback: Callable) -> list[str]:
    where = f"{info.route} [{', '.join(_methods(callback))}]"
    reasons = [
        f"{FOREIGN_RULE} ({item['rule_module']} {item['pattern']!r})" for item in route_map.foreign_rule_matches([info])
    ]
    if info.area is None:
        reasons.append(UNMAPPED)
    elif info.area != STAFF_BASELINE and info.area not in {item.key for item in registry.areas()}:
        reasons.append(f"{UNKNOWN_AREA} ({info.area})")
    return [f"{where}: {reason}" for reason in reasons]


def _methods(callback: Callable) -> list[str]:
    """The HTTP methods the view handles (``OPTIONS`` left out — every view answers it); ``*`` for a function view."""
    if actions := getattr(callback, "actions", None):
        return sorted(method.upper() for method in actions)
    view = getattr(callback, "cls", None) or getattr(callback, "view_class", None)
    if view is None:
        return ["*"]
    return sorted(name.upper() for name in view.http_method_names if name != "options" and hasattr(view, name))
