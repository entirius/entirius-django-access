# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""System checks (tag ``entirius_config``): a broken access catalogue, gate mode or view area is caught at boot; a
per-process cache and a gate that does not enforce in production warn; modules still on the access default rules are
listed (Info). ``check --deploy`` also refuses an enforcing gate over unmapped admin routes (``E011``).

An area whose module is not installed is not an error — the default catalogue covers modules a deployment may not run.
"""

import re
from collections import Counter

from django.apps import apps
from django.conf import settings
from django.core import checks

from django_access.catalogue import registry
from django_access.catalogue.areas import AREA_KEY_RE, LEVEL_SETS, READ, SENSITIVE_FLAGS, STAFF_BASELINE, WRITE, Area
from django_access.catalogue.defaults import AREA_OVERRIDES, RouteRule
from django_access.services import gate, route_map
from django_access.services.gate import ENFORCE, MODE_SETTING, MODES

PROCESS_LOCAL_CACHES = frozenset(
    {"django.core.cache.backends.locmem.LocMemCache", "django.core.cache.backends.dummy.DummyCache"}
)
HTTP_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE", "TRACE"})
UNMAPPED_SHOWN = 10


@checks.register("entirius_config")
def catalogue_is_consistent(app_configs=None, **kwargs) -> list[checks.CheckMessage]:
    try:
        catalogue = registry.catalogue()
    except TypeError as exc:
        return [checks.Error(f"Unreadable access declaration: {exc}", id="django_access.E006")]
    known = {item.key for item in catalogue.areas}
    return [
        *_duplicates((item.key for item in catalogue.areas), "area", "django_access.E001"),
        *_duplicates((item.key for item in catalogue.scopes), "token scope", "django_access.E002"),
        *(error for item in catalogue.areas for error in _area_errors(item)),
        *(error for rule in catalogue.rules for error in _rule_errors(rule, known)),
        *_override_errors(known),
    ]


def _override_errors(known: set[str]) -> list[checks.Error]:
    """An area override naming an area a module's own declaration dropped would refuse everyone but superusers."""
    return [
        checks.Error(f"Area override {item.pattern!r} names unknown area {item.area!r}", id="django_access.E003")
        for item in AREA_OVERRIDES
        if item.area not in known
    ]


def _duplicates(keys, what: str, check_id: str) -> list[checks.Error]:
    counts = Counter(keys)
    return [checks.Error(f"Duplicate {what} key {key!r}", id=check_id) for key, n in counts.items() if n > 1]


def _area_errors(item: Area) -> list[checks.Error]:
    problems = []
    if not AREA_KEY_RE.match(item.key) or item.key == STAFF_BASELINE:
        problems.append("key must match <module>.<name> in lowercase and not be the staff baseline")
    if tuple(item.levels) not in LEVEL_SETS:
        problems.append(f"levels must be one of {LEVEL_SETS}")
    if not set(item.sensitive) <= SENSITIVE_FLAGS:
        problems.append(f"sensitive flags must be among {sorted(SENSITIVE_FLAGS)}")
    return [checks.Error(f"Invalid area {item.key!r}: {problem}", id="django_access.E004") for problem in problems]


def _rule_errors(rule: RouteRule, known: set[str]) -> list[checks.Error]:
    errors = []
    if rule.area != STAFF_BASELINE and rule.area not in known:
        errors.append(
            checks.Error(f"Route rule {rule.pattern!r} names unknown area {rule.area!r}", id="django_access.E003")
        )
    try:
        re.compile(rule.pattern)
    except re.error as exc:
        errors.append(checks.Error(f"Route rule {rule.pattern!r} is not a valid regex: {exc}", id="django_access.E005"))
    return errors


@checks.register("entirius_config")
def permission_cache_is_shared(app_configs=None, **kwargs) -> list[checks.CheckMessage]:
    """The permission cache version must reach every process: a per-process default cache delays revocations."""
    backend = settings.CACHES.get("default", {}).get("BACKEND", "")
    if settings.DEBUG or backend not in PROCESS_LOCAL_CACHES:
        return []
    return [
        checks.Warning(
            f"The default cache is {backend.rsplit('.', 1)[-1]}: permission changes reach other processes only after "
            "the cache TIMEOUT",
            hint="Use a shared cache (Redis) as the default cache.",
            id="django_access.W002",
        )
    ]


@checks.register("entirius_config")
def gate_mode_is_valid(app_configs=None, **kwargs) -> list[checks.CheckMessage]:
    """An unknown ``ACCESS_GATE_MODE`` is enforced (and an error); ``observe``/``off`` without ``DEBUG`` warn."""
    value = getattr(settings, MODE_SETTING, ENFORCE)
    if value not in MODES:
        return [
            checks.Error(
                f"{MODE_SETTING} {value!r} is not one of {', '.join(MODES)}: the gate enforces",
                id="django_access.E010",
            )
        ]
    if value != ENFORCE and not settings.DEBUG:
        return [checks.Warning(f"{MODE_SETTING} is {value!r}: the admin gate does not refuse", id="django_access.W010")]
    return []


@checks.register("entirius_config")
def modules_declare_own_rules(app_configs=None, **kwargs) -> list[checks.CheckMessage]:
    """Migration progress: installed apps with at least one admin route whose area still comes from the access
    defaults. Silent on an unreadable declaration (``E006`` reports it)."""
    try:
        owners = {
            info.owner for info, _ in route_map.unique_entries() if info.admin and info.area_source == route_map.DEFAULT
        }
    except TypeError:
        return []
    labels = sorted(
        config.label for config in apps.get_app_configs() if config.label in owners and config.label != "django_access"
    )
    if not labels:
        return []
    return [
        checks.Info(
            f"{len(labels)} module(s) own admin routes still mapped by the access defaults: {', '.join(labels)}",
            hint="Set access_area on the views (or declare access_route_rules) and declare access_areas on the "
            "module's AppConfig (django_access docs/module-authors.md).",
            id="django_access.I001",
        )
    ]


@checks.register("entirius_config")
def view_areas_are_valid(app_configs=None, **kwargs) -> list[checks.CheckMessage]:
    """A view's ``access_area`` must name a catalogue area (``E007``), its ``access_levels`` known methods and levels
    the area offers (``E008``), and its route must be an admin route the gate acts on (``W003``)."""
    try:
        entries = route_map.unique_entries()
        known = {item.key: item.levels for item in registry.areas()}
    except TypeError:
        return []
    return [message for info, callback in entries for message in _view_messages(info, callback, known)]


def _view_messages(info: route_map.RouteInfo, callback, known: dict) -> list[checks.CheckMessage]:
    area = route_map.view_attribute(callback, route_map.AREA_ATTR)
    levels = route_map.view_attribute(callback, route_map.LEVELS_ATTR)
    messages = [] if levels is None else _level_errors(info, levels, known)
    if area is None:
        return messages
    if not isinstance(area, str) or (area != STAFF_BASELINE and area not in known):
        messages.append(checks.Error(f"{info.route}: access_area {area!r} is not an area", id="django_access.E007"))
    if not info.admin:
        messages.append(
            checks.Warning(f"{info.route}: access_area on a route outside the admin set", id="django_access.W003")
        )
    return messages


def _level_errors(info: route_map.RouteInfo, levels: object, known: dict) -> list[checks.Error]:
    if not isinstance(levels, dict):
        return [checks.Error(f"{info.route}: access_levels must be a dict", id="django_access.E008")]
    offered = known.get(info.area, ()) if isinstance(info.area, str) else ()
    problems = [
        f"{method}: {level}"
        for method, level in levels.items()
        if str(method).upper() not in HTTP_METHODS or level not in (READ, WRITE) or level not in offered
    ]
    if not problems:
        return []
    message = f"{info.route}: access_levels for area {info.area!r} not offered: {', '.join(problems)}"
    return [checks.Error(message, id="django_access.E008")]


@checks.register("entirius_config", deploy=True)
def enforce_has_no_unmapped_routes(app_configs=None, **kwargs) -> list[checks.CheckMessage]:
    """``check --deploy``: an enforcing gate refuses every unmapped admin route to everyone but superusers."""
    if gate.mode() != ENFORCE:
        return []
    try:
        unmapped = route_map.unmapped_admin([info for info, _ in route_map.unique_entries()])
    except TypeError:
        return []
    if not unmapped:
        return []
    return [
        checks.Error(
            f"{len(unmapped)} admin route(s) without an access area while the gate enforces: "
            f"{', '.join(unmapped[:UNMAPPED_SHOWN])}",
            hint="run manage.py access_routes --unmapped; deploy with ACCESS_GATE_MODE=observe until the report is "
            "clean",
            id="django_access.E011",
        )
    ]
