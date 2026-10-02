# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""System checks (tag ``entirius_config``): a broken access catalogue or gate mode is caught at boot; a per-process
cache and a gate that does not enforce in production warn; modules still on the access default rules are listed (Info).

An area whose module is not installed is not an error — the default catalogue covers modules a deployment may not run.
"""

import re
from collections import Counter

from django.apps import AppConfig, apps
from django.conf import settings
from django.core import checks

from django_access.catalogue import registry
from django_access.catalogue.areas import AREA_KEY_RE, LEVEL_SETS, SENSITIVE_FLAGS, STAFF_BASELINE, Area
from django_access.catalogue.defaults import AREA_OVERRIDES, RouteRule
from django_access.services import route_map
from django_access.services.gate import ENFORCE, MODE_SETTING, MODES

PROCESS_LOCAL_CACHES = frozenset(
    {"django.core.cache.backends.locmem.LocMemCache", "django.core.cache.backends.dummy.DummyCache"}
)


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
    """Migration progress: installed apps owning admin routes that declare neither ``access_areas`` nor
    ``access_route_rules`` — their routes still live on the access defaults. Silent on an unreadable declaration
    (``E006`` reports it)."""
    try:
        owners = {info.owner for info, _ in route_map.unique_entries() if info.admin}
    except TypeError:
        return []
    labels = sorted(
        config.label
        for config in apps.get_app_configs()
        if config.label in owners and config.label != "django_access" and not _declares_own(config)
    )
    if not labels:
        return []
    return [
        checks.Info(
            f"{len(labels)} module(s) own admin routes but declare no access rules of their own: {', '.join(labels)}",
            hint="Declare access_areas and access_route_rules on the module's AppConfig (django_access "
            "docs/module-authors.md).",
            id="django_access.I001",
        )
    ]


def _declares_own(config: AppConfig) -> bool:
    return any(getattr(config, name, None) is not None for name in registry.OWN_DECLARATIONS)
