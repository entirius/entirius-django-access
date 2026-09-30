# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""The effective catalogue: the defaults plus what installed apps declare on their ``AppConfig``.

An app declaring ``access_areas``, ``access_route_rules`` or ``access_token_scopes`` (a list of the dataclass or of
dicts with its fields) replaces the defaults of that kind for its own label only; ``module`` is always set to the
declaring app's label. Computed once and cached; ``reset()`` recomputes on the next call (tests, settings changes).
"""

import dataclasses
import functools

from django.apps import apps

from django_access.catalogue.areas import DEFAULT_AREAS, WRITE, Area
from django_access.catalogue.defaults import DEFAULT_RULES, RouteRule
from django_access.catalogue.scopes import DEFAULT_SCOPES, TokenScope


@dataclasses.dataclass(frozen=True)
class Catalogue:
    areas: tuple[Area, ...]
    scopes: tuple[TokenScope, ...]
    rules: tuple[RouteRule, ...]


def _coerce(cls: type, item: object, label: str) -> object:
    if isinstance(item, dict):
        return cls(**{**item, "module": label})
    return dataclasses.replace(item, module=label)


def _merge(defaults: tuple, attr: str, cls: type) -> tuple:
    merged = list(defaults)
    for config in apps.get_app_configs():
        declared = getattr(config, attr, None)
        if declared is None:
            continue
        try:
            own = [_coerce(cls, item, config.label) for item in declared]
        except TypeError as exc:
            raise TypeError(f"{config.label}.{attr}: {exc}") from exc
        merged = _replace_module(merged, config.label, own)
    return tuple(merged)


def _replace_module(items: list, label: str, own: list) -> list:
    """Swap the module's entries for its own, at the position of its first default (rule order is first-match)."""
    index = next((i for i, item in enumerate(items) if item.module == label), len(items))
    kept = [item for item in items if item.module != label]
    return kept[:index] + own + kept[index:]


@functools.cache
def catalogue() -> Catalogue:
    return Catalogue(
        areas=_merge(DEFAULT_AREAS, "access_areas", Area),
        scopes=_merge(DEFAULT_SCOPES, "access_token_scopes", TokenScope),
        rules=_merge(DEFAULT_RULES, "access_route_rules", RouteRule),
    )


@functools.cache
def _areas_by_key() -> dict[str, Area]:
    return {item.key: item for item in catalogue().areas}


def reset() -> None:
    catalogue.cache_clear()
    _areas_by_key.cache_clear()


def areas() -> tuple[Area, ...]:
    return catalogue().areas


def scopes() -> tuple[TokenScope, ...]:
    return catalogue().scopes


def route_rules() -> tuple[RouteRule, ...]:
    return catalogue().rules


def area(key: str) -> Area:
    """The area with this key; ``KeyError`` when the catalogue has none."""
    return _areas_by_key()[key]


def perm_key(area_key: str, level: str) -> str:
    """``<area>:<level>``; ``ValueError`` for an unknown area or a level the area does not offer."""
    known = _areas_by_key().get(area_key)
    if known is None or level not in known.levels:
        raise ValueError(f"Unknown permission: {area_key}:{level}")
    return f"{area_key}:{level}"


def parse_perm(key: str) -> tuple[Area, str]:
    """Split and validate a permission key into ``(area, level)``; ``ValueError`` when invalid."""
    area_key, _, level = key.rpartition(":")
    perm_key(area_key, level)
    return area(area_key), level


def implies(held: str, needed: str) -> bool:
    """Whether holding permission ``held`` satisfies ``needed``: the same area, and write implies read."""
    held_area, _, held_level = held.rpartition(":")
    needed_area, _, needed_level = needed.rpartition(":")
    return held_area == needed_area and held_level in (needed_level, WRITE)
