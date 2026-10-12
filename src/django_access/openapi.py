# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""drf-spectacular postprocessing hook: the ``ApiKeyAuth`` scheme (header ``X-API-KEY``) on every key route.

The key routes are the token scopes' ``routes`` patterns — ``{name}`` is one path segment, ``/**`` the rest of the
path (or none). The hook touches no module: it adds the key to each security requirement an operation already has (a route that
also takes the customer JWT gets ``{"ApiKeyAuth": [], "jwtAuth": []}``, whatever the JWT scheme is called there).
Wire it in ``SPECTACULAR_SETTINGS["POSTPROCESSING_HOOKS"]`` after drf-spectacular's default hooks.
"""

import re

from django_access.catalogue import registry
from django_access.catalogue.scopes import route_regex

SCHEME_NAME = "ApiKeyAuth"
API_KEY_SCHEME = {"type": "apiKey", "in": "header", "name": "X-API-KEY"}


def key_route_matcher() -> re.Pattern:
    routes = {route for scope in registry.scopes() for route in scope.routes}
    return re.compile("|".join(f"(?:{route_regex(route)})" for route in sorted(routes)) or "(?!)")


def _with_key(security: list[dict] | None) -> list[dict]:
    """Every existing alternative now also needs the key; an operation without security needs the key alone."""
    requirements: list[dict] = []
    for requirement in security or [{}]:
        if (merged := {SCHEME_NAME: [], **requirement}) not in requirements:
            requirements.append(merged)
    return requirements


def add_api_key_security(result: dict, generator, request, public: bool) -> dict:
    result.setdefault("components", {}).setdefault("securitySchemes", {})[SCHEME_NAME] = API_KEY_SCHEME
    matcher = key_route_matcher()
    for path, item in result.get("paths", {}).items():
        if not matcher.fullmatch(path):
            continue
        for operation in item.values():
            if isinstance(operation, dict) and "responses" in operation:
                operation["security"] = _with_key(operation.get("security"))
    return result
