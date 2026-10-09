# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Plain helpers shared by test modules — never import from a conftest or another test module."""

from datetime import timedelta

from rest_framework_simplejwt.tokens import AccessToken

from django_access.models import AuditAction, AuditEntry

# Measured: the gate loads the JWT user (1), the view authenticates again (1); permissions come from the warm cache.
STAFF_GET_QUERIES = 2

TOKEN_API_URL = "/api/access/v2/admin/"
TOKEN_ENDPOINTS = [
    ("get", "applications/", None),
    ("post", "applications/", {"name": "Widget"}),
    ("get", "applications/{application}/", None),
    ("patch", "applications/{application}/", {"description": "Shop"}),
    ("get", "applications/{application}/tokens/", None),
    ("post", "applications/{application}/tokens/", {"scopes": ["checkout.storefront"]}),
    ("post", "tokens/{token}/rotate/", {}),
    ("post", "tokens/{token}/revoke/", None),
    ("post", "tokens/{token}/expiry/", {"expires_at": None}),
]


def bearer(user, **lifetime) -> dict:
    token = AccessToken.for_user(user)
    if lifetime:
        token.set_exp(lifetime=timedelta(**lifetime))
    return {"HTTP_AUTHORIZATION": f"Bearer {token}"}


def bypass_rows() -> list[dict]:
    """The ``detail`` of every ``gate.bypass`` row, oldest first."""
    rows = AuditEntry.objects.filter(action=AuditAction.GATE_BYPASS).order_by("pk")
    return list(rows.values_list("detail", flat=True))


def call_token_api(client, method: str, path: str, body: dict | None, ids: dict):
    return getattr(client, method)(TOKEN_API_URL + path.format(**ids), body, format="json")
