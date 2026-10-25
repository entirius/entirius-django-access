# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""``POST token/exchange``: an application key with an admin scope → a short-lived JWT every admin view accepts.

The key never opens an admin route itself; the JWT it buys is decided by the gate against that key's scopes and state
on every admin request. Throttled per presented key and per address; every refusal is the same 401.
"""

from django.core.exceptions import ImproperlyConfigured
from django.http import JsonResponse
from django_utils.api.v2_errors import ErrorDetail, ErrorResponse
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.throttling import SimpleRateThrottle
from rest_framework.views import APIView

from django_access.api.admin.views._base import no_store
from django_access.exceptions import InvalidApiKey
from django_access.schemas.responses import TokenExchangeResponse
from django_access.services import gate, tokens

INVALID_API_KEY = "INVALID_API_KEY"
_INVALID_DESCRIPTION = "An active application key with an admin scope is required in X-API-KEY."


class _ExchangeThrottle(SimpleRateThrottle):
    """A scope rate from ``DEFAULT_THROTTLE_RATES``, else the class rate — never ``None``, never malformed."""

    def get_rate(self) -> str:
        try:
            rate = super().get_rate()
        except ImproperlyConfigured:  # scope missing from DEFAULT_THROTTLE_RATES
            return self.rate
        if not rate or "/" not in rate:  # a malformed rate must not disable throttling
            return self.rate
        return rate


class KeyThrottle(_ExchangeThrottle):
    scope = "access_token_exchange"
    rate = "30/min"

    def get_cache_key(self, request: Request, view) -> str | None:
        presented = tokens.presented_key(request)
        if presented is None:
            return None  # the address throttle still counts it
        return self.cache_format % {"scope": self.scope, "ident": tokens.hash_key(presented)}


class AddressThrottle(_ExchangeThrottle):
    scope = "access_token_exchange_address"
    rate = "120/min"

    def get_cache_key(self, request: Request, view) -> str:
        return self.cache_format % {"scope": self.scope, "ident": self.get_ident(request)}


def _invalid_key() -> JsonResponse:
    detail = ErrorDetail(field=None, location="header", issue=INVALID_API_KEY, description=_INVALID_DESCRIPTION)
    body = ErrorResponse(
        error="AUTHENTICATION_REQUIRED",
        message=gate.AUTHENTICATION_MESSAGE,
        debug_id=gate.new_debug_id(),
        details=[detail],
    )
    return JsonResponse(body.model_dump(), status=401)


class TokenExchangeView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]
    throttle_classes = [KeyThrottle, AddressThrottle]

    @extend_schema(
        tags=["Access Tokens"],
        operation_id="access_token_exchange",
        summary="Exchange an application key for a short-lived admin JWT",
        description=(
            "Send the key in `X-API-KEY` (alias `X-API-ADMIN-KEY`), no body. The key needs at least one admin scope "
            "(`<area>:read|write`). The JWT acts as the application's service account; the gate checks every admin "
            "request against the key's scopes, so a revoked key stops the JWT at once. No refresh token: exchange "
            "again when it expires. Every refusal is 401 `INVALID_API_KEY`; 429 above the rate."
        ),
        request=None,
        responses={
            200: TokenExchangeResponse,
            401: OpenApiResponse(description="INVALID_API_KEY"),
            429: OpenApiResponse(description="Throttled"),
        },
    )
    def post(self, request: Request) -> Response | JsonResponse:
        try:
            _, jwt = tokens.exchange(request)
        except InvalidApiKey:
            return _invalid_key()
        body = TokenExchangeResponse(access=str(jwt), expires_in=int(tokens.exchange_ttl().total_seconds()))
        return no_store(Response(body.model_dump(mode="json")))
