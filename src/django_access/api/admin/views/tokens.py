# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Admin API v2 — application tokens: the raw value appears once, in the create or rotate response (never cached);
every other response shows ``prefix`` and ``last_four`` only, and no response carries ``key_hash``."""

from contextlib import suppress

from django.utils import timezone
from drf_spectacular.utils import extend_schema
from rest_framework.request import Request
from rest_framework.response import Response

from django_access.api.admin.views._base import (
    ERROR_RESPONSES,
    PAGE_PARAMETERS,
    WRITE_ERRORS,
    AdminView,
    actor,
    no_store,
    parse,
    service_errors,
)
from django_access.exceptions import AccessConflict
from django_access.models import ApiToken, Application
from django_access.schemas.requests import PageQuery, TokenCreateRequest, TokenExpiryRequest, TokenRotateRequest
from django_access.schemas.responses import TokenListResponse, TokenResponse, TokenSecretResponse
from django_access.services import tokens

_TAGS = ["Access Tokens"]
_SHOWN_ONCE = "The raw value is in this response only (`Cache-Control: no-store`)."


_COMPUTED = frozenset({"state", "age_days", "rotation_due"})


def _fields(token: ApiToken) -> dict:
    """The response whitelist read off the row, plus the state, age and rotation flag — never ``key_hash``."""
    now = timezone.now()
    computed = {
        "state": tokens.token_state(token, now),
        "age_days": tokens.token_age_days(token, now),
        "rotation_due": tokens.rotation_due(token, now),
    }
    return {**{name: getattr(token, name) for name in TokenResponse.model_fields.keys() - _COMPUTED}, **computed}


def dump(token: ApiToken) -> dict:
    return TokenResponse(**_fields(token)).model_dump(mode="json")


def shown_once(token: ApiToken, raw: str) -> Response:
    return no_store(Response(TokenSecretResponse(**_fields(token), raw=raw).model_dump(mode="json"), status=201))


class ApplicationTokenListView(AdminView):
    @extend_schema(
        tags=_TAGS,
        operation_id="access_tokens_list",
        summary="An application's tokens, newest first (never their values)",
        parameters=PAGE_PARAMETERS,
        responses={200: TokenListResponse, **ERROR_RESPONSES},
    )
    def get(self, request: Request, pk: int) -> Response:
        parse(PageQuery, request.query_params.dict())
        application = self.one(Application.objects.all(), pk)
        return self.paginated(request, application.tokens.select_related("application"), dump)

    @extend_schema(
        tags=_TAGS,
        summary="Issue a token",
        description=f"{_SHOWN_ONCE} Unknown scope, mixed publishable and secret scopes → 400.",
        request=TokenCreateRequest,
        responses={201: TokenSecretResponse, **WRITE_ERRORS},
    )
    def post(self, request: Request, pk: int) -> Response:
        data = parse(TokenCreateRequest, request.data)
        application = self.one(Application.objects.all(), pk)
        with service_errors():
            token, raw = tokens.issue_token(application, **data.model_dump(), actor=actor(request))
        return shown_once(token, raw)


class TokenRotateView(AdminView):
    @extend_schema(
        tags=_TAGS,
        summary="Rotate a token: a successor with the same scopes and channel",
        description=f"{_SHOWN_ONCE} The old token keeps working for `overlap_hours`. A revoked token → 409.",
        request=TokenRotateRequest,
        responses={201: TokenSecretResponse, **WRITE_ERRORS},
    )
    def post(self, request: Request, pk: int) -> Response:
        data = parse(TokenRotateRequest, request.data)
        token = self.one(ApiToken.objects.all(), pk)
        with service_errors():
            successor, raw = tokens.rotate_token(token, actor=actor(request), **data.model_dump())
        return shown_once(successor, raw)


class TokenRevokeView(AdminView):
    @extend_schema(
        tags=_TAGS,
        summary="Revoke a token at once",
        description="Idempotent: an already revoked token answers 200 again, without a second audit row.",
        request=None,
        responses={200: TokenResponse, **ERROR_RESPONSES},
    )
    def post(self, request: Request, pk: int) -> Response:
        token = self.one(ApiToken.objects.all(), pk)
        with suppress(AccessConflict):  # already revoked
            tokens.revoke_token(token, actor=actor(request))
        token.refresh_from_db()
        return Response(dump(token))


class TokenExpiryView(AdminView):
    @extend_schema(
        tags=_TAGS,
        summary="Set or clear a token's expiry",
        description="Audited `token.expiry`. Legacy keys never expire by themselves; a team sets or clears it here.",
        request=TokenExpiryRequest,
        responses={200: TokenResponse, **WRITE_ERRORS},
    )
    def post(self, request: Request, pk: int) -> Response:
        data = parse(TokenExpiryRequest, request.data)
        token = self.one(ApiToken.objects.all(), pk)
        with service_errors():
            token = tokens.set_token_expiry(token, expires_at=data.expires_at, actor=actor(request))
        return Response(dump(token))
