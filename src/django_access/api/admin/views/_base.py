# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Shared wiring of the access admin views — auth declared explicitly, never inherited from service defaults."""

import ipaddress
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import TypeVar

from django.db.models import QuerySet
from django_utils.api.v2_errors import raise_pydantic_as_drf
from drf_spectacular.utils import OpenApiParameter
from pydantic import BaseModel, ValidationError
from rest_framework.exceptions import APIException, NotFound
from rest_framework.exceptions import ErrorDetail as DrfErrorDetail
from rest_framework.exceptions import ValidationError as DrfValidationError
from rest_framework.pagination import PageNumberPagination
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.settings import api_settings
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication

from django_access.api.permissions import HasAreaPermission, IsStaffUser
from django_access.exceptions import AccessConflict, ReservedPermission, TokenExpiryError
from django_access.schemas.requests import MAX_PAGE_SIZE
from django_access.services.access_service import Actor

SchemaT = TypeVar("SchemaT", bound=BaseModel)

ERROR_RESPONSES = {400: None, 401: None, 403: None, 404: None}
WRITE_ERRORS = {**ERROR_RESPONSES, 409: None}
PAGE_PARAMETERS = [OpenApiParameter("page", int), OpenApiParameter("page_size", int)]
RESERVED_DESCRIPTION = "access.manage belongs to the built-in Administrator role only"


class Conflict(APIException):
    status_code = 409
    default_detail = "The request conflicts with the current state."
    default_code = "conflict"


class AdminPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = "page_size"
    max_page_size = MAX_PAGE_SIZE


class StaffView(APIView):
    """Staff baseline: any active staff user."""

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsStaffUser]


class AdminView(APIView):
    """``access.manage``: read for GET, write otherwise."""

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsStaffUser, HasAreaPermission]

    def paginated(self, request: Request, rows: QuerySet, dump: Callable[[object], dict]) -> Response:
        paginator = AdminPagination()
        page = paginator.paginate_queryset(rows, request, view=self)
        return paginator.get_paginated_response([dump(row) for row in page])

    @staticmethod
    def one(rows: QuerySet, pk: int):
        row = rows.filter(pk=pk).first()
        if row is None:
            raise NotFound()
        return row


def parse(schema: type[SchemaT], data: object) -> SchemaT:
    """Validate request data; a Pydantic error becomes the v2 400 shape."""
    try:
        return schema.model_validate(data)
    except ValidationError as exc:
        raise_pydantic_as_drf(exc)


@contextmanager
def service_errors() -> Iterator[None]:
    """Service refusals as v2 errors: ``access.manage`` in a custom role → 400 ``ACCESS_MANAGE_RESERVED``, a secret
    token's expiry → 400 ``EXPIRY_REQUIRED`` / ``EXPIRY_TOO_LONG`` / ``EXPIRY_IN_PAST``, any other ``ValueError`` → 400, ``AccessConflict``
    (built-in role, duplicate, lockout, revoked token) → 409 ``CONFLICT``."""
    try:
        yield
    except ReservedPermission:
        code = ReservedPermission.ACCESS_MANAGE_RESERVED
        raise DrfValidationError({"permissions": [DrfErrorDetail(RESERVED_DESCRIPTION, code=code)]}) from None
    except TokenExpiryError as exc:
        raise DrfValidationError({"expires_at": [DrfErrorDetail(str(exc), code=exc.code)]}) from None
    except ValueError as exc:
        raise DrfValidationError({"non_field_errors": [str(exc)]}) from None
    except AccessConflict as exc:
        raise Conflict(str(exc)) from None


def client_ip(request: Request) -> str | None:
    """The client address by DRF's ``NUM_PROXIES`` rule, as its throttles take it: set → the ``X-Forwarded-For`` entry
    ``min(NUM_PROXIES, entries)`` hops from the right; unset, ``0`` or no header → ``REMOTE_ADDR``."""
    address = request.META.get("REMOTE_ADDR")
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
    num_proxies = api_settings.NUM_PROXIES
    if num_proxies and forwarded:
        hops = forwarded.split(",")
        address = hops[-min(num_proxies, len(hops))].strip()
    try:
        return str(ipaddress.ip_address(address))
    except ValueError:
        return None


def actor(request: Request) -> Actor:
    return Actor(user=request.user, ip=client_ip(request))
