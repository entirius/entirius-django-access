# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Admin API v2 — roles: built-in and custom; only custom roles change (built-in → 409), never with access.manage
(400 ACCESS_MANAGE_RESERVED); a change that would leave nobody managing access → 409."""

from drf_spectacular.utils import extend_schema
from rest_framework.request import Request
from rest_framework.response import Response

from django_access.api.admin.views._base import (
    ERROR_RESPONSES,
    PAGE_PARAMETERS,
    WRITE_ERRORS,
    AdminView,
    actor,
    parse,
    service_errors,
)
from django_access.models import Role
from django_access.schemas.requests import PageQuery, RoleCreateRequest, RoleUpdateRequest
from django_access.schemas.responses import RoleDetailResponse, RoleListResponse, RoleResponse
from django_access.services import access_service, directory, permissions

_TAGS = ["Access Roles"]


def dump(role: Role) -> dict:
    return RoleResponse.model_validate(role).model_dump(mode="json")


def dump_detail(role: Role) -> dict:
    fields = RoleResponse.model_validate(role).model_dump()
    detail = RoleDetailResponse(**fields, permissions=permissions.role_permissions(role))
    return detail.model_dump(mode="json")


class RoleListView(AdminView):
    @extend_schema(
        tags=_TAGS,
        operation_id="access_roles_list",
        summary="Built-in and custom roles with grant counts",
        parameters=PAGE_PARAMETERS,
        responses={200: RoleListResponse, **ERROR_RESPONSES},
    )
    def get(self, request: Request) -> Response:
        parse(PageQuery, request.query_params.dict())
        return self.paginated(request, directory.roles(), dump)

    @extend_schema(
        tags=_TAGS,
        summary="Create a custom role",
        description="400 ACCESS_MANAGE_RESERVED for any access.manage key; 409 for a key in use (built-in included).",
        request=RoleCreateRequest,
        responses={201: RoleDetailResponse, **WRITE_ERRORS},
    )
    def post(self, request: Request) -> Response:
        data = parse(RoleCreateRequest, request.data)
        with service_errors():
            role = access_service.create_role(access_service.RoleInput(**data.model_dump()), actor(request))
        return Response(dump_detail(self.one(directory.roles(), role.pk)), status=201)


class RoleDetailView(AdminView):
    @extend_schema(
        tags=_TAGS,
        summary="One role with its effective permissions",
        responses={200: RoleDetailResponse, **ERROR_RESPONSES},
    )
    def get(self, request: Request, pk: int) -> Response:
        return Response(dump_detail(self.one(directory.roles(), pk)))

    @extend_schema(
        tags=_TAGS,
        summary="Update a custom role",
        description="`permissions` replaces the whole set. Built-in roles and lockout → 409; access.manage → 400.",
        request=RoleUpdateRequest,
        responses={200: RoleDetailResponse, **WRITE_ERRORS},
    )
    def patch(self, request: Request, pk: int) -> Response:
        updates = parse(RoleUpdateRequest, request.data).model_dump(exclude_unset=True)
        role = self.one(Role.objects.all(), pk)
        with service_errors():
            access_service.update_role(role, updates, actor(request))
        return Response(dump_detail(self.one(directory.roles(), pk)))

    @extend_schema(
        tags=_TAGS,
        summary="Delete a custom role with its grants",
        description="Built-in roles and lockout → 409.",
        responses={204: None, **WRITE_ERRORS},
    )
    def delete(self, request: Request, pk: int) -> Response:
        role = self.one(Role.objects.all(), pk)
        with service_errors():
            access_service.delete_role(role, actor(request))
        return Response(status=204)
