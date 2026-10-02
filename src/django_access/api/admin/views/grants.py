# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Admin API v2 — grants of roles to active staff users or to ``auth.Group``s; a revoke that would leave nobody
managing access → 409."""

from drf_spectacular.utils import OpenApiParameter, extend_schema
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
from django_access.models import Grant
from django_access.schemas.requests import GrantCreateRequest, GrantListQuery
from django_access.schemas.responses import GrantListResponse, GrantResponse
from django_access.services import access_service, directory

_TAGS = ["Access grants"]
_FILTERS = [OpenApiParameter("role", str), OpenApiParameter("user_id", int), OpenApiParameter("group_id", int)]


def grant_body(grant: Grant) -> dict:
    user = {"id": grant.user.pk, "username": grant.user.get_username()} if grant.user else None
    group = {"id": grant.group.pk, "name": grant.group.name} if grant.group else None
    role = {"id": grant.role.pk, "key": grant.role.key, "name": grant.role.name}
    body = {"id": grant.pk, "role": role, "user": user, "group": group, "created_at": grant.created_at}
    return GrantResponse.model_validate(body).model_dump(mode="json")


class GrantListView(AdminView):
    @extend_schema(
        tags=_TAGS,
        operation_id="access_grants_list",
        summary="Grants, filterable by role key, user and group",
        parameters=[*_FILTERS, *PAGE_PARAMETERS],
        responses={200: GrantListResponse, **ERROR_RESPONSES},
    )
    def get(self, request: Request) -> Response:
        query = parse(GrantListQuery, request.query_params.dict())
        return self.paginated(request, directory.grants(query.role, query.user_id, query.group_id), grant_body)

    @extend_schema(
        tags=_TAGS,
        summary="Grant a role to one active staff user or one group",
        description="Exactly one of `user_id` and `group_id`; a user who is not active staff → 400; a duplicate → 409.",
        request=GrantCreateRequest,
        responses={201: GrantResponse, **WRITE_ERRORS},
    )
    def post(self, request: Request) -> Response:
        data = parse(GrantCreateRequest, request.data)
        with service_errors():
            role, user, group = directory.grant_target(data.role, data.user_id, data.group_id)
            grant = access_service.grant_role(role, user=user, group=group, actor=actor(request))
        return Response(grant_body(grant), status=201)


class GrantDetailView(AdminView):
    @extend_schema(
        tags=_TAGS,
        summary="Revoke a grant",
        description="409 when nobody active would be left to manage access.",
        responses={204: None, **WRITE_ERRORS},
    )
    def delete(self, request: Request, pk: int) -> Response:
        grant = self.one(directory.grants(), pk)
        with service_errors():
            access_service.revoke_grant(grant, actor(request))
        return Response(status=204)
