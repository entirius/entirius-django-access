# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Admin API v2 — the staff directory and ``auth.Group``s. Only active staff users are listed; any other id → 404 with
the body of an unknown id."""

from django.contrib.auth.models import Group
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework.exceptions import NotFound
from rest_framework.request import Request
from rest_framework.response import Response

from django_access.api.admin.views._base import ERROR_RESPONSES, PAGE_PARAMETERS, AdminView, parse
from django_access.api.admin.views.grants import grant_body
from django_access.schemas.requests import PageQuery, StaffListQuery
from django_access.schemas.responses import GroupListResponse, StaffDetailResponse, StaffListResponse
from django_access.services import directory

_TAGS = ["Access staff"]


def staff_body(user) -> dict:
    roles = [
        {"key": item["role"].key, "name": item["role"].name, "via_group": item["via_group"]}
        for item in directory.staff_roles(user)
    ]
    return {
        "id": user.pk,
        "username": user.get_username(),
        "email": user.email,
        "name": user.get_full_name(),
        "is_superuser": user.is_superuser,
        "roles": roles,
    }


def group_body(group: Group) -> dict:
    grants = [grant_body(grant) for grant in group.access_grants.all()]
    return {"id": group.pk, "name": group.name, "member_count": group.member_count, "grants": grants}


class StaffListView(AdminView):
    @extend_schema(
        tags=_TAGS,
        operation_id="access_staff_list",
        summary="Active staff users with their roles (direct and through groups)",
        parameters=[OpenApiParameter("search", str), *PAGE_PARAMETERS],
        responses={200: StaffListResponse, **ERROR_RESPONSES},
    )
    def get(self, request: Request) -> Response:
        query = parse(StaffListQuery, request.query_params.dict())
        return self.paginated(request, directory.staff_users(query.search), staff_body)


class StaffDetailView(AdminView):
    @extend_schema(
        tags=_TAGS,
        summary="One active staff user with groups and grants",
        responses={200: StaffDetailResponse, **ERROR_RESPONSES},
    )
    def get(self, request: Request, user_id: int) -> Response:
        try:
            user = directory.staff_user(user_id)
        except directory.NotStaff:
            raise NotFound() from None
        groups = [{"id": group.pk, "name": group.name} for group in user.groups.all()]
        grants = [grant_body(grant) for grant in directory.user_grants(user)]
        body = StaffDetailResponse(**staff_body(user), groups=groups, grants=grants)
        return Response(body.model_dump(mode="json"))


class GroupListView(AdminView):
    @extend_schema(
        tags=_TAGS,
        operation_id="access_groups_list",
        summary="Groups with member counts and grants",
        parameters=PAGE_PARAMETERS,
        responses={200: GroupListResponse, **ERROR_RESPONSES},
    )
    def get(self, request: Request) -> Response:
        parse(PageQuery, request.query_params.dict())
        return self.paginated(request, directory.groups(), group_body)
