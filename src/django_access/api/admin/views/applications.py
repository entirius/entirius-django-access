# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Admin API v2 — applications: machine clients holding tokens; never deleted, deactivated instead."""

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
from django_access.models import Application
from django_access.schemas.requests import ApplicationCreateRequest, ApplicationUpdateRequest, PageQuery
from django_access.schemas.responses import ApplicationListResponse, ApplicationResponse
from django_access.services import tokens

_TAGS = ["Access applications"]


def dump(application: Application) -> dict:
    return ApplicationResponse.model_validate(application).model_dump(mode="json")


class ApplicationListView(AdminView):
    @extend_schema(
        tags=_TAGS,
        operation_id="access_applications_list",
        summary="Applications by name",
        parameters=PAGE_PARAMETERS,
        responses={200: ApplicationListResponse, **ERROR_RESPONSES},
    )
    def get(self, request: Request) -> Response:
        parse(PageQuery, request.query_params.dict())
        return self.paginated(request, Application.objects.all(), dump)

    @extend_schema(
        tags=_TAGS,
        summary="Create an application",
        description="409 for a name in use.",
        request=ApplicationCreateRequest,
        responses={201: ApplicationResponse, **WRITE_ERRORS},
    )
    def post(self, request: Request) -> Response:
        data = parse(ApplicationCreateRequest, request.data)
        with service_errors():
            application = tokens.create_application(data.name, description=data.description, actor=actor(request))
        return Response(dump(application), status=201)


class ApplicationDetailView(AdminView):
    @extend_schema(tags=_TAGS, summary="One application", responses={200: ApplicationResponse, **ERROR_RESPONSES})
    def get(self, request: Request, pk: int) -> Response:
        return Response(dump(self.one(Application.objects.all(), pk)))

    @extend_schema(
        tags=_TAGS,
        summary="Rename, describe, activate or deactivate an application",
        description="Only `name`, `description` and `is_active`; no DELETE — deactivate instead. 409 for a name in use.",
        request=ApplicationUpdateRequest,
        responses={200: ApplicationResponse, **WRITE_ERRORS},
    )
    def patch(self, request: Request, pk: int) -> Response:
        updates = parse(ApplicationUpdateRequest, request.data).model_dump(exclude_unset=True)
        application = self.one(Application.objects.all(), pk)
        with service_errors():
            tokens.update_application(application, updates, actor=actor(request))
        return Response(dump(application))
