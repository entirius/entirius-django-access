# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Admin API v2 — the permission catalogue (staff baseline): areas by module and the built-in roles."""

from drf_spectacular.utils import extend_schema
from rest_framework.request import Request
from rest_framework.response import Response

from django_access.api.admin.views._base import ERROR_RESPONSES, StaffView
from django_access.schemas.responses import CatalogueResponse
from django_access.services import directory


class CatalogueView(StaffView):
    @extend_schema(
        tags=["Access catalogue"],
        operation_id="access_catalogue",
        summary="Areas by module and the built-in roles with their computed permissions",
        responses={200: CatalogueResponse, **ERROR_RESPONSES},
    )
    def get(self, request: Request) -> Response:
        return Response(CatalogueResponse.model_validate(directory.catalogue()).model_dump(mode="json"))
