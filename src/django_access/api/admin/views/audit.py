# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Admin API v2 — the audit log, newest first."""

from datetime import datetime

from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework.request import Request
from rest_framework.response import Response

from django_access.api.admin.views._base import ERROR_RESPONSES, PAGE_PARAMETERS, AdminView, parse
from django_access.models import AuditEntry
from django_access.schemas.requests import AuditListQuery
from django_access.schemas.responses import AuditEntryResponse, AuditListResponse
from django_access.services import directory

_FILTERS = [
    OpenApiParameter("action", str),
    OpenApiParameter("actor", int, description="Actor user id."),
    OpenApiParameter("from", datetime, description="Created at or after (ISO 8601 with offset)."),
    OpenApiParameter("to", datetime, description="Created at or before (ISO 8601 with offset)."),
]


def dump(entry: AuditEntry) -> dict:
    return AuditEntryResponse.model_validate(entry).model_dump(mode="json")


class AuditListView(AdminView):
    @extend_schema(
        tags=["Access Audit"],
        operation_id="access_audit_list",
        summary="Audit entries, newest first",
        parameters=[*_FILTERS, *PAGE_PARAMETERS],
        responses={200: AuditListResponse, **ERROR_RESPONSES},
    )
    def get(self, request: Request) -> Response:
        query = parse(AuditListQuery, request.query_params.dict())
        where = directory.AuditFilter(query.action, query.actor, query.from_, query.to)
        return self.paginated(request, directory.audit_entries(where), dump)
