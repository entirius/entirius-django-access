# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""``GET me``: what the logged-in user may do — any authenticated user; a customer gets no gate mode, roles or areas."""

from drf_spectacular.utils import extend_schema
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication

from django_access.schemas.responses import MeResponse, MeUserResponse
from django_access.services import directory


class MeView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=["Access Me"],
        operation_id="access_me",
        summary="The current user's roles and effective area permissions",
        description=(
            "Any authenticated user: staff get the gate mode, granted roles and effective area permissions; a customer "
            "gets the user block only."
        ),
        responses={200: MeResponse, 401: None},
    )
    def get(self, request: Request) -> Response:
        body = MeResponse(user=MeUserResponse.model_validate(request.user), **directory.me(request.user))
        return Response(body.model_dump(mode="json"))
