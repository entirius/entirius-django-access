# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Fake key routes (paths of the token-scope catalogue) and one non-key route, for the OpenAPI hook tests."""

from django.urls import path
from drf_spectacular.utils import extend_schema
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication


class _View(APIView):
    authentication_classes = [JWTAuthentication]

    @extend_schema(responses={200: None})
    def get(self, request, **kwargs):
        return Response()


class OptionalJwtView(_View):
    permission_classes = [AllowAny]


class JwtView(_View):
    permission_classes = [IsAuthenticated]


class KeyOnlyView(_View):
    authentication_classes = []
    permission_classes = [AllowAny]


urlpatterns = [
    path("api/checkout/v2/<str:channel_idx>/carts/<str:cart_id>/", OptionalJwtView.as_view()),
    path("api/vault/v1/<str:channel_idx>/payment_card/", JwtView.as_view()),
    path("api/contact-forms/v2/<str:channel_idx>/form-types/", KeyOnlyView.as_view()),
    path("api-admin/accounts/v1/<str:channel_idx>/customer/delete", KeyOnlyView.as_view()),
    path("api/contact-forms/v2/<str:channel_idx>/bookings", KeyOnlyView.as_view()),
    path("api/checkout/v2/<str:channel_idx>/products/", JwtView.as_view()),
    path("api/checkout/v2/<str:channel_idx>/cartsx/", JwtView.as_view()),
]
