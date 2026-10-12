# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""One route per gate class. Every view answers GET and POST with 200 when it runs; DRF admin views carry the
platform's ``IsAdminUser`` (is_staff), so a refusal by the view is told apart from one by the gate."""

from django.contrib import admin
from django.http import HttpResponse
from django.urls import path
from django.views.decorators.csrf import csrf_exempt
from rest_framework import permissions
from rest_framework.authentication import SessionAuthentication
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication

from tests.route_map_urls import owned


class _View(APIView):
    def get(self, request, **kwargs):
        return Response({"ran": True})

    def post(self, request, **kwargs):
        return Response({"ran": True})


class JwtAdminView(_View):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]


class JwtSessionAdminView(_View):
    authentication_classes = [JWTAuthentication, SessionAuthentication]
    permission_classes = [permissions.IsAdminUser]


class DefaultAuthAdminView(_View):
    """DRF's default authenticators (Session + Basic): the gate cannot see Basic, so the view is not self-auth."""

    permission_classes = [permissions.IsAdminUser]


class PublicView(_View):
    permission_classes = [permissions.AllowAny]


@csrf_exempt
def unauthenticated(request, **kwargs):
    """Like the pim staff viewer before 3.3.1: no authentication of its own."""
    return HttpResponse(b"ran")


ADMIN = "/api/agreements/v2/admin/definitions/"
EXPORT = "/api/agreements/v2/admin/marketing-subscribers/export/"
VIEWER = "/api-viewer/pim/v1/shop/products/"
DEFAULT_AUTH = "/api/pim/v2/admin/products/"
JWT_SESSION = "/api/faq/v2/admin/faq/"
BASELINE = "/api/regional/v2/admin/countries/"
UNMAPPED = "/api/mystery/v2/admin/things/"
READ_ONLY = "/api/lookup/v2/admin/products/"
PUBLIC = "/api/faq/v2/faq/"
KEY = "/api/checkout/v2/default/carts/"

urlpatterns = [
    path(ADMIN[1:], owned("django_agreements", JwtAdminView).as_view()),
    path(EXPORT[1:], owned("django_agreements", JwtAdminView).as_view()),
    path("api-viewer/pim/<str:version>/<str:shop>/products/", owned("django_pim", unauthenticated)),
    path(DEFAULT_AUTH[1:], owned("django_pim", DefaultAuthAdminView).as_view()),
    path(JWT_SESSION[1:], owned("django_faq", JwtSessionAdminView).as_view()),
    path(BASELINE[1:], owned("django_regional", JwtAdminView).as_view()),
    path(UNMAPPED[1:], owned("django_mystery", JwtAdminView).as_view()),
    path(READ_ONLY[1:], owned("django_lookup", JwtAdminView).as_view()),
    path(PUBLIC[1:], owned("django_faq", PublicView).as_view()),
    path("api/checkout/v2/<str:channel_idx>/carts/", owned("django_checkout", PublicView).as_view()),
    path("admin/", admin.site.urls),
]
