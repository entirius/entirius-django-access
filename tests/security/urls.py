# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Recording urlconf of the security suite: one route per gate route class. Every view appends ``(route, method)``
to ``RAN`` when it runs, so a test proves "the view never ran" instead of trusting a status code."""

from django.http import HttpResponse
from django.urls import path
from django.views.decorators.csrf import csrf_exempt
from rest_framework import permissions
from rest_framework.authentication import BasicAuthentication, SessionAuthentication
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication

from tests.route_map_urls import owned

RAN: list[tuple[str, str]] = []


class Recording(APIView):
    def _ran(self, request, **kwargs):
        RAN.append((request.path, request.method))
        return Response({"ran": True}, status=int(kwargs.get("code", 200)))

    get = post = put = patch = delete = options = _ran


class JwtAdmin(Recording):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]


class JwtSessionAdmin(Recording):
    authentication_classes = [JWTAuthentication, SessionAuthentication]
    permission_classes = [permissions.IsAdminUser]


class DefaultAuthAdmin(Recording):
    """DRF's default authenticators (Session + Basic): the gate cannot see Basic, so the view is not self-auth."""

    permission_classes = [permissions.IsAdminUser]


class JwtAllowAny(Recording):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.AllowAny]


class JwtCustomer(Recording):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]


class Public(Recording):
    permission_classes = [permissions.AllowAny]


class BasicJwtAdmin(Recording):
    authentication_classes = [BasicAuthentication, JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]


class LenientJWT(JWTAuthentication):
    """A subclass the gate does not run: its view is not self-auth whatever it does."""


class SubclassJwtAdmin(Recording):
    authentication_classes = [LenientJWT]
    permission_classes = [permissions.IsAdminUser]


class Failing(JwtAdmin):
    def post(self, request, **kwargs):
        RAN.append((request.path, request.method))
        raise RuntimeError("view crashed")


@csrf_exempt
def unauthenticated(request, **kwargs):
    """Like the pim staff viewer before 3.3.1: no authentication of its own."""
    RAN.append((request.path, request.method))
    return HttpResponse(b"ran")


RW_READ = "/api/agreements/v2/admin/definitions/"
RW_WRITE = "/api/faq/v2/admin/faq/"
READ_ONLY = "/api/lookup/v2/admin/products/"
WRITE_ONLY = "/api/leads/v2/admin/default/test/"
EXPORT = "/api/agreements/v2/admin/marketing-subscribers/export/"
BASELINE = "/api/regional/v2/admin/countries/"
DEFAULT_AUTH = "/api/pim/v2/admin/products/"
ALLOW_ANY = "/api/faq/v2/admin/open/"
FUNCTION = "/api-viewer/pim/v1/shop/products/"
PII_DOWNLOAD = "/api/returns/attachments/order_return/3f2a/"
UNMAPPED = "/api/mystery/v2/admin/things/"
PUBLIC = "/api/faq/v2/faq/"
CUSTOMER = "/api/accounts/v2/customer/profile/"
KEY = "/api/checkout/v2/default/carts/"
BASIC_JWT = "/api/faq/v2/admin/basic/"
SUBCLASS_JWT = "/api/faq/v2/admin/lenient/"
STATUS = "/api/faq/v2/admin/status/{code}/"
FAILING = "/api/faq/v2/admin/failing/"

urlpatterns = [
    path(RW_READ[1:], owned("django_agreements", JwtAdmin).as_view()),
    path(RW_WRITE[1:], owned("django_faq", JwtSessionAdmin).as_view()),
    path(READ_ONLY[1:], owned("django_lookup", JwtAdmin).as_view()),
    path("api/leads/v2/admin/<str:channel_idx>/test/", owned("django_leads", JwtAdmin).as_view()),
    path(EXPORT[1:], owned("django_agreements", JwtAdmin).as_view()),
    path(BASELINE[1:], owned("django_regional", JwtAdmin).as_view()),
    path(DEFAULT_AUTH[1:], owned("django_pim", DefaultAuthAdmin).as_view()),
    path(ALLOW_ANY[1:], owned("django_faq", JwtAllowAny).as_view()),
    path("api-viewer/pim/<str:version>/<str:shop>/products/", owned("django_pim", unauthenticated)),
    path("api/returns/attachments/order_return/<str:uuid>/", owned("django_returns", unauthenticated)),
    path(UNMAPPED[1:], owned("django_mystery", JwtAdmin).as_view()),
    path(PUBLIC[1:], owned("django_faq", Public).as_view()),
    path(CUSTOMER[1:], owned("django_accounts", JwtCustomer).as_view()),
    path("api/checkout/v2/<str:channel_idx>/carts/", owned("django_checkout", Public).as_view()),
    path(BASIC_JWT[1:], owned("django_faq", BasicJwtAdmin).as_view()),
    path(SUBCLASS_JWT[1:], owned("django_faq", SubclassJwtAdmin).as_view()),
    path("api/faq/v2/admin/status/<int:code>/", owned("django_faq", JwtAdmin).as_view()),
    path(FAILING[1:], owned("django_faq", Failing).as_view()),
]
