# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""A urlconf with one route per route-map branch: admin by path, by permission (local, DRF, IsSuperUser, composite),
by exception; a DRF router with format twins, nested ``include``, ``re_path``, function views, a key route.

Views carry the ``__module__`` of the module serving them (``owned``): route rules apply only to their own module."""

from django.http import HttpResponse
from django.urls import include, path, re_path
from rest_framework import permissions
from rest_framework.response import Response
from rest_framework.routers import DefaultRouter
from rest_framework.views import APIView
from rest_framework.viewsets import ViewSet


class IsAdminUser(permissions.BasePermission):
    """A module-local copy (15 modules have one): staff or superuser."""

    def has_permission(self, request, view) -> bool:
        return bool(request.user and (request.user.is_staff or request.user.is_superuser))


class IsSuperUser(permissions.BasePermission):
    def has_permission(self, request, view) -> bool:
        return bool(request.user and request.user.is_superuser)


class ContentTypePermission(permissions.BasePermission):
    pass


class _View(APIView):
    def get(self, request, **kwargs):
        return Response({})


class DrfAdminView(_View):
    permission_classes = [permissions.IsAdminUser]


class LocalAdminView(_View):
    permission_classes = [IsAdminUser]


class SuperUserView(_View):
    permission_classes = [IsSuperUser]


class PublicView(_View):
    permission_classes = [permissions.AllowAny]


class ContentTypeViewSet(ViewSet):
    permission_classes = [permissions.IsAuthenticated & (permissions.IsAdminUser | ContentTypePermission)]

    def list(self, request, **kwargs):
        return Response([])

    def retrieve(self, request, pk=None, **kwargs):
        return Response({})


def owned(module: str, view):
    """A copy of a view class (a subclass) or function view that ``module`` serves."""
    if isinstance(view, type):
        return type(view.__name__, (view,), {"__module__": f"{module}.views"})

    def function_view(request, **kwargs):
        return view(request, **kwargs)

    function_view.__module__ = f"{module}.views"
    return function_view


def download(request, **kwargs):
    return HttpResponse(b"")


router = DefaultRouter()
router.register("content-types", owned("django_contentdb", ContentTypeViewSet), basename="content-types")

urlpatterns = [
    path("api/faq/v2/admin/questions/", owned("django_faq", DrfAdminView).as_view()),
    path("api/qms/v2/stock/", LocalAdminView.as_view()),
    path(
        "api/suppliers/v2/admin/suppliers/<slug:supplier_idx>/credentials/",
        owned("django_suppliers", SuperUserView).as_view(),
    ),
    path("api/faq/v2/questions/", owned("django_faq", PublicView).as_view()),
    path("api/leads/v2/admin/", include([re_path(r"^gdpr/export/$", owned("django_leads", DrfAdminView).as_view())])),
    re_path(r"^api/lookup/v2/admin/(?P<kind>search|check)/$", owned("django_lookup", LocalAdminView).as_view()),
    path("api-admin/contentdb/<str:version>/", include(router.urls)),
    path("api/returns/attachments/order_return/<uuid:pk>", owned("django_returns", download)),
    path("api-admin/accounts/<str:version>/<str:channel_idx>/customer/delete", owned("django_accounts", download)),
]
