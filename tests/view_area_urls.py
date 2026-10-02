# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Areas on views (D30): a DRF class, a Django class and a decorated function view carrying ``access_area`` /
``access_levels``, next to routes that take their area from an app's own rules or from the access defaults."""

from django.http import HttpResponse
from django.urls import path
from django.views import View
from rest_framework.decorators import api_view
from rest_framework.response import Response

from tests.route_map_urls import DrfAdminView, PublicView, owned


class _DjangoPage(View):
    def get(self, request, **kwargs):
        return HttpResponse(b"")


def _export(request, **kwargs):
    return Response({})


_export.__module__ = "django_leads.views"

FaqQuestions = owned("django_faq", DrfAdminView)  # view area beats the faq stub's own rule
FaqQuestions.access_area = "staff.baseline"
FaqAnswers = owned("django_faq", DrfAdminView)  # the faq stub's own rule
FaqPublic = owned("django_faq", PublicView)  # an area on a route the gate ignores
CheckoutOrders = owned("django_checkout", _DjangoPage)  # a Django class view beats the checkout default rule
CheckoutOrders.access_area = "checkout.discounts"
CheckoutSettings = owned("django_checkout", DrfAdminView)  # the checkout default rule
PimProduct = owned("django_pim", DrfAdminView)  # the SKU-delete area override still applies on top
PimProduct.access_area = "pim.products"
WidgetThings = owned("django_widgets", DrfAdminView)  # a module without any rule, owned by its view
WidgetThings.access_area = "staff.baseline"
gdpr_export = api_view(["POST"])(_export)  # set after decoration: the callback carries it
gdpr_export.access_area = "leads.gdpr"
gdpr_export.access_levels = {"post": "read"}

urlpatterns = [
    path("api/faq/v2/admin/questions/", FaqQuestions.as_view()),
    path("api/faq/v2/admin/answers/", FaqAnswers.as_view()),
    path("api/faq/v2/questions/", FaqPublic.as_view()),
    path("api/checkout/v2/admin/<str:channel_idx>/orders/", CheckoutOrders.as_view()),
    path("api/checkout/v2/admin/<str:channel_idx>/settings/", CheckoutSettings.as_view()),
    path("api/pim/v2/admin/<str:channel_idx>/products/<path:sku>/", PimProduct.as_view()),
    path("api/widgets/v2/admin/things/", WidgetThings.as_view()),
    path("api/leads/v2/admin/gdpr/export/", gdpr_export),
]
