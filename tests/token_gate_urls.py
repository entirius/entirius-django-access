# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""The gate routes plus the access urlconf (the exchange) and two PIM admin routes of different areas."""

from django.urls import include, path
from rest_framework.response import Response

from tests import gate_urls
from tests.gate_urls import JwtAdminView
from tests.route_map_urls import owned

PRODUCTS = "/api/pim/v2/admin/emporium/products/"
SCHEMA = "/api/pim/v2/admin/features/"
PRODUCT_DELETE = "/api/pim/v2/admin/emporium/products/SKU-1/"
EXCHANGE = "/api/access/v2/token/exchange/"


class DeletableAdminView(JwtAdminView):
    def delete(self, request, **kwargs):
        return Response({"ran": True})


urlpatterns = [
    path(PRODUCTS[1:], owned("django_pim", JwtAdminView).as_view()),
    path(SCHEMA[1:], owned("django_pim", JwtAdminView).as_view()),
    path("api/pim/v2/admin/<str:channel_idx>/products/<path:sku>/", owned("django_pim", DeletableAdminView).as_view()),
    path("", include("django_access.urls")),
    *gate_urls.urlpatterns,
]
