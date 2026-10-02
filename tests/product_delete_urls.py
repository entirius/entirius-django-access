# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""The SKU-deleting routes (memo 09b) and their product-route neighbours, as the zeno resolver builds them. Every view
answers 200 when it runs, so a 403 is the gate's; the access URLs (``me``, catalogue) ride along."""

from django.urls import include, path
from rest_framework.response import Response

from tests.gate_urls import JwtAdminView
from tests.route_map_urls import owned

PIM_ROOTS = ("api/pim/v2/admin/", "api/pim/admin/")
PRODUCT = "{root}default/products/1C01/N/"
PICTURE = "{root}default/products/1C01/N/pictures/7/"
FILE = "{root}default/products/1C01/N/files/7/"
LINK = "{root}default/products/1C01/N/links/7/"
MERGES = ("/api/atlas/v2/admin/realproducts/merge-by-ean/", "/api/suppliers/v2/admin/realproducts/merge-by-ean/")


class ProductView(JwtAdminView):
    def patch(self, request, **kwargs):
        return Response({"ran": True})

    def delete(self, request, **kwargs):
        return Response({"ran": True})


def _pim_routes(root: str) -> list:
    sub = [f"{root}<str:channel_idx>/products/<path:sku>/{item}/<int:pk>/" for item in ("pictures", "files", "links")]
    detail = f"{root}<str:channel_idx>/products/<path:sku>/"  # last: <path:sku> swallows the sub-routes
    return [path(route, owned("django_pim", ProductView).as_view()) for route in (*sub, detail)]


urlpatterns = [
    *(route for root in PIM_ROOTS for route in _pim_routes(root)),
    path(MERGES[0][1:], owned("django_atlas", ProductView).as_view()),
    path(MERGES[1][1:], owned("django_suppliers", ProductView).as_view()),
    path("", include("django_access.urls")),
]
