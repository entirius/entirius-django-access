# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""The PIM attribute-value routes and their schema neighbours, on both PIM admin roots."""

from django.urls import path

from tests.product_delete_urls import ProductView
from tests.route_map_urls import owned

PIM_ROOTS = ("api/pim/v2/admin/", "api/pim/admin/")
VALUE_ROUTES = (
    "attributes/",
    "attributes/reorder/",
    "attributes/<str:feature_idx>/<str:idx>/",
    "<str:channel_idx>/attributes/",
)
SCHEMA_ROUTES = (
    "features/<str:idx>/attributes/",
    "<str:channel_idx>/features/<str:idx>/attributes/",
    "attributes-groups/",
    "features/",
)

urlpatterns = [
    path(root + route, owned("django_pim", ProductView).as_view())
    for root in PIM_ROOTS
    for route in (*VALUE_ROUTES, *SCHEMA_ROUTES)
]
