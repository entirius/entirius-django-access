# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Every admin route mapped: the audit fails here only through a foreign rule match."""

from django.urls import path
from rest_framework import permissions

from tests.route_map_urls import DrfAdminView, PublicView, SuperUserView, owned

urlpatterns = [
    path("api/faq/v2/admin/questions/", owned("django_faq", DrfAdminView).as_view()),
    path(
        "api/suppliers/v2/admin/suppliers/<slug:supplier_idx>/credentials/",
        owned("django_suppliers", SuperUserView).as_view(),
    ),
    path(
        "api/faq/v2/questions/",
        owned("django_faq", PublicView).as_view(
            permission_classes=[permissions.IsAuthenticated | permissions.AllowAny]
        ),
    ),
]
