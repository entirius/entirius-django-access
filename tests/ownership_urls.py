# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Module ownership: faq declares its own rules, checkout lives on the defaults, widgets has neither."""

from django.urls import include, path
from rest_framework.routers import SimpleRouter

from tests.route_map_urls import ContentTypeViewSet, DrfAdminView, PublicView, owned

router = SimpleRouter()
router.register("things", owned("django_widgets", ContentTypeViewSet), basename="things")

urlpatterns = [
    path("api/faq/v2/admin/questions/", owned("django_faq", DrfAdminView).as_view()),
    path("api/faq/v2/questions/", owned("django_faq", PublicView).as_view()),
    path("api/checkout/v2/admin/<str:channel_idx>/orders/", owned("django_checkout", DrfAdminView).as_view()),
    path("api/widgets/v2/admin/", include(router.urls)),
]
