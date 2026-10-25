# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Root URL config for django_access — ``me``, the key exchange and the admin API v2 namespace."""

from django.urls import include, path

from django_access.api.exchange import TokenExchangeView
from django_access.api.me import MeView

urlpatterns = [
    path("api/access/v2/me/", MeView.as_view(), name="access-me"),
    path("api/access/v2/token/exchange/", TokenExchangeView.as_view(), name="access-token-exchange"),
    path("api/access/v2/admin/", include("django_access.api.admin.urls")),
]
