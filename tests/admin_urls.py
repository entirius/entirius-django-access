# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""The Django admin site and the OpenAPI views as a service mounts them."""

from django.contrib import admin
from django.urls import path
from drf_spectacular.views import SpectacularAPIView
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAdminUser
from rest_framework_simplejwt.authentication import JWTAuthentication

urlpatterns = [
    path("admin/", admin.site.urls),
    path(
        "api/schema/",
        SpectacularAPIView.as_view(
            permission_classes=[IsAdminUser], authentication_classes=[JWTAuthentication, SessionAuthentication]
        ),
    ),
]
