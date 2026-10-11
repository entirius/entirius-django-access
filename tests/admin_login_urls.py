# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""The Django admin site with its login behind the failed-login guard, as a service mounts it."""

from django.contrib import admin
from django.urls import path

from django_access.services.login_guard import guarded_admin_login

urlpatterns = [
    path("admin/login/", guarded_admin_login(admin.site.login)),
    path("admin/", admin.site.urls),
]
