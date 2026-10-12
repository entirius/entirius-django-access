# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
from django.apps import AppConfig


class FaqStubConfig(AppConfig):
    """Stands in for django_faq: declares its own areas and rules on the AppConfig."""

    name = "tests.faq_stub"
    label = "django_faq"
    access_areas = [{"key": "faq.items", "label": "FAQ items"}]
    access_route_rules = [{"pattern": "api/faq/v2/admin/", "area": "faq.items"}]
