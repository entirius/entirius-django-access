# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
from django.apps import AppConfig


class WidgetsStubConfig(AppConfig):
    """A new module with an admin route: neither declarations of its own nor access defaults."""

    name = "tests.widgets_stub"
    label = "django_widgets"
