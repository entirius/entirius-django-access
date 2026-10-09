# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
from django.apps import AppConfig
from django.db.models.signals import post_migrate


class DjangoAccessConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "django_access"
    label = "django_access"
    is_volkanos = True

    def ready(self) -> None:
        from django_access import (
            checks,  # noqa: F401 — registers the catalogue system checks
            signals,
        )
        from django_access.services.legacy import import_after_migrate

        signals.connect()
        post_migrate.connect(import_after_migrate, sender=self, dispatch_uid="django_access_legacy_import")
