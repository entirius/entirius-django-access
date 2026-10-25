# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""1.1.0: attribute values leave ``pim.schema`` for their own area, ``pim.attribute_values``. A custom role keeps what
it could do: every role holding ``pim.schema:<level>`` gets ``pim.attribute_values:<level>``. Built-in roles are
computed from the catalogue and need nothing. Idempotent; reverse removes the new area's rows.
"""

from django.db import migrations

SCHEMA = "pim.schema"
ATTRIBUTE_VALUES = "pim.attribute_values"
LEVELS = ("read", "write")


def add_attribute_values(apps, schema_editor) -> None:
    RolePermission = apps.get_model("django_access", "RolePermission")
    for level in LEVELS:
        roles = RolePermission.objects.filter(permission=f"{SCHEMA}:{level}").values_list("role_id", flat=True)
        for role_id in roles:
            RolePermission.objects.get_or_create(role_id=role_id, permission=f"{ATTRIBUTE_VALUES}:{level}")


def remove_attribute_values(apps, schema_editor) -> None:
    RolePermission = apps.get_model("django_access", "RolePermission")
    RolePermission.objects.filter(permission__startswith=f"{ATTRIBUTE_VALUES}:").delete()


class Migration(migrations.Migration):
    dependencies = [("django_access", "0006_application_service_user")]

    operations = [migrations.RunPython(add_attribute_values, remove_attribute_values)]
