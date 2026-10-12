# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Create the four built-in roles and grant Manager to every active, non-superuser staff user (operator override of D2:
access management stays with superusers until someone is explicitly granted Administrator; superusers bypass).

Grants are written only on first adoption (no grant exists yet), so migrating back and forward again never re-grants a
revoked or group-only user. Values are frozen here on purpose: a migration must not follow code.
"""

from django.conf import settings
from django.db import migrations

ADMINISTRATOR = "administrator"
MANAGER = "manager"
BUILTIN_ROLES = {
    ADMINISTRATOR: ("Administrator", "Everything, including access management."),
    MANAGER: ("Manager", "Everything except access management."),
    "editor": ("Editor", "Writes content, catalogue, FAQ and e-mail templates; reads the rest."),
    "viewer": ("Viewer", "Reads everything except access management."),
}


def create_builtin_roles(apps) -> dict:
    Role = apps.get_model("django_access", "Role")
    return {
        key: Role.objects.get_or_create(key=key, defaults={"name": name, "description": text, "builtin": True})[0]
        for key, (name, text) in BUILTIN_ROLES.items()
    }


def grant_manager_to_staff(apps, schema_editor) -> None:
    manager = create_builtin_roles(apps)[MANAGER]
    Grant = apps.get_model("django_access", "Grant")
    if Grant.objects.exists():
        return
    AuditEntry = apps.get_model("django_access", "AuditEntry")
    for user in apps.get_model(settings.AUTH_USER_MODEL).objects.filter(
        is_active=True, is_staff=True, is_superuser=False
    ):
        grant = Grant.objects.create(role=manager, user=user)
        AuditEntry.objects.create(
            actor_label="system",
            action="grant.migrate",
            target_type="django_access.grant",
            target_id=str(grant.pk),
            target_label=f"{MANAGER} → user {user.pk}",
            detail={"role": MANAGER, "user_id": user.pk, "group_id": None},
        )


class Migration(migrations.Migration):
    # Renamed before the first release; a database that recorded the old name keeps it as applied.
    replaces = [("django_access", "0002_builtin_roles_and_staff_administrators")]
    dependencies = [
        ("django_access", "0001_initial"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [migrations.RunPython(grant_manager_to_staff, migrations.RunPython.noop)]
