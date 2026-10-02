# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""D28: legacy keys never expire by themselves. Clears the automatic import-time expiry of every legacy token — the
expiries a team chose stay: a ``token.expiry`` audit row names the token, or a rotation replaced it (``token.rotate``
``detail.replaces``: its expiry is the overlap cutoff). A second run finds nothing."""

from django.db import migrations

# Audit action names, frozen here: migrations never import app code.
TOKEN_EXPIRY = "token.expiry"  # noqa: S105
TOKEN_ROTATE = "token.rotate"  # noqa: S105


def clear_automatic_expiry(apps, schema_editor) -> None:
    ApiToken = apps.get_model("django_access", "ApiToken")
    AuditEntry = apps.get_model("django_access", "AuditEntry")
    team_set = AuditEntry.objects.filter(action=TOKEN_EXPIRY, target_type="django_access.apitoken")
    rotated = AuditEntry.objects.filter(action=TOKEN_ROTATE).values_list("detail__replaces", flat=True)
    kept = {int(pk) for pk in team_set.values_list("target_id", flat=True)} | {int(pk) for pk in rotated if pk}
    ApiToken.objects.filter(legacy=True, expires_at__isnull=False).exclude(pk__in=kept).update(expires_at=None)


class Migration(migrations.Migration):
    dependencies = [("django_access", "0003_applications_and_tokens")]

    operations = [migrations.RunPython(clear_automatic_expiry, migrations.RunPython.noop)]
