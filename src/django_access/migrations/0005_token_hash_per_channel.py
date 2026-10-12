# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""D2: one legacy secret on several channels becomes one pinned token per channel. ``key_hash`` is no longer unique on
its own (the index stays); at most one token per hash and channel, one unpinned (``NULLS NOT DISTINCT``, PostgreSQL 15+).
"""

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("django_access", "0004_legacy_tokens_without_expiry")]

    operations = [
        migrations.AlterField(
            model_name="apitoken", name="key_hash", field=models.CharField(db_index=True, max_length=64)
        ),
        migrations.AddConstraint(
            model_name="apitoken",
            constraint=models.UniqueConstraint(
                fields=("key_hash", "channel_idx"), name="django_access_token_hash_channel", nulls_distinct=False
            ),
        ),
    ]
