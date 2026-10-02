# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""`manage.py access_legacy_report [--json PATH] [--module LABEL]` — who still uses which legacy key (D28).

One row per legacy token, sorted by source: id, application, source, ``prefix…last_four``, scopes, channel, created,
last used (or ``never``), expiry (or ``none``), state. Never a raw value, a legacy value or ``key_hash``.
"""

import json

from django.core.management.base import BaseCommand

from django_access.services import legacy

COLUMNS = (
    "id",
    "application",
    "source",
    "display",
    "scopes",
    "channel_idx",
    "created_at",
    "last_used_at",
    "expires_at",
    "state",
)


def _cell(value: object) -> str:
    if isinstance(value, list):
        return ",".join(value)
    return "*" if value is None else str(value)


class Command(BaseCommand):
    help = "List every legacy token with its source, last use, expiry and state (never a key or a hash)."

    def add_arguments(self, parser):
        parser.add_argument("--json", dest="json_path", metavar="PATH", help="also write the rows as JSON")
        parser.add_argument("--module", help="only the tokens of this app label (e.g. django_checkout)")

    def handle(self, *args, json_path: str | None, module: str | None, **options) -> None:
        rows = legacy.legacy_report(module)
        self.stdout.write("\t".join(COLUMNS))
        for row in rows:
            self.stdout.write("\t".join(_cell(row[column]) for column in COLUMNS))
        self.stdout.write(f"{len(rows)} legacy token(s)")
        if json_path:
            with open(json_path, "w", encoding="utf-8") as handle:
                json.dump(rows, handle, indent=2)
