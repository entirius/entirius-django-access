# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""`manage.py access_purge_legacy_keys [--dry-run] [--force]` — delete the plaintext legacy key rows.

A row goes once its token's window is over or the token was revoked. A row still inside the window is refused (kept,
listed, exit 1) unless ``--force``, which also deletes rows never imported. Prints ``legacy_source`` ids only.
"""

from django.core.management.base import BaseCommand, CommandError

from django_access.services import legacy
from django_access.services.access_service import Actor

VERDICTS = (legacy.DELETED, legacy.REFUSED, legacy.NOT_IMPORTED)


class Command(BaseCommand):
    help = "Delete the legacy key rows whose 90-day token window is over (refused earlier unless --force)."

    def add_arguments(self, parser):
        parser.add_argument("--dry-run", action="store_true", help="report what would be deleted, delete nothing")
        parser.add_argument("--force", action="store_true", help="also delete in-window and never-imported rows")

    def handle(self, *args, dry_run: bool, force: bool, **options) -> None:
        report = legacy.purge_legacy_sources(force=force, dry_run=dry_run, actor=Actor())
        if dry_run:
            self.stdout.write("Dry run: nothing deleted.")
        for name, verdicts in sorted(report.sources.items()):
            self._source(name, verdicts)
        for setting in report.remove_settings:
            self.stdout.write(f"remove {setting} from settings_local")
        if refused := report.ids(legacy.REFUSED):
            raise CommandError(f"{len(refused)} legacy row(s) still inside the window — kept (wait, or --force)")

    def _source(self, name: str, verdicts: dict[str, list[str]]) -> None:
        self.stdout.write(
            f"{name}: " + ", ".join(f"{verdict} {len(verdicts.get(verdict, []))}" for verdict in VERDICTS)
        )
        for verdict in VERDICTS:
            if ids := verdicts.get(verdict):
                self.stdout.write(f"  {verdict}: {', '.join(ids)}")
