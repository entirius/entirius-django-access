# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""`manage.py access_purge_legacy_keys [--yes] [--force] [--recent-days N]` — delete the plaintext legacy key rows.

On demand, no time gate (D28). Without ``--yes`` it only lists what it would delete (``--dry-run`` is an accepted
alias). A row whose legacy token was used within ``--recent-days`` (30) is refused — kept, listed with its last use,
exit 1 — unless ``--force``, which also deletes rows never imported. Prints ``legacy_source`` ids only.
"""

from django.core.management.base import BaseCommand, CommandError

from django_access.services import legacy
from django_access.services.access_service import Actor

VERDICTS = (legacy.DELETED, legacy.REFUSED, legacy.NOT_IMPORTED)


def _days(value: str) -> int:
    number = int(value)
    if number < 0:
        raise ValueError(value)
    return number


class Command(BaseCommand):
    help = "Delete the plaintext rows of imported legacy keys (lists only without --yes; keys in use need --force)."

    def add_arguments(self, parser):
        parser.add_argument("--yes", action="store_true", help="delete; without it the command only lists")
        parser.add_argument("--dry-run", action="store_true", help="list only (the default; kept as an alias)")
        parser.add_argument("--force", action="store_true", help="also delete recently used and never-imported rows")
        parser.add_argument(
            "--recent-days", type=_days, default=legacy.RECENT_DAYS, help="a key used within N days is refused"
        )

    def handle(self, *args, yes: bool, dry_run: bool, force: bool, recent_days: int, **options) -> None:
        listing = dry_run or not yes
        report = legacy.purge_legacy_sources(legacy.PurgeOptions(force, listing, recent_days), actor=Actor())
        if listing:
            self.stdout.write("Listing only: nothing deleted (add --yes to delete).")
        for name, verdicts in sorted(report.sources.items()):
            self._source(name, verdicts, report)
        for setting in report.remove_settings:
            self.stdout.write(f"remove {setting} from settings_local")
        if refused := report.ids(legacy.REFUSED):
            raise CommandError(f"{len(refused)} legacy row(s) used within {recent_days} days — kept (or --force)")

    def _source(self, name: str, verdicts: dict[str, list[str]], report: legacy.PurgeReport) -> None:
        self.stdout.write(
            f"{name}: " + ", ".join(f"{verdict} {len(verdicts.get(verdict, []))}" for verdict in VERDICTS)
        )
        for verdict in VERDICTS:
            if ids := verdicts.get(verdict):
                self.stdout.write(f"  {verdict}: {', '.join(self._label(ref, report) for ref in ids)}")

    @staticmethod
    def _label(ref: str, report: legacy.PurgeReport) -> str:
        used = report.last_used.get(ref)
        return f"{ref} (last used {used.isoformat()})" if used else ref
