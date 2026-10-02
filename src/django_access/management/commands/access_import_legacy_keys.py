# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""`manage.py access_import_legacy_keys [--dry-run] [--report] [--check]` — the legacy key import on demand.

Prints counts per source (and ``legacy_source`` ids with ``--report`` / ``--check``) — never a key or a hash.
``--check`` writes nothing and exits 1 while a legacy key is not imported, a mixed secret exists, an imported token
does not serve a row added later (``stale``) or a source fails:
the deploy step between ``migrate`` and traffic.
"""

from django.core.management.base import BaseCommand, CommandError

from django_access.services import legacy

KINDS = ("imported", "present", "skipped", "unpinned", "short", "mixed", "stale")


def _labels(check: bool) -> dict[str, str]:
    """Under ``--check`` nothing is written, so ``imported`` means "not imported yet"."""
    return {kind: "missing" if check and kind == "imported" else kind for kind in KINDS}


def _source_lines(name: str, entry: legacy.SourceReport, *, ids: bool, check: bool) -> list[str]:
    labels = _labels(check)
    counts = ", ".join(f"{labels[kind]} {len(getattr(entry, kind))}" for kind in KINDS)
    lines = [f"{name}: {counts}{' FAILED' if entry.failed else ''}"]
    if ids:
        lines += [f"  {labels[kind]}: {', '.join(getattr(entry, kind))}" for kind in KINDS if getattr(entry, kind)]
    return lines


def report_lines(report: legacy.LegacyReport, *, ids: bool, check: bool = False) -> list[str]:
    lines = [
        line
        for name, entry in sorted(report.sources.items())
        for line in _source_lines(name, entry, ids=ids, check=check)
    ]
    lines += [
        f"MIXED legacy secret in {', '.join(group)} — not imported, rotate before deploying "
        "(rotate: issue separate tokens for both callers)"
        for group in report.mixed
    ]
    return lines or ["No legacy keys found."]


class Command(BaseCommand):
    help = "Import the legacy per-module keys as hashed tokens with a 90-day window (never prints a key or a hash)."

    def add_arguments(self, parser):
        parser.add_argument("--dry-run", action="store_true", help="report what would be imported, write nothing")
        parser.add_argument("--report", action="store_true", help="list the legacy_source ids per outcome")
        parser.add_argument(
            "--check", action="store_true", help="write nothing; exit 1 while a key is not imported or mixed"
        )

    def handle(self, *args, dry_run: bool, report: bool, check: bool, **options) -> None:
        result = legacy.import_legacy_keys(dry_run=dry_run or check)
        for line in report_lines(result, ids=report or check, check=check):
            self.stdout.write(line)
        if check:
            self._check(result)

    def _check(self, result: legacy.LegacyReport) -> None:
        missing, stale, mixed, failed = (
            result.total("imported"),
            result.total("stale"),
            len(result.mixed),
            len(result.failed),
        )
        if missing or stale or mixed or failed:
            raise CommandError(
                f"Legacy keys not ready: {missing} not imported, {stale} stale, {mixed} mixed, {failed} failed source(s)"
            )
        self.stdout.write("Legacy keys OK: every legacy key is present as a token.")
