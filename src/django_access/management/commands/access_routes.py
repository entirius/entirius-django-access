# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""`manage.py access_routes [--check] [--json PATH]` — the route audit: every admin route of the resolver needs an area."""

from django.core.management.base import BaseCommand, CommandError

from django_access.services.route_map import audit_routes


class Command(BaseCommand):
    help = "Classify every route of the resolver; list admin routes without an access area."

    def add_arguments(self, parser):
        parser.add_argument("--check", action="store_true", help="exit non-zero when an admin route has no area")
        parser.add_argument("--json", dest="json_path", metavar="PATH", help="write the report as JSON")

    def handle(self, *args, check: bool, json_path: str | None, **options) -> None:
        if audit_routes(self.stdout, json_path) and check:
            raise CommandError("admin routes without an access area — see the list above")
