# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""`manage.py access_routes [--check] [--unmapped] [--json PATH]` — the route audit: every admin route of the resolver
needs an area. ``--unmapped`` is the upgrade preflight: only the admin routes without an area, exit 1 when any."""

from django.core.management.base import BaseCommand, CommandError

from django_access.services.route_map import audit_routes, audit_unmapped


class Command(BaseCommand):
    help = "Classify every route of the resolver; list admin routes without an access area."

    def add_arguments(self, parser):
        parser.add_argument("--check", action="store_true", help="exit non-zero when an admin route has no area")
        parser.add_argument(
            "--unmapped", action="store_true", help="list only admin routes without an area (owner, methods); exit 1"
        )
        parser.add_argument("--json", dest="json_path", metavar="PATH", help="write the report as JSON")

    def handle(self, *args, check: bool, unmapped: bool, json_path: str | None, **options) -> None:
        if unmapped:
            if audit_unmapped(self.stdout, json_path):
                raise CommandError("admin routes without an access area — the gate refuses them (UNMAPPED_ROUTE)")
            return
        if audit_routes(self.stdout, json_path) and check:
            raise CommandError("admin routes without an access area — see the list above")
