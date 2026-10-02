# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""`manage.py access_token create|rotate|revoke|expire|list` — application tokens from the command line.

``create`` and ``rotate`` print the raw value once, alone on its stdout line (the rest goes to stderr); ``list`` shows
``prefix…last_four`` only. Nothing here ever prints ``key_hash``.
"""

from datetime import date, datetime, time, timedelta

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from django_access.exceptions import AccessConflict
from django_access.models import ApiToken, Application
from django_access.services import tokens
from django_access.services.access_service import Actor


def _positive(value: str) -> int:
    number = int(value)
    if number < 1:
        raise ValueError(value)
    return number


def _midnight(value: str) -> datetime:
    """``YYYY-MM-DD`` → the start of that day in the current time zone."""
    return timezone.make_aware(datetime.combine(date.fromisoformat(value), time.min))


class Command(BaseCommand):
    help = "Create, rotate, revoke, expire and list application tokens."

    def add_arguments(self, parser):
        sub = parser.add_subparsers(dest="action", required=True)
        create = sub.add_parser("create", help="issue a token; prints the raw value once")
        create.add_argument("--application", required=True, help="application name")
        create.add_argument("--create-application", action="store_true", help="create the application when missing")
        create.add_argument("--scope", action="append", required=True, dest="scopes", help="token scope (repeatable)")
        create.add_argument("--channel", dest="channel_idx", help="pin the token to one channel idx")
        create.add_argument("--expires-days", type=_positive, help="lifetime in days (required for secret scopes)")
        create.add_argument("--name", default="", help="token name")
        rotate = sub.add_parser("rotate", help="issue a successor; prints the new raw value once")
        rotate.add_argument("token_id", type=int)
        rotate.add_argument("--overlap-hours", type=int, default=24, help="hours the old token stays valid")
        revoke = sub.add_parser("revoke", help="revoke a token at once")
        revoke.add_argument("token_id", type=int)
        expire = sub.add_parser("expire", help="set or clear a token's expiry (audited)")
        expire.add_argument("token_id", type=int)
        when = expire.add_mutually_exclusive_group(required=True)
        when.add_argument("--at", type=_midnight, help="expire at the start of this day (YYYY-MM-DD)")
        when.add_argument("--clear", action="store_true", help="remove the expiry")
        listing = sub.add_parser("list", help="list tokens (never a raw value)")
        listing.add_argument("--application", help="only this application's tokens")

    def handle(self, *args, action: str, **options) -> None:
        handlers = {
            "create": self._create,
            "rotate": self._rotate,
            "revoke": self._revoke,
            "expire": self._expire,
            "list": self._list,
        }
        try:
            handlers[action](options)
        except (ValueError, AccessConflict) as exc:
            raise CommandError(str(exc)) from exc

    def _application(self, name: str, create: bool) -> Application:
        if application := Application.objects.filter(name=name).first():
            return application
        if not create:
            raise CommandError(f"No application {name!r} (add --create-application)")
        return tokens.create_application(name, actor=Actor())

    def _token(self, token_id: int) -> ApiToken:
        if token := ApiToken.objects.filter(pk=token_id).first():
            return token
        raise CommandError(f"No token {token_id}")

    @transaction.atomic
    def _create(self, options: dict) -> None:
        days = options["expires_days"]
        token, raw = tokens.issue_token(
            self._application(options["application"], options["create_application"]),
            scopes=options["scopes"],
            channel_idx=options["channel_idx"],
            expires_at=timezone.now() + timedelta(days=days) if days else None,
            name=options["name"],
            actor=Actor(),
        )
        self._show_once(token, raw, "created")

    def _rotate(self, options: dict) -> None:
        token = self._token(options["token_id"])
        successor, raw = tokens.rotate_token(token, actor=Actor(), overlap_hours=options["overlap_hours"])
        self._show_once(successor, raw, f"replaces token {token.pk}")

    def _show_once(self, token: ApiToken, raw: str, note: str) -> None:
        self.stdout.write(raw)
        self.stderr.write(f"Token {token.pk} {token.display} {note}. The value above is shown once — store it now.")

    def _revoke(self, options: dict) -> None:
        token = tokens.revoke_token(self._token(options["token_id"]), actor=Actor())
        self.stdout.write(f"Token {token.pk} {token.display} revoked.")

    def _expire(self, options: dict) -> None:
        token = tokens.set_token_expiry(self._token(options["token_id"]), expires_at=options["at"], actor=Actor())
        expires = token.expires_at.isoformat() if token.expires_at else "never"
        self.stdout.write(f"Token {token.pk} {token.display} expires {expires}.")

    def _list(self, options: dict) -> None:
        queryset = ApiToken.objects.select_related("application").order_by("application__name", "id")
        if options["application"]:
            queryset = queryset.filter(application__name=options["application"])
        now = timezone.now()
        for token in queryset:
            self.stdout.write(self._row(token, tokens.token_state(token, now)))

    def _row(self, token: ApiToken, state: str) -> str:
        expires = token.expires_at.isoformat() if token.expires_at else "never"
        used = token.last_used_at.isoformat() if token.last_used_at else "never"
        return (
            f"{token.pk}\t{token.application.name}\t{token.name}\t{token.display}\t{','.join(token.scopes)}\t"
            f"channel={token.channel_idx or '*'}\texpires={expires}\tlast_used={used}\t{state}"
        )
