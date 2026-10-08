# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Application tokens: issue, rotate, revoke and ``verify_api_key``.

A raw value (``ent_api_`` + 256 random bits) exists only in the return value of ``issue_token`` / ``rotate_token``;
the database keeps its SHA-256 (unique index), ``prefix`` and ``last_four``. Verify hashes the presented header value
and runs one uncached lookup by that hash — no scan, no Python comparison of secrets, and the same ``None`` for every
failure. Neither the raw value nor ``key_hash`` is ever logged or written to an audit row.
"""

import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Any

from django.conf import settings
from django.db import transaction
from django.db.models import F, Q
from django.utils import timezone

from django_access.catalogue import registry
from django_access.exceptions import AccessConflict, TokenExpiryError
from django_access.models import ApiToken, Application, AuditAction
from django_access.services.access_service import Actor, record_audit, unique_or_conflict

TOKEN_PREFIX = "ent_api_"  # noqa: S105 — the public marker of every raw value
MAX_PRESENTED_LENGTH = 256
KEY_HEADERS = ("HTTP_X_API_KEY", "HTTP_X_API_ADMIN_KEY")
ACTIVE, REVOKED, EXPIRED, INACTIVE = "active", "revoked", "expired", "application inactive"
_EDITABLE_APPLICATION_FIELDS = frozenset({"name", "description", "is_active"})
MAX_OVERLAP_HOURS = 365 * 24


def hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def rotation_days() -> int:
    """``ACCESS_TOKEN_ROTATION_DAYS``: the age from which a token is due for rotation (0 = never recommended)."""
    return getattr(settings, "ACCESS_TOKEN_ROTATION_DAYS", 365)


def _last_used_interval() -> timedelta:
    return timedelta(seconds=getattr(settings, "ACCESS_TOKEN_LAST_USED_INTERVAL_S", 300))


def _publishable() -> dict[str, bool]:
    return {scope.key: scope.publishable for scope in registry.scopes()}


def is_secret(scopes: list[str]) -> bool:
    publishable = _publishable()
    return not all(publishable.get(key, False) for key in scopes)


def _validated_scopes(scopes: list[str]) -> list[str]:
    """Deduplicated, sorted catalogue keys of one group; ``ValueError`` when empty, unknown or mixed."""
    publishable = _publishable()
    if not scopes:
        raise ValueError("A token needs at least one scope")
    if unknown := set(scopes) - publishable.keys():
        raise ValueError(f"Unknown token scopes: {sorted(unknown)}")
    if len({publishable[key] for key in scopes}) > 1:
        raise ValueError("Publishable and secret scopes cannot share a token")
    return sorted(set(scopes))


def _check_expiry(expires_at: datetime | None, now: datetime) -> None:
    """An expiry is optional and has no maximum (D31); a given one must lie in the future — to stop a token, revoke it."""
    if expires_at is not None and expires_at <= now:
        raise TokenExpiryError(
            TokenExpiryError.EXPIRY_IN_PAST, "The expiry must be in the future (or revoke the token)"
        )


def token_detail(token: ApiToken) -> dict:
    """The audit ``detail`` of a token — never the raw value, never ``key_hash``."""
    return {
        "token_id": token.pk,
        "name": token.name,
        "application_id": token.application_id,
        "scopes": token.scopes,
        "channel_idx": token.channel_idx,
        "expires_at": token.expires_at.isoformat() if token.expires_at else None,
        "prefix": token.prefix,
        "last_four": token.last_four,
    }


def _create(actor: Actor, **fields) -> tuple[ApiToken, str]:
    raw = TOKEN_PREFIX + secrets.token_urlsafe(32)
    token = ApiToken.objects.create(
        key_hash=hash_key(raw), prefix=raw[:12], last_four=raw[-4:], created_by=actor.user, **fields
    )
    return token, raw


@transaction.atomic
def create_application(name: str, *, description: str = "", actor: Actor) -> Application:
    message = f"Application {name!r} already exists"
    if Application.objects.filter(name=name).exists():
        raise AccessConflict(message)
    with unique_or_conflict(message):
        application = Application.objects.create(name=name, description=description, created_by=actor.user)
    record_audit(AuditAction.APPLICATION_CREATE, actor, application, {"name": name})
    return application


@transaction.atomic
def update_application(application: Application, updates: dict[str, Any], *, actor: Actor) -> Application:
    """Change ``name``, ``description`` or ``is_active`` (deactivating stops every token of the application)."""
    if invalid := set(updates) - _EDITABLE_APPLICATION_FIELDS:
        raise ValueError(f"Fields not editable via update_application: {sorted(invalid)}")
    message = f"Application {updates.get('name', application.name)!r} already exists"
    if Application.objects.filter(name=updates.get("name")).exclude(pk=application.pk).exists():
        raise AccessConflict(message)
    changes = {key: {"from": getattr(application, key), "to": value} for key, value in updates.items()}
    for key, value in updates.items():
        setattr(application, key, value)
    with unique_or_conflict(message):
        application.save()
    changed = {key: change for key, change in changes.items() if change["from"] != change["to"]}
    record_audit(AuditAction.APPLICATION_UPDATE, actor, application, {"name": application.name, "changes": changed})
    return application


@transaction.atomic
def issue_token(
    application: Application,
    *,
    scopes: list[str],
    channel_idx: str | None = None,
    expires_at: datetime | None = None,
    name: str = "",
    actor: Actor,
) -> tuple[ApiToken, str]:
    """A new token and its raw value — the only time the raw value exists."""
    scopes = _validated_scopes(scopes)
    _check_expiry(expires_at, timezone.now())
    token, raw = _create(
        actor, application=application, name=name, scopes=scopes, channel_idx=channel_idx, expires_at=expires_at
    )
    record_audit(AuditAction.TOKEN_CREATE, actor, token, token_detail(token))
    return token, raw


def _shorten(token: ApiToken, now: datetime, overlap_hours: int) -> None:
    """The old token expires ``overlap_hours`` from ``now`` (0 = at once) unless it expires earlier anyway."""
    if not 0 <= overlap_hours <= MAX_OVERLAP_HOURS:
        raise ValueError(f"overlap_hours must be between 0 and {MAX_OVERLAP_HOURS}")
    cutoff = now + timedelta(hours=overlap_hours)
    token.expires_at = min(token.expires_at, cutoff) if token.expires_at else cutoff
    token.save(update_fields=["expires_at"])


def _copied(token: ApiToken) -> dict:
    """What a successor inherits — not ``legacy``, not the expiry."""
    return {"application_id": token.application_id, "name": token.name, "channel_idx": token.channel_idx}


@transaction.atomic
def rotate_token(
    token: ApiToken, *, actor: Actor, overlap_hours: int = 24, expires_at: datetime | None = None
) -> tuple[ApiToken, str]:
    """A successor with the same application, scopes and channel, expiring at ``expires_at`` (none by default); the old
    token expires after ``overlap_hours``."""
    token = ApiToken.objects.select_for_update().get(pk=token.pk)
    if token.revoked_at:
        raise AccessConflict("A revoked token cannot be rotated")
    now = timezone.now()
    scopes = _validated_scopes(token.scopes)
    _check_expiry(expires_at, now)
    _shorten(token, now, overlap_hours)
    successor, raw = _create(actor, **_copied(token), scopes=scopes, expires_at=expires_at)
    replaced = {"replaces": token.pk, "replaces_expires_at": token.expires_at.isoformat()}
    record_audit(AuditAction.TOKEN_ROTATE, actor, successor, {**token_detail(successor), **replaced})
    return successor, raw


@transaction.atomic
def revoke_token(token: ApiToken, *, actor: Actor) -> ApiToken:
    token = ApiToken.objects.select_for_update().get(pk=token.pk)
    if token.revoked_at:
        raise AccessConflict("The token is already revoked")
    token.revoked_at = timezone.now()
    token.revoked_by = actor.user
    token.save(update_fields=["revoked_at", "revoked_by"])
    record_audit(AuditAction.TOKEN_REVOKE, actor, token, token_detail(token))
    return token


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


@transaction.atomic
def set_token_expiry(token: ApiToken, *, expires_at: datetime | None, actor: Actor) -> ApiToken:
    """Set or clear (``None``) a token's expiry: any future date or none, for every token (D28, D31). To stop a token
    now, revoke it."""
    token = ApiToken.objects.select_for_update().get(pk=token.pk)
    if token.revoked_at:
        raise AccessConflict("A revoked token cannot get a new expiry")
    _check_expiry(expires_at, timezone.now())
    change = {"token_id": token.pk, "legacy": token.legacy, "from": _iso(token.expires_at), "to": _iso(expires_at)}
    token.expires_at = expires_at
    token.save(update_fields=["expires_at"])
    record_audit(AuditAction.TOKEN_EXPIRY, actor, token, change)
    return token


def lifecycle_state(token: ApiToken, now: datetime) -> str:
    """``revoked``, ``expired`` or ``active`` — the token's own state, whatever its application."""
    if token.revoked_at:
        return REVOKED
    if token.expires_at and token.expires_at <= now:
        return EXPIRED
    return ACTIVE


def token_age_days(token: ApiToken, now: datetime) -> int:
    """Whole days since the token was issued (or imported)."""
    return (now - token.created_at).days


def rotation_due(token: ApiToken, now: datetime) -> bool:
    """An active token at least ``ACCESS_TOKEN_ROTATION_DAYS`` old — a recommendation only, nothing is refused (D31)."""
    days = rotation_days()
    return days > 0 and lifecycle_state(token, now) == ACTIVE and token_age_days(token, now) >= days


def token_state(token: ApiToken, now: datetime) -> str:
    state = lifecycle_state(token, now)
    return INACTIVE if state == ACTIVE and not token.application.is_active else state


def _allows(token: ApiToken, scope: str, channel_idx: str | None) -> bool:
    """Default-deny: an empty scope list allows nothing; a pinned token only on its own channel — never where the caller
    passes no channel, since the pin cannot be checked there."""
    pin_holds = token.channel_idx is None or (channel_idx is not None and token.channel_idx == str(channel_idx))
    return scope in token.scopes and pin_holds


def _presented(request) -> str | None:
    """``X-API-KEY``, else ``X-API-ADMIN-KEY``; an empty or over-long value counts as none."""
    value = next((request.META[header] for header in KEY_HEADERS if request.META.get(header)), None)
    return value if value and len(value) <= MAX_PRESENTED_LENGTH else None


def _touch(token: ApiToken, now: datetime) -> None:
    """At most one ``last_used_at`` write per token per interval, across every process (a conditional UPDATE)."""
    threshold = now - _last_used_interval()
    if token.last_used_at and token.last_used_at >= threshold:
        return
    stale = Q(last_used_at__isnull=True) | Q(last_used_at__lt=threshold)
    if ApiToken.objects.filter(stale, pk=token.pk).update(last_used_at=now):
        token.last_used_at = now


def _candidate(presented: str, scope: str, channel_idx: str | None) -> ApiToken | None:
    """One query over the rows of the hash (several only for a legacy secret split per channel): the row pinned to the
    route's channel, else the unpinned one — the first of them that holds ``scope``."""
    rows = ApiToken.objects.select_related("application").filter(key_hash=hash_key(presented))
    if channel_idx is None:
        rows = rows.filter(channel_idx__isnull=True)
    else:
        rows = rows.filter(Q(channel_idx=str(channel_idx)) | Q(channel_idx__isnull=True))
    ordered = rows.order_by(F("channel_idx").asc(nulls_last=True))
    return next((token for token in ordered if scope in token.scopes), None)


def verify_api_key(request, scope: str, channel_idx: str | None = None) -> ApiToken | None:
    """The token presented by ``request`` when it may use ``scope`` on ``channel_idx``, else ``None`` (any reason).

    ``channel_idx=None`` (a route without a channel) accepts unpinned tokens only: a pinned token is refused there."""
    presented = _presented(request)
    if presented is None:
        return None
    token = _candidate(presented, scope, channel_idx)
    now = timezone.now()
    if token is None or token_state(token, now) != ACTIVE or not _allows(token, scope, channel_idx):
        return None
    _touch(token, now)
    request.access_token = token
    return token
