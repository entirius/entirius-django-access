# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Legacy keys (D6, D28): import the eight per-module key sources as hashed tokens, report their use, purge their
plaintext rows on demand.

Import keeps each secret: the token's ``key_hash`` is the SHA-256 of the legacy value, so every caller keeps working.
A legacy token never expires by itself (D28) — a team sets or clears an expiry per token (``tokens.set_token_expiry``),
revokes or rotates it. Idempotent by ``key_hash`` — an existing token is never changed, so a re-run never revives an
expired or revoked token. A secret found in a publishable and a secret source is not imported (``mixed``); a secret
shorter than 32 characters shows no character (``short``).

Purge deletes the module rows of imported keys, no time gate; a row whose token was used within ``recent_days`` is
refused unless ``force`` (that row is the only way back if access is ever removed). One ``legacy.purge`` audit row per
run that deleted something. Neither the value nor its hash is ever logged, reported or audited — only counts and
``legacy_source`` ids (``<app>.<Model>#<pk>``). A failing source is logged by exception class, never ``str(exc)``.
"""

import logging
from collections import defaultdict
from dataclasses import dataclass, field, fields
from datetime import datetime, timedelta

from django.apps import apps
from django.conf import settings
from django.db import DEFAULT_DB_ALIAS, connections, models, transaction
from django.utils import timezone

from django_access.models import ApiToken, Application, AuditAction, AuditEntry
from django_access.services.access_service import Actor
from django_access.services.tokens import ACTIVE, hash_key, is_secret, lifecycle_state, rotation_due, token_age_days

logger = logging.getLogger("django_access.legacy")

AGREEMENTS_SOURCE = "settings.AGREEMENTS_API_KEY"
AGREEMENTS_SCOPE = "agreements.subscribe"
SHORT_SECRET_LENGTH = 32
SHORT_PREFIX = "legacy"
LEGACY_PREFIX_LENGTH = 6
LEGACY_SOURCE_LENGTH = ApiToken._meta.get_field("legacy_source").max_length
CONTACT_FORM_SCOPES = {"contact_form": "contact_forms.submit", "booking": "contact_forms.booking"}
DELETED, REFUSED, NOT_IMPORTED = "deleted", "refused", "not_imported"
RECENT_DAYS = 30
NEVER, NONE = "never", "none"


@dataclass(frozen=True)
class Source:
    """A legacy key model: ``scope`` None = by the row's ``scope`` field (contact forms); ``channel`` = FK pinned."""

    model: str
    scope: str | None
    channel: bool = False

    @property
    def module(self) -> str:
        return self.model.split(".")[0]


SOURCES = (
    Source("django_accounts.APIAdminKey", "accounts.erase", channel=True),
    Source("django_checkout.APIAdminKey", "checkout.erase", channel=True),
    Source("django_checkout.APIKey", "checkout.storefront", channel=True),
    Source("django_contact_forms.APIKey", None, channel=True),
    Source("django_returns.APIKey", "returns.api"),
    Source("django_reviews.APIKey", "reviews.moderate"),
    Source("django_vault.APIKey", "vault.api"),
)


@dataclass(frozen=True)
class LegacyKey:
    source: str
    ref: str
    value: str
    scope: str
    channel_idx: str | None
    module: str


@dataclass
class SourceReport:
    imported: list[str] = field(default_factory=list)
    present: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    unpinned: list[str] = field(default_factory=list)
    short: list[str] = field(default_factory=list)
    mixed: list[str] = field(default_factory=list)
    stale: list[str] = field(default_factory=list)
    failed: bool = False


@dataclass
class LegacyReport:
    """Per source: ``legacy_source`` ids by outcome; ``mixed`` = the id groups of every mixed secret."""

    sources: dict[str, SourceReport] = field(default_factory=dict)
    mixed: list[list[str]] = field(default_factory=list)

    def source(self, name: str) -> SourceReport:
        return self.sources.setdefault(name, SourceReport())

    def add(self, kind: str, keys: list[LegacyKey]) -> None:
        for key in keys:
            getattr(self.source(key.source), kind).append(key.ref)

    def total(self, kind: str) -> int:
        return sum(len(getattr(entry, kind)) for entry in self.sources.values())

    @property
    def failed(self) -> list[str]:
        return [name for name, entry in self.sources.items() if entry.failed]

    def as_dict(self) -> dict:
        """Sources with an outcome only: counts would repeat the id lists."""
        return {name: counts for name, entry in sorted(self.sources.items()) if (counts := _counts(entry))}


def _counts(entry: SourceReport) -> dict:
    """The non-empty outcomes with their ids — the shape of the audit detail and the log line."""
    return {f.name: getattr(entry, f.name) for f in fields(entry) if getattr(entry, f.name)}


@dataclass
class PurgeReport:
    """Per source the ids by verdict; ``last_used`` = when the token of each refused id was last used."""

    sources: dict[str, dict[str, list[str]]] = field(default_factory=lambda: defaultdict(lambda: defaultdict(list)))
    remove_settings: list[str] = field(default_factory=list)
    last_used: dict[str, datetime] = field(default_factory=dict)

    def add(self, verdict: str, source: str, ref: str) -> None:
        self.sources[source][verdict].append(ref)

    def ids(self, verdict: str) -> list[str]:
        return [ref for verdicts in self.sources.values() for ref in verdicts.get(verdict, [])]


@dataclass(frozen=True)
class _Run:
    now: datetime
    dry_run: bool
    report: LegacyReport


@dataclass(frozen=True)
class PurgeOptions:
    """``dry_run`` lists only; ``force`` also deletes recently used and never-imported rows."""

    force: bool = False
    dry_run: bool = False
    recent_days: int = RECENT_DAYS


@dataclass(frozen=True)
class _Purge:
    now: datetime
    options: PurgeOptions
    report: PurgeReport

    @property
    def recent(self) -> datetime:
        return self.now - timedelta(days=self.options.recent_days)


def _model(source: Source) -> type[models.Model] | None:
    """The source's model when its module is installed (looked up by app label), else None."""
    try:
        return apps.get_model(source.model)
    except LookupError:
        return None


def _rows(model: type[models.Model], source: Source) -> list[dict]:
    extra = (["channel__idx"] if source.channel else []) + ([] if source.scope else ["scope"])
    with transaction.atomic():
        return list(model._default_manager.order_by("pk").values("pk", "key", *extra))


def _key(source: Source, row: dict) -> LegacyKey | None:
    """None for a row that authenticates nothing today: empty value, no channel on a channel source, unknown scope."""
    scope = source.scope or CONTACT_FORM_SCOPES.get(row.get("scope"))
    channel_idx = row.get("channel__idx")
    if not row["key"] or not scope or (source.channel and channel_idx is None):
        return None
    ref = f"{source.model}#{row['pk']}"
    return LegacyKey(source.model, ref, row["key"], scope, channel_idx, source.module)


def _failed(report: LegacyReport, names: list[str], exc: Exception) -> None:
    """Logged by exception class only: an ``IntegrityError`` message carries the ``key_hash``."""
    for name in names:
        report.source(name).failed = True
    logger.error("Legacy key import failed for %s (%s)", ", ".join(names), type(exc).__name__)


def _read(source: Source, report: LegacyReport) -> list[LegacyKey]:
    if (model := _model(source)) is None:
        return []
    try:
        rows = _rows(model, source)
    except Exception as exc:
        _failed(report, [source.model], exc)
        return []
    keys = [(row, _key(source, row)) for row in rows]
    report.source(source.model).skipped += [f"{source.model}#{row['pk']}" for row, key in keys if key is None]
    return [key for _, key in keys if key is not None]


def _agreements_keys() -> list[LegacyKey]:
    if not (value := getattr(settings, "AGREEMENTS_API_KEY", "")):
        return []
    return [LegacyKey(AGREEMENTS_SOURCE, AGREEMENTS_SOURCE, value, AGREEMENTS_SCOPE, None, "django_agreements")]


def _by_secret(keys: list[LegacyKey]) -> list[list[LegacyKey]]:
    """Keys grouped by value, each group and the list ordered by ``legacy_source`` id."""
    groups = defaultdict(list)
    for key in keys:
        groups[key.value].append(key)
    return sorted((sorted(group, key=lambda key: key.ref) for group in groups.values()), key=lambda g: g[0].ref)


def _refs(group: list[LegacyKey]) -> list[str]:
    return [key.ref for key in group]


def _legacy_source(refs: list[str]) -> str:
    """Every id when they fit the column; else the leading whole ids and ``+N more`` — never an id cut in half."""
    if len(joined := ",".join(refs)) <= LEGACY_SOURCE_LENGTH:
        return joined
    budget = LEGACY_SOURCE_LENGTH - len(f",+{len(refs)} more")
    kept: list[str] = []
    for ref in refs:
        if len(",".join([*kept, ref])) > budget:
            break
        kept.append(ref)
    return ",".join([*kept, f"+{len(refs) - len(kept)} more"])


def _create_token(group: list[LegacyKey], scopes: list[str]) -> None:
    value, channels = group[0].value, {key.channel_idx for key in group}
    short = len(value) < SHORT_SECRET_LENGTH
    application, _ = Application.objects.get_or_create(name=f"Legacy keys: {group[0].module}")
    ApiToken.objects.create(
        application=application,
        name=f"Legacy {group[0].source}"[:128],
        key_hash=hash_key(value),
        prefix=SHORT_PREFIX if short else value[:LEGACY_PREFIX_LENGTH],
        last_four="" if short else value[-4:],
        scopes=scopes,
        channel_idx=next(iter(channels)) if len(channels) == 1 else None,
        expires_at=None,
        legacy=True,
        legacy_source=_legacy_source(_refs(group)),
    )


def _covers(token: ApiToken, group: list[LegacyKey]) -> bool:
    """The existing token serves every row: all their scopes, and unpinned or pinned to their one channel."""
    channels = {key.channel_idx for key in group}
    pinned_right = token.channel_idx is None or channels == {token.channel_idx}
    return {key.scope for key in group} <= set(token.scopes) and pinned_right


def _store(group: list[LegacyKey], scopes: list[str], run: _Run) -> None:
    """``present`` leaves the token as it is; ``stale`` = a row added later that the token does not serve."""
    if token := ApiToken.objects.filter(key_hash=hash_key(group[0].value)).first():
        run.report.add("present" if _covers(token, group) else "stale", group)
        return
    if not run.dry_run:
        try:
            with transaction.atomic():
                _create_token(group, scopes)
        except Exception as exc:
            _failed(run.report, sorted({key.source for key in group}), exc)
            return
    run.report.add("imported", group)


def _import_group(group: list[LegacyKey], run: _Run) -> None:
    """One secret: ``mixed`` (publishable + secret scopes) gets no token; several channels → one unpinned token."""
    scopes = sorted({key.scope for key in group})
    if len({is_secret([scope]) for scope in scopes}) > 1:
        run.report.add("mixed", group)
        run.report.mixed.append(_refs(group))
        return
    if len({key.channel_idx for key in group}) > 1:
        run.report.add("unpinned", group)
    if len(group[0].value) < SHORT_SECRET_LENGTH:
        run.report.add("short", group)
    _store(group, scopes, run)


def _record_run(action: str, actor: Actor, detail: dict) -> None:
    AuditEntry.objects.create(
        actor=actor.user,
        actor_label=actor.label,
        action=action,
        target_type="legacy",
        target_id="",
        target_label="legacy keys",
        detail=detail,
    )


def import_legacy_keys(*, dry_run: bool = False, now: datetime | None = None) -> LegacyReport:
    """Import every installed legacy source; a failing source is reported and the others still run."""
    run = _Run(now or timezone.now(), dry_run, LegacyReport())
    keys = [key for source in SOURCES for key in _read(source, run.report)] + _agreements_keys()
    for group in _by_secret(keys):
        _import_group(group, run)
    if run.report.total("imported") and not dry_run:
        _record_run(AuditAction.LEGACY_IMPORT, Actor(), run.report.as_dict())
    return run.report


def _tokens_ready(using: str) -> bool:
    """The default database with the token table: ``migrate --database=<other>`` or a partial migrate imports nothing."""
    return using == DEFAULT_DB_ALIAS and ApiToken._meta.db_table in connections[using].introspection.table_names()


def import_after_migrate(sender, using: str = DEFAULT_DB_ALIAS, **kwargs) -> None:
    """``post_migrate`` receiver: import and log the report; never fails ``migrate``."""
    if not _tokens_ready(using):
        return
    try:
        report = import_legacy_keys()
    except Exception as exc:
        logger.error("Legacy key import failed (%s)", type(exc).__name__)
        return
    logger.info("Legacy key import: %s", report.as_dict())


def _in_use(token: ApiToken, purge: _Purge) -> bool:
    """An active token used within ``recent_days``: its plaintext row is the only way back for a key still in use."""
    recently = token.last_used_at is not None and token.last_used_at >= purge.recent
    return recently and lifecycle_state(token, purge.now) == ACTIVE


def _verdict(token: ApiToken | None, purge: _Purge) -> str:
    """Deleted unless the key was never imported or is still in use — both only with ``force``."""
    if purge.options.force:
        return DELETED
    if token is None:
        return NOT_IMPORTED
    return REFUSED if _in_use(token, purge) else DELETED


def _tokens_by_hash(values: list[str]) -> dict[str, ApiToken]:
    hashes = {hash_key(value) for value in values if value}
    return {token.key_hash: token for token in ApiToken.objects.filter(key_hash__in=hashes)}


def _judge(token: ApiToken | None, ref: str, source: str, purge: _Purge) -> str:
    verdict = _verdict(token, purge)
    purge.report.add(verdict, source, ref)
    if verdict == REFUSED:
        purge.report.last_used[ref] = token.last_used_at
    return verdict


def _purge_source(model: type[models.Model], source: Source, purge: _Purge) -> None:
    rows = list(model._default_manager.order_by("pk").values_list("pk", "key"))
    tokens = _tokens_by_hash([value for _, value in rows])
    doomed = []
    for pk, value in rows:
        token = tokens.get(hash_key(value)) if value else None
        if _judge(token, f"{source.model}#{pk}", source.model, purge) == DELETED:
            doomed.append(pk)
    if doomed and not purge.options.dry_run:
        model._default_manager.filter(pk__in=doomed).delete()


def _purge_agreements(purge: _Purge) -> None:
    """The setting cannot be deleted by code: name it once imported and not in use (or with ``force``)."""
    if not (value := getattr(settings, "AGREEMENTS_API_KEY", "")):
        return
    token = _tokens_by_hash([value]).get(hash_key(value))
    if token is not None and _verdict(token, purge) == DELETED:
        purge.report.remove_settings.append("AGREEMENTS_API_KEY")


@transaction.atomic
def purge_legacy_sources(
    options: PurgeOptions | None = None, *, now: datetime | None = None, actor: Actor
) -> PurgeReport:
    """Delete the plaintext rows of imported legacy keys, no time gate; recently used keys are refused unless forced."""
    options = options or PurgeOptions()
    purge = _Purge(now or timezone.now(), options, PurgeReport())
    for source in SOURCES:
        if (model := _model(source)) is not None:
            _purge_source(model, source, purge)
    _purge_agreements(purge)
    if (deleted := purge.report.ids(DELETED)) and not options.dry_run:
        detail = {"deleted": len(deleted), "ids": deleted, "force": options.force, "recent_days": options.recent_days}
        _record_run(AuditAction.LEGACY_PURGE, actor, detail)
    return purge.report


def module_of(legacy_source: str) -> str:
    """The module a legacy token came from: the app label of its first id, ``django_agreements`` for the setting."""
    return "django_agreements" if legacy_source.startswith(AGREEMENTS_SOURCE) else legacy_source.split(".")[0]


def _report_row(token: ApiToken, now: datetime) -> dict:
    """One legacy token as the report shows it — ``prefix…last_four`` only, never a value or ``key_hash``."""
    return {
        "id": token.pk,
        "application": token.application.name,
        "source": token.legacy_source,
        "display": token.display,
        "scopes": token.scopes,
        "channel_idx": token.channel_idx,
        "created_at": token.created_at.isoformat(),
        "last_used_at": token.last_used_at.isoformat() if token.last_used_at else NEVER,
        "expires_at": token.expires_at.isoformat() if token.expires_at else NONE,
        "state": lifecycle_state(token, now),
        "age_days": token_age_days(token, now),
        "rotation_due": rotation_due(token, now),
    }


def legacy_report(module: str | None = None) -> list[dict]:
    """Every legacy token (of ``module`` when given), sorted by source: who still uses which legacy key."""
    now = timezone.now()
    rows = ApiToken.objects.filter(legacy=True).select_related("application").order_by("legacy_source", "pk")
    return [_report_row(token, now) for token in rows if module is None or module_of(token.legacy_source) == module]
