---
title: Gotchas
description: The one list of rules that bite — read before touching the catalogue, the route map, the gate, tokens or the legacy import.
---

Install-time traps (middleware order, shared cache, proxy depth) live in `install.md`. Each item: the rule, then
where it is enforced.

## Contracts

- **Never rename the package, the app label or the table prefix `django_access`**, and never edit a released
  migration. `0002_builtin_roles_and_staff_administrators` keeps its name although it grants Manager — `0003`
  depends on it by name.
- **`catalogue/` and `services/route_map.py` import no models at module import, and `services/__init__.py` stays
  empty.** The service's route audit imports the route map before the app is installed.
- **Every mutation goes through `access_service` / `tokens`.** They write the audit row in the same transaction and
  run the lockout guard; a direct `Grant.objects.create` skips both.

## Route map and gate

- **Rules are owner-scoped.** A rule applies only to routes whose view lives in the rule's own module (top-level
  package = app label). An app whose label differs from its package never matches its own rules — the audit shows
  the routes as `UNMAPPED`.
- **`self_auth` is strict.** Only a DRF view on exactly `JWTAuthentication` / `SessionAuthentication` with a
  permission that requires a user, or a view the Django admin site marks itself, lets anonymous callers through to
  its own 401. A view on DRF's default Session + Basic gets the gate's 401.
- **The route map is memoized per process.** URLs added at run time (tests patching the urlconf) need
  `route_map.reset()`.
- **A superuser without `is_staff` is refused** (`STAFF_ONLY`) although `effective_permissions` gives them
  everything.

## Tokens

- **`key_hash` never leaves the database** — not in an API body, the Django admin, a log line or an audit row.
  `ApiToken.__str__` is `prefix…last_four`, so audit labels are safe. Django's SQL debug log (`django.db.backends`
  at DEBUG) prints query parameters, including the hash of a presented value: never route it at DEBUG where real
  tokens arrive.
- **One answer for every failure.** A key module must not turn `None` into different statuses per reason.
- **Revoking an already revoked token** raises `AccessConflict` in the service; only the API treats it as success.
- **Rotating an expired token is allowed** and yields a live successor (rotate refuses revoked tokens only).

## Legacy keys

- **Values are secrets; the report holds ids.** Never log, print or audit a legacy value or its hash. Exceptions
  are logged by class: an `IntegrityError` message carries the `key_hash`.
- **Idempotent by `key_hash`.** An existing token is never changed — no expiry extension, no added scope, no
  revival. A row that later shares a secret with an imported token stays covered by that token's scopes only.
- **Sources are looked up by app label** (`apps.get_model`), so the fake modules in `tests/legacy_apps/` stand in
  for the real ones.
- **A null-channel row of a channel source is skipped** — it authenticates nothing today, and an unpinned token
  would give it every channel.
- **`post_migrate` swallows errors** so `migrate` never fails; `--check` is the only gate. Seed and deploy must run
  it.
- **The purge cannot be undone**, and removing the app after it leaves the key modules without keys.
