---
title: Operations
description: Day 2 — the legacy key import and its check, rotation, revocation, the 90-day window and the purge, the lockout guard, the route audit.
---

Install-time facts (apps, middleware, settings, deploy order) are in `install.md`.

## Management commands

| Command | Flags | What it does |
|---|---|---|
| `access_import_legacy_keys` | `--dry-run`, `--report`, `--check` | imports the legacy keys (the same as `post_migrate`) and prints counts per source; `--report` adds the `legacy_source` ids; `--check` writes nothing and exits 1 while a key is missing, a secret is `mixed` or `stale`, or a source fails |
| `access_purge_legacy_keys` | `--dry-run`, `--force` | deletes the plaintext legacy rows whose token's window is over; exits 1 when a row is still inside the window |
| `access_token` | `create`, `rotate`, `revoke`, `list` | tokens from the command line; `create` / `rotate` print the raw value once, alone on stdout |
| `access_routes` | `--check`, `--json PATH` | the route audit: admin routes per module, unmapped and foreign-rule matches |

None of them prints a raw legacy value or a `key_hash` — only counts and `legacy_source` ids
(`django_checkout.APIKey#3`, `settings.AGREEMENTS_API_KEY`).

## Legacy import

`post_migrate` runs the import after every `migrate` and logs the report (`django_access.legacy`). A failing source
is logged by exception class and source, never its message, and the other sources still run.

Report outcomes per source:

| Outcome | Meaning |
|---|---|
| `imported` | a token was created (under `--check`: `missing`, not imported yet) |
| `present` | a token with that hash exists — left as it is, its expiry untouched |
| `skipped` | the row authenticates nothing today (no channel, empty value, unknown scope) |
| `unpinned` | the secret was found on several channels, or in a channel source and a channel-less one; one unpinned token holds it and works on **every** channel |
| `stale` | a token with that hash exists but does not serve the row (another scope or channel added later); the token is never widened — `--check` fails |
| `short` | under 32 characters; the token shows `legacy…` |
| `mixed` | found in a publishable and a secret source; **no token** |

One `legacy.import` audit row per run that imported something.

A `mixed` secret prints `MIXED legacy secret in <ids> — not imported, rotate before deploying`. Rotate: issue a
publishable token for the browser caller and a secret one for the server caller (`access_token create` or the API),
switch both callers, delete the old rows in Django admin of the key module, run `--check` again.

A legacy row added after the import with a new secret is imported by the next `migrate` or
`access_import_legacy_keys`; `--check` shows it as `missing` until then. A row added later that reuses an imported
secret on another channel or scope is `stale`: issue that caller its own token and delete the row.

## The 90-day window

Every imported key expires `ACCESS_LEGACY_KEY_TTL_DAYS` after its import, and a re-run never extends it. During the
window:

1. List the legacy tokens: `access_token list` (`legacy` application names) or the token API (`legacy: true`).
2. Issue each integrator a new token with the same scope and pin; they switch.
3. Revoke the legacy token once the caller is gone (`access_token revoke <id>`).

After the window the legacy token answers like any expired token — `verify_api_key` returns `None`.

## Purge

`access_purge_legacy_keys` deletes the plaintext rows from the module tables:

- a row whose token is past its window or revoked → deleted;
- a row whose token is still inside the window → **refused**: kept, listed, exit 1;
- a row never imported (no channel, `mixed`) → kept and listed as `not_imported`;
- `--force` deletes both of the last two;
- `--dry-run` deletes nothing and prints the same lists.

Idempotent — a second run deletes nothing new and writes no audit row (refused and `not_imported` rows are listed
again). One `legacy.purge` audit row per run that deleted something (count, ids,
`force`). The agreements setting cannot be deleted by code: past the window the command prints
`remove AGREEMENTS_API_KEY from settings_local`.

The purge is final: removing the app afterwards cannot bring the legacy keys back (`install.md` § Rollback), and
backups taken before it still hold the plaintext — expire them on the backup schedule.

## Rotation and revocation

- **Rotate** (`tokens/<id>/rotate/`, `access_token rotate`): a successor with the same application, scopes and pin;
  the old token stays valid for `overlap_hours` (default 24, API 0–168). A secret token's successor keeps the old
  lifetime, capped at 365 days.
- **Revoke** (`tokens/<id>/revoke/`, `access_token revoke`): refused on the next request — verification is never
  cached.
- **Deactivate an application** (`PATCH applications/<id>/ {"is_active": false}`): every token of it stops.

## Lockout guard

A role change, role delete or grant revoke that leaves no access manager (an active staff superuser or an
Administrator holder) is refused with 409 and rolls back. To hand over: grant Administrator to the new person first,
then revoke the old grant. A lost last manager is recovered with `createsuperuser`.

## Monitoring

| Signal | Where |
|---|---|
| Refusals in `observe` mode | logger `django_access.gate` |
| Admin route without an area | `UNMAPPED_ROUTE` 403 + error log; `access_routes --check` |
| Superuser writes | `gate.bypass` audit rows (status included) |
| Legacy import result | logger `django_access.legacy` after `migrate`; `--check` in the deploy |
| Audit IPs | correct only with `NUM_PROXIES` set to the real proxy depth (`install.md` § Production hardening) |
