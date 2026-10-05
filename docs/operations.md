---
title: Operations
description: Day 2 — the legacy key import and its check, legacy key lifetime, report, expiry and purge, rotation, revocation, the lockout guard, the route audit.
---

Install-time facts (apps, middleware, settings, deploy order) are in `install.md`.

## Management commands

| Command | Flags | What it does |
|---|---|---|
| `access_import_legacy_keys` | `--dry-run`, `--report`, `--check` | imports the legacy keys (the same as `post_migrate`) and prints counts per source; `--report` adds the `legacy_source` ids; `--check` writes nothing and exits 1 while a key is missing, a secret is `mixed` or `stale`, or a source fails |
| `access_legacy_report` | `--json PATH`, `--module LABEL` | one row per legacy token: source, scopes, channel, created, last used, expiry, state, age, rotation due |
| `access_purge_legacy_keys` | `--yes`, `--force`, `--recent-days N`, `--dry-run` | lists (default) or with `--yes` deletes the plaintext rows of imported legacy keys; exits 1 when a key used within `N` (30) days is refused |
| `access_token` | `create`, `rotate`, `revoke`, `expire`, `list` | tokens from the command line; `create` / `rotate` print the raw value once, alone on stdout; `expire <id> --at YYYY-MM-DD` / `--clear` |
| `access_routes` | `--check`, `--unmapped`, `--json PATH` | the route audit: admin routes per module, area sources, unmapped and foreign-rule matches; `--unmapped` is the upgrade preflight (`upgrade.md`) |

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

A secret shared by rows of two modules (say `django_checkout.APIKey` and `django_contact_forms.APIKey`) becomes
**one** token under the application of the module whose id sorts first (`Legacy keys: django_checkout`); its
`legacy_source` lists both modules' ids. Deactivating that application or revoking that token stops the other
module's caller too — give each caller its own token first.

## Legacy keys: lifetime, report, expiry, purge

Imported legacy keys never expire by themselves — rotation is each team's policy. A legacy token keeps working until
somebody revokes, rotates or expires it; the key modules never fall back to their old tables.

- **Report** — `access_legacy_report` lists every legacy token sorted by source: who still calls with which key, when
  it was last used (`never`), its expiry (`none`), state, age in days and `rotation due` (age counts from the import,
  not from the legacy row). `--module django_checkout` narrows it, `--json PATH`
  writes the rows. `prefix…last_four` only (`legacy…` for a short secret).
- **Expiry** — a team sets or clears one per token: `access_token expire <id> --at 2027-06-30` / `--clear`, or
  `POST tokens/<id>/expiry/` (`api.md`). Any future date or none, for every token (D31). A past date is refused —
  revoke instead. One `token.expiry` audit row each.
- **Move a caller off a legacy key** — issue a new token with the same scope and pin, switch the caller, revoke the
  legacy token (`access_token revoke <id>`).

## Purge

`access_purge_legacy_keys` deletes the plaintext rows of imported keys from the module tables, on demand:

- without `--yes` it only lists what it would delete (`--dry-run` is the same);
- a row whose token was used within `--recent-days` (30) and is still active → **refused**: kept, listed with its last
  use, exit 1 — that row is the only way back for a key in use if access is ever removed;
- a row never imported (no channel, `mixed`) → kept and listed as `not_imported`;
- `--force` deletes both of the last two.

Idempotent — a second run deletes nothing new and writes no audit row. One `legacy.purge` audit row per run that
deleted something (count, ids, `force`, `recent_days`). The agreements setting cannot be deleted by code: the command
prints `remove AGREEMENTS_API_KEY from settings_local` once the key is imported and not in use.

The purge is final: removing the app afterwards cannot bring the legacy keys back (`install.md` § Rollback), and
backups taken before it still hold the plaintext — expire them on the backup schedule.

## Rotation and revocation

- **Rotate** (`tokens/<id>/rotate/`, `access_token rotate`): a successor with the same application, scopes and pin;
  the old token stays valid for `overlap_hours` (default 24, 0–8760 from the API and the CLI). The successor gets the given `expires_at`
  or none — no inherited or capped lifetime (D31).
- **When to rotate**: no token is forced to expire. Every token shows `age_days` and `rotation_due` (active and at
  least `ACCESS_TOKEN_ROTATION_DAYS`, default 365, old) in the API, `access_token list` (`age=<n>d`, `rotation due`)
  and `access_legacy_report`; the CMS reads the rule from the catalogue's `token_rotation_days`. Nothing is refused,
  logged or audited for age — rotate the flagged tokens on your schedule; `0` turns the flag off.
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
| Admin route without an area | `UNMAPPED_ROUTE` 403 + error log; `access_routes --unmapped`; `check --deploy` (`E011`) |
| Who still uses legacy keys | `access_legacy_report` |
| Superuser writes | `gate.bypass` audit rows (status included) |
| Legacy import result | logger `django_access.legacy` after `migrate`; `--check` in the deploy |
| Audit IPs | correct only with `NUM_PROXIES` set to the real proxy depth (`install.md` § Production hardening) |
