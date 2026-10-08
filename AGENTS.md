# AGENTS.md

Staff roles and permissions per module area, an admin API gate, and hashed application tokens for the Volkanos
platform — distribution `entirius-django-access`, Django app `django_access`.

## Commands

| Command | Meaning |
|---|---|
| `make install` | sync dependencies (uv, incl. extras) |
| `make check` | lint + format-check (ruff) |
| `make fix` | auto-fix lint + format |
| `make test` | test suite (pytest + pytest-django) |

## Conventions

- English only: code, docs, commits, branches, PRs.
- MPL-2.0: every non-trivial source file carries the license header (pre-commit inserts it).
- Toolchain: uv + ruff + hatchling + pytest; all config in `pyproject.toml`; `uv.lock` committed.
- Git flow: `master` (production) + `develop` (integration); changes land via PR; semver tag on `master`.
- Never rename the package / Django app_label / DB table prefix `django_access` — it is a schema contract.
- Migrations are part of the public contract — never edit an already released migration.
- Default: do not commit — git is the user's call.

## Commit Message Format

**NEVER add `Co-Authored-By: Claude ...` (or any other Claude/Anthropic attribution) to commit messages.**

This overrides the default Claude Code behavior of appending a `Co-Authored-By` trailer. Commit messages MUST contain only the user's authored content — no robot footer, no "Generated with Claude Code" line, no co-author trailer.

Same rule applies to PR descriptions: no `Generated with [Claude Code]` footer.

## Architecture

Read first: `docs/install.md` (host) · `docs/upgrade.md` (before the first deploy) · `docs/api.md` (caller) ·
`docs/concept.md` (why) · `docs/operations.md` (day 2) · `docs/gotchas.md` (before editing) · `docs/testing.md` ·
`docs/module-authors.md` (other modules). This section is the map; it explains nothing twice.

```
src/django_access/
├── apps.py (checks, cache signals, post_migrate legacy import)  middleware.py (AccessGateMiddleware)
│   openapi.py (ApiKeyAuth hook)  checks.py (E001–E008, E010, E011, W002, W003, W010, I001)  exceptions.py  urls.py
│   signals.py (cache invalidation, staff_user_created)
│   testing.py (assert_routes_covered, for module test suites)
├── catalogue/    areas (49)  scopes (9 token scopes)  defaults (route rules, method and area overrides)  registry
├── models/       role (Role, RolePermission)  grant  audit (AuditEntry, AuditAction)  application  token (ApiToken)
├── services/     access_service (every role/grant mutation, staff create + audit + lockout guard)  permissions (cached)
│                 route_map (classify, audit_routes)  gate (decide)  tokens (issue, rotate, revoke, verify_api_key)
│                 legacy (import, legacy_report, purge_legacy_sources)  directory (read queries of the API)
│                 login_guard (failed-login counter of the service's password logins)
├── schemas/      requests.py  responses.py (Pydantic, extra="forbid")
├── api/          me.py  permissions.py (IsStaffUser, HasAreaPermission)  admin/ (urls, thin views)
└── management/commands/  access_routes  access_token  access_import_legacy_keys  access_legacy_report
                          access_purge_legacy_keys
```

Flow: request → resolve → gate (admin set only: principal → role permissions → allow / 401 / 403) → view. Key routes:
the module's own auth → `verify_api_key(request, scope, channel_idx)` → one lookup by hash (the row of the channel,
else the unpinned one). `migrate` →
`post_migrate` → legacy import (no expiry; teams set one per token) → `access_import_legacy_keys --check` in the deploy
→ `access_legacy_report` shows who still uses them → `access_purge_legacy_keys --yes` on demand. Route areas: the
view's `access_area` → the module's `AppConfig` rules → the access defaults.

| Question | Answer |
|---|---|
| Areas, roles, gate decision table, token rules, legacy mapping | `docs/concept.md` |
| Settings, middleware, URLs, OpenAPI hook, deploy order, rollback, hardening | `docs/install.md` |
| Endpoint, body, response, errors; `verify_api_key` contract | `docs/api.md`; `docs/openapi.yaml` |
| Upgrade preflight: `access_routes --unmapped`, `check --deploy` (`E011`), observe first | `docs/upgrade.md` |
| Legacy import report, `--check`, legacy report, expiry, purge, rotation, revocation, lockout | `docs/operations.md` |
| Which test covers what; fake legacy modules | `docs/testing.md` |
| `access_area` on views, a module's own areas/rules, `assert_routes_covered`, the dependency | `docs/module-authors.md` |
| ERD groupings | `docs/erd-config.yaml` |

## Testing

- `make test` (sqlite) and, in zeno, `make module-test MODULE=entirius-django-access` (PostgreSQL — the lockout
  race runs wherever `DATABASE_URL` is set and fails off Postgres; sqlite skips it).
- `tests/legacy_apps/` installs fake key modules under the real app labels; `tests/security/` is the security
  suite.
- The one-token-per-hash-and-channel constraint (`nulls_distinct=False`) exists on PostgreSQL 15+ only: its tests
  skip on sqlite (`models.W047`, silenced in `tests/settings.py`).
- `docs/openapi.yaml` is generated from `django_access.urls` (`docs/testing.md`) — regenerate it with the API.
- Never put a real or shared key in a test: generate secrets in the test.
