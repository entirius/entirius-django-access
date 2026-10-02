---
title: Testing
description: Which test file covers what, the fake legacy modules, the security suite, and the run in the zeno harness.
---

## Module suite

`make test` — pytest + pytest-django, `tests/settings.py`: `DATABASE_URL` when set (CI, zeno), else sqlite in
memory. The lockout race test needs two connections: it runs whenever `DATABASE_URL` is set (CI, zeno
`make module-test MODULE=entirius-django-access`) and fails there on anything but PostgreSQL; the local sqlite run
skips it and names the skip (`-rs`). The guard's row lock is pinned on sqlite too. Every test secret is generated in the test; no fixture
holds a real or shared key.

**Fake legacy modules.** `tests/legacy_apps/` installs six apps under the real labels (`django_accounts`,
`django_checkout`, `django_contact_forms`, `django_returns`, `django_reviews`, `django_vault`) with the real model
names and key fields — the real modules are not installed here. The `legacy_row` fixture creates a row with a fresh
64-hex secret.

| File | Covers |
|---|---|
| `test_catalogue.py` / `test_registry.py` | areas, scopes, default rules, `AppConfig` overrides per label; checks `E001`–`E006` |
| `test_checks.py` | `W002` (`E010`/`W010` are in `test_gate.py` and `security/test_modes.py`) |
| `test_ownership.py` | `assert_routes_covered` per reason (`unmapped`, `foreign_rule`, `unknown_area`, `defaults`) on fixture apps (`faq_stub` declares, the checkout stub lives on the defaults, `widgets_stub` has neither; `ownership_urls.py`), `I001` |
| `test_route_map.py` / `test_route_map_scoping.py` | classification, owner-scoped rules, `self_auth` per branch, Django admin rules, the route audit |
| `test_permissions.py` / `test_access_service.py` / `test_migration_0002.py` | effective permissions and cache versions (every user flag, membership, cascaded grants), every mutation with its audit row, service field whitelists, lockout guard, reserved `access.manage`, grant targets, 0002 → Manager and its 0001 round trip |
| `test_gate.py` | the gate decision table, modes, bypass audit |
| `test_product_delete.py` | `pim.product_delete`: built-in roles, both PIM roots, the RealProduct merge, media/file/link deletes, `me`, the audit report |
| `test_tokens.py` / `test_access_token_command.py` | issue, rotate, revoke, verify, expiry rules, the CLI |
| `test_admin_api.py` / `test_me_api.py` / `test_token_api.py` | every endpoint: auth matrix, bodies, conflicts, whitelists |
| `test_openapi.py` | `spectacular --validate --fail-on-warn`, the `ApiKeyAuth` hook |
| `test_legacy.py` | every legacy source, idempotency without expiry extension, shared secrets, null-channel skip, the agreements setting, a failing source, dry run, the `post_migrate` receiver, the command |

Shared helpers (`bearer`, `bypass_rows`, the token API endpoints, the measured query count) live in
`tests/helpers.py` — test modules never import from a conftest or from each other.

## Security suite (`tests/security/`)

| File | Covers |
|---|---|
| `test_matrix.py`, `test_auth_paths.py`, `test_paths.py`, `test_modes.py`, `test_failures.py`, `test_cost.py`, `test_bypass_audit.py`, `test_log_hygiene.py` | the gate: principal × route class × method × mode, authenticators the gate does not run, path mutations, fail-closed, zero cost outside the admin set |
| `test_tokens_lifecycle.py`, `test_tokens_lookup.py`, `test_tokens_hygiene.py`, `test_token_api.py` | token lifecycle, one query by hash, no raw value or hash in logs, audit, CLI or API |
| `test_admin_api_*.py` | escalation, IDOR, leakage, audit, the lockout race |
| `test_legacy.py` | short secrets, mixed secrets, `--check`, the purge (window, revoked, `--force`, `--dry-run`, idempotency), expiry bite without revival, no value or hash in logs, output or audit |

## In zeno

```bash
make module-test MODULE=entirius-django-access   # this suite on PostgreSQL, inside the service container
```

`docs/openapi.yaml` is generated from the module urlconf — regenerate it after touching a view or a schema:

```bash
PYTHONPATH=. uv run django-admin spectacular --settings tests.settings --urlconf django_access.urls \
  --validate --fail-on-warn --file /tmp/openapi.yaml
```

(then keep the first comment line of `docs/openapi.yaml` and replace the rest).
