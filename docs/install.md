---
title: Install
description: Service wiring — app, middleware, URLs, OpenAPI hook, settings, gate modes and the kill switch, deploy order and rollback.
---

Read this once before `migrate`. Upgrading an installation that already runs: `upgrade.md` first. Day-2 work (legacy
keys, rotation, revocation, the purge, lockouts): `operations.md`.

## Prerequisites

| Requirement | Why | Verify |
|---|---|---|
| Python ≥ 3.11, Django ≥ 5.1, DRF + `rest_framework_simplejwt` + `drf_spectacular`, Pydantic 2 | the admin API is JWT + Pydantic; the gate reads the views' DRF classes | `manage.py check` |
| `entirius-django-utils` ≥ 2.2.0, its v2 handler as `REST_FRAMEWORK["EXCEPTION_HANDLER"]` | refusal and error bodies are the v2 envelope | a 403 carries `debug_id` |
| `SPECTACULAR_SETTINGS["OAS_VERSION"] = "3.1.0"` | Pydantic examples are JSON Schema 2020-12 | `manage.py spectacular --validate` |
| A shared cache (Redis) as `CACHES["default"]` | permission cache versions and failed-login counters must reach every process | no `django_access.W002`; `check --deploy` without `django_access.E012` |

## INSTALLED_APPS, middleware, URLs

```python
INSTALLED_APPS = [
    # ...
    "rest_framework",
    "rest_framework_simplejwt",
    "drf_spectacular",
    "django_access",
]

MIDDLEWARE = [
    # ... SessionMiddleware, AuthenticationMiddleware, ...
    "django_access.middleware.AccessGateMiddleware",  # after authentication, last is fine
]

SPECTACULAR_SETTINGS = {
    # ...
    "POSTPROCESSING_HOOKS": [
        "drf_spectacular.hooks.postprocess_schema_enums",
        "django_access.openapi.add_api_key_security",  # ApiKeyAuth on every token-scope route
    ],
}
```

```python
# main/urls.py
from django_access.services.login_guard import guarded_admin_login

urlpatterns = [
    path("admin/login/", guarded_admin_login(admin.site.login)),  # before the admin site: it resolves first
    path("admin/", admin.site.urls),
    # ...
]
urlpatterns.append(path("", include("django_access.urls")))
```

`guarded_admin_login` puts the admin login form on the failed-login counters of `api/token/` (same keys, limits and
windows): a blocked POST answers 429 with `Retry-After` before the password is checked, and a login blocked on one is
blocked on the other. Without the line the admin form accepts guesses the API login refuses.

`django_access.urls` mounts `api/access/v2/me/` and `api/access/v2/admin/…` (`api.md`). Keep the Django admin site
at `admin/`: the route map puts that prefix in the admin set and opens it to superusers only (its login, logout and
password pages to every active staff user); a second `AdminSite` or another prefix stays outside the gate.

The gate classifies the whole resolver once per process. Run `manage.py access_routes --check` after wiring: it
fails on any admin route without an area and on any rule matching another module's routes.

## Settings

| Setting | Default | Meaning |
|---|---|---|
| `ACCESS_GATE_MODE` | `"enforce"` | `enforce` refuses; `observe` logs refusals (`django_access.gate`) and lets through; `off` decides nothing. Any other value is enforced + `E010`; a non-`enforce` mode with `DEBUG=False` warns `W010` |
| `ACCESS_TOKEN_ROTATION_DAYS` | `365` | an active token this many days old is `rotation_due` (API, CLI, legacy report, catalogue `token_rotation_days`); a recommendation, nothing is refused; `0` turns it off |
| `AUTH_TOKEN_FAILURE_WINDOW_S` | `900` | window of the per username + address and per address failed-login counters (`services.login_guard`: `api/token/` and the admin login form); a login they block answers 429 for this long |
| `AUTH_TOKEN_MAX_FAILURES_PER_USER_IP` / `AUTH_TOKEN_MAX_FAILURES_PER_IP` | `10` / `100` | failed logins per username + address / per address before 429 |
| `AUTH_TOKEN_MAX_FAILURES_PER_USER` | `50` | failed logins per username from any address before 429 — slows guesses spread over many addresses; the price: anyone who knows a username can hold it at 429 for up to `AUTH_TOKEN_USER_FAILURE_WINDOW_S` |
| `AUTH_TOKEN_USER_FAILURE_WINDOW_S` | `3600` | window of the per-username counter, from the first failure; a success does not clear it |
| `ACCESS_TOKEN_LAST_USED_INTERVAL_S` | `300` | `last_used_at` is written at most once per token per interval |
| `ACCESS_TOKEN_EXCHANGE_TTL_S` | `300` | lifetime of a JWT bought at `token/exchange/` |
| `REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"]` `access_token_exchange` / `access_token_exchange_address` | `30/min` / `120/min` | exchanges per key / per address; a missing or malformed rate falls back to the default |
| `AGREEMENTS_API_KEY` | `""` | read by the legacy import only (agreements' own setting) |

The mode is a setting only — no API, admin page or database row changes it.

**Kill switch.** `ACCESS_GATE_MODE = "off"` (or `observe`) and a restart: every admin route behaves as before the
module for people. Tokens and `verify_api_key` are not affected by the mode, and a JWT bought at `token/exchange/` is
decided by its token in every mode.

## Hosts with their own gate

A host may run its own route matrix in front of the admin API and keep the access gate in `observe`. Token requests
are still enforced by access (above). The host's gate sees an ordinary staff JWT of the service user
(`access-app-<application id>`), so it must also let that user through in its own model — grant it there what the
token's scopes allow, nothing more. Both gates then have to say yes; access alone revokes at once.

## Production hardening

- **Shared cache — a hard requirement in production.** Permissions are cached per process-local version key, so with
  LocMem a revoke or role change reaches only the process that made it; a revoked grant keeps working in the other
  workers until the cache timeout, and every worker counts failed logins on its own, so the login limits multiply by
  the worker count. LocMem or Dummy as the default cache is the Error `django_access.E012` under `check --deploy` (any
  `DEBUG`), which stops the deploy; a plain `check` with `DEBUG=False` warns `django_access.W002`.
- **Proxy depth.** Audit IPs and every per-IP throttle use DRF's `NUM_PROXIES`. On Volkanos set the service setting
  `DRF_NUM_PROXIES` to the real proxy depth — `1` behind Cloudflare → Caddy → nginx; other hosts set
  `REST_FRAMEWORK["NUM_PROXIES"]`. Unset, the client address is `REMOTE_ADDR`, and a client-chosen
  `X-Forwarded-For` never counts.
- **OpenAPI.** The service serves its schema, swagger and redoc to staff only by default (`API_SCHEMA_PUBLIC`
  False) — the document maps every admin route. Turn it on only where the map is public anyway.
- **Secret scanning.** Raw tokens start with `ent_api_`; add a gitleaks rule for that prefix to the canonical config.

## Deploy order

```
manage.py access_routes --unmapped                 # exit 1 → stop, or deploy in observe (upgrade.md)
manage.py check --deploy --fail-level ERROR        # E011: enforce over unmapped admin routes; E012: per-process cache
manage.py migrate                                  # 0001–0004; post_migrate imports the legacy keys
manage.py access_import_legacy_keys --check        # exit 1 → stop: a key is not imported or mixed
# only now: traffic to the new release
```

The `post_migrate` import never fails `migrate` — it logs and moves on. `--check` is how the deploy finds out: once
a key module calls `verify_api_key` there is no fallback to its legacy table, so an unimported key is a refused
caller. Fix a `mixed` secret by rotation (`operations.md`) before the deploy goes on.

After the upgrade migration `0002` every active non-superuser staff user holds **Manager**. Access management and
token issuing stay with superusers until someone is granted Administrator — the `grant.migrate` rows in the audit list
who got what. The Django admin site stays with superusers whatever the grants.

## Rollback

| Problem | Do |
|---|---|
| The gate refuses something it should not | `ACCESS_GATE_MODE = "off"` (or `observe` to keep the log), restart |
| A token problem | remove the app (and the middleware): the key modules return to their legacy tables; tokens issued since stop working. Impossible after `access_purge_legacy_keys` — the plaintext is gone |

Never run `migrate django_access zero` while the app is installed: it drops every role, grant, token and audit row.
