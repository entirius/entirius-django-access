# Changelog

## Unreleased

- Permission catalogue as code: 48 areas (read/write per module area), 9 application-token scopes, default route
  rules for the 25 modules that own admin routes (full `ResolverMatch.route` regex, first match wins, a catch-all per
  admin root), staff-baseline pseudo-area.
- `AppConfig.access_areas` / `access_route_rules` / `access_token_scopes`: a module's declaration replaces the
  defaults of that kind for its own label.
- `catalogue.registry`: `areas()`, `scopes()`, `route_rules()`, `area()`, `perm_key()`, `parse_perm()`, `implies()`,
  cached, `reset()` for tests.
- System checks (tag `entirius_config`, `django_access.E001`–`E006`): duplicate area or scope keys, invalid areas,
  rules naming an unknown area or carrying an invalid regex, unreadable declarations.
- Models `Role`, `RolePermission`, `Grant` (one user or one `auth.Group`), `AuditEntry`; read-only Django admin.
- Built-in roles `administrator`, `manager`, `editor`, `viewer`, computed from the catalogue at run time; custom roles
  hold validated permission keys.
- `services.permissions`: `effective_permissions(user)`, `has_permission(user, key)`, `granted_roles(user)`,
  `manages_access(user)`; cached per user under a version bumped by every access change, group membership and
  `is_staff` / `is_superuser` / `is_active` changes.
- `services.access_service`: `create_role`, `update_role`, `delete_role`, `grant_role`, `revoke_grant` — each in one
  transaction with its audit row; a change that removes the last access manager (active staff superuser or
  Administrator holder) raises `AccessLockout`. `access.manage` is built-in only: a custom role asking for
  `access.manage:read` or `:write` raises `ReservedPermission` (`ACCESS_MANAGE_RESERVED`); `registry.custom_role_areas()`
  lists the assignable areas. Grants go only to active staff users (or to a group).
- Migration `0002_builtin_roles_and_staff_managers` (renamed from `…_staff_administrators`, which it `replaces`): the
  built-in roles, and Manager for every active non-superuser staff user on first adoption
  (`grant.migrate` audit rows); access management stays with superusers until someone is granted Administrator.
- `services.route_map`: `walk()` yields every route as `ResolverMatch.route`, `classify()` gives owner, admin flag,
  area and method overrides (no models imported), `required_permission()` the `<area>:<level>` a method needs,
  `audit_routes()` the per-module route audit (JSON report on request). Admin set = `admin/` segment or `api-admin/`
  path ∪ an `IsAdminUser`/`IsSuperUser` permission class (DRF `&`/`|` composites walked) ∪ the munin health, returns
  download and pim viewer exceptions; the X-API-ADMIN-KEY erase routes are not admin. Route rules are owner-scoped
  (a rule applies only to its own module's routes); framework routes match `FRAMEWORK_RULES` only — the Django admin
  site is `access.manage` (login, logout, jsi18n and password change on the staff baseline), the contentdb router root
  `content.pages`, the OpenAPI views the staff baseline. `RouteInfo.self_auth` / `auth`: whether the view answers an
  anonymous caller itself (a DRF view on exactly SimpleJWT `JWTAuthentication` / DRF `SessionAuthentication` with a
  permission requiring a user, no `get_authenticators`/`get_permissions`/`check_permissions` override; or a view the
  Django admin site marks itself); classes from `as_view` initkwargs first. The JSON report
  adds `foreign_rule_matches` (the audit fails on any), `admin_not_self_auth` and `non_admin` with an audience.
- `catalogue.defaults.METHOD_OVERRIDES`: 10 POST-reads → read, leads GDPR export and 6 GET PII exports/downloads →
  write, contentdb GET `…/published/` → `content.publish:write`. `returns.attachments` is write-only.
- `manage.py access_routes [--check] [--json PATH]`.
- System check `django_access.W002`: a `LocMemCache`/`DummyCache` default cache with `DEBUG=False` (permission
  changes reach other processes only after the cache timeout).
- Application tokens: models `Application` and `ApiToken` (migration `0003`). Raw value `ent_api_` +
  `secrets.token_urlsafe(32)`, shown once; stored as SHA-256 `key_hash` (unique index), `prefix` (12) and `last_four`.
- `services.tokens`: `issue_token`, `rotate_token` (successor + overlap window), `revoke_token`, `create_application`
  (each audited `application.create` / `token.create|rotate|revoke`, never with the raw value or `key_hash`), and
  `verify_api_key(request, scope, channel_idx=None)`: `X-API-KEY`, else `X-API-ADMIN-KEY`; one uncached lookup by
  hash; `None` for every failure (unknown, expired, revoked, inactive application, wrong or empty scopes, channel
  mismatch); values over 256 characters run no query; `last_used_at` by a conditional update at most once per
  `ACCESS_TOKEN_LAST_USED_INTERVAL_S` (300).
- Scope rules: at least one catalogue scope; publishable and secret scopes never share a token; a token with a secret
  scope must expire within `ACCESS_SECRET_TOKEN_MAX_TTL_DAYS` (365) — `TokenExpiryError` (`EXPIRY_REQUIRED` /
  `EXPIRY_TOO_LONG`); rotation keeps a secret token's lifetime within the cap.
- `manage.py access_token create|rotate|revoke|list`; read-only Django admin for applications and tokens, no add,
  no `key_hash`.
- `django_access.middleware.AccessGateMiddleware` (append after the authentication middleware) +
  `services.gate.decide()`: acts only on the admin set (outside it one memoized `classify()`, no authentication,
  cache or query); the principal is what the view's own JWT/session authenticators would see (a session never counts
  on a JWT-only view; API-key headers are never read); anonymous callers reach only self-authenticating views, else
  401 `NOT_AUTHENTICATED` + `WWW-Authenticate: Bearer realm="api"`; superuser passes, with one `gate.bypass` audit
  row per write (GET PII exports included, any unsafe method on a route without an area with `needed: null`) written
  after the response with its status; non-staff → 403 `STAFF_ONLY`, admin route without an area → 403
  `UNMAPPED_ROUTE`, missing permission or a write on a read-only area → 403 `ACCESS_DENIED` (v2 envelope); an
  exception in the decision → the v2 500 envelope, view not run.
- `ACCESS_GATE_MODE` = `enforce` (default) | `observe` (log refusals on `django_access.gate`, let through) | `off`;
  any other value is enforced. System checks `django_access.E010` (invalid mode) and `W010` (not `enforce` with
  `DEBUG=False`).
- The gate decides HEAD like GET (Django serves HEAD with the GET handler): a HEAD of a GET PII export needs the
  export's write permission and leaves a superuser bypass row.
- Admin API v2 under `api/access/v2/admin/` (`django_access.urls`): `catalogue/` (staff baseline: areas by module with
  `assignable`, built-in roles with computed permissions), `roles/` + `roles/<id>/` (custom roles only change; built-in
  or lockout → 409, `access.manage` → 400 `ACCESS_MANAGE_RESERVED`), `grants/` + `grants/<id>/`, `staff/` +
  `staff/<user_id>/` (active staff only; anything else → 404), `groups/`, `audit/` (filters `action`, `actor`, `from`,
  `to`). JWT only, `IsStaffUser` + `HasAreaPermission` (`access.manage:read`/`:write`) on every admin view, Pydantic
  schemas with `extra="forbid"`; `GET api/access/v2/me/` for any authenticated user. Audit rows carry the client
  address by DRF's throttle rule (`NUM_PROXIES` set → the `X-Forwarded-For` entry `min(NUM_PROXIES, entries)` from the
  right; unset → `REMOTE_ADDR`). The staff baseline (`IsStaffUser`) is active staff only. A racing duplicate role or grant is a conflict,
  not an `IntegrityError`.
- Token API v2 under `api/access/v2/admin/`: `applications/` + `applications/<id>/` (list, create, PATCH `name`,
  `description`, `is_active`; no DELETE; a name in use → 409), `applications/<id>/tokens/` (list, issue),
  `tokens/<id>/rotate/` (`overlap_hours` 0–168, default 24; revoked → 409) and `tokens/<id>/revoke/` (idempotent, one
  audit row). The raw value is only in the issue and rotate responses (`Cache-Control: no-store`, `Pragma: no-cache`);
  no response carries `key_hash`; token rows show `state` `active` | `expired` | `revoked`. Secret-scope expiry errors
  → 400 `EXPIRY_REQUIRED` / `EXPIRY_TOO_LONG` on `expires_at`. `services.tokens.update_application` (field whitelist,
  audited `application.update`) and `lifecycle_state`. The catalogue lists the token scopes.
- `django_access.openapi.add_api_key_security`: drf-spectacular postprocessing hook adding the `ApiKeyAuth` scheme
  (`apiKey`, header `X-API-KEY`) and requiring it on every operation matching a token scope's routes, next to the
  operation's existing requirements.
- Legacy keys (`services.legacy`): `import_legacy_keys(dry_run=, now=)` imports the seven module key tables
  (accounts/checkout `APIAdminKey`, checkout and contact-forms `APIKey` pinned to their channel, returns, reviews and
  vault `APIKey`) and `AGREEMENTS_API_KEY` as tokens with the same secret — one `Legacy keys: <app_label>`
  application per module, `legacy=True`, `legacy_source` `<app>.<Model>#<pk>`, no expiry (D28: legacy keys never
  expire by themselves; the setting `ACCESS_LEGACY_KEY_TTL_DAYS` of earlier 0.1.0 builds is gone — 0.1.0 is
  unreleased). Idempotent by `key_hash`: an existing token is never changed (no revival). A secret on several channels → one unpinned token; a row added later that the existing token does not serve →
  `stale`; a secret in a publishable and a secret
  source → not imported (`mixed`); a secret under 32 characters → `prefix "legacy"`, empty `last_four`; a row
  without a channel → skipped. Runs on `post_migrate` (errors logged by class, `migrate` never fails); one
  `legacy.import` audit row per run that imported something.
- `manage.py access_import_legacy_keys [--dry-run] [--report] [--check]`: counts and `legacy_source` ids only, never
  a value or a hash; `--check` exits 1 while a key is not imported, a secret is `mixed` or `stale`, or a source fails.
- `purge_legacy_sources(PurgeOptions)` + `manage.py access_purge_legacy_keys [--yes] [--force] [--recent-days N]`:
  deletes the plaintext rows of imported legacy keys on demand, no time gate; without `--yes` it only lists
  (`--dry-run` kept as an alias); a key used within `N` (30) days is refused (exit 1, listed with its last use) unless
  `--force`, which also deletes never-imported rows; idempotent; one `legacy.purge` audit row per run that deleted
  something; names `AGREEMENTS_API_KEY` for removal from the settings.
- Migration `0004_legacy_tokens_without_expiry`: clears the automatic import-time expiry of every legacy token no
  `token.expiry` audit row names (reverse: no-op).
- `tokens.set_token_expiry(token, expires_at=, actor=)`: set or clear one token's expiry, audited `token.expiry`
  (token id, `legacy`, from, to). Legacy and publishable tokens take any future date or none; an issued secret token
  keeps the 365-day cap (`EXPIRY_REQUIRED` / `EXPIRY_TOO_LONG`); a past date → `EXPIRY_IN_PAST`; a revoked token →
  `AccessConflict`. API `POST admin/tokens/<id>/expiry/` (200 token row); CLI `access_token expire <id> --at
  YYYY-MM-DD | --clear`.
- `manage.py access_legacy_report [--json PATH] [--module LABEL]`: one row per legacy token (source, scopes, channel,
  created, last used, expiry, state), never a value or a hash.
- Module docs: `docs/concept.md`, `install.md` (wiring, settings, deploy order, rollback, production hardening),
  `api.md`, `operations.md`, `testing.md`, `gotchas.md`, `erd-config.yaml`, `openapi.yaml`.
- Requires Django 5.1+ and DRF 3.15.2+.
- Area `pim.product_delete` (write only, flag `destructive`, 49 areas): `catalogue.defaults.AREA_OVERRIDES` make the
  PIM product `DELETE` (both roots) and the atlas/suppliers `realproducts/merge-by-ean/` need it instead of
  `pim.products` / `*.products`; `RouteInfo.method_areas`, `method_areas` in the route audit JSON. Administrator and
  Manager hold it, Editor does not. `E003` also fires on an area override naming an unknown area.
- Module ownership: `django_access.testing.assert_routes_covered(app_label, urlconf=None, require_own=False)` for a
  module's own test suite (fails on `unmapped`, `foreign_rule`, `unknown_area`, and `defaults` with `require_own`:
  no `access_areas` declared or an owned admin route still mapped by the access defaults); check `django_access.I001`
  (Info) lists installed apps with an admin route mapped by the defaults; `route_map.unique_entries()` /
  `foreign_rule_matches()` public; guide `docs/module-authors.md`.
- Areas on views (D30): a view class or function may carry `access_area` and `access_levels` (method → `read` /
  `write`); precedence view → the owner's `access_route_rules` → the access defaults; `access_levels` win per method
  over `METHOD_OVERRIDES`, `AREA_OVERRIDES` still apply on top. `RouteInfo.area_source` (`view` | `app` | `default` |
  `framework` | None), in the route audit JSON and output. Checks `E007` (unknown view area), `E008` (bad
  `access_levels`), `W003` (view area outside the admin set).
- Upgrade preflight (D29): `manage.py access_routes --unmapped` (route, owner, methods; exit 1 when any) and the
  deploy check `django_access.E011` (`check --deploy`: the gate enforces over unmapped admin routes); guide
  `docs/upgrade.md`.

## 0.1.0 (unreleased)

- Scaffold from the Entirius module template.
