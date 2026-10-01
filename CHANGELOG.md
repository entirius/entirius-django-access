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
  transaction with its audit row; a change that removes the last access manager raises `AccessLockout`.
- Migration `0002`: the built-in roles, and Administrator for every active staff user on first adoption
  (`grant.migrate` audit rows).
- `services.route_map`: `walk()` yields every route as `ResolverMatch.route`, `classify()` gives owner, admin flag,
  area and method overrides (no models imported), `required_permission()` the `<area>:<level>` a method needs,
  `audit_routes()` the per-module route audit (JSON report on request). Admin set = `admin/` segment or `api-admin/`
  path ∪ an `IsAdminUser`/`IsSuperUser` permission class (DRF `&`/`|` composites walked) ∪ the munin health, returns
  download and pim viewer exceptions; the Django admin site and the X-API-ADMIN-KEY erase routes are not admin.
- `catalogue.defaults.METHOD_OVERRIDES`: 10 POST-reads → read, leads GDPR export and 6 GET PII exports/downloads →
  write, contentdb GET `…/published/` → `content.publish:write`. `returns.attachments` is write-only.
- `manage.py access_routes [--check] [--json PATH]`.
- Requires Django 5.1+.

## 0.1.0 (unreleased)

- Scaffold from the Entirius module template.
