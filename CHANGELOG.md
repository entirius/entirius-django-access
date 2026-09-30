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

## 0.1.0 (unreleased)

- Scaffold from the Entirius module template.
