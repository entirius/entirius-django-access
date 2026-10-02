---
title: Module authors
description: How a module declares its own access areas and route rules, proves coverage in its own CI, and when it depends on entirius-django-access.
---

Every new module and every new admin route declares its own areas and route rules on the module's `AppConfig` and
proves the coverage in the module's own test suite. The 25 modules that owned admin routes before access existed still
live on the access defaults (`catalogue/defaults.py`); each moves its rules into its own `AppConfig` at its next
regular release. `manage.py check` shows who is left (`django_access.I001`).

## Declare

Plain dicts on the `AppConfig` — no import of `django_access` needed:

```python
class FaqConfig(AppConfig):
    name = "django_faq"
    access_areas = [
        {"key": "faq.faq", "label": "FAQ"},
        {"key": "faq.export", "label": "FAQ export", "levels": ("write",), "sensitive": ("pii",)},
    ]
    access_route_rules = [
        {"pattern": "api/faq/v2/admin/export/", "area": "faq.export"},
        {"pattern": "api/faq/v2/admin/", "area": "faq.faq"},  # catch-all on the admin root, last
    ]
```

| Field | Meaning |
|---|---|
| area `key` | `<module>.<name>`, lowercase; the permission keys are `<key>:read` and `<key>:write` |
| area `label` | English; the CMS translates by key |
| area `levels` | `("read", "write")` (default), `("read",)` or `("write",)` |
| area `sensitive` | flags among `pii`, `money`, `secret`, `ai_cost`, `config`, `destructive` |
| rule `pattern` | regex, `re.match` against the full `ResolverMatch.route` (`api/faq/v2/admin/<int:pk>/`) — converters stay literal |
| rule `area` | an area key, or `staff.baseline` for routes every active staff user reaches |

The dataclass form works too (`django_access.catalogue.areas.Area`, `catalogue.defaults.RouteRule`) — it needs the
import. `module` is always forced to the declaring app's label; do not set it. `access_token_scopes` follows the same
rules for application-token scopes.

## Precedence

- A declaration replaces **all** defaults of that kind for the app's own label — declare every area and every rule
  the module needs, not the difference. `access_areas = []` drops the module's default areas.
- Rules are first-match, in declaration order; put specific patterns before the catch-all on the admin root. The
  module's rules take the position of its first default rule.
- A rule applies only to the routes its module owns. The owner is the top-level package of the view's `__module__`
  — it must equal the app label, so a view served from another package is not covered by your rules.
- Framework routes (the Django admin site, DRF router roots, the OpenAPI views) match only the access module's
  framework rules; a module cannot declare them.
- Per-method level and area overrides (a POST that reads, a GET that exports PII, the SKU delete) stay in
  `catalogue/defaults.py` — ask in the access module when a route needs one. Dropping an area such an override names
  is an `E003` error.
- Without any declaration the defaults apply; a route matched by neither is unmapped and the gate answers 403
  `UNMAPPED_ROUTE` to everyone but superusers.

## Test

`django_access` in the test settings' `INSTALLED_APPS`, then one test:

```python
from django_access.testing import assert_routes_covered


def test_admin_routes_are_covered():
    assert_routes_covered("django_faq", require_own=True)
```

It walks `ROOT_URLCONF` (or `urlconf="..."`) and raises `AssertionError` listing every admin route the module owns,
its methods and the reason:

| Reason | Meaning | Fix |
|---|---|---|
| `unmapped` | no rule of the module matches | add a rule (or a catch-all on the admin root) |
| `foreign_rule` | a rule of another module also matches the route | narrow the other pattern — two owners for one path drift |
| `unknown_area` | the matching rule names an area outside the catalogue | declare the area or fix the key |
| `defaults` | `require_own=True` and the module declares no `access_areas` / `access_route_rules` | move the rules into the `AppConfig` |

Plain `AssertionError`, no pytest import: it runs under pytest, `unittest` or `manage.py test`. Leave `require_own` off
while the module still lives on the defaults. Admin routes are those under an `admin/` segment or `api-admin/`, plus
views with an `IsAdminUser` / `IsSuperUser` permission class — the same set the gate guards.

## Dependency

Add `entirius-django-access` to the module's `pyproject.toml` dependencies once it declares rules: from then on the
module's coverage test imports it, and every service running the module requires access anyway. A module that
declares nothing needs no dependency. Pin the lower bound to the release that ships `django_access.testing`.

## No second check

The gate is the only permission decision. A module adds no permission class of its own that re-checks areas or
roles: two checks drift, and the one nobody updates refuses (or worse, allows) on its own. Keep the view's existing
`IsAdminUser` / `IsAuthenticated` — it is what makes the route admin and lets the view answer anonymous callers
itself. Object-level rules that are not about areas (a channel the user may not see, a record's state) stay in the
module's services.
