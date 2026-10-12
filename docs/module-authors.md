---
title: Module authors
description: How a module maps its admin routes to access areas — on the view, in the AppConfig — proves coverage in its own CI, and when it depends on entirius-django-access.
---

A module owns its access mapping: its areas in its `AppConfig`, the area of every admin route on the view that serves
it. The 25 modules that owned admin routes before access existed still live on the access defaults
(`catalogue/defaults.py`); each moves its mapping into its own code at its next regular release. `manage.py check`
lists who is left (`django_access.I001`).

## Areas on the view (the default for new code)

```python
class QuestionViewSet(viewsets.ViewSet):
    permission_classes = [IsAdminUser]
    access_area = "faq.faq"
    access_levels = {"POST": "read"}  # optional: a POST that only reads


@api_view(["GET"])
@permission_classes([IsAdminUser])
def export(request): ...


export.access_area = "faq.export"  # after the decorators: the URL callback carries it
```

- `access_area` — an area key of the catalogue, or `staff.baseline` for routes every active staff user reaches.
- `access_levels` — optional, HTTP method → `read` / `write`; replaces the default for that method (GET, HEAD,
  OPTIONS read, the rest write) and the access module's per-method override for the route.
- Works on DRF `APIView` / `ViewSet`, Django `View` and function views. The attribute never changes the owner, the
  admin set or whether the view authenticates itself.

## Areas in the AppConfig (always)

Plain dicts — no import of `django_access` needed:

```python
class FaqConfig(AppConfig):
    name = "django_faq"
    access_areas = [
        {"key": "faq.faq", "label": "FAQ"},
        {"key": "faq.export", "label": "FAQ export", "levels": ("write",), "sensitive": ("pii",)},
    ]
```

| Field | Meaning |
|---|---|
| `key` | `<module>.<name>`, lowercase; the permission keys are `<key>:read` and `<key>:write` |
| `label` | English; the CMS translates by key |
| `levels` | `("read", "write")` (default), `("read",)` or `("write",)` |
| `sensitive` | flags among `pii`, `money`, `secret`, `ai_cost`, `config`, `destructive` |

`access_areas` replaces **all** default areas of the module — declare every area it needs; `[]` drops them.
`access_token_scopes` follows the same rule for application-token scopes. `module` is forced to the app label.

## Path rules (only where no view can be annotated)

Django admin pages, third-party views and DRF router roots carry no attribute of yours. For those, rules in the
`AppConfig`:

```python
    access_route_rules = [{"pattern": "api/faq/v2/admin/legacy/", "area": "faq.faq"}]
```

`pattern` is a regex, `re.match`ed against the full `ResolverMatch.route` (converters stay literal). First match
wins, in declaration order; the list replaces every default rule of the module.

## Precedence

1. The view's `access_area` (`area_source` `view`).
2. The first matching rule of the owner's `access_route_rules` (`app`).
3. The access defaults for that owner (`default`); framework routes take only the access module's framework rules
   (`framework`).

The owner is the top-level package of the view's `__module__` — it must equal the app label. Area overrides stay on
top (the SKU delete needs `pim.product_delete` whatever the route's area). A route matched by nothing is unmapped: the
gate answers 403 `UNMAPPED_ROUTE` to everyone but superusers. `access_routes` prints the source of every route.

Checks: `E007` an `access_area` outside the catalogue, `E008` an unknown method or level in `access_levels` (or one
the area does not offer), `W003` an `access_area` on a route outside the admin set (the gate ignores it).

## Test

`django_access` in the test settings' `INSTALLED_APPS`, then one test:

```python
from django_access.testing import assert_routes_covered


def test_admin_routes_are_covered():
    assert_routes_covered("django_faq", require_own=True)
```

| Reason | Meaning | Fix |
|---|---|---|
| `unmapped` | neither the view nor a rule gives the route an area | set `access_area` on the view |
| `foreign_rule` | a rule of another module also matches the route | narrow the other pattern |
| `unknown_area` | the route's area is outside the catalogue | declare the area or fix the key |
| `defaults` | `require_own=True`: no `access_areas` declared, or a route still mapped by the access defaults | declare the areas; annotate the view |

`require_own=True` passes when the app declares `access_areas` (an empty list counts) and every admin route it owns
takes its area from a view attribute or its own rules. Leave it off while the module still lives on the defaults.
Plain `AssertionError`, no pytest import. Admin routes are those under an `admin/` segment or `api-admin/`, plus
views with an `IsAdminUser` / `IsSuperUser` permission class — the set the gate guards.

## Dependency

Add `entirius-django-access` to the module's `pyproject.toml` once the coverage test imports it; every service running
the module requires access anyway. The attributes and `access_areas` need no import. Pin the lower bound to the
release that ships `django_access.testing`.

## No second check

The gate is the only permission decision. A module adds no permission class of its own that re-checks areas or roles:
two checks drift. Keep the view's existing `IsAdminUser` / `IsAuthenticated` — it makes the route admin and lets the
view answer anonymous callers itself. Object-level rules (a channel the user may not see, a record's state) stay in
the module's services.
