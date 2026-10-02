---
title: Admin API
description: Every access API v2 endpoint — method, path, permission, body, response shape, errors — and the verify_api_key contract for key modules.
---

All endpoints live under `/api/access/v2/` (the host includes `django_access.urls`). The machine-readable contract is
`docs/openapi.yaml` (generated from the module urlconf); this page adds what the schema cannot say. Views are thin:
parse into a Pydantic schema (`schemas/requests.py`, `extra="forbid"`), call a service, dump a response schema
(`schemas/responses.py`). Field whitelists and every access rule live in the services.

## Auth and paging

| | |
|---|---|
| Authentication | `JWTAuthentication`, declared on every view |
| Permission | `IsStaffUser` + `HasAreaPermission`: `access.manage:read` for GET, `access.manage:write` otherwise; `catalogue/` is staff baseline; `me/` any authenticated user |
| Refusals | customer → 403 `STAFF_ONLY`; a superuser without `is_staff` → 403 from `IsStaffUser` (any gate mode); staff without the permission → 403 `ACCESS_DENIED`; no or bad JWT → 401 |
| Paged lists | `?page=&page_size=` (default 20, max 100) → `{count, next, previous, results}` |
| Audit IP | DRF's throttle rule: `REST_FRAMEWORK["NUM_PROXIES"]` set → the `X-Forwarded-For` entry `min(NUM_PROXIES, entries)` from the right; unset, `0` or no header → `REMOTE_ADDR` |

## Me

| Method | Path | Success |
|---|---|---|
| GET | `me/` | 200 `{user {id, username, email, first_name, last_name, is_staff, is_superuser}, gate_mode, manages_access, roles [{key, name}], permissions {area: read\|write}}` |

A superuser gets every area at its top level. A non-staff user gets `permissions: {}` and `gate_mode: null`.

## Catalogue, roles, grants

| Method | Path | Body / params | Success |
|---|---|---|---|
| GET | `admin/catalogue/` | — | 200 `{modules [{module, areas [{key, label, levels, sensitive, assignable}]}], roles [built-in with computed permissions], scopes [{key, label, module, publishable, routes}]}` |
| GET | `admin/roles/` | paging | 200 built-in and custom roles with `grant_count` |
| POST | `admin/roles/` | `key` (slug), `name`, `description`, `permissions` (`<area>:read\|write`) | 201 role with `permissions` |
| GET / PATCH / DELETE | `admin/roles/<id>/` | PATCH: `name`, `description`, `permissions` (replaces the set) | 200 / 200 / 204 |
| GET | `admin/grants/` | `role`, `user_id`, `group_id`, paging | 200 `{id, role, user, group, created_at}` |
| POST | `admin/grants/` | `role` and exactly one of `user_id` (active staff) / `group_id` | 201 |
| DELETE | `admin/grants/<id>/` | — | 204 |
| GET | `admin/staff/` | `search`, paging | 200 active staff with their roles (`via_group`) |
| GET | `admin/staff/<user_id>/` | — | 200 + `groups`, `grants`; anything but an active staff user → 404 |
| GET | `admin/groups/` | paging | 200 `{id, name, member_count, grants}` |
| GET | `admin/audit/` | `action`, `actor`, `from`, `to`, paging (newest first) | 200 `{id, created_at, actor_id, actor_label, action, target_type, target_id, target_label, detail, ip}` |

Role errors: a built-in role changed or deleted → 409; any `access.manage:*` key → 400 `ACCESS_MANAGE_RESERVED`;
an unknown key → 400. A change that leaves no access manager → 409 and nothing changes. A grant of an unknown role,
to an unknown group or to anyone but an active staff user → 400 (the message never says which); a duplicate
grant → 409.

## Applications and tokens

| Method | Path | Body / params | Success |
|---|---|---|---|
| GET | `admin/applications/` | paging (by name) | 200 `{id, name, description, is_active, created_at}` |
| POST | `admin/applications/` | `name`, `description` | 201; a name in use → 409 |
| GET / PATCH | `admin/applications/<id>/` | PATCH: `name`, `description`, `is_active` (none, null or another field → 400) | 200; no DELETE (405) |
| GET | `admin/applications/<id>/tokens/` | paging (newest first) | 200 token rows, never `raw` |
| POST | `admin/applications/<id>/tokens/` | `scopes` (required), `name`, `channel_idx`, `expires_at` (aware, future) | 201 token row + `raw` |
| POST | `admin/tokens/<id>/rotate/` | `overlap_hours` (0–168, default 24), `expires_at` | 201 successor + `raw`; revoked → 409 |
| POST | `admin/tokens/<id>/revoke/` | — | 200; already revoked → 200, no second audit row |
| POST | `admin/tokens/<id>/expiry/` | `expires_at` (aware datetime, or `null` to clear; required) | 200 token row; revoked → 409; audited `token.expiry` |

Token row: `id, name, prefix, last_four, scopes, channel_idx, expires_at, last_used_at, revoked_at, legacy,
legacy_source, state` (`active` | `expired` | `revoked` — the token's own state; check the application's
`is_active` next to it). A legacy row has `legacy: true`, a 6-character `prefix` (`legacy` with an empty
`last_four` for a short secret) and its `legacy_source` ids.

`raw` is in the create and rotate responses only, with `Cache-Control: no-store` and `Pragma: no-cache`. No response
ever carries `key_hash`.

Token errors (400, v2 envelope): unknown or mixed scopes (`non_field_errors`); a secret scope without `expires_at`
→ `issue: EXPIRY_REQUIRED`, more than 365 days ahead → `EXPIRY_TOO_LONG` (both on `field: expires_at`). The expiry
endpoint: a past date → `EXPIRY_IN_PAST`; legacy and publishable tokens take any future date or `null`, an issued
secret token keeps both rules above.

## Errors

The v2 envelope of `django_utils.api.v2_errors`:

```json
{"error": "PERMISSION_DENIED", "message": "You do not have permission to perform this action.",
 "debug_id": "3f2a9c1e", "details": [{"field": null, "location": "path", "issue": "ACCESS_DENIED",
 "description": "needs pim.products:write"}]}
```

The gate's refusals use the same envelope on every admin route of the service (`concept.md` § The gate);
`STAFF_ONLY` names no area.

## Key routes: `verify_api_key`

Key modules call `django_access.services.tokens.verify_api_key(request, scope, channel_idx=None)` from their own
authentication class or decorator:

- reads `X-API-KEY`, else `X-API-ADMIN-KEY`; values over 256 characters → `None` without a query;
- returns the token and sets `request.access_token`, or `None` for every failure — answer it with the module's
  existing 401/400, never a different status per reason;
- throttle per `request.access_token.pk`, never by the header value.

The OpenAPI hook `django_access.openapi.add_api_key_security` adds the `ApiKeyAuth` scheme (`apiKey`, header
`X-API-KEY`) to every operation matching a token scope's routes.
