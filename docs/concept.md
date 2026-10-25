---
title: Concept
description: Areas, roles and grants, the admin gate, application tokens on key and admin routes, legacy keys — what django-access decides and why.
---

django-access answers two questions for a Volkanos service: may this staff user call this admin route, and may this
machine client call this key-protected route. The first is the **gate** (roles per module area); the second is the
**application token** (`verify_api_key`). An integration on admin routes sits between them: its key buys a short-lived
JWT, and the gate decides that JWT by the key's admin scopes (§ Integrations on admin routes). Neither replaces a
module's own view checks — the gate refuses earlier, it never grants.

## Areas and permissions

The catalogue (`catalogue/`) is code, not data: 50 **areas** (`pim.products`, `checkout.orders`, …, `access.manage`,
`platform.devtools`), each offering `read` and usually `write`. A permission key is `<area>:read` or `<area>:write`;
write implies read. A module can replace its own defaults with `AppConfig.access_areas`,
`access_route_rules` and `access_token_scopes` — only for its own app label (`module-authors.md`).

**Deleting a SKU** is its own write-only area, `pim.product_delete` (flag `destructive`): editing the catalogue
(`pim.products`) does not include it. It guards the PIM product `DELETE` (`api/pim/v2/admin/` and the legacy
`api/pim/admin/`, which removes the SKU from one channel) and the atlas and suppliers `realproducts/merge-by-ean/`
(which deletes the losing SKU in every channel). Deleting a SKU's pictures, files, videos or links stays
`pim.products:write`. Administrator and Manager hold it, Editor and Viewer do not; custom roles may.

**Attribute values** (`pim.attribute_values`) are apart from the schema (`pim.schema`: features, feature sets,
attribute groups, channels, link types, file categories): an integration that adds a new value — a new brand
option — needs no right to change the schema. Every built-in role holds it at its `pim.schema` level; migration `0007`
gave every custom role holding `pim.schema` the same level on it. The access defaults map the PIM `attributes/` routes
there; a PIM release that declares its own areas (3.4.0 does) replaces those defaults, so on it the routes stay
`pim.schema` until a PIM release declares `pim.attribute_values` and annotates its attribute views.

**Staff baseline** — every active staff user, no grant needed: `me`, `catalogue`, regional reference lists,
contentdb self-permission reads, the notifications inbox, the Django admin login/logout/password pages.

**Superusers only** — the rest of the Django admin site (pseudo-area `superuser.only`). The CMS replaced it for
clients: no role opens it, Administrator included (403 `ACCESS_DENIED`, description `superuser only`). Like the staff
baseline it is never grantable, never in `me` and not a catalogue area.

## Roles and grants

| Role | Permissions (computed from the catalogue at run time) |
|---|---|
| `administrator` | write on every area |
| `manager` | write on every area except `access.manage` |
| `editor` | write on `content.*`, `pim.products`, `pim.categories`, `pim.schema`, `pim.attribute_values`, `pim.quality`, `faq.faq`, `email.templates`; read on the rest except `access.manage` |
| `viewer` | read on every area except `access.manage` |

Built-in roles are neither editable nor deletable; a new area joins them without a migration. Custom roles store
validated permission keys and never hold `access.manage` — only Administrator does (400 `ACCESS_MANAGE_RESERVED`).

A **grant** gives one role to one active staff user or to one `auth.Group`. A user's permissions are the union of
their direct and group grants. No per-user overrides, no deny rules. Superusers hold everything.

The **lockout guard** refuses any change (role update or delete, grant revoke) that leaves no access manager — an
active staff superuser or an Administrator holder. The whole transaction rolls back (`AccessLockout`, 409).

**Upgrade default.** Migration `0002` grants **Manager** to every active non-superuser staff user on first adoption
(one `grant.migrate` audit row each). Nobody gets Administrator: until a superuser grants it, access management
and token issuing stay with superusers. The Django admin site stays with superusers for good.

Permissions are cached per user under a version that every access change, group membership change and
`is_staff`/`is_superuser`/`is_active` change bumps. With a per-process cache (LocMem) other processes see a change
only after the timeout — production needs a shared cache (`django_access.W002`; an Error, `E012`, under
`check --deploy`).

## The gate

`AccessGateMiddleware` acts only on the **admin set**: routes under an `admin/` segment or `api-admin/`, plus views
with an `IsAdminUser`/`IsSuperUser` permission class. Outside it the gate does nothing — no authentication, no cache,
no query. The route map (`services/route_map.py`) classifies every resolver route by owner (the view's top-level
package), area and method; rules apply only to their own module's routes.

| Caller | Answer |
|---|---|
| anonymous or invalid credentials, view authenticates itself (`self_auth`) | passes — the view's own 401 drives the CMS token refresh |
| anonymous, any other admin view | 401 `NOT_AUTHENTICATED` + `WWW-Authenticate: Bearer realm="api"` |
| superuser | passes; a write (any unsafe method on a route without an area too) leaves one `gate.bypass` audit row after the response; without `is_staff` the view's `IsAdminUser` / `IsStaffUser` refuses |
| authenticated non-staff | 403 `STAFF_ONLY` |
| staff, admin route without an area | 403 `UNMAPPED_ROUTE` + error log |
| staff, Django admin page (`superuser.only`) | 403 `ACCESS_DENIED` (`superuser only`) — whatever the roles |
| staff without the permission, or a write on a read-only area | 403 `ACCESS_DENIED` |
| staff with the permission | passes |
| exchanged JWT (claim `access_token_id`), token revoked, expired, its application inactive or not this user's | 403 `TOKEN_INACTIVE` — in every mode |
| exchanged JWT, the token's admin scopes lack the permission, a write on the staff baseline, `superuser.only` | 403 `ACCESS_DENIED` — in every mode; an unmapped route stays 403 `UNMAPPED_ROUTE`; staff-baseline reads pass |
| exchanged JWT with the permission | passes — never by role, never by the superuser bypass |

GET/HEAD/OPTIONS read, everything else writes — except the catalogue overrides: POST-reads count as read, the GET PII
exports and downloads count as write (a Viewer never exports PII), and the SKU-deleting routes need
`pim.product_delete:write` instead of their route's area. The principal is what the view's own
authenticators would see, from SimpleJWT `JWTAuthentication` and DRF `SessionAuthentication` only; a session never
counts on a JWT-only view, and API-key headers never open an admin route — a key reaches one only through the
exchanged JWT.

`ACCESS_GATE_MODE`: `enforce` (default), `observe` (log refusals on `django_access.gate`, let everything through),
`off`. Any other value is enforced and fails the system check `E010`. The mode applies to people: an exchanged JWT is
decided and refused in every mode, since nothing else limits it to its key's scopes (in `off` the gate checks each
Bearer JWT's signature for the claim and decides only those requests).

## Application tokens

A machine client is an **Application**; it holds **tokens**. The raw value is `ent_api_` + 43 URL-safe characters,
shown once. The database keeps its SHA-256 (`key_hash`), `prefix` (12 characters) and `last_four`. At most one token
per hash and channel, one unpinned (`UniqueConstraint(key_hash, channel_idx, nulls_distinct=False)`): issued tokens
have random values, only the legacy import puts one secret on several pinned rows.

- **Scopes** (9): `checkout.storefront`, `contact_forms.submit`, `contact_forms.booking`, `agreements.subscribe`
  (publishable — they ship to browsers) and `checkout.erase`, `accounts.erase`, `returns.api`, `reviews.moderate`,
  `vault.api` (secret). One token never mixes the two groups.
- **Admin scopes**: any staff permission key `<area>:read|write` of the catalogue except `access.manage` (a machine
  never manages access). They are secret, a token holding one is never pinned to a channel, and they open nothing by
  themselves — only through the exchange below. A token may hold admin and secret key-route scopes together.
- **Lifetime**: an expiry is optional for every scope and has no maximum; a past date is refused (revoke
  instead). Every token shows its age (`age_days`) and `rotation_due` — active and at least
  `ACCESS_TOKEN_ROTATION_DAYS` (365) old. A recommendation only: nothing is refused, logged or audited for age.
- **Channel pin**: a pinned token passes only where the route's channel equals the pin; a caller that passes no
  channel (`channel_idx=None`) cannot check it, so a pinned token is refused there. A pin on an erase token
  limits the URL channel, not the erase's reach — accounts and checkout erase by e-mail across channels.
- `verify_api_key(request, scope, channel_idx=None)` reads `X-API-KEY` (alias `X-API-ADMIN-KEY`), runs one uncached
  query by hash — of the row pinned to the route's channel and the unpinned row, the first (pinned first) that holds
  the scope — and returns the token or `None` — one answer for unknown, expired, revoked, inactive application,
  wrong scope and channel mismatch. Revocation applies on the next request.
- Rotation issues a successor (no expiry unless one is given) and keeps the old token valid for an overlap
  (default 24 h).

## Integrations on admin routes

Every module's admin views authenticate a SimpleJWT and demand `is_staff`, so an integration needs a staff JWT — never
a person's password. The key buys one:

1. **Service user.** The first live admin-scoped token of an application creates its service user
   (`Application.service_user`): username `access-app-<application id>`, unusable password, never a superuser, no
   grants (the grant service refuses it), left out of the staff list. It is `is_staff` while the application is active
   and holds a live admin-scoped token; every token and application change recomputes it (a token that expires by
   time leaves the flag until the next change — the exchange and the gate check each token themselves). Applications are never
   deleted, so the row stays for the modules' `request.user` foreign keys. `django_access.E013` (a `database` check:
   `migrate`, `check --database default`) flags a service user that is a superuser, has a usable password, a group or a
   user permission.
2. **Exchange.** `POST api/access/v2/token/exchange/` with the key in `X-API-KEY` returns a SimpleJWT access token of
   the service user (no refresh token) with the claim `access_token_id`, valid `ACCESS_TOKEN_EXCHANGE_TTL_S` (300 s).
   One 401 for every refusal; throttled per key and per address; `last_used_at` as for any key use; no audit row.
3. **Gate.** On an admin route the JWT's token decides: live, its application's service user, and an admin scope that
   implies the route's permission (write implies read). Of the staff baseline a token only reads. Revoking the key
   stops its JWT on the next admin request.

Outside the admin set the gate does nothing, by design: until it expires, the JWT works on non-admin JWT routes as
the service user, a staff account without a customer profile — the reason the lifetime is short.

## Legacy keys

Six modules kept plaintext keys in seven tables of their own, agreements in a setting. django-access imports them as
tokens **with the same secret**, so every caller keeps working the day a module switches to `verify_api_key`.

| Source | Scope | Pin |
|---|---|---|
| `django_accounts.APIAdminKey` | `accounts.erase` | channel |
| `django_checkout.APIAdminKey` | `checkout.erase` | channel |
| `django_checkout.APIKey` | `checkout.storefront` | channel |
| `django_contact_forms.APIKey` | `contact_forms.submit` or `contact_forms.booking` (by `scope`) | channel |
| `django_returns.APIKey` | `returns.api` | — |
| `django_reviews.APIKey` | `reviews.moderate` | — |
| `django_vault.APIKey` | `vault.api` | — |
| `settings.AGREEMENTS_API_KEY` | `agreements.subscribe` | — |

Rules: one application per module (`Legacy keys: <app_label>`); `legacy=True`, `legacy_source` =
`<app>.<Model>#<pk>` (comma-separated for a shared secret; past 255 characters the leading whole ids and `+N more`);
a secret shared by two modules is one token under the first module's application (`operations.md`); no expiry — a
legacy key never expires by itself, and a re-run never changes an existing token. A row
without a channel authenticates nothing today, so it is skipped. A secret on several channels becomes one token per
channel, each pinned to its channel with that channel's scopes; its channel-less rows (`AGREEMENTS_API_KEY`, the
channel-less sources) get an unpinned token with only their scopes — reported `per_channel`, and no token is wider
than the key it replaces. A secret found in a publishable and a secret source is **not imported** (`mixed`) — a key that ships to
browsers never gets erase, returns, reviews or vault power. A secret under 32 characters shows no character
(`prefix "legacy"`, empty `last_four`).

Rotation is each team's policy, not a deadline: a team sets or clears an expiry per token, `access_legacy_report`
shows who still uses which key and which is `rotation due` (legacy tokens count their age from the import), and
`access_purge_legacy_keys` deletes the plaintext rows on demand (`operations.md`).

## Audit

Every access change writes one `AuditEntry` in the same transaction: `role.*`, `grant.*`, `grant.migrate`,
`staff.create`, `application.*`, `token.*`, `legacy.import`, `legacy.purge`, `gate.bypass`. Labels are copied, so a row survives its
actor and target. No row ever holds a raw token or `key_hash`.
