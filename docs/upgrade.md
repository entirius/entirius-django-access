---
title: Upgrade
description: Before the first deploy of django-access into a running installation — the preflight, observe first, legacy keys.
---

Run this on the release candidate, against the production settings, before traffic reaches it. Install-time wiring
is in `install.md`.

## Preflight

```bash
manage.py access_routes --unmapped                  # admin routes without an area: route, owner, methods; exit 1
manage.py access_import_legacy_keys --check         # after migrate: every legacy key present as a token; exit 1
manage.py check --deploy --fail-level ERROR         # E011: the gate enforces over unmapped admin routes
manage.py access_legacy_report                      # after the upgrade: plaintext keys stay until the purge (D28)
```

An unmapped admin route answers 403 `UNMAPPED_ROUTE` to everyone but superusers once the gate enforces. `E011` stops
that deploy; it is silent in `observe` and `off`.

Fix an unmapped route where it lives: `access_area` on the view or a rule in the module's `AppConfig`
(`module-authors.md`). A route of a module the access defaults do not know is always unmapped until then.

## Installations with their own Django apps

The access defaults cover the Entirius modules only. An installation that runs its own apps deploys the first time
in observe:

1. `ACCESS_GATE_MODE = "observe"` in the settings; deploy.
2. Read the `django_access.gate` log (every refusal the gate would have answered) and `access_routes --unmapped`.
3. Map what is missing, grant the roles the log shows people need.
4. Switch to `enforce` once both are clean: no unmapped route, no refusal you did not expect.

`observe` with `DEBUG=False` warns `W010` on purpose — it is a migration state, not a configuration.

## Legacy keys

The import keeps every legacy key working, and it never expires by itself. Nothing breaks on a date: callers move to
issued tokens on each team's schedule. `access_legacy_report` shows who still uses which key and when it was last
used; a team may set an expiry per token (`operations.md`). The plaintext rows stay in the module tables until
someone runs `access_purge_legacy_keys --yes`.

## Rollback

`ACCESS_GATE_MODE = "off"` (or `observe`) and a restart undo the gate. The rest is in `install.md` § Rollback.
