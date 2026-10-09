# entirius-django-access

A Django module for staff access in Entirius, the open-source modular ecommerce platform: roles per module area, an
admin API gate, and application tokens. It replaces the per-module API keys with hashed, scoped tokens and records
every access change in an audit log.

[![PyPI](https://img.shields.io/pypi/v/entirius-django-access.svg)](https://pypi.org/project/entirius-django-access/)
[![Python](https://img.shields.io/pypi/pyversions/entirius-django-access.svg)](https://pypi.org/project/entirius-django-access/)
[![License: MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](https://github.com/entirius/entirius-django-access/blob/develop/LICENSE)

## What it does

- Grants staff roles per module area: the built-in Administrator, Manager, Editor and Viewer, plus custom roles.
- Gates every admin API route by role, with the modes `enforce`, `observe` and `off` (`ACCESS_GATE_MODE`).
- Issues hashed application tokens with scopes, channel pinning, expiry and rotation.
- Imports the modules' legacy API keys as tokens, so existing callers keep working.
- Writes an audit log of every role, grant and token change.
- Guards the service's password login against repeated failed attempts.

Token scopes: `checkout.storefront`, `checkout.erase`, `accounts.erase`, `contact_forms.submit`,
`contact_forms.booking`, `returns.api`, `reviews.moderate`, `vault.api`, `agreements.subscribe`.

## Installation

```shell
uv add entirius-django-access
pip install entirius-django-access
```

```python
INSTALLED_APPS = [
    ...
    "rest_framework",
    "rest_framework_simplejwt",
    "drf_spectacular",
    "django_access",
]

MIDDLEWARE = [
    ...  # SessionMiddleware, AuthenticationMiddleware
    "django_access.middleware.AccessGateMiddleware",  # after authentication
]

SPECTACULAR_SETTINGS = {
    ...
    "POSTPROCESSING_HOOKS": [
        "drf_spectacular.hooks.postprocess_schema_enums",
        "django_access.openapi.add_api_key_security",
    ],
}

# urls.py
urlpatterns = [
    path("", include("django_access.urls")),
]
```

The Entirius backend service (Volkanos) wires all of this itself when the package is installed.

Settings: `ACCESS_GATE_MODE` (default `enforce`) and `ACCESS_TOKEN_ROTATION_DAYS`, next to the failed-login limits;
the reference with defaults, the prerequisites and the deploy order are in
https://github.com/entirius/entirius-django-access/blob/develop/docs/install.md.

## Quick start

Issue a token for an application; the raw value is printed once:

```shell
python manage.py access_token create --application storefront --create-application \
    --scope checkout.storefront --channel <idx>
```

A module that protects a route with a key checks the request against a scope:

```python
from django_access.services.tokens import verify_api_key

token = verify_api_key(request, "checkout.storefront", channel_idx)  # the token, or None
```

## Requirements

- Python 3.11 or newer, Django 5.1 or newer.
- Django REST Framework, SimpleJWT, drf-spectacular and Pydantic 2.
- A shared cache (Redis) in production.
- PostgreSQL 15 or newer for the one-token-per-hash-and-channel constraint.
- Entirius packages pulled in: `entirius-django-utils`.

## Documentation

- Module docs: https://github.com/entirius/entirius-django-access/tree/develop/docs
- Entirius documentation: https://docs.entirius.com/
- Changelog: https://github.com/entirius/entirius-django-access/blob/develop/CHANGELOG.md

## Part of Entirius

This module runs inside the Entirius backend service (Volkanos) and verifies the keys of the modules next to it.

- Backend service: https://github.com/entirius/entirius-service-volkanos
- Docker harness: https://github.com/entirius/entirius-zeno
- Sibling modules: https://github.com/entirius/entirius-django-checkout,
  https://github.com/entirius/entirius-django-accounts, https://github.com/entirius/entirius-django-contact-forms

## Development

```shell
make install     # sync dependencies (uv)
make check       # lint + format check (ruff)
make test        # test suite (pytest + pytest-django)
```

Development and agent instructions: https://github.com/entirius/entirius-django-access/blob/develop/AGENTS.md

## License

Mozilla Public License 2.0 (MPL-2.0) — see https://github.com/entirius/entirius-django-access/blob/develop/LICENSE.
