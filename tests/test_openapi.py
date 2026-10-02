# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
import pytest
from django.core.management import call_command
from drf_spectacular.generators import SchemaGenerator
from drf_spectacular.settings import SPECTACULAR_DEFAULTS, patched_settings
from drf_spectacular.validation import validate_schema

from django_access.openapi import add_api_key_security

HTTP_METHODS = {"get", "post", "put", "patch", "delete"}


def test_openapi_schema_validates(tmp_path):
    call_command(
        "spectacular",
        "--urlconf",
        "django_access.urls",
        "--validate",
        "--fail-on-warn",
        "--file",
        str(tmp_path / "schema.yaml"),
    )


def test_every_operation_has_a_response_schema():
    schema = SchemaGenerator(urlconf="django_access.urls").get_schema(request=None, public=True)
    operations = [(path, method, op) for path, item in schema["paths"].items() for method, op in item.items()]
    assert len([op for _, method, op in operations if method in HTTP_METHODS]) == 22
    for path, method, operation in operations:
        success = {code: answer for code, answer in operation["responses"].items() if code.startswith("2")}
        assert success, f"{method} {path}"
        for code, answer in success.items():
            assert code == "204" or answer["content"]["application/json"]["schema"], f"{method} {path} {code}"


@pytest.fixture
def key_schema():
    """The fake key routes' document generated with the hook wired after drf-spectacular's default hooks."""
    hooks = [*SPECTACULAR_DEFAULTS["POSTPROCESSING_HOOKS"], "django_access.openapi.add_api_key_security"]
    with patched_settings({"POSTPROCESSING_HOOKS": hooks}):
        return SchemaGenerator(urlconf="tests.key_urls").get_schema(request=None, public=True)


def security(schema: dict, path: str) -> list[dict]:
    return schema["paths"][path]["get"].get("security")


def test_hook_adds_the_api_key_scheme(key_schema):
    assert key_schema["components"]["securitySchemes"]["ApiKeyAuth"] == {
        "type": "apiKey",
        "in": "header",
        "name": "X-API-KEY",
    }
    validate_schema(key_schema)


@pytest.mark.parametrize(
    ("path", "requirements"),
    [
        ("/api/checkout/v2/{channel_idx}/carts/{cart_id}/", [{"ApiKeyAuth": [], "jwtAuth": []}, {"ApiKeyAuth": []}]),
        ("/api/vault/v1/{channel_idx}/payment_card/", [{"ApiKeyAuth": [], "jwtAuth": []}]),
        ("/api/contact-forms/v2/{channel_idx}/form-types/", [{"ApiKeyAuth": []}]),
        ("/api-admin/accounts/v1/{channel_idx}/customer/delete", [{"ApiKeyAuth": []}]),
        ("/api/contact-forms/v2/{channel_idx}/bookings", [{"ApiKeyAuth": []}]),
        ("/api/checkout/v2/{channel_idx}/products/", [{"jwtAuth": []}]),
        ("/api/checkout/v2/{channel_idx}/cartsx/", [{"jwtAuth": []}]),
    ],
)
def test_hook_requires_the_key_on_key_routes_only(key_schema, path, requirements):
    assert security(key_schema, path) == requirements


def test_hook_keeps_the_documents_jwt_scheme_name():
    result = {
        "paths": {"/api/vault/v1/{channel_idx}/payment_card/": {"get": {"responses": {}, "security": [{"b": []}]}}}
    }
    add_api_key_security(result, generator=None, request=None, public=True)
    assert result["paths"]["/api/vault/v1/{channel_idx}/payment_card/"]["get"]["security"] == [
        {"ApiKeyAuth": [], "b": []}
    ]


def test_access_admin_routes_get_no_api_key():
    schema = SchemaGenerator(urlconf="django_access.urls").get_schema(request=None, public=True)
    add_api_key_security(schema, generator=None, request=None, public=True)
    requirements = [req for item in schema["paths"].values() for op in item.values() for req in op.get("security", [])]
    assert requirements and all("ApiKeyAuth" not in requirement for requirement in requirements)
