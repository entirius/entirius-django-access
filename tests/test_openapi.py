# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
from django.core.management import call_command
from drf_spectacular.generators import SchemaGenerator

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
    assert len([op for _, method, op in operations if method in HTTP_METHODS]) == 14
    for path, method, operation in operations:
        success = {code: answer for code, answer in operation["responses"].items() if code.startswith("2")}
        assert success, f"{method} {path}"
        for code, answer in success.items():
            assert code == "204" or answer["content"]["application/json"]["schema"], f"{method} {path} {code}"
