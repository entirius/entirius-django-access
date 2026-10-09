# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""No leakage: an unhandled exception in a view is the v2 500 envelope with a ``debug_id`` and no exception text."""

import re

import pytest

from django_access.services import access_service, directory

pytestmark = pytest.mark.django_db

URL = "/api/access/v2/admin/"
SECRET_TEXT = "relation django_access_role at /srv/app/db.py"


def explode(*args, **kwargs):
    raise RuntimeError(SECRET_TEXT)


@pytest.mark.parametrize(
    ("target", "method", "path", "body"),
    [
        ((directory, "roles"), "get", URL + "roles/", None),
        ((access_service, "create_role"), "post", URL + "roles/", {"key": "boom", "name": "Boom"}),
        ((directory, "catalogue"), "get", URL + "catalogue/", None),
        ((directory, "me"), "get", "/api/access/v2/me/", None),
    ],
)
def test_unhandled_error_is_the_v2_500_envelope(admin_api, monkeypatch, target, method, path, body):
    monkeypatch.setattr(*target, explode)
    response = getattr(admin_api, method)(path, body, format="json")
    assert response.status_code == 500
    payload = response.json()
    assert payload["error"] == "INTERNAL_ERROR" and payload["details"] == []
    assert re.fullmatch(r"[0-9a-f]{8}", payload["debug_id"])
    assert "RuntimeError" not in response.content.decode() and "django_access_role" not in response.content.decode()
