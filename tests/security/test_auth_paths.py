# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Authenticators the gate does not run: HTTP Basic, a ``JWTAuthentication`` subclass, a session on a JWT-only view.

Credentials the gate cannot see never reach an admin view undecided: the gate answers 401 itself.
"""

import base64
import secrets

import pytest
from django.test import Client

from tests.helpers import bearer, bypass_rows
from tests.security import urls
from tests.security.contract import GATE401, VIEW401, assert_answer

pytestmark = [pytest.mark.django_db, pytest.mark.urls("tests.security.urls")]


@pytest.fixture
def basic_superuser(make_user) -> dict:
    password = secrets.token_urlsafe(16)
    user = make_user(is_superuser=True)
    user.set_password(password)
    user.save()
    credentials = base64.b64encode(f"{user.username}:{password}".encode()).decode()
    return {"HTTP_AUTHORIZATION": f"Basic {credentials}"}


@pytest.mark.parametrize("path", [urls.BASIC_JWT, urls.DEFAULT_AUTH])
@pytest.mark.parametrize("method", ["GET", "POST", "DELETE"])
def test_basic_credentials_of_a_superuser_get_the_gate_401(client, basic_superuser, ran, path, method):
    response = client.generic(method, path, **basic_superuser)
    assert_answer(response, GATE401, ran, path, method)
    assert bypass_rows() == []


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_jwt_subclass_view_is_not_self_auth(client, make_user, ran, method):
    """The gate never runs a subclass: anonymous callers and even a valid superuser token get the gate's 401."""
    assert_answer(client.generic(method, urls.SUBCLASS_JWT), GATE401, ran, urls.SUBCLASS_JWT, method)
    superuser = bearer(make_user(is_superuser=True))
    assert_answer(client.generic(method, urls.SUBCLASS_JWT, **superuser), GATE401, ran, urls.SUBCLASS_JWT, method)


@pytest.mark.parametrize("path", [urls.RW_READ, urls.EXPORT, urls.UNMAPPED])
def test_cross_site_session_superuser_on_a_jwt_only_view(make_user, ran, path):
    """Cookie only, no CSRF token: anonymous to the gate, the view's 401, no forged bypass row."""
    cross_site = Client(enforce_csrf_checks=True)
    cross_site.force_login(make_user(is_superuser=True))
    assert_answer(cross_site.post(path), VIEW401, ran, path, "POST")
    assert bypass_rows() == []
