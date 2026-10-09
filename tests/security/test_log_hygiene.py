# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Log hygiene: every logger at DEBUG during the whole matrix (every principal × route × method × mode), Basic
credentials and a failing gate — no record's message, args or exception text holds a JWT, a cookie value, an API key
or a password."""

import base64
import logging
import secrets

import pytest
from django.test import Client, override_settings

from django_access.services import permissions
from tests.security.contract import METHODS, MODES, PRINCIPALS, ROUTES

pytestmark = [pytest.mark.django_db, pytest.mark.urls("tests.security.urls")]

_FORMATTER = logging.Formatter()


def record_texts(record: logging.LogRecord) -> list[str]:
    texts = [record.getMessage(), repr(record.args)]
    if record.exc_info:
        texts.append(_FORMATTER.formatException(record.exc_info))
    return texts + [record.exc_text or ""]


def header_secrets(headers: dict) -> list[str]:
    """The secret part of every credential header (the JWT without ``Bearer``, the raw key)."""
    return [value.split()[-1] for value in headers.values()]


def run_matrix(client_for, principal) -> list[str]:
    seen: list[str] = []
    for who in PRINCIPALS:
        headers = principal(who)
        client = client_for(who)
        seen += header_secrets(headers) + [cookie.value for cookie in client.cookies.values()]
        for mode in MODES:
            with override_settings(ACCESS_GATE_MODE=mode):
                for route in ROUTES.values():
                    for method in METHODS:
                        client.generic(method, route.path, **headers)
    return seen


def run_password_requests(user, password: str) -> list[str]:
    """Basic credentials on every route, then a password login session posting to every route."""
    basic = base64.b64encode(f"{user.username}:{password}".encode()).decode()
    login = Client()
    assert login.login(username=user.username, password=password)
    for route in ROUTES.values():
        Client().post(route.path, HTTP_AUTHORIZATION=f"Basic {basic}")
        login.post(route.path)
    return [password, basic, *(cookie.value for cookie in login.cookies.values())]


@pytest.fixture
def password_user(make_user):
    password = secrets.token_urlsafe(16)
    user = make_user(is_superuser=True)
    user.set_password(password)
    user.save()
    return user, password


@pytest.fixture
def every_logger_at_debug(caplog):
    for name in [None, *logging.root.manager.loggerDict]:
        caplog.set_level(logging.DEBUG, logger=name)
    return caplog


def test_no_record_holds_a_credential(client, principal, password_user, monkeypatch, every_logger_at_debug):
    seen = run_matrix(lambda who: client if who == "session_superuser" else Client(), principal)
    seen += run_password_requests(*password_user)
    monkeypatch.setattr(permissions, "has_permission", lambda *args: 1 / 0)  # the gate's ERROR with a traceback
    viewer = principal("viewer")
    assert Client().get(ROUTES["rw_read"].path, **viewer).status_code == 500
    seen += header_secrets(viewer)
    seen = [value for value in seen if value]  # an empty value would match every record
    records = every_logger_at_debug.records
    assert {logging.WARNING, logging.ERROR} <= {record.levelno for record in records}, "nothing to scan"
    leaked = {record.name for record in records for text in record_texts(record) for value in seen if value in text}
    assert not leaked, f"a credential in log records of {sorted(leaked)}"
