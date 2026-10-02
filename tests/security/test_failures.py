# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Fail-closed: the permission check, the cache and the user query each fail. ``enforce`` answers the v2 500 envelope
(view not run, no exception text); ``observe`` lets the request through and logs at ERROR; a non-admin request never
notices — the gate does no work there."""

import logging
import re

import pytest
from django.contrib.auth import get_user_model
from django.core.cache.backends.locmem import LocMemCache
from django.db import DatabaseError, connection
from django.test import override_settings

from django_access.services import permissions
from tests.security import urls

pytestmark = [pytest.mark.django_db, pytest.mark.urls("tests.security.urls")]

FAILURE_TEXT = "boom-internal-detail"


class FailUserQuery:
    """``connection.execute_wrapper``: the first ``times`` reads of the user table raise before reaching the database
    (so a Postgres test transaction is not aborted)."""

    def __init__(self, times: int) -> None:
        self.left = times
        self.fragment = f"FROM {connection.ops.quote_name(get_user_model()._meta.db_table)}"

    def __call__(self, execute, sql, params, many, context):
        if self.left and self.fragment in sql:
            self.left -= 1
            raise DatabaseError(FAILURE_TEXT)
        return execute(sql, params, many, context)


def _raise_connection_error(*args, **kwargs):
    raise ConnectionError(FAILURE_TEXT)


def _raise_runtime_error(*args, **kwargs):
    raise RuntimeError(FAILURE_TEXT)


@pytest.fixture
def viewer(principal):
    return principal("viewer")


@pytest.fixture(params=["has_permission", "cache", "user_query"])
def failure(request, monkeypatch):
    """Breaks one dependency; the user query is broken per request in ``request_under``."""
    if request.param == "has_permission":
        monkeypatch.setattr(permissions, "has_permission", _raise_runtime_error)
    elif request.param == "cache":
        monkeypatch.setattr(LocMemCache, "get", _raise_connection_error)
    return request.param


def request_under(client, failure: str, path: str, headers: dict, times: int = 1_000):
    if failure != "user_query":
        return client.get(path, **headers)
    with connection.execute_wrapper(FailUserQuery(times)):
        return client.get(path, **headers)


def test_enforce_fails_closed(client, viewer, failure, ran, caplog):
    with caplog.at_level(logging.ERROR, logger="django_access.gate"):
        response = request_under(client, failure, urls.RW_READ, viewer)
    assert response.status_code == 500
    body = response.json()
    assert (body["error"], body["details"]) == ("INTERNAL_ERROR", [])
    assert re.fullmatch(r"[0-9a-f]{8}", body["debug_id"])
    assert FAILURE_TEXT not in response.content.decode()
    assert body["message"] == "An internal error occurred."
    assert ran == []
    assert f"[{body['debug_id']}]" in caplog.text


@override_settings(ACCESS_GATE_MODE="observe")
def test_observe_passes_and_logs_an_error(client, viewer, failure, ran, caplog):
    with caplog.at_level(logging.ERROR, logger="django_access.gate"):
        response = request_under(client, failure, urls.RW_READ, viewer, times=1)  # the view's own read succeeds
    assert response.status_code == 200
    assert ran == [(urls.RW_READ, "GET")]
    assert [record.levelno for record in caplog.records if record.name == "django_access.gate"] == [logging.ERROR]


@pytest.fixture
def customer(principal):
    return principal("customer")


@pytest.mark.parametrize("path", [urls.PUBLIC, urls.KEY])
def test_non_admin_request_is_unaffected(client, customer, failure, ran, path):
    assert request_under(client, failure, path, customer).status_code == 200
    assert ran == [(path, "GET")]
