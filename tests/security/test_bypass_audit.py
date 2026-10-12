# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""The superuser bypass trail: one ``gate.bypass`` row per write request with the response status (the view's 4xx and
5xx too), GET/HEAD of a PII export counted as writes, reads never recorded, and an audit failure that changes nothing
but an ERROR log line."""

import logging

import pytest
from django.db import connection
from django.test import Client

from django_access.models import AuditEntry
from tests.helpers import bypass_rows
from tests.security import urls
from tests.security.contract import SAFE, WRITES

pytestmark = [pytest.mark.django_db, pytest.mark.urls("tests.security.urls")]


@pytest.fixture
def superuser(principal):
    return principal("superuser")


def test_one_row_per_write_request_with_its_status(client, superuser):
    for method in WRITES:
        assert client.generic(method, urls.RW_READ, **superuser).status_code == 200
    rows = bypass_rows()
    assert [(row["method"], row["status"], row["needed"]) for row in rows] == [
        (method, 200, "agreements.definitions:write") for method in WRITES
    ]
    assert {row["route"] for row in rows} == {urls.RW_READ[1:]}


@pytest.mark.parametrize("code", [400, 404, 409, 500, 503])
def test_the_views_error_status_is_recorded(client, superuser, code):
    path = urls.STATUS.format(code=code)
    assert client.post(path, **superuser).status_code == code
    assert [row["status"] for row in bypass_rows()] == [code]


def test_a_crashing_view_is_recorded_as_500(superuser, ran):
    response = Client(raise_request_exception=False).post(urls.FAILING, **superuser)
    assert response.status_code == 500
    assert ran == [(urls.FAILING, "POST")]
    assert [row["status"] for row in bypass_rows()] == [500]


@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_superuser_read_of_a_pii_export_is_recorded(client, superuser, method):
    assert client.generic(method, urls.EXPORT, **superuser).status_code == 200
    assert [(row["method"], row["needed"]) for row in bypass_rows()] == [(method, "agreements.consents:write")]


READS = [
    *((path, method) for path in (urls.RW_READ, urls.RW_WRITE, urls.READ_ONLY, urls.FUNCTION) for method in SAFE),
    (urls.EXPORT, "OPTIONS"),  # a GET/HEAD PII export is a write
]


@pytest.mark.parametrize(("path", "method"), READS)
def test_superuser_reads_are_not_recorded(client, superuser, path, method):
    assert client.generic(method, path, **superuser).status_code == 200
    assert bypass_rows() == []


def _reject_audit_insert(execute, sql, params, many, context):
    if sql.startswith(f"INSERT INTO {connection.ops.quote_name(AuditEntry._meta.db_table)}"):
        raise RuntimeError("audit store down")
    return execute(sql, params, many, context)


def test_failed_audit_write_keeps_the_response_and_logs_an_error(client, superuser, ran, caplog):
    with caplog.at_level(logging.ERROR, logger="django_access.gate"), connection.execute_wrapper(_reject_audit_insert):
        response = client.post(urls.RW_READ, **superuser)
    assert (response.status_code, response.json()) == (200, {"ran": True})
    assert ran == [(urls.RW_READ, "POST")]
    errors = [record for record in caplog.records if record.levelno == logging.ERROR]
    assert [record.getMessage().split(" [")[0] for record in errors] == ["Gate bypass audit failed"]  # it fired
