# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Gate: exact refusal bodies, the superuser bypass audit row, modes and the kill switch, fail-closed exceptions,
system checks E010/W010 and the query cost of a staff request."""

import logging
import re

import pytest
from django.db import connection
from django.test import override_settings
from django.test.utils import CaptureQueriesContext

from django_access.checks import gate_mode_is_valid
from django_access.models import AuditEntry
from django_access.services import access_service, gate
from django_access.services.permissions import VIEWER
from tests import gate_urls as urls
from tests.security.test_matrix import bearer

pytestmark = [pytest.mark.django_db, pytest.mark.urls("tests.gate_urls")]

DEBUG_ID = re.compile(r"^[0-9a-f]{8}$")


@pytest.fixture
def viewer(make_user, role, system):
    user = make_user()
    access_service.grant_role(role(VIEWER), user=user, actor=system)
    return bearer(user)


@pytest.fixture
def superuser(make_user):
    return bearer(make_user(is_superuser=True))


def body_without_debug_id(response) -> dict:
    body = response.json()
    assert DEBUG_ID.match(body.pop("debug_id"))
    return body


def test_gate_401_body_and_header(client):
    response = client.get(urls.VIEWER)
    assert response.status_code == 401
    assert response["WWW-Authenticate"] == 'Bearer realm="api"'
    assert body_without_debug_id(response) == {
        "error": "AUTHENTICATION_REQUIRED",
        "message": "Authentication credentials were not provided or are invalid.",
        "details": [
            {
                "field": None,
                "location": "header",
                "issue": "NOT_AUTHENTICATED",
                "description": "Authentication credentials were not provided or are invalid.",
            }
        ],
    }


@pytest.mark.parametrize(
    ("path", "who", "issue", "description"),
    [
        (urls.ADMIN, "viewer", "ACCESS_DENIED", "needs agreements.definitions:write"),
        (urls.READ_ONLY, "viewer", "ACCESS_DENIED", "needs lookup.search:write"),
        (urls.UNMAPPED, "viewer", "UNMAPPED_ROUTE", "This admin route has no access area."),
        (urls.ADMIN, "customer", "STAFF_ONLY", "A staff account is required."),
    ],
)
def test_gate_403_bodies(client, make_user, viewer, path, who, issue, description):
    headers = viewer if who == "viewer" else bearer(make_user(is_staff=False))
    response = client.post(path, **headers)
    assert response.status_code == 403
    assert "WWW-Authenticate" not in response
    assert body_without_debug_id(response) == {
        "error": "PERMISSION_DENIED",
        "message": "You do not have permission to perform this action.",
        "details": [{"field": None, "location": "path", "issue": issue, "description": description}],
    }


def test_unmapped_route_is_logged_at_error(client, viewer, caplog):
    with caplog.at_level(logging.ERROR, logger="django_access.gate"):
        client.get(urls.UNMAPPED, **viewer)
    assert "api/mystery/v2/admin/things/" in caplog.text


@pytest.mark.parametrize(
    ("method", "path", "needed"),
    [("POST", urls.ADMIN, "agreements.definitions:write"), ("GET", urls.EXPORT, "agreements.consents:write")],
)
def test_superuser_write_leaves_one_bypass_row_with_status(client, superuser, method, path, needed):
    assert client.generic(method, path, **superuser).status_code == 200
    [row] = AuditEntry.objects.filter(action="gate.bypass")
    assert row.actor is not None and row.target_label == path[1:]
    assert row.detail == {"method": method, "route": path[1:], "needed": needed, "status": 200}


def test_superuser_read_leaves_no_row(client, superuser):
    client.get(urls.ADMIN, **superuser)
    client.get(urls.BASELINE, **superuser)
    assert not AuditEntry.objects.filter(action="gate.bypass").exists()


def test_bypass_row_records_the_view_refusal(client, make_user):
    response = client.post(urls.ADMIN, **bearer(make_user(is_superuser=True, is_staff=False)))
    assert response.status_code == 403
    assert AuditEntry.objects.get(action="gate.bypass").detail["status"] == 403


def test_bypass_audit_failure_keeps_the_response(client, superuser, monkeypatch, caplog):
    def broken(*args, **kwargs):
        raise RuntimeError("audit down")

    monkeypatch.setattr(gate, "record_bypass", broken)
    with caplog.at_level(logging.ERROR, logger="django_access.gate"):
        assert client.post(urls.ADMIN, **superuser).status_code == 200
    assert "Gate bypass audit failed" in caplog.text


@override_settings(ACCESS_GATE_MODE="observe")
def test_observe_logs_refusals_and_lets_them_through(client, make_user, caplog):
    customer = make_user(is_staff=False)
    with caplog.at_level(logging.WARNING, logger="django_access.gate"):
        assert client.post(urls.ADMIN, **bearer(customer), QUERY_STRING="secret=1").status_code == 403
        assert client.post(urls.VIEWER).status_code == 200
    assert f"user={customer.pk} method=POST route=api/agreements/v2/admin/definitions/" in caplog.text
    assert "issue=STAFF_ONLY" in caplog.text and "issue=NOT_AUTHENTICATED" in caplog.text
    assert "secret" not in caplog.text and "Bearer" not in caplog.text


@override_settings(ACCESS_GATE_MODE="observe")
def test_observe_still_audits_superuser_writes(client, superuser):
    client.post(urls.ADMIN, **superuser)
    assert AuditEntry.objects.filter(action="gate.bypass").count() == 1


@override_settings(ACCESS_GATE_MODE="off")
def test_off_does_no_work(client, superuser):
    response = client.post(urls.VIEWER, **superuser)
    assert response.status_code == 200
    assert not hasattr(response.wsgi_request, "_access_decision")
    assert not AuditEntry.objects.filter(action="gate.bypass").exists()


@override_settings(ACCESS_GATE_MODE="of")
def test_invalid_mode_is_enforced_and_logged_once(client, monkeypatch, caplog):
    monkeypatch.setattr(gate, "_reported_modes", set())
    with caplog.at_level(logging.ERROR, logger="django_access.gate"):
        assert client.get(urls.VIEWER).status_code == 401
        assert client.get(urls.VIEWER).status_code == 401
    assert caplog.text.count("Invalid ACCESS_GATE_MODE 'of'") == 1


def _raise(*args, **kwargs):
    raise RuntimeError("database gone")


def test_exception_in_enforce_fails_closed(client, viewer, monkeypatch, caplog):
    monkeypatch.setattr(gate.permissions, "has_permission", _raise)
    with caplog.at_level(logging.ERROR, logger="django_access.gate"):
        response = client.get(urls.ADMIN, **viewer)
    assert response.status_code == 500
    assert f"[{response.json()['debug_id']}]" in caplog.text
    body = body_without_debug_id(response)
    assert body == {"error": "INTERNAL_ERROR", "message": "An internal error occurred.", "details": []}
    assert "ran" not in response.content.decode()


@override_settings(ACCESS_GATE_MODE="observe")
def test_exception_in_observe_passes(client, viewer, monkeypatch):
    monkeypatch.setattr(gate.permissions, "has_permission", _raise)
    assert client.get(urls.ADMIN, **viewer).json() == {"ran": True}


def test_unknown_path_stays_404(client, superuser):
    assert client.get("/api/agreements/v2/admin/nope/", **superuser).status_code == 404


def test_public_route_costs_no_query_and_no_authentication(client, django_assert_num_queries):
    with django_assert_num_queries(0):
        response = client.get(urls.PUBLIC, HTTP_AUTHORIZATION="Bearer not.a.token")
    assert response.status_code == 200
    assert not hasattr(response.wsgi_request, "_access_principal")


# Measured: the gate loads the JWT user (1), the view authenticates again (1); permissions come from the warm cache.
STAFF_GET_QUERIES = 2


def test_staff_get_with_a_warm_cache(client, viewer):
    assert client.get(urls.ADMIN, **viewer).status_code == 200
    with CaptureQueriesContext(connection) as queries:
        assert client.get(urls.ADMIN, **viewer).status_code == 200
    assert len(queries) == STAFF_GET_QUERIES


@pytest.mark.parametrize(
    ("mode", "debug", "ids"),
    [
        ("enforce", False, []),
        ("observe", True, []),
        ("observe", False, ["django_access.W010"]),
        ("off", False, ["django_access.W010"]),
        ("enforced", True, ["django_access.E010"]),
        (["enforce"], True, ["django_access.E010"]),
    ],
)
def test_mode_checks(mode, debug, ids):
    with override_settings(ACCESS_GATE_MODE=mode, DEBUG=debug):
        assert [message.id for message in gate_mode_is_valid()] == ids
