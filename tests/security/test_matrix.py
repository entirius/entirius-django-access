# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Gate matrix: every principal × route class × method × mode through the full middleware chain, one assertion set
per cell: status, issue, whether the recording view ran, the bypass audit row. The expected cell is the README contract
(``tests.security.contract``). Below the matrix: plan 04's targeted principal tests on ``tests.gate_urls``.
"""

import base64
import secrets

import pytest
from django.test import Client, override_settings
from rest_framework_simplejwt.settings import api_settings as jwt_settings

from django_access.models import AuditEntry
from django_access.services import access_service
from django_access.services.permissions import ADMINISTRATOR, MANAGER, VIEWER
from tests import gate_urls as urls
from tests.helpers import bearer
from tests.security.contract import (
    ACCESS_DENIED,
    CASES,
    MODES,
    PRINCIPALS,
    RAN,
    ROUTES,
    assert_answer,
    expected,
    expects_bypass_row,
)

pytestmark = [pytest.mark.django_db, pytest.mark.urls("tests.gate_urls")]
_DENIED = ACCESS_DENIED


@pytest.mark.urls("tests.security.urls")
@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(("who", "route", "method"), CASES)
def test_cell(client, principal, ran, who, route, method, mode):
    headers, target = principal(who), ROUTES[route]
    with override_settings(ACCESS_GATE_MODE=mode):
        response = client.generic(method, target.path, **headers)
    assert_answer(response, expected(PRINCIPALS[who], target, method, mode), ran, target.path, method)
    rows = [
        (row["method"], row["status"])
        for row in AuditEntry.objects.filter(action="gate.bypass").values_list("detail", flat=True)
    ]
    assert rows == (
        [(method, response.status_code)] if expects_bypass_row(PRINCIPALS[who], target, method, mode) else []
    )
    assert hasattr(response.wsgi_request, "_access_decision") is (mode != "off")


def test_oracle_sanity_readme_invariants():
    """An explicit check of the oracle itself, as literal cells: Viewer and Editor never reach a PII export; only a
    staff superuser reaches an unmapped route (without is_staff the view refuses); a token-only request is
    anonymous."""
    export, download, unmapped = ROUTES["pii_export"], ROUTES["pii_download"], ROUTES["unmapped"]
    for who in ("viewer", "editor"):
        assert expected(PRINCIPALS[who], export, "GET", "enforce") == ACCESS_DENIED, who
        assert expected(PRINCIPALS[who], download, "GET", "enforce") == ACCESS_DENIED, who
    assert expected(PRINCIPALS["superuser"], unmapped, "POST", "enforce") == RAN
    assert expected(PRINCIPALS["superuser_not_staff"], unmapped, "POST", "enforce") == "view403"
    assert expected(PRINCIPALS["manager"], unmapped, "GET", "enforce") == "UNMAPPED_ROUTE"
    assert expected(PRINCIPALS["token_every_scope"], unmapped, "GET", "enforce") == "view401"


def assert_outcome(response, outcome: str) -> None:
    if outcome == "ok":
        assert response.status_code == 200
        return
    body = response.json()
    if outcome in ("view401", "view403"):
        assert (response.status_code, body["details"]) == (int(outcome[-3:]), [])
        return
    status, issue = (401, "NOT_AUTHENTICATED") if outcome == "gate401" else (403, outcome)
    assert response.status_code == status
    assert [item["issue"] for item in body["details"]] == [issue]


def test_inactive_user_is_refused_even_when_the_authenticator_accepts_it(client, principal, monkeypatch):
    monkeypatch.setattr(jwt_settings, "CHECK_USER_IS_ACTIVE", False)
    assert_outcome(client.get(urls.ADMIN, **principal("inactive_staff")), "gate401")


def test_default_auth_view_session_counts_basic_never(client, make_user, role, system):
    """A view on DRF's default Session + Basic: the session decides; Basic alone is anonymous → the gate's 401."""
    user = make_user()
    password = secrets.token_urlsafe(16)
    user.set_password(password)
    user.save()
    access_service.grant_role(role(VIEWER), user=user, actor=system)
    basic = base64.b64encode(f"{user.username}:{password}".encode()).decode()
    assert_outcome(client.get(urls.DEFAULT_AUTH, HTTP_AUTHORIZATION=f"Basic {basic}"), "gate401")
    client.force_login(user)
    assert_outcome(client.get(urls.DEFAULT_AUTH), "ok")
    assert_outcome(client.post(urls.DEFAULT_AUTH), _DENIED)


def test_jwt_and_session_view_walks_its_authenticators_in_order(client, make_user):
    """JWT first: a valid customer token decides even with a superuser session; a rejected token ends the walk as in
    DRF (the view answers 401), the session behind it is never used."""
    client.force_login(make_user(is_superuser=True))
    assert_outcome(client.get(urls.JWT_SESSION, **bearer(make_user(is_staff=False))), "STAFF_ONLY")
    assert_outcome(client.post(urls.JWT_SESSION, HTTP_AUTHORIZATION="Bearer not.a.token"), "view401")
    assert_outcome(client.get(urls.JWT_SESSION), "ok")


def test_session_without_csrf_is_anonymous_on_a_drf_view(make_user):
    """A cross-site POST riding a superuser session: the view refuses on CSRF and no bypass row is written."""
    csrf_client = Client(enforce_csrf_checks=True)
    csrf_client.force_login(make_user(is_superuser=True))
    response = csrf_client.post(urls.JWT_SESSION)
    assert response.status_code == 403 and response.json()["details"] == []
    assert not AuditEntry.objects.filter(action="gate.bypass").exists()


def test_session_never_counts_on_a_jwt_only_view(client, make_user):
    client.force_login(make_user(is_superuser=True))
    assert_outcome(client.post(urls.ADMIN), "view401")
    assert not AuditEntry.objects.filter(action="gate.bypass").exists()


def test_session_counts_on_a_non_drf_view(client, make_user):
    client.force_login(make_user(is_staff=False))
    assert_outcome(client.get(urls.VIEWER), "STAFF_ONLY")


@pytest.mark.parametrize("header", ["HTTP_X_API_KEY", "HTTP_X_API_ADMIN_KEY"])
def test_token_never_opens_an_admin_route(client, issue, header):
    _, raw = issue()
    assert_outcome(client.get(urls.ADMIN, **{header: raw}), "view401")
    assert_outcome(client.get(urls.VIEWER, **{header: raw}), "gate401")


def test_key_route_with_a_token_is_untouched(client, django_assert_num_queries):
    with django_assert_num_queries(0):
        response = client.post(urls.KEY, HTTP_X_API_KEY="ent_api_whatever")
    assert response.status_code == 200
    assert not hasattr(response.wsgi_request, "_access_principal")


def test_django_admin_anonymous_gets_the_login_redirect(client):
    assert client.get("/admin/").status_code == 302


@pytest.fixture
def role_holder(make_user, role, system):
    def make(role_key: str):
        user = make_user()
        access_service.grant_role(role(role_key), user=user, actor=system)
        return user

    return make


@pytest.mark.parametrize("path", ["/admin/", "/admin/django_access/role/"])
@pytest.mark.parametrize("role_key", [ADMINISTRATOR, MANAGER, VIEWER])
def test_django_admin_is_superuser_only(client, role_holder, role_key, path):
    """D32: no role opens the Django admin site, the Administrator's included."""
    client.force_login(role_holder(role_key))
    response = client.get(path)
    assert_outcome(response, _DENIED)
    assert response.json()["details"][0]["description"] == "superuser only"


def test_an_administrator_keeps_the_django_admin_login_pages(client, role_holder):
    administrator = role_holder(ADMINISTRATOR)
    assert client.get("/admin/login/", **bearer(administrator)).status_code == 200
    client.force_login(administrator)
    assert client.get("/admin/password_change/").status_code == 200
    assert client.post("/admin/logout/").status_code == 200


def test_a_superuser_passes_the_django_admin_and_writes_are_audited(client, make_user):
    client.force_login(make_user(is_superuser=True))
    assert client.get("/admin/django_access/role/").status_code == 200
    client.post("/admin/django_access/role/", {})
    [row] = AuditEntry.objects.filter(action="gate.bypass")
    assert row.detail["needed"] == "superuser.only"
