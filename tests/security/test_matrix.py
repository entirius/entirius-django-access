# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Gate matrix: principal × route class × GET/POST × mode through the full middleware chain.

Outcomes: ``ok`` the view ran (200); ``view401``/``view403`` the view refused (v2 envelope without details);
``gate401`` the gate's 401; an issue code = the gate's 403 with that issue. ``EXPECTED`` is the enforce answer; in
``observe`` and ``off`` every gate refusal becomes what the view itself answers.
"""

import base64
from datetime import timedelta

import pytest
from django.test import Client, override_settings
from rest_framework_simplejwt.settings import api_settings as jwt_settings
from rest_framework_simplejwt.tokens import AccessToken

from django_access.models import AuditEntry
from django_access.services import access_service
from django_access.services.permissions import ADMINISTRATOR, EDITOR, MANAGER, VIEWER
from tests import gate_urls as urls

pytestmark = [pytest.mark.django_db, pytest.mark.urls("tests.gate_urls")]

ROUTES = {
    "admin": urls.ADMIN,
    "export": urls.EXPORT,
    "viewer": urls.VIEWER,
    "baseline": urls.BASELINE,
    "unmapped": urls.UNMAPPED,
    "read_only": urls.READ_ONLY,
    "public": urls.PUBLIC,
}
_NOBODY = "view401 view401 | view401 view401 | gate401 gate401 | view401 view401 | view401 view401 | view401 view401"
_STAFF_ONLY = " | ".join(["STAFF_ONLY STAFF_ONLY"] * 6)
_DENIED = "ACCESS_DENIED"
_WRITER = f"ok ok | ok ok | ok ok | ok ok | UNMAPPED_ROUTE UNMAPPED_ROUTE | ok {_DENIED}"
# GET POST per route, in ROUTES order without "public" (always ok ok).
EXPECTED = {
    "anonymous": _NOBODY,
    "invalid_jwt": _NOBODY,
    "expired_jwt": _NOBODY,
    "inactive_staff": _NOBODY,
    "customer": _STAFF_ONLY,
    "staff_no_role": f"{_DENIED} {_DENIED} | {_DENIED} {_DENIED} | {_DENIED} {_DENIED} | ok ok | "
    f"UNMAPPED_ROUTE UNMAPPED_ROUTE | {_DENIED} {_DENIED}",
    "viewer": f"ok {_DENIED} | {_DENIED} {_DENIED} | ok {_DENIED} | ok ok | UNMAPPED_ROUTE UNMAPPED_ROUTE | ok {_DENIED}",
    "editor": f"ok {_DENIED} | {_DENIED} {_DENIED} | ok ok | ok ok | UNMAPPED_ROUTE UNMAPPED_ROUTE | ok {_DENIED}",
    "manager": _WRITER,
    "administrator_group": _WRITER,
    "superuser": "ok ok | ok ok | ok ok | ok ok | ok ok | ok ok",
    "superuser_not_staff": "view403 view403 | view403 view403 | ok ok | view403 view403 | view403 view403 | "
    "view403 view403",
}
CASES = [
    (who, route, method, outcome)
    for who, row in EXPECTED.items()
    for route, pair in zip([r for r in ROUTES if r != "public"], row.split(" | "), strict=True)
    for method, outcome in zip(("GET", "POST"), pair.split(), strict=True)
] + [(who, "public", method, "ok") for who in EXPECTED for method in ("GET", "POST")]


def bearer(user, **lifetime) -> dict:
    token = AccessToken.for_user(user)
    if lifetime:
        token.set_exp(lifetime=timedelta(**lifetime))
    return {"HTTP_AUTHORIZATION": f"Bearer {token}"}


@pytest.fixture
def credentials(make_user, role, group, system):
    """``credentials(name)`` → request headers of that principal."""

    def granted(role_key: str) -> dict:
        user = make_user()
        access_service.grant_role(role(role_key), user=user, actor=system)
        return bearer(user)

    def inactive() -> dict:
        user = make_user()
        headers = bearer(user)
        user.is_active = False
        user.save()
        return headers

    def via_group() -> dict:
        user = make_user()
        user.groups.add(group)
        access_service.grant_role(role(ADMINISTRATOR), group=group, actor=system)
        return bearer(user)

    builders = {
        "anonymous": dict,
        "invalid_jwt": lambda: {"HTTP_AUTHORIZATION": "Bearer not.a.token"},
        "expired_jwt": lambda: bearer(make_user(), minutes=-1),
        "inactive_staff": inactive,
        "customer": lambda: bearer(make_user(is_staff=False)),
        "staff_no_role": lambda: bearer(make_user()),
        "viewer": lambda: granted(VIEWER),
        "editor": lambda: granted(EDITOR),
        "manager": lambda: granted(MANAGER),
        "administrator_group": via_group,
        "superuser": lambda: bearer(make_user(is_superuser=True)),
        "superuser_not_staff": lambda: bearer(make_user(is_superuser=True, is_staff=False)),
    }
    return lambda name: builders[name]()


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


def view_answer(route: str, outcome: str) -> str:
    """What the view answers when the gate lets a refused request through: the pim viewer serves anyone, the DRF
    views' ``IsAdminUser`` refuses only non-staff (``STAFF_ONLY``)."""
    if outcome not in ("gate401", "STAFF_ONLY", _DENIED, "UNMAPPED_ROUTE"):
        return outcome
    return "view403" if outcome == "STAFF_ONLY" and route != "viewer" else "ok"


@pytest.mark.parametrize("mode", ["enforce", "observe", "off"])
@pytest.mark.parametrize(("who", "route", "method", "outcome"), CASES)
def test_matrix(client, credentials, who, route, method, outcome, mode):
    with override_settings(ACCESS_GATE_MODE=mode):
        response = client.generic(method, ROUTES[route], **credentials(who))
    assert_outcome(response, outcome if mode == "enforce" else view_answer(route, outcome))
    assert hasattr(response.wsgi_request, "_access_decision") is (mode != "off")


def test_inactive_user_is_refused_even_when_the_authenticator_accepts_it(client, credentials, monkeypatch):
    monkeypatch.setattr(jwt_settings, "CHECK_USER_IS_ACTIVE", False)
    assert_outcome(client.get(urls.ADMIN, **credentials("inactive_staff")), "gate401")


def test_default_auth_view_session_counts_basic_never(client, make_user, role, system):
    """A view on DRF's default Session + Basic: the session decides; Basic alone is anonymous → the gate's 401."""
    user = make_user()
    user.set_password("pw-for-test")
    user.save()
    access_service.grant_role(role(VIEWER), user=user, actor=system)
    basic = base64.b64encode(f"{user.username}:pw-for-test".encode()).decode()
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


def test_django_admin_needs_access_manage(client, make_user, role, system):
    manager = make_user()
    access_service.grant_role(role(MANAGER), user=manager, actor=system)
    client.force_login(manager)
    assert_outcome(client.get("/admin/"), _DENIED)
    assert client.get("/admin/password_change/").status_code == 200
