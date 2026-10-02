# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Admin API v2: the auth matrix of every endpoint, role CRUD with built-in refusals, grants with the lockout guard,
the staff directory, groups and the audit filters."""

from datetime import timedelta

import pytest
from django.test import override_settings
from django.utils import timezone

from django_access.models import AuditAction, AuditEntry, Grant, Role
from django_access.services import access_service
from django_access.services.access_service import RoleInput
from django_access.services.permissions import ADMINISTRATOR, VIEWER

pytestmark = pytest.mark.django_db

URL = "/api/access/v2/admin/"
OK = {"get": 200, "post": 201, "patch": 200, "delete": 204}
MANAGE_ENDPOINTS = [
    ("get", "roles/", None),
    ("post", "roles/", {"key": "warehouse", "name": "Warehouse", "permissions": ["qms.stock:write"]}),
    ("get", "roles/{role}/", None),
    ("patch", "roles/{role}/", {"name": "Renamed"}),
    ("delete", "roles/{role}/", None),
    ("get", "grants/", None),
    ("post", "grants/", {"role": VIEWER, "user_id": "{staff}"}),
    ("delete", "grants/{grant}/", None),
    ("get", "staff/", None),
    ("get", "staff/{staff}/", None),
    ("get", "groups/", None),
    ("get", "audit/", None),
]
REFUSED = {"anonymous": 401, "customer": 403, "staff": 403, "viewer": 403, "manager": 403}


@pytest.fixture
def targets(make_user, system):
    """A custom role granted to a staff user — the ids the matrix URLs and bodies point at."""
    staff = make_user()
    custom = access_service.create_role(RoleInput("stock", "Stock", permissions=["qms.stock:read"]), system)
    grant = access_service.grant_role(custom, user=staff, actor=system)
    return {"role": custom.pk, "staff": staff.pk, "grant": grant.pk}


def call(client, method: str, path: str, body: dict | None, ids: dict):
    url = URL + path.format(**ids)
    if body is not None:
        body = {key: int(value.format(**ids)) if value == "{staff}" else value for key, value in body.items()}
    return getattr(client, method)(url, body, format="json")


def client_of(name: str, person, api_as):
    return api_as(None if name == "anonymous" else person(name))


@pytest.mark.parametrize(("method", "path", "body"), MANAGE_ENDPOINTS)
@pytest.mark.parametrize("name", [*REFUSED, "administrator", "superuser"])
def test_auth_matrix(name, method, path, body, targets, person, api_as):
    response = call(client_of(name, person, api_as), method, path, body, targets)
    assert response.status_code == REFUSED.get(name, OK[method]), response.content


@pytest.mark.parametrize("name", ["anonymous", "customer", "staff", "viewer", "manager", "administrator", "superuser"])
def test_catalogue_is_the_staff_baseline(name, person, api_as):
    expected = {"anonymous": 401, "customer": 403}.get(name, 200)
    assert client_of(name, person, api_as).get(URL + "catalogue/").status_code == expected


@override_settings(ACCESS_GATE_MODE="off")
@pytest.mark.parametrize(("method", "path", "body"), MANAGE_ENDPOINTS)
@pytest.mark.parametrize("name", ["customer", "viewer", "manager"])
def test_views_refuse_without_the_gate(name, method, path, body, targets, person, api_as):
    response = call(client_of(name, person, api_as), method, path, body, targets)
    assert response.status_code == 403
    assert response.json()["error"] == "PERMISSION_DENIED"


def test_catalogue_groups_areas_by_module_and_computes_builtin_roles(admin_api):
    body = admin_api.get(URL + "catalogue/").json()
    modules = {item["module"]: item["areas"] for item in body["modules"]}
    assert [area["key"] for area in modules["django_pim"]][:2] == ["pim.products", "pim.categories"]
    assert {role["key"] for role in body["roles"]} == {"administrator", "manager", "editor", "viewer"}
    viewer = next(role for role in body["roles"] if role["key"] == VIEWER)
    assert viewer["permissions"]["pim.products"] == "read" and "access.manage" not in viewer["permissions"]


def test_role_list_counts_grants(admin_api, targets):
    body = admin_api.get(URL + "roles/").json()
    rows = {row["key"]: row for row in body["results"]}
    assert body["count"] == 5 and rows["stock"]["grant_count"] == 1 and rows["stock"]["builtin"] is False
    assert rows[ADMINISTRATOR]["builtin"] is True and rows[ADMINISTRATOR]["grant_count"] == 1


def test_create_role_returns_its_permissions_and_audits(admin_api):
    body = {"key": "warehouse", "name": "Warehouse", "permissions": ["qms.stock:write", "pim.products:read"]}
    response = admin_api.post(URL + "roles/", body, format="json")
    assert response.status_code == 201
    created = response.json()
    assert created["permissions"] == {"pim.products": "read", "qms.stock": "write"} and created["grant_count"] == 0
    entry = AuditEntry.objects.get(action=AuditAction.ROLE_CREATE)
    assert entry.target_id == str(created["id"]) and entry.ip == "127.0.0.1"


def test_create_role_with_unknown_permission_is_400(admin_api):
    response = admin_api.post(
        URL + "roles/", {"key": "x1", "name": "X", "permissions": ["no.such:read"]}, format="json"
    )
    assert response.status_code == 400 and response.json()["error"] == "VALIDATION_ERROR"
    assert not Role.objects.filter(key="x1").exists()


def test_create_role_with_a_taken_key_is_409(admin_api, targets):
    response = admin_api.post(URL + "roles/", {"key": "stock", "name": "Again"}, format="json")
    assert response.status_code == 409 and response.json()["error"] == "CONFLICT"


def test_builtin_role_detail_lists_its_computed_permissions(admin_api, role):
    body = admin_api.get(f"{URL}roles/{role(ADMINISTRATOR).pk}/").json()
    assert body["builtin"] is True and body["permissions"]["access.manage"] == "write"


@pytest.mark.parametrize(("method", "body"), [("patch", {"name": "Boss"}), ("delete", None)])
def test_builtin_roles_never_change(admin_api, role, method, body):
    response = getattr(admin_api, method)(f"{URL}roles/{role(VIEWER).pk}/", body, format="json")
    assert response.status_code == 409 and response.json()["error"] == "CONFLICT"
    assert role(VIEWER).name == "Viewer"


def test_patch_replaces_the_permission_set(admin_api, targets):
    url = f"{URL}roles/{targets['role']}/"
    response = admin_api.patch(url, {"permissions": ["faq.faq:write"], "description": "FAQ"}, format="json")
    assert response.status_code == 200
    assert response.json()["permissions"] == {"faq.faq": "write"} and response.json()["description"] == "FAQ"


@pytest.mark.parametrize("body", [{}, {"name": None}, {"permissions": None}, {"name": ""}])
def test_patch_without_a_value_is_400(admin_api, targets, body):
    assert admin_api.patch(f"{URL}roles/{targets['role']}/", body, format="json").status_code == 400


def test_delete_role_takes_its_grants(admin_api, targets):
    assert admin_api.delete(f"{URL}roles/{targets['role']}/").status_code == 204
    assert not Grant.objects.filter(pk=targets["grant"]).exists()


def test_unknown_role_is_404(admin_api):
    assert admin_api.get(f"{URL}roles/999999/").status_code == 404
    assert admin_api.delete(f"{URL}grants/999999/").status_code == 404


def test_grant_list_filters(admin_api, targets, group, role, system):
    access_service.grant_role(role(VIEWER), group=group, actor=system)
    assert admin_api.get(URL + "grants/").json()["count"] == 3
    assert [row["role"]["key"] for row in admin_api.get(URL + "grants/?role=stock").json()["results"]] == ["stock"]
    by_user = admin_api.get(f"{URL}grants/?user_id={targets['staff']}").json()["results"]
    assert [row["id"] for row in by_user] == [targets["grant"]] and by_user[0]["group"] is None
    by_group = admin_api.get(f"{URL}grants/?group_id={group.pk}").json()["results"]
    assert by_group[0]["group"] == {"id": group.pk, "name": group.name} and by_group[0]["user"] is None


def test_grant_to_a_group_and_a_duplicate(admin_api, group):
    body = {"role": VIEWER, "group_id": group.pk}
    assert admin_api.post(URL + "grants/", body, format="json").status_code == 201
    assert admin_api.post(URL + "grants/", body, format="json").status_code == 409


@pytest.mark.parametrize("body", [{"role": "nosuchrole", "user_id": 1}, {"role": VIEWER, "group_id": 999999}])
def test_grant_with_an_unknown_role_or_group_is_400(admin_api, body):
    assert admin_api.post(URL + "grants/", body, format="json").status_code == 400


def test_revoking_the_last_administrator_is_409(admin_api):
    grant = Grant.objects.get(role__key=ADMINISTRATOR)
    response = admin_api.delete(f"{URL}grants/{grant.pk}/")
    assert response.status_code == 409 and response.json()["error"] == "CONFLICT"
    assert Grant.objects.filter(pk=grant.pk).exists()


def test_staff_directory_lists_active_staff_with_roles(admin_api, make_user, group, role, system):
    member = make_user(username="kowalski", email="jan@example.test", first_name="Jan", last_name="Kowalski")
    member.groups.add(group)
    access_service.grant_role(role(VIEWER), group=group, actor=system)
    make_user(is_staff=False, username="kowalski-customer")
    make_user(is_active=False, username="kowalski-gone")
    for search in ("kowal", "jan@", "Jan"):
        rows = admin_api.get(f"{URL}staff/?search={search}").json()["results"]
        assert [row["username"] for row in rows] == ["kowalski"]
    row = admin_api.get(f"{URL}staff/?search=kowal").json()["results"][0]
    assert row["name"] == "Jan Kowalski" and row["roles"] == [{"key": VIEWER, "name": "Viewer", "via_group": "editors"}]


def test_staff_detail_adds_groups_and_grants(admin_api, targets, group, role, system):
    staff_user = Grant.objects.get(pk=targets["grant"]).user
    staff_user.groups.add(group)
    access_service.grant_role(role(VIEWER), group=group, actor=system)
    body = admin_api.get(f"{URL}staff/{targets['staff']}/").json()
    assert body["groups"] == [{"id": group.pk, "name": "editors"}]
    assert sorted(grant["role"]["key"] for grant in body["grants"]) == ["stock", VIEWER]
    assert sorted(item["key"] for item in body["roles"]) == ["stock", VIEWER]


def test_groups_list_member_counts_and_grants(admin_api, group, make_user, role, system):
    make_user().groups.add(group)
    access_service.grant_role(role(VIEWER), group=group, actor=system)
    row = admin_api.get(URL + "groups/").json()["results"][0]
    assert row["member_count"] == 1 and [grant["role"]["key"] for grant in row["grants"]] == [VIEWER]


def test_audit_is_newest_first_and_filters(admin_api, targets):
    rows = admin_api.get(URL + "audit/").json()["results"]
    assert [row["id"] for row in rows] == sorted((row["id"] for row in rows), reverse=True)
    assert {row["action"] for row in admin_api.get(URL + "audit/?action=role.create").json()["results"]} == {
        "role.create"
    }
    assert admin_api.get(URL + "audit/?actor=999999").json()["count"] == 0
    future = (timezone.now() + timedelta(days=1)).isoformat()
    assert admin_api.get(URL + "audit/", {"from": future}).json()["count"] == 0
    assert admin_api.get(URL + "audit/", {"to": future}).json()["count"] == AuditEntry.objects.count()


def test_audit_actor_filter(admin_api, person):
    admin_api.post(URL + "roles/", {"key": "warehouse", "name": "Warehouse"}, format="json")
    actor_id = AuditEntry.objects.get(action=AuditAction.ROLE_CREATE).actor_id
    assert [row["action"] for row in admin_api.get(f"{URL}audit/?actor={actor_id}").json()["results"]] == [
        "role.create"
    ]


@pytest.mark.parametrize(
    "query",
    [
        "audit/?from=2026-01-01T00:00:00",
        "audit/?page_size=101",
        f"staff/?search={'x' * 101}",
        "grants/?role=A",
        "grants/?role_key=viewer",
        "audit/?actor_id=1",
    ],
)
def test_query_limits_are_400(admin_api, query):
    assert admin_api.get(URL + query).status_code == 400


@pytest.mark.parametrize("create", ["role", "grant"])
def test_a_concurrent_duplicate_is_a_conflict_not_an_error(monkeypatch, make_user, role, system, create):
    """The second of two racing creates passes the ``exists()`` check; the unique constraint answers instead."""
    user = make_user()
    access_service.create_role(RoleInput("stock", "Stock"), system)
    access_service.grant_role(role(VIEWER), user=user, actor=system)
    monkeypatch.setattr("django.db.models.QuerySet.exists", lambda self: False)
    with pytest.raises(access_service.AccessConflict):
        if create == "role":
            access_service.create_role(RoleInput("stock", "Again"), system)
        else:
            access_service.grant_role(role(VIEWER), user=user, actor=system)
