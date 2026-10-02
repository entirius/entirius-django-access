# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Deleting a SKU is its own permission, ``pim.product_delete:write`` (plan 09b): the area, the route overrides, the
built-in roles, the gate on both PIM roots and the RealProduct merge, ``me`` and the catalogue."""

import io
import json

import pytest
from django.test import override_settings

from django_access.catalogue.areas import DESTRUCTIVE, PIM_PRODUCT_DELETE, WRITE, WRITE_ONLY
from django_access.services import access_service
from django_access.services.access_service import RoleInput
from django_access.services.permissions import builtin_permissions
from django_access.services.route_map import audit_routes, classify, required_permission, walk
from tests import product_delete_urls as urls

pytestmark = [pytest.mark.django_db, pytest.mark.urls("tests.product_delete_urls")]

NEEDED = f"{PIM_PRODUCT_DELETE}:write"
ROOTS = pytest.mark.parametrize("root", urls.PIM_ROOTS)


def url(template: str, root: str) -> str:
    return "/" + template.format(root=root)


@pytest.fixture
def custom(make_user, system, api_as):
    """``custom(*permissions)`` → an API client of a staff user holding one custom role with those permissions."""

    def make(*permissions: str):
        role = access_service.create_role(RoleInput("catalogue", "Catalogue", permissions=list(permissions)), system)
        user = make_user()
        access_service.grant_role(role, user=user, actor=system)
        return api_as(user)

    return make


def test_area_is_write_only_destructive_and_assignable(admin_api):
    body = admin_api.get("/api/access/v2/admin/catalogue/").json()
    pim = next(module["areas"] for module in body["modules"] if module["module"] == "django_pim")
    area = next(item for item in pim if item["key"] == PIM_PRODUCT_DELETE)
    assert area["levels"] == list(WRITE_ONLY) and area["sensitive"] == [DESTRUCTIVE] and area["assignable"] is True
    assert area["label"] == "Delete products (SKU)"


def test_builtin_roles():
    assert builtin_permissions("administrator")[PIM_PRODUCT_DELETE] == WRITE
    assert builtin_permissions("manager")[PIM_PRODUCT_DELETE] == WRITE
    assert PIM_PRODUCT_DELETE not in builtin_permissions("editor")
    assert builtin_permissions("editor")["pim.products"] == WRITE
    assert PIM_PRODUCT_DELETE not in builtin_permissions("viewer")


@pytest.mark.parametrize(("name", "held"), [("editor", False), ("viewer", False), ("manager", True)])
def test_me(person, api_as, name, held):
    permissions = api_as(person(name)).get("/api/access/v2/me/").json()["permissions"]
    assert (permissions.get(PIM_PRODUCT_DELETE) == WRITE) is held


def routes() -> dict:
    return dict(walk("tests.product_delete_urls"))


@pytest.mark.parametrize(
    ("suffix", "method", "expected"),
    [
        ("<str:channel_idx>/products/<path:sku>/", "DELETE", NEEDED),
        ("<str:channel_idx>/products/<path:sku>/", "PATCH", "pim.products:write"),
        ("<str:channel_idx>/products/<path:sku>/", "GET", "pim.products:read"),
        ("<str:channel_idx>/products/<path:sku>/pictures/<int:pk>/", "DELETE", "pim.products:write"),
        ("<str:channel_idx>/products/<path:sku>/files/<int:pk>/", "DELETE", "pim.products:write"),
        ("<str:channel_idx>/products/<path:sku>/links/<int:pk>/", "DELETE", "pim.products:write"),
    ],
)
@ROOTS
def test_required_permission_on_pim_routes(root, suffix, method, expected):
    route = root + suffix
    assert required_permission(classify(route, routes()[route]), method) == expected


@pytest.mark.parametrize("route", [item[1:] for item in urls.MERGES])
def test_required_permission_on_the_realproduct_merge(route):
    info = classify(route, routes()[route])
    assert required_permission(info, "POST") == NEEDED
    assert required_permission(info, "GET") == f"{info.area}:read"


@override_settings(ROOT_URLCONF="tests.product_delete_urls")
def test_audit_names_the_permission_for_exactly_those_routes(tmp_path):
    report = tmp_path / "routes.json"
    audit_routes(io.StringIO(), str(report))
    named = {entry["route"]: entry["method_areas"] for entry in json.loads(report.read_text())["admin"]}
    deleting = {route: areas for route, areas in named.items() if areas}
    assert deleting == {
        **{f"{root}<str:channel_idx>/products/<path:sku>/": {"DELETE": PIM_PRODUCT_DELETE} for root in urls.PIM_ROOTS},
        **{merge[1:]: {"POST": PIM_PRODUCT_DELETE} for merge in urls.MERGES},
    }


def refusal(response) -> dict:
    assert response.status_code == 403
    return response.json()["details"][0]


@ROOTS
def test_editor_edits_but_cannot_delete(person, api_as, root):
    client = api_as(person("editor"))
    assert client.patch(url(urls.PRODUCT, root), {}, format="json").status_code == 200
    detail = refusal(client.delete(url(urls.PRODUCT, root)))
    assert detail["issue"] == "ACCESS_DENIED" and detail["description"] == f"needs {NEEDED}"


@pytest.mark.parametrize("name", ["manager", "administrator"])
@ROOTS
def test_manager_and_administrator_delete(person, api_as, name, root):
    assert api_as(person(name)).delete(url(urls.PRODUCT, root)).status_code == 200


@ROOTS
def test_custom_role_needs_the_delete_permission(custom, root):
    assert refusal(custom("pim.products:write").delete(url(urls.PRODUCT, root)))["issue"] == "ACCESS_DENIED"


@ROOTS
def test_custom_role_with_the_delete_permission_deletes(custom, root):
    client = custom("pim.products:write", NEEDED)
    assert client.delete(url(urls.PRODUCT, root)).status_code == 200


@pytest.mark.parametrize("template", [urls.PICTURE, urls.FILE, urls.LINK])
@ROOTS
def test_media_file_and_link_delete_need_only_products_write(custom, template, root):
    assert custom("pim.products:write").delete(url(template, root)).status_code == 200


@pytest.mark.parametrize("merge", urls.MERGES)
def test_realproduct_merge_needs_the_delete_permission(person, api_as, merge):
    detail = refusal(api_as(person("editor")).post(merge, {}, format="json"))
    assert detail["description"] == f"needs {NEEDED}"
    assert api_as(person("manager")).post(merge, {}, format="json").status_code == 200
