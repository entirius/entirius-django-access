# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Route map: the walked route key, the admin set, owner, area and the level per HTTP method; the route audit."""

import io
import json

import pytest
from django.core.management import CommandError, call_command
from django.test import override_settings
from django.urls import resolve

from django_access.catalogue.defaults import DEFAULT_RULES, FRAMEWORK_RULES, METHOD_OVERRIDES
from django_access.services.route_map import audit_routes, classify, required_permission, walk
from tests import route_map_urls as views

URLCONF = "tests.route_map_urls"
CT = "(?P<content_type>[^/.]+)"
FORMAT = r"\.(?P<format>[a-z0-9]+)/?$"
# Every walked route → a path that resolves to it.
SAMPLES = {
    "api/faq/v2/admin/questions/": "/api/faq/v2/admin/questions/",
    "api/qms/v2/stock/": "/api/qms/v2/stock/",
    "api/suppliers/v2/admin/suppliers/<slug:supplier_idx>/credentials/": "/api/suppliers/v2/admin/suppliers/s1/credentials/",
    "api/faq/v2/questions/": "/api/faq/v2/questions/",
    "api/leads/v2/admin/gdpr/export/$": "/api/leads/v2/admin/gdpr/export/",
    "^api/lookup/v2/admin/(?P<kind>search|check)/$": "/api/lookup/v2/admin/search/",
    "api-admin/contentdb/<str:version>/content-types/$": "/api-admin/contentdb/v1/content-types/",
    f"api-admin/contentdb/<str:version>/content-types{FORMAT}": "/api-admin/contentdb/v1/content-types.json",
    "api-admin/contentdb/<str:version>/content-types/(?P<pk>[^/.]+)/$": "/api-admin/contentdb/v1/content-types/7/",
    f"api-admin/contentdb/<str:version>/content-types/(?P<pk>[^/.]+){FORMAT}": "/api-admin/contentdb/v1/content-types/7.json",
    "api-admin/contentdb/<str:version>/": "/api-admin/contentdb/v1/",
    "api-admin/contentdb/<str:version>/<drf_format_suffix:format>": "/api-admin/contentdb/v1/.json",
    "api/returns/attachments/order_return/<uuid:pk>": "/api/returns/attachments/order_return/0b6c8a52-3f0e-4a59-9d3e-2f1f1b5c9d11",
    "api-admin/accounts/<str:version>/<str:channel_idx>/customer/delete": "/api-admin/accounts/v1/shop/customer/delete",
    "api/agreements/v2/<str:channel_idx>/newsletter/subscribe/confirm/": "/api/agreements/v2/shop/newsletter/subscribe/confirm/",
}


def walked() -> dict:
    return dict(walk(URLCONF))


def info(route: str):
    return classify(route, walked()[route])


def served(route: str):
    """A function view of the module whose default rule matches the route (rules apply to their own module only)."""
    path = route.removeprefix("^")
    module = next((rule.module for rule in (*DEFAULT_RULES, *FRAMEWORK_RULES) if rule.matches(path)), "tests")
    return views.owned(module, views.download)


def test_walked_route_is_resolver_match_route():
    routes = walked()
    assert set(routes) == set(SAMPLES)
    for route, sample in SAMPLES.items():
        assert resolve(sample, urlconf=URLCONF).route == route


@pytest.mark.parametrize(
    ("route", "admin", "area"),
    [
        ("api/faq/v2/admin/questions/", True, "faq.faq"),  # path + DRF IsAdminUser
        ("api/qms/v2/stock/", True, None),  # local IsAdminUser only — admin, no rule
        ("api/suppliers/v2/admin/suppliers/<slug:supplier_idx>/credentials/", True, "suppliers.credentials"),
        ("api/faq/v2/questions/", False, None),
        ("api/leads/v2/admin/gdpr/export/$", True, "leads.gdpr"),  # include + re_path joined
        ("^api/lookup/v2/admin/(?P<kind>search|check)/$", True, "lookup.search"),  # leading ^ ignored
        ("api-admin/contentdb/<str:version>/content-types/$", True, "content.schema"),
        (f"api-admin/contentdb/<str:version>/content-types{FORMAT}", True, "content.schema"),
        ("api/returns/attachments/order_return/<uuid:pk>", True, "returns.attachments"),  # exception, function view
        ("api-admin/accounts/<str:version>/<str:channel_idx>/customer/delete", False, None),  # key route
    ],
)
def test_admin_set_and_area(route, admin, area):
    assert (info(route).admin, info(route).area) == (admin, area)


@pytest.mark.parametrize(
    ("permission_classes", "admin"),
    [
        ([views.IsAdminUser], True),
        ([views.permissions.IsAdminUser], True),
        ([views.IsSuperUser], True),
        ([views.permissions.IsAuthenticated & (views.permissions.IsAdminUser | views.ContentTypePermission)], True),
        ([views.permissions.IsAuthenticated, views.permissions.IsAdminUser], True),
        ([views.permissions.IsAuthenticated | views.permissions.AllowAny], False),
        ([views.permissions.IsAuthenticated], False),
        ([~views.permissions.IsAdminUser], False),
        ([], False),
    ],
)
def test_permission_classifier(permission_classes, admin):
    view = type("V", (views._View,), {"permission_classes": permission_classes})
    assert classify("api/x/v2/thing/", view.as_view()).admin is admin


def test_exceptions_by_path():
    viewer = "api-viewer/pim/<str:version>/<str:shop_idx>/products/"
    assert classify("api/munin/v2/health/check/", served("api/munin/v2/health/check/")).admin is True
    assert (classify(viewer, served(viewer)).admin, classify(viewer, served(viewer)).area) == (True, "pim.products")
    erase = "api-admin/checkout/<str:version>/<str:channel_idx>/customer/delete"
    assert classify(erase, views.owned("django_checkout", views.download)).admin is False


def test_owner_from_view_class_function_or_rule():
    assert info("api/faq/v2/admin/questions/").owner == "django_faq"
    assert info("api-admin/contentdb/<str:version>/content-types/$").owner == "django_contentdb"
    assert info("api/returns/attachments/order_return/<uuid:pk>").owner == "django_returns"
    assert info("api/qms/v2/stock/").owner == "tests"
    assert info("api-admin/contentdb/<str:version>/").owner == "django_contentdb"  # DRF router root


def test_classify_is_memoized_by_route():
    first = classify("api/faq/v2/admin/questions/", views.DrfAdminView.as_view())
    assert classify("api/faq/v2/admin/questions/", views.PublicView.as_view()) is first


@pytest.mark.parametrize(
    ("route", "method", "expected"),
    [
        ("api/faq/v2/admin/questions/", "GET", "faq.faq:read"),
        ("api/faq/v2/admin/questions/", "head", "faq.faq:read"),
        ("api/faq/v2/admin/questions/", "PATCH", "faq.faq:write"),
        ("api/lookup/v2/admin/search/", "POST", "lookup.search:read"),  # POST-read override
        ("api/lookup/v2/admin/search/", "DELETE", "lookup.search:write"),  # write on a read-only area: never held
        ("api/leads/v2/admin/gdpr/export/", "POST", "leads.gdpr:write"),
        ("api/returns/attachments/order_return/<uuid:pk>", "GET", "returns.attachments:write"),
        ("api/returns/attachments/order_return/<uuid:pk>", "HEAD", "returns.attachments:write"),  # write-only area
        (
            "api-admin/contentdb/<str:version>/content/(?P<ct>[^/.]+)/(?P<uid>[^/.]+)/published/$",
            "GET",
            "content.publish:write",
        ),
        ("api/regional/v2/admin/countries/", "POST", "staff.baseline"),
        ("api/qms/v2/stock/", "GET", None),
    ],
)
def test_required_permission(route, method, expected):
    assert required_permission(classify(route, served(route)), method) == expected


# The 19 r01 §9 routes as the zeno resolver builds them, with the method and level the override gives.
OVERRIDDEN = [
    *(
        (route, "POST", "read")
        for route in (
            "api/lookup/v2/admin/search/",
            "api/lookup/v2/admin/check/",
            "api/pricemanager/v2/admin/<str:channel_idx>/prices/<path:sku>/preview/",
            "api/deliverypoints/v2/admin/geocode/search/",
            "api/suppliers/v2/admin/suppliers/<slug:supplier_idx>/feeds/<slug:idx>/test/",
            "api/suppliers/v2/admin/suppliers/<slug:supplier_idx>/mapping-profiles/<slug:idx>/validate/",
            "api/atlas/v2/admin/sources/<slug:source_idx>/feeds/<slug:idx>/test/",
            "api/atlas/v2/admin/sources/<slug:source_idx>/mapping-profiles/<slug:idx>/validate/",
            "api/munin/v2/health/check/",
            "api/communicator/v2/admin/<str:channel_idx>/templates/<int:pk>/test-generate/",
        )
    ),
    ("api/leads/v2/admin/gdpr/export/", "POST", "write"),
    *(
        (route, "GET", "write")
        for route in (
            "api/agreements/v2/admin/marketing-subscribers/export/",
            "api/contact-forms/v2/admin/submissions/<str:pk>/attachments/<int:attachment_id>/download/",
            "api/checkout/v2/admin/<str:channel_idx>/orders/<str:uid>/attachments/",
            "api/enrichment/v2/admin/proposals/<int:pk>/staged-file/",
            "api/returns/attachments/order_return/<uuid:pk>",
            "api/returns/attachments/order_attachment/<int:pk>",
            f"api-admin/contentdb/<str:version>/content/{CT}/(?P<uid>[^/.]+)/published/$",
            f"api-admin/contentdb/<str:version>/layout-extender/{CT}/(?P<uid>[^/.]+)/published/$",
        )
    ),
]


def test_the_19_overrides():
    assert len(OVERRIDDEN) == 19
    for route, method, level in OVERRIDDEN:
        assert classify(route, views.download).method_levels == {method: level}, route


@pytest.mark.parametrize(
    "route",
    [
        "api/suppliers/v2/admin/suppliers/<slug:supplier_idx>/feeds/<slug:idx>/trigger/",
        "api/pricemanager/v2/admin/<str:channel_idx>/prices/<path:sku>/",
        f"api-admin/contentdb/<str:version>/published/{CT}/(?P<uid>[^/.]+)/$",
        "api/leads/v2/admin/gdpr/erase/",
    ],
)
def test_neighbours_are_not_overridden(route):
    assert not any(item.matches(route) for item in METHOD_OVERRIDES)


@override_settings(ROOT_URLCONF=URLCONF)
def test_audit_lists_unmapped_admin_routes(tmp_path):
    out, report = io.StringIO(), tmp_path / "routes.json"
    assert audit_routes(out, str(report)) == 1
    data = json.loads(report.read_text())
    assert data["unmapped_admin"] == ["api/qms/v2/stock/"]
    assert (data["routes"], data["admin_routes"]) == (15, 12)
    assert data["modules"]["tests"] == {"routes": 1, "admin": 1, "mapped": 0, "unmapped": 1}
    assert data["modules"]["django_contentdb"] == {"routes": 6, "admin": 6, "mapped": 6, "unmapped": 0}
    assert data["foreign_rule_matches"] == []
    assert "UNMAPPED admin route: api/qms/v2/stock/" in out.getvalue()


@override_settings(ROOT_URLCONF="tests.urls")
def test_audit_passes_without_unmapped_routes():
    assert audit_routes(io.StringIO()) == 0


@override_settings(ROOT_URLCONF=URLCONF)
def test_command_check_fails_on_unmapped(tmp_path):
    call_command("access_routes", stdout=io.StringIO())
    with pytest.raises(CommandError):
        call_command("access_routes", "--check", "--json", str(tmp_path / "r.json"), stdout=io.StringIO())
    assert json.loads((tmp_path / "r.json").read_text())["unmapped_admin"] == ["api/qms/v2/stock/"]
