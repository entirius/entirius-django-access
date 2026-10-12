# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Areas on views (D30): precedence, ``area_source``, ownership semantics and the checks E007, E008, W003."""

import json
from io import StringIO

import pytest
from django.apps import apps
from django.conf import settings
from django.test import override_settings

from django_access.checks import modules_declare_own_rules, view_areas_are_valid
from django_access.services import route_map
from django_access.testing import assert_routes_covered
from tests import view_area_urls

URLCONF = "tests.view_area_urls"


@pytest.fixture(autouse=True)
def module_apps():
    stubs = ["tests.faq_stub", "tests.widgets_stub"]
    with override_settings(INSTALLED_APPS=[*settings.INSTALLED_APPS, *stubs], ROOT_URLCONF=URLCONF):
        yield


def info(route: str) -> route_map.RouteInfo:
    return {entry.route: entry for entry, _ in route_map.unique_entries()}[route]


@pytest.mark.parametrize(
    ("route", "area", "source"),
    [
        ("api/faq/v2/admin/questions/", "staff.baseline", "view"),
        ("api/faq/v2/admin/answers/", "faq.items", "app"),
        ("api/checkout/v2/admin/<str:channel_idx>/orders/", "checkout.discounts", "view"),
        ("api/checkout/v2/admin/<str:channel_idx>/settings/", "checkout.discounts", "default"),
        ("api/leads/v2/admin/gdpr/export/", "leads.gdpr", "view"),
    ],
)
def test_the_view_area_beats_the_app_rule_and_the_defaults(route, area, source):
    assert (info(route).area, info(route).area_source) == (area, source)


def test_the_route_audit_names_the_source_of_every_admin_route(tmp_path):
    report, out = tmp_path / "routes.json", StringIO()
    route_map.audit_routes(out, str(report))
    assert "admin area sources: view 5, app 1, default 1, framework 0" in out.getvalue()
    assert all(entry["area_source"] in route_map.AREA_SOURCES for entry in json.loads(report.read_text())["admin"])


def test_the_route_audit_shows_the_view_levels(tmp_path):
    report = tmp_path / "routes.json"
    route_map.audit_routes(StringIO(), str(report))
    levels = {entry["route"]: entry["method_levels"] for entry in json.loads(report.read_text())["admin"]}
    assert levels["api/leads/v2/admin/gdpr/export/"] == {"POST": "read"}


def test_access_levels_beat_a_method_override():
    route = info("api/leads/v2/admin/gdpr/export/")
    assert route_map.required_permission(route, "POST") == "leads.gdpr:read"


def test_an_area_override_still_applies_on_top_of_a_view_area():
    route = info("api/pim/v2/admin/<str:channel_idx>/products/<path:sku>/")
    assert route_map.required_permission(route, "PATCH") == "pim.products:write"
    assert route_map.required_permission(route, "DELETE") == "pim.product_delete:write"


def test_the_view_area_never_changes_owner_or_admin_membership():
    route = info("api/leads/v2/admin/gdpr/export/")
    assert (route.owner, route.admin, view_area_urls.gdpr_export.cls.__module__) == (
        "django_leads",
        True,
        "django_leads.views",
    )


def test_require_own_passes_for_a_module_owning_its_routes_by_attributes(monkeypatch):
    monkeypatch.setattr(apps.get_app_config("django_widgets"), "access_areas", [], raising=False)
    assert_routes_covered("django_widgets", require_own=True)


def test_require_own_needs_the_access_areas_declaration():
    with pytest.raises(AssertionError, match="django_widgets: defaults \\(declare access_areas"):
        assert_routes_covered("django_widgets", require_own=True)


def test_require_own_fails_while_one_route_is_default_sourced(monkeypatch):
    discounts = [{"key": "checkout.discounts", "label": "Discounts"}]
    monkeypatch.setattr(apps.get_app_config("django_checkout"), "access_areas", discounts, raising=False)
    assert_routes_covered("django_checkout")
    with pytest.raises(AssertionError) as raised:
        assert_routes_covered("django_checkout", require_own=True)
    assert str(raised.value).splitlines()[1:] == [
        "api/checkout/v2/admin/<str:channel_idx>/settings/ [GET]: defaults "
        "(set access_area on the view or declare access_route_rules)"
    ]


def test_i001_lists_exactly_the_default_sourced_apps():
    [message] = modules_declare_own_rules()
    assert message.msg.endswith(": django_checkout")


def test_valid_view_areas_raise_nothing():
    assert view_areas_are_valid() == []


@pytest.fixture
def faq_public_area(monkeypatch):
    monkeypatch.setattr(view_area_urls.FaqPublic, "access_area", "faq.items", raising=False)


def test_e007_accepts_the_superuser_only_pseudo_area(monkeypatch):
    monkeypatch.setattr(view_area_urls.FaqAnswers, "access_area", "superuser.only", raising=False)
    assert view_areas_are_valid() == []


@pytest.mark.parametrize("area", ["faq.gone", ["faq.items"]])
def test_e007_on_an_area_the_catalogue_lacks(monkeypatch, area):
    monkeypatch.setattr(view_area_urls.FaqAnswers, "access_area", area, raising=False)
    assert [message.id for message in view_areas_are_valid()] == ["django_access.E007"]


@pytest.mark.parametrize(
    ("view", "levels", "detail"),
    [
        ("CheckoutOrders", {"FETCH": "read", "post": "admin", "GET": "read"}, "FETCH: read, post: admin"),
        ("FaqQuestions", {"GET": "read"}, "GET: read"),  # the staff baseline offers no level
        ("PimProduct", ["GET"], "must be a dict"),
    ],
)
def test_e008_on_an_unknown_method_or_level(monkeypatch, view, levels, detail):
    monkeypatch.setattr(getattr(view_area_urls, view), "access_levels", levels, raising=False)
    [message] = view_areas_are_valid()
    assert message.id == "django_access.E008" and detail in message.msg


def test_w003_on_a_view_area_outside_the_admin_set(faq_public_area):
    assert [(message.id, message.msg) for message in view_areas_are_valid()] == [
        ("django_access.W003", "api/faq/v2/questions/: access_area on a route outside the admin set")
    ]
