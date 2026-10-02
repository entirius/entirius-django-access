# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Route map hardening (FIX-01): owner-scoped rules, self-authenticating views, the Django admin site, the report."""

import io
import json

import pytest
from django.apps import apps
from django.conf import settings
from django.contrib import admin
from django.test import override_settings
from drf_spectacular.views import SpectacularAPIView
from rest_framework import authentication, permissions
from rest_framework_simplejwt.authentication import JWTAuthentication

from django_access.catalogue import registry
from django_access.services.route_map import audit_routes, classify, walk
from tests import route_map_urls as views

JWT = "rest_framework_simplejwt.authentication.JWTAuthentication"
SESSION = "rest_framework.authentication.SessionAuthentication"
ORDERS = "api/checkout/v2/admin/<str:channel_idx>/orders/<str:uid>/"


@pytest.fixture
def greedy_faq(monkeypatch):
    """The faq stub declares a rule broad enough to match every module's routes."""
    with override_settings(INSTALLED_APPS=[*settings.INSTALLED_APPS, "tests.faq_stub"]):
        config = apps.get_app_config("django_faq")
        monkeypatch.setattr(config, "access_route_rules", [{"pattern": "api", "area": "faq.items"}])
        registry.reset()
        yield
    registry.reset()


def view(auth=None, perms=None, base=views._View, **attrs):
    """A DRF view class with the given authentication / permission classes (None = not declared)."""
    if auth is not None:
        attrs["authentication_classes"] = auth
    if perms is not None:
        attrs["permission_classes"] = perms
    return type("V", (base,), attrs)


def test_a_foreign_rule_does_not_reclassify_another_modules_route(greedy_faq):
    orders = views.owned("django_checkout", views.DrfAdminView).as_view()
    assert classify(ORDERS, orders).area == "checkout.orders"
    questions = views.owned("django_faq", views.DrfAdminView).as_view()
    assert classify("api/faq/v2/admin/questions/", questions).area == "faq.items"


@override_settings(ROOT_URLCONF="tests.foreign_urls")
def test_the_audit_passes_without_foreign_rule_matches():
    assert audit_routes(io.StringIO()) == 0


@override_settings(ROOT_URLCONF="tests.foreign_urls")
def test_the_audit_fails_on_foreign_rule_matches(greedy_faq, tmp_path):
    out, report = io.StringIO(), tmp_path / "routes.json"
    assert audit_routes(out, str(report)) == 1
    foreign = json.loads(report.read_text())["foreign_rule_matches"]
    assert {
        "route": "api/suppliers/v2/admin/suppliers/<slug:supplier_idx>/credentials/",
        "owner": "django_suppliers",
        "rule_module": "django_faq",
        "pattern": "api",
    } in foreign
    assert all(item["rule_module"] == "django_faq" and item["owner"] != "django_faq" for item in foreign)
    assert "FOREIGN rule django_faq 'api' matches django_suppliers route" in out.getvalue()


def test_framework_routes_match_only_framework_rules():
    root = classify("api-admin/contentdb/<str:version>/", views.owned("rest_framework", views.download))
    assert (root.owner, root.area, root.admin) == ("django_contentdb", "content.pages", True)
    stray = classify("api/faq/v2/admin/stray/", views.owned("django", views.download))
    assert (stray.owner, stray.area) == ("django", None)


@pytest.mark.parametrize(
    ("auth", "perms", "expected"),
    [
        ([JWTAuthentication], [permissions.IsAdminUser], True),
        ([JWTAuthentication, authentication.SessionAuthentication], [views.IsAdminUser], True),
        ([authentication.SessionAuthentication], [permissions.IsAuthenticated], True),
        (None, [permissions.IsAdminUser], False),  # DRF defaults: Session + Basic
        ([authentication.BasicAuthentication, JWTAuthentication], [permissions.IsAdminUser], False),
        ([type("LenientJWT", (JWTAuthentication,), {})], [permissions.IsAdminUser], False),
        ([], [permissions.IsAdminUser], False),
        ([JWTAuthentication], [permissions.AllowAny], False),
        ([JWTAuthentication], [], False),
        ([JWTAuthentication], [permissions.IsAdminUser | permissions.AllowAny], False),
        ([JWTAuthentication], [permissions.IsAdminUser | views.IsSuperUser], True),
        (
            [JWTAuthentication],
            [permissions.IsAuthenticated & (permissions.IsAdminUser | views.ContentTypePermission)],
            True,
        ),
        ([JWTAuthentication], [~permissions.IsAdminUser], False),
        ([JWTAuthentication], [permissions.AllowAny, permissions.IsAdminUser], True),
    ],
)
def test_self_auth(auth, perms, expected):
    assert classify("api/faq/v2/admin/x/", view(auth, perms).as_view()).self_auth is expected


def test_default_authenticators_are_reported():
    info = classify("api/faq/v2/admin/x/", view(None, [permissions.IsAdminUser]).as_view())
    assert info.auth == (SESSION, "rest_framework.authentication.BasicAuthentication")


@pytest.mark.parametrize("method", ["get_authenticators", "get_permissions", "check_permissions"])
def test_an_overridden_getter_is_never_self_auth(method):
    cls = view([JWTAuthentication], [permissions.IsAdminUser], **{method: lambda self: []})
    assert classify("api/faq/v2/admin/x/", cls.as_view()).self_auth is False


def test_initkwargs_win_over_the_class():
    callback = view([authentication.BasicAuthentication], [permissions.AllowAny]).as_view(
        authentication_classes=[JWTAuthentication], permission_classes=[permissions.IsAdminUser]
    )
    info = classify("api/x/v2/thing/", callback)
    assert (info.admin, info.self_auth, info.auth) == (True, True, (JWT,))


def test_a_plain_function_view_is_not_self_auth():
    assert classify("api/returns/attachments/x/", views.owned("django_returns", views.download)).self_auth is False


def admin_routes() -> dict:
    return {route: callback for route, callback in walk("tests.admin_urls") if route.startswith("admin/")}


@pytest.mark.parametrize(
    ("route", "area"),
    [
        ("admin/login/", "staff.baseline"),
        ("admin/logout/", "staff.baseline"),
        ("admin/password_change/", "staff.baseline"),
        ("admin/password_change/done/", "staff.baseline"),
        ("admin/jsi18n/", "staff.baseline"),
        ("admin/", "access.manage"),
        ("admin/auth/user/", "access.manage"),
        ("admin/auth/user/<path:object_id>/change/", "access.manage"),
        ("admin/django_access/role/", "access.manage"),
    ],
)
def test_django_admin_site_is_gated(route, area):
    info = classify(route, admin_routes()[route])
    assert (info.owner, info.admin, info.area, info.self_auth, info.auth) == ("django", True, area, True, ())


def test_every_django_admin_route_is_gated_and_marked_views_self_auth():
    infos = [classify(route, callback) for route, callback in admin_routes().items()]
    assert len(infos) > 20
    assert all(info.admin and info.area and info.owner == "django" for info in infos)
    # UserAdmin wraps its password view with admin_view() only — unmarked, so the gate answers anonymous callers.
    assert [info.route for info in infos if not info.self_auth] == ["admin/auth/user/<id>/password/"]


def test_a_module_view_on_the_admin_site_is_framework_but_not_self_auth():
    def import_csv(request):
        return views.download(request)

    import_csv.__module__ = "django_reviews.admin"
    callback = admin.site.admin_view(import_csv)
    info = classify("admin/django_reviews/review/import-csv/", callback)
    assert (callback.__module__, info.owner, info.area, info.self_auth) == (
        "django_reviews.admin",
        "django",
        "access.manage",
        False,
    )


def test_an_unwrapped_view_under_admin_is_not_self_auth():
    info = classify("admin/export/", views.owned("django_pim", views.download))
    assert (info.owner, info.admin, info.area, info.self_auth) == ("django", True, "access.manage", False)


def test_openapi_view_with_admin_permission_is_staff_baseline():
    callback = dict(walk("tests.admin_urls"))["api/schema/"]
    info = classify("api/schema/", callback)
    assert (info.owner, info.admin, info.area, info.self_auth, info.auth) == (
        "drf_spectacular",
        True,
        "staff.baseline",
        True,
        (JWT, SESSION),
    )


def test_public_openapi_view_is_not_admin():
    info = classify("api/schema/", SpectacularAPIView.as_view(permission_classes=[permissions.AllowAny]))
    assert (info.admin, info.self_auth) == (False, False)


@override_settings(ROOT_URLCONF="tests.route_map_urls")
def test_report_fields(tmp_path):
    report = tmp_path / "routes.json"
    audit_routes(io.StringIO(), str(report))
    data = json.loads(report.read_text())
    assert all({"self_auth", "auth"} <= entry.keys() for entry in data["admin"])
    assert "api/returns/attachments/order_return/<uuid:pk>" in data["admin_not_self_auth"]
    audiences = {entry["route"]: entry["audience"] for entry in data["non_admin"]}
    assert audiences == {
        "api/faq/v2/questions/": "public",
        "api-admin/accounts/<str:version>/<str:channel_idx>/customer/delete": "key",
    }
    public = next(entry for entry in data["non_admin"] if entry["route"] == "api/faq/v2/questions/")
    assert (public["owner"], public["permissions"]) == ("django_faq", ["AllowAny"])


@override_settings(ROOT_URLCONF="tests.foreign_urls")
def test_report_names_composite_permissions(tmp_path):
    report = tmp_path / "routes.json"
    audit_routes(io.StringIO(), str(report))
    [entry] = json.loads(report.read_text())["non_admin"]
    assert (entry["permissions"], entry["audience"]) == (["(IsAuthenticated OR AllowAny)"], "public")
