# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Module ownership (09c): ``assert_routes_covered`` per reason, ``require_own``, and the I001 migration check."""

import pytest
from django.apps import apps
from django.conf import settings
from django.test import override_settings

from django_access.checks import catalogue_is_consistent, modules_declare_own_rules
from django_access.testing import assert_routes_covered

URLCONF = "tests.ownership_urls"


@pytest.fixture(autouse=True)
def module_apps():
    with override_settings(INSTALLED_APPS=[*settings.INSTALLED_APPS, "tests.faq_stub", "tests.widgets_stub"]):
        yield


def failure(app_label: str, **kwargs) -> str:
    with pytest.raises(AssertionError) as raised:
        assert_routes_covered(app_label, urlconf=URLCONF, **kwargs)
    return str(raised.value)


def test_a_module_with_its_own_declarations_passes():
    assert_routes_covered("django_faq", urlconf=URLCONF, require_own=True)


def test_a_module_on_the_defaults_passes_until_it_requires_its_own():
    assert_routes_covered("django_checkout", urlconf=URLCONF)
    assert failure("django_checkout", require_own=True) == (
        "django_checkout: admin routes not covered by its own rules:\n"
        "api/checkout/v2/admin/<str:channel_idx>/orders/ [GET]: defaults "
        "(set access_area on the view or declare access_route_rules)\n"
        "django_checkout: defaults (declare access_areas on its AppConfig)"
    )


def test_an_admin_route_without_a_rule_is_unmapped_with_its_methods():
    assert failure("django_widgets").splitlines()[1:] == [
        "api/widgets/v2/admin/things/$ [GET]: unmapped",
        "api/widgets/v2/admin/things/(?P<pk>[^/.]+)/$ [GET]: unmapped",
    ]


def test_a_rule_of_another_module_matching_the_route_is_foreign(monkeypatch):
    checkout = apps.get_app_config("django_checkout")
    monkeypatch.setattr(checkout, "access_route_rules", [{"pattern": "api/", "area": "checkout.orders"}], raising=False)
    assert failure("django_faq").splitlines()[1:] == [
        "api/faq/v2/admin/questions/ [GET]: foreign_rule (django_checkout 'api/')"
    ]


def test_a_rule_naming_an_area_outside_the_catalogue_is_unknown(monkeypatch):
    faq = apps.get_app_config("django_faq")
    monkeypatch.setattr(faq, "access_route_rules", [{"pattern": "api/faq/v2/admin/", "area": "faq.gone"}])
    assert failure("django_faq").splitlines()[1:] == ["api/faq/v2/admin/questions/ [GET]: unknown_area (faq.gone)"]


@override_settings(ROOT_URLCONF=URLCONF)
def test_the_root_urlconf_is_the_default():
    assert_routes_covered("django_faq")
    with pytest.raises(AssertionError, match="unmapped"):
        assert_routes_covered("django_widgets")


def test_an_app_label_that_is_not_installed_raises():
    with pytest.raises(LookupError):
        assert_routes_covered("django_fqa", urlconf=URLCONF)


@override_settings(ROOT_URLCONF=URLCONF)
def test_i001_lists_exactly_the_apps_with_default_sourced_routes():
    [message] = modules_declare_own_rules()
    assert message.id == "django_access.I001"
    assert message.msg.endswith(": django_checkout")  # widgets has no area at all: access_routes --unmapped, E011
    assert "module-authors.md" in message.hint


@override_settings(ROOT_URLCONF=URLCONF)
def test_i001_silent_when_every_route_owning_app_declares(monkeypatch):
    for label in ("django_checkout", "django_widgets"):
        monkeypatch.setattr(apps.get_app_config(label), "access_route_rules", [], raising=False)
    assert modules_declare_own_rules() == []


@override_settings(ROOT_URLCONF=URLCONF)
def test_i001_leaves_an_unreadable_declaration_to_e006(monkeypatch):
    monkeypatch.setattr(apps.get_app_config("django_faq"), "access_route_rules", [{"regex": "api/"}])
    assert modules_declare_own_rules() == []
    assert [message.id for message in catalogue_is_consistent()] == ["django_access.E006"]


def test_i001_ignores_the_access_module_itself():
    assert modules_declare_own_rules() == []
