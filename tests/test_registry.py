# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Registry: defaults merged with AppConfig declarations, permission keys, implication; system checks."""

import pytest
from django.apps import apps
from django.conf import settings
from django.test import override_settings

from django_access import checks
from django_access.catalogue import registry
from django_access.catalogue.areas import Area
from django_access.catalogue.defaults import DEFAULT_RULES, AreaOverride, RouteRule
from django_access.checks import catalogue_is_consistent


@pytest.fixture(autouse=True)
def fresh_registry():
    registry.reset()
    yield
    registry.reset()


@pytest.fixture
def faq_stub():
    with override_settings(INSTALLED_APPS=[*settings.INSTALLED_APPS, "tests.faq_stub"]):
        registry.reset()
        yield apps.get_app_config("django_faq")


def ids(messages) -> list[str]:
    return sorted(message.id for message in messages)


def test_defaults_without_declarations():
    assert len(registry.areas()) == 49
    assert len(registry.scopes()) == 9
    assert registry.route_rules() == DEFAULT_RULES
    assert registry.area("faq.faq").module == "django_faq"


def test_declaring_app_replaces_only_its_own_module(faq_stub):
    keys = {item.key for item in registry.areas()}
    assert "faq.items" in keys and "faq.faq" not in keys
    assert registry.area("faq.items") == Area("faq.items", "django_faq", "FAQ items")
    faq_rules = [rule for rule in registry.route_rules() if rule.module == "django_faq"]
    assert faq_rules == [RouteRule("django_faq", "api/faq/v2/admin/", "faq.items")]
    others = [rule for rule in registry.route_rules() if rule.module != "django_faq"]
    assert others == [rule for rule in DEFAULT_RULES if rule.module != "django_faq"]
    default_position = next(i for i, rule in enumerate(DEFAULT_RULES) if rule.module == "django_faq")
    assert registry.route_rules()[default_position] == faq_rules[0]
    assert len(registry.scopes()) == 9
    assert catalogue_is_consistent() == []


def test_declared_module_is_forced_to_the_declaring_label(faq_stub, monkeypatch):
    monkeypatch.setattr(faq_stub, "access_areas", [Area("faq.items", "django_pim", "FAQ items")])
    registry.reset()
    assert registry.area("faq.items").module == "django_faq"
    assert registry.area("pim.products").module == "django_pim"


def test_area_unknown_key():
    with pytest.raises(KeyError):
        registry.area("nope.nope")


def test_perm_key_and_parse_perm():
    assert registry.perm_key("pim.products", "write") == "pim.products:write"
    assert registry.parse_perm("checkout.orders:read") == (registry.area("checkout.orders"), "read")
    for bad in ("accounts.customers:write", "content.publish:read", "nope.nope:read", "pim.products:delete"):
        with pytest.raises(ValueError, match="Unknown permission"):
            registry.parse_perm(bad)
    with pytest.raises(ValueError, match="Unknown permission"):
        registry.parse_perm("pim.products")


@pytest.mark.parametrize(
    ("held", "needed", "expected"),
    [
        ("pim.products:write", "pim.products:read", True),
        ("pim.products:write", "pim.products:write", True),
        ("pim.products:read", "pim.products:read", True),
        ("pim.products:read", "pim.products:write", False),
        ("pim.products:write", "pim.categories:read", False),
    ],
)
def test_implies(held, needed, expected):
    assert registry.implies(held, needed) is expected


def test_checks_pass_on_the_defaults():
    assert catalogue_is_consistent() == []


def test_checks_fire_on_a_broken_declaration(faq_stub, monkeypatch):
    monkeypatch.setattr(
        faq_stub,
        "access_areas",
        [
            {"key": "faq.items", "label": "FAQ items"},
            {"key": "faq.items", "label": "Again"},
            {"key": "FAQ", "label": "Bad key", "levels": ("delete",), "sensitive": ("gossip",)},
        ],
    )
    monkeypatch.setattr(
        faq_stub,
        "access_route_rules",
        [{"pattern": "api/faq/v2/admin/", "area": "faq.ghost"}, {"pattern": "api/faq/(", "area": "faq.items"}],
    )
    monkeypatch.setattr(faq_stub, "access_token_scopes", [{"key": "checkout.erase", "label": "Clash"}], raising=False)
    registry.reset()
    assert ids(catalogue_is_consistent()) == sorted(
        ["django_access.E001", "django_access.E002", "django_access.E003", "django_access.E005"]
        + ["django_access.E004"] * 3
    )


def test_checks_fire_on_an_area_override_naming_an_unknown_area(monkeypatch):
    """E.g. django_pim declaring its own areas without pim.product_delete: the SKU delete would refuse every staff user."""
    monkeypatch.setattr(checks, "AREA_OVERRIDES", (AreaOverride("api/pim/v2/admin/", "DELETE", "pim.ghost"),))
    [message] = catalogue_is_consistent()
    assert message.id == "django_access.E003" and "pim.ghost" in message.msg


def test_checks_report_an_unreadable_declaration(faq_stub, monkeypatch):
    monkeypatch.setattr(faq_stub, "access_areas", [{"key": "faq.items", "title": "wrong field"}])
    registry.reset()
    [message] = catalogue_is_consistent()
    assert message.id == "django_access.E006"
    assert "django_faq.access_areas" in message.msg


def test_area_of_an_uninstalled_module_is_not_an_error():
    assert not apps.is_installed("django_pim")
    assert registry.area("pim.products")
    assert catalogue_is_consistent() == []
