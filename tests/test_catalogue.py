# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""The default catalogue: areas, token scopes and route rules as shipped."""

import pytest

from django_access.catalogue.areas import AREA_KEY_RE, DEFAULT_AREAS, LEVEL_SETS, SENSITIVE_FLAGS, STAFF_BASELINE
from django_access.catalogue.defaults import DEFAULT_RULES
from django_access.catalogue.scopes import DEFAULT_SCOPES

AREA_KEYS = {item.key for item in DEFAULT_AREAS}


def area_for(route: str) -> str | None:
    return next((rule.area for rule in DEFAULT_RULES if rule.matches(route)), None)


def test_counts():
    assert len(DEFAULT_AREAS) == 49
    assert len(DEFAULT_SCOPES) == 9
    assert len({rule.module for rule in DEFAULT_RULES}) == 26  # the 25 modules + access itself


def test_keys_are_unique_and_well_formed():
    assert len(AREA_KEYS) == len(DEFAULT_AREAS)
    assert len({scope.key for scope in DEFAULT_SCOPES}) == len(DEFAULT_SCOPES)
    assert all(AREA_KEY_RE.match(key) for key in AREA_KEYS | {scope.key for scope in DEFAULT_SCOPES})
    assert STAFF_BASELINE not in AREA_KEYS


def test_areas_are_valid():
    for item in DEFAULT_AREAS:
        assert item.levels in LEVEL_SETS, item.key
        assert set(item.sensitive) <= SENSITIVE_FLAGS, item.key
        assert item.label and item.module.startswith("django_"), item.key


def test_read_only_and_write_only_areas():
    levels = {item.key: item.levels for item in DEFAULT_AREAS}
    assert [key for key, value in levels.items() if value == ("read",)] == [
        "lookup.search",
        "accounts.customers",
    ]
    assert [key for key, value in levels.items() if value == ("write",)] == [
        "pim.product_delete",
        "content.publish",
        "returns.attachments",
        "platform.devtools",
    ]


def test_publishable_scopes():
    publishable = {scope.key for scope in DEFAULT_SCOPES if scope.publishable}
    assert publishable == {
        "checkout.storefront",
        "contact_forms.submit",
        "contact_forms.booking",
        "agreements.subscribe",
    }
    assert all(scope.routes for scope in DEFAULT_SCOPES)


def test_every_rule_names_a_known_area():
    assert {rule.area for rule in DEFAULT_RULES} <= AREA_KEYS | {STAFF_BASELINE}


@pytest.mark.parametrize(
    ("route", "area"),
    [
        ("api/pim/v2/admin/<str:channel_idx>/products/<path:sku>/pictures/<int:pk>/", "pim.products"),
        ("api/pim/admin/<str:channel_idx>/products/<path:sku>/", "pim.products"),
        ("api/pim/v2/admin/pictures/upload/", "pim.products"),
        ("api/pim/v2/admin/<str:channel_idx>/categories/<str:idx>/products/reorder/", "pim.categories"),
        ("api/pim/v2/admin/features/<str:idx>/attributes/", "pim.schema"),
        ("api/pim/v2/admin/<str:channel_idx>/feature-sets/<str:idx>/features/", "pim.schema"),
        ("api/pim/v2/admin/files-categories/<str:code>/", "pim.schema"),
        ("api/pim/v2/admin/gap-definitions/", "pim.quality"),
        ("api/pim/v2/admin/<str:channel_idx>/gaps/exemptions/<int:pk>/", "pim.quality"),
        (
            "api-viewer/pim/<str:version>/<str:shop_idx>/features/<str:idx>/attributes/<str:attr_idx>/extension/",
            "pim.schema",
        ),
        ("api-viewer/pim/<str:version>/<str:shop_idx>/products/<path:sku>/", "pim.products"),
        ("api/pricemanager/v2/admin/tax-classes/<str:idx>/rates/", "pricemanager.settings"),
        ("api/pricemanager/v2/admin/<str:channel_idx>/prices/<path:sku>/preview/", "pricemanager.prices"),
        ("api/pricefighter/v2/admin/rules/<int:pk>/", "pricefighter.rules"),
        ("api/pricefighter/v2/admin/apply/", "pricefighter.decisions"),
        ("api/suppliers/v2/admin/suppliers/<slug:idx>/credentials/", "suppliers.credentials"),
        ("api/suppliers/v2/admin/suppliers/<slug:supplier_idx>/feeds/<slug:idx>/test/", "suppliers.sources"),
        ("api/suppliers/v2/admin/pim-sku/<path:sku>/force-repush/", "suppliers.products"),
        ("api/atlas/v2/admin/sources/<slug:idx>/credentials/", "atlas.credentials"),
        ("api/atlas/v2/admin/observations/", "atlas.products"),
        ("api/atlas/v2/admin/competitors/<slug:idx>/", "atlas.sources"),
        ("api/enrichment/v2/admin/spawn-rules/<slug:key>/run/", "enrichment.rules"),
        ("api/enrichment/v2/admin/proposals/<int:pk>/staged-file/", "enrichment.proposals"),
        (
            "api-admin/contentdb/<str:version>/content/(?P<content_type>[^/.]+)/(?P<uid>[^/.]+)/published/$",
            "content.publish",
        ),
        (
            "api-admin/contentdb/<str:version>/layout-extender/(?P<content_type>[^/.]+)/(?P<uid>[^/.]+)"
            r"/published\.(?P<format>[a-z0-9]+)/?$",
            "content.publish",
        ),
        (
            "api-admin/contentdb/<str:version>/published/(?P<content_type>[^/.]+)/(?P<uid>[^/.]+)/draft/$",
            "content.pages",
        ),
        ("api-admin/contentdb/<str:version>/content/(?P<content_type>[^/.]+)/$", "content.pages"),
        ("api-admin/contentdb/<str:version>/content-permissions/", STAFF_BASELINE),
        ("api-admin/contentdb/<str:version>/images/(?P<uid>[^/.]+)/$", "content.media"),
        (r"api-admin/contentdb/<str:version>/image-tags\.(?P<format>[a-z0-9]+)/?$", "content.media"),
        ("api-admin/contentdb/<str:version>/content-types/(?P<slug>[^/.]+)/$", "content.schema"),
        ("api-admin/contentdb/<str:version>/attributes/(?P<attribute_slug>[^/.]+)/values/$", "content.schema"),
        ("api-admin/contentdb/<str:version>/", "content.pages"),
        ("api/contentdb/v2/admin/authors/<uuid:uid>/", "content.pages"),
        ("api/contentdb-translator/v2/admin/<str:shop_idx>/bulk/jobs/", "contentdb_translator.translate"),
        ("api/pim-translator/v2/admin/<str:shop_idx>/bulk/translate/", "pim_translator.translate"),
        ("api/agreements/v2/admin/marketing-subscribers/export/", "agreements.consents"),
        ("api/agreements/v2/admin/definitions/<str:slug>/content-history/", "agreements.definitions"),
        ("api/accounts/v2/admin/groups/", "accounts.customers"),
        ("api/checkout/v2/admin/<str:channel_idx>/orders/<str:uid>/attachments/", "checkout.orders"),
        ("api/checkout/v2/admin/<str:channel_idx>/discount-rules/<int:rule_id>/codes/", "checkout.discounts"),
        ("api/returns/attachments/order_return/<uuid:pk>", "returns.attachments"),
        (
            "api/contact-forms/v2/admin/submissions/<str:pk>/attachments/<int:attachment_id>/download/",
            "contact_forms.submissions",
        ),
        ("api/contact-forms/v2/admin/offline-conversions/<int:pk>/retry/", "contact_forms.leads"),
        ("api/contact-forms/v2/admin/channels/<str:channel_idx>/integrations/", "contact_forms.settings"),
        ("api/leads/v2/admin/gdpr/export/", "leads.gdpr"),
        ("api/leads/v2/admin/<str:channel_idx>/companies/<int:pk>/transition/", "leads.companies"),
        ("api/leads/v2/admin/<str:channel_idx>/recipient-profiles/", "leads.settings"),
        ("api/leads/v2/admin/<str:channel_idx>/test/import-now/", "platform.devtools"),
        ("api/communicator/v2/admin/<str:channel_idx>/review/<int:pk>/accept/", "communicator.review"),
        ("api/communicator/v2/admin/<str:channel_idx>/templates/<int:pk>/test-generate/", "communicator.content"),
        ("api/communicator/v2/admin/<str:channel_idx>/mailbox/", "communicator.settings"),
        ("api/communicator/v2/admin/<str:channel_idx>/threads/<int:pk>/", "communicator.conversations"),
        ("api/communicator/v2/admin/<str:channel_idx>/test/clock/", "platform.devtools"),
        ("api/siteintel/v2/admin/<str:channel_idx>/audits/<uuid:audit_id>/rerun/", "siteintel.audits"),
        ("api/siteintel/v2/admin/<str:channel_idx>/test/expire-now/", "platform.devtools"),
        ("api/notifications/v2/admin/<str:channel_idx>/notifications/read-all/", STAFF_BASELINE),
        ("api/notifications/v2/admin/<str:channel_idx>/test/notify/", "platform.devtools"),
        ("api/munin/v2/health/check/", "munin.config"),
        ("api/munin/v2/admin/entries/<str:key>/", "munin.config"),
        ("api/regional/v2/admin/currencies/", STAFF_BASELINE),
        ("api/lookup/v2/admin/check/", "lookup.search"),
        ("api/qms/v2/admin/stock-by-sku/<str:sku>/edit/", "qms.stock"),
        ("api/faq/v2/admin/<str:channel_idx>/items/<int:pk>/translations/", "faq.faq"),
        ("api/deliverypoints/v2/admin/geocode/search/", "deliverypoints.points"),
        ("api/email/v2/admin/<str:shop_idx>/templates/<slug:email_type>/", "email.templates"),
    ],
)
def test_route_maps_to_area(route, area):
    assert area_for(route) == area


@pytest.mark.parametrize(
    ("route", "area"),
    [
        ("api/pim/v2/admin/brand-new/", "pim.products"),
        ("api-viewer/pim/<str:version>/<str:shop_idx>/brand-new/", "pim.schema"),
        ("api/pim-translator/v2/admin/brand-new/", "pim_translator.translate"),
        ("api/pricemanager/v2/admin/brand-new/", "pricemanager.prices"),
        ("api/pricefighter/v2/admin/brand-new/", "pricefighter.decisions"),
        ("api/qms/v2/admin/brand-new/", "qms.stock"),
        ("api/suppliers/v2/admin/brand-new/", "suppliers.sources"),
        ("api/atlas/v2/admin/brand-new/", "atlas.sources"),
        ("api/enrichment/v2/admin/brand-new/", "enrichment.proposals"),
        ("api/lookup/v2/admin/brand-new/", "lookup.search"),
        ("api-admin/contentdb/<str:version>/brand-new/", "content.pages"),
        ("api/contentdb/v2/admin/brand-new/", "content.pages"),
        ("api/contentdb-translator/v2/admin/brand-new/", "contentdb_translator.translate"),
        ("api/faq/v2/admin/brand-new/", "faq.faq"),
        ("api/deliverypoints/v2/admin/brand-new/", "deliverypoints.points"),
        ("api/email/v2/admin/brand-new/", "email.templates"),
        ("api/agreements/v2/admin/brand-new/", "agreements.definitions"),
        ("api/accounts/v2/admin/brand-new/", "accounts.customers"),
        ("api/checkout/v2/admin/<str:channel_idx>/brand-new/", "checkout.discounts"),
        ("api/returns/attachments/brand-new/", "returns.attachments"),
        ("api/contact-forms/v2/admin/brand-new/", "contact_forms.settings"),
        ("api/leads/v2/admin/<str:channel_idx>/brand-new/", "leads.settings"),
        ("api/communicator/v2/admin/<str:channel_idx>/brand-new/", "communicator.conversations"),
        ("api/siteintel/v2/admin/<str:channel_idx>/brand-new/", "siteintel.audits"),
        ("api/notifications/v2/admin/<str:channel_idx>/brand-new/", "notifications.inbox"),
        ("api/munin/v2/admin/brand-new/", "munin.config"),
        ("api/munin/v2/health/brand-new/", "munin.config"),
        ("api/regional/v2/admin/brand-new/", STAFF_BASELINE),
    ],
)
def test_new_route_of_a_known_module_lands_in_its_catch_all(route, area):
    assert area_for(route) == area


@pytest.mark.parametrize(
    "route",
    [
        "api/checkout/v2/<str:channel_idx>/carts/",
        "api-admin/accounts/<str:version>/<str:channel_idx>/customer/delete",
        "api/faq/v2/<str:channel_idx>/items/",
        "api/munin/v2/<str:key>/",
        "api/contact-forms/v2/<str:channel_idx>/submit/",
    ],
)
def test_non_admin_routes_match_no_rule(route):
    assert area_for(route) is None
