# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Default route rules: admin route → area for the 25 modules that own admin routes today.

A rule's ``pattern`` is a regex matched (``re.match``, anchored at the start) against the full route string as Django
builds ``ResolverMatch.route`` — e.g. ``api/pim/v2/admin/<str:channel_idx>/products/<path:sku>/``. Converters stay
literal in that string, so ``[^/]+/`` matches one path segment. First match wins; every module ends with a catch-all
on its admin root, so a new route of a known module lands in the module's broadest area.
"""

import re
from dataclasses import dataclass

from django_access.catalogue.areas import READ, STAFF_BASELINE, WRITE

SEGMENT = r"[^/]+/"
# DRF router routes end a name with "/" or with the format-suffix twin "\.(?P<format>…)".
ROUTER_END = r"(?=/|\\)"


@dataclass(frozen=True)
class RouteRule:
    module: str
    pattern: str
    area: str

    def matches(self, route: str) -> bool:
        return re.match(self.pattern, route) is not None


def _module(label: str, root: str, catch_all: str, *rules: tuple[str, str]) -> tuple[RouteRule, ...]:
    """Rules of one admin root: ``(suffix regex, area)`` pairs, then the catch-all on the root itself."""
    return (*(RouteRule(label, root + suffix, area) for suffix, area in rules), RouteRule(label, root, catch_all))


_OPTIONAL_CHANNEL = rf"(?:{SEGMENT})?"
_PIM_SCHEMA = "(?:channels|features|feature-sets|attributes|attributes-groups|link-types|files-categories)/"
_FEED_PRODUCTS = "(?:products|product-links|pim-sku|realproducts|auto-matched|duplicates|push)/"
_CONTENTDB_V1 = rf"api-admin/contentdb/{SEGMENT}"
_CONTENTDB_SCHEMA = (
    "(?:content-types|content-sets|attributes|attribute-sets|layout-extender-types|layout-extender-sets"
    "|languages|channels)"
)

DEFAULT_RULES: tuple[RouteRule, ...] = (
    # pim — admin root api/pim/v2/admin/ + legacy alias api/pim/admin/; staff viewer api-viewer/pim/<version>/<shop>/
    *_module(
        "django_pim",
        "api/pim/(?:v2/)?admin/",
        "pim.products",
        (f"{_OPTIONAL_CHANNEL}categories/", "pim.categories"),
        (f"(?:gap-definitions/|{_OPTIONAL_CHANNEL}gaps/)", "pim.quality"),
        (f"{_OPTIONAL_CHANNEL}{_PIM_SCHEMA}", "pim.schema"),
    ),
    *_module(
        "django_pim",
        f"api-viewer/pim/{SEGMENT}{SEGMENT}",
        "pim.schema",
        ("categories/", "pim.categories"),
        ("products/", "pim.products"),
    ),
    # pim_translator — api/pim-translator/v2/admin/<shop_idx>/
    *_module("django_pim_translator", "api/pim-translator/v2/admin/", "pim_translator.translate"),
    # pricemanager — api/pricemanager/v2/admin/ (prices under <channel_idx>/)
    *_module(
        "django_pricemanager",
        "api/pricemanager/v2/admin/",
        "pricemanager.prices",
        ("(?:channels|tax-classes)/", "pricemanager.settings"),
    ),
    # pricefighter — api/pricefighter/v2/admin/
    *_module(
        "django_pricefighter", "api/pricefighter/v2/admin/", "pricefighter.decisions", ("rules/", "pricefighter.rules")
    ),
    # qms — api/qms/v2/admin/
    *_module("django_qms", "api/qms/v2/admin/", "qms.stock"),
    # suppliers — api/suppliers/v2/admin/
    *_module(
        "django_suppliers",
        "api/suppliers/v2/admin/",
        "suppliers.sources",
        (f"suppliers/{SEGMENT}credentials/", "suppliers.credentials"),
        (_FEED_PRODUCTS, "suppliers.products"),
    ),
    # atlas — api/atlas/v2/admin/
    *_module(
        "django_atlas",
        "api/atlas/v2/admin/",
        "atlas.sources",
        (f"sources/{SEGMENT}credentials/", "atlas.credentials"),
        (_FEED_PRODUCTS, "atlas.products"),
        ("observations/", "atlas.products"),
    ),
    # enrichment — api/enrichment/v2/admin/
    *_module(
        "django_enrichment", "api/enrichment/v2/admin/", "enrichment.proposals", ("spawn-rules/", "enrichment.rules")
    ),
    # lookup — api/lookup/v2/admin/
    *_module("django_lookup", "api/lookup/v2/admin/", "lookup.search"),
    # contentdb — v1 DefaultRouter api-admin/contentdb/<version>/ (format-suffix twins) + v2 api/contentdb/v2/admin/
    *_module(
        "django_contentdb",
        _CONTENTDB_V1,
        "content.pages",
        (f"(?:content|layout-extender)/.*/published{ROUTER_END}", "content.publish"),
        (f"(?:content|layout-extender)-permissions{ROUTER_END}", STAFF_BASELINE),
        (f"(?:images|image-tags){ROUTER_END}", "content.media"),
        (f"{_CONTENTDB_SCHEMA}{ROUTER_END}", "content.schema"),
    ),
    *_module("django_contentdb", "api/contentdb/v2/admin/", "content.pages"),
    # contentdb_translator — api/contentdb-translator/v2/admin/<shop_idx>/
    *_module("django_contentdb_translator", "api/contentdb-translator/v2/admin/", "contentdb_translator.translate"),
    # faq — api/faq/v2/admin/
    *_module("django_faq", "api/faq/v2/admin/", "faq.faq"),
    # deliverypoints — api/deliverypoints/v2/admin/
    *_module("django_deliverypoints", "api/deliverypoints/v2/admin/", "deliverypoints.points"),
    # email — api/email/v2/admin/<shop_idx>/
    *_module("django_email", "api/email/v2/admin/", "email.templates"),
    # agreements — api/agreements/v2/admin/
    *_module(
        "django_agreements",
        "api/agreements/v2/admin/",
        "agreements.definitions",
        ("(?:people|consents|orders|marketing-subscribers|tokens|cookie-consents)/", "agreements.consents"),
    ),
    # accounts — api/accounts/v2/admin/ (the X-API-ADMIN-KEY erase route is a token route, not admin)
    *_module("django_accounts", "api/accounts/v2/admin/", "accounts.customers"),
    # checkout — api/checkout/v2/admin/<channel_idx>/
    *_module(
        "django_checkout", "api/checkout/v2/admin/", "checkout.discounts", (f"{SEGMENT}orders/", "checkout.orders")
    ),
    # returns — api/returns/attachments/ (Django session downloads)
    *_module("django_returns", "api/returns/attachments/", "returns.attachments"),
    # contact_forms — api/contact-forms/v2/admin/
    *_module(
        "django_contact_forms",
        "api/contact-forms/v2/admin/",
        "contact_forms.settings",
        ("(?:submissions|bookings)/", "contact_forms.submissions"),
        ("(?:leads|offline-conversions)/", "contact_forms.leads"),
    ),
    # leads — api/leads/v2/admin/<channel_idx>/ + api/leads/v2/admin/gdpr/
    *_module(
        "django_leads",
        "api/leads/v2/admin/",
        "leads.settings",
        ("gdpr/", "leads.gdpr"),
        (f"{SEGMENT}test/", "platform.devtools"),
        (f"{SEGMENT}(?:companies|contacts|activities|imports)/", "leads.companies"),
    ),
    # communicator — api/communicator/v2/admin/<channel_idx>/
    *_module(
        "django_communicator",
        "api/communicator/v2/admin/",
        "communicator.conversations",
        (f"{SEGMENT}test/", "platform.devtools"),
        (f"{SEGMENT}review/", "communicator.review"),
        (f"{SEGMENT}(?:templates|sequences|footers|models)/", "communicator.content"),
        (f"{SEGMENT}(?:channel|policy|mailbox)/", "communicator.settings"),
    ),
    # siteintel — api/siteintel/v2/admin/<channel_idx>/
    *_module(
        "django_siteintel", "api/siteintel/v2/admin/", "siteintel.audits", (f"{SEGMENT}test/", "platform.devtools")
    ),
    # notifications — api/notifications/v2/admin/<channel_idx>/; the inbox is staff baseline
    *_module(
        "django_notifications",
        "api/notifications/v2/admin/",
        "notifications.inbox",
        (f"{SEGMENT}test/", "platform.devtools"),
        (f"{SEGMENT}notifications/", STAFF_BASELINE),
    ),
    # munin — api/munin/v2/admin/ + api/munin/v2/health/
    *_module("django_munin", "api/munin/v2/admin/", "munin.config"),
    *_module("django_munin", "api/munin/v2/health/", "munin.config"),
    # regional — api/regional/v2/admin/ (reference lists: staff baseline)
    *_module("django_regional", "api/regional/v2/admin/", STAFF_BASELINE),
)


@dataclass(frozen=True)
class MethodOverride:
    """The level ``method`` needs on routes matching ``pattern`` when the HTTP method alone decides wrong."""

    pattern: str
    method: str
    level: str

    def matches(self, route: str) -> bool:
        return re.match(self.pattern, route) is not None


def _overrides(method: str, level: str, *patterns: str) -> tuple[MethodOverride, ...]:
    return tuple(MethodOverride(pattern, method, level) for pattern in patterns)


_FEED_CHECKS = f"{SEGMENT}(?:feeds/{SEGMENT}test|mapping-profiles/{SEGMENT}validate)/$"

# r01 §9 + README § Contract: 10 POST-reads → read; leads GDPR export POST, 6 GET PII exports/downloads and the 2
# contentdb GET …/published/ → write (Viewer and Editor never export PII; reading publish state is publish).
METHOD_OVERRIDES: tuple[MethodOverride, ...] = (
    *_overrides(
        "POST",
        READ,
        "api/lookup/v2/admin/(?:search|check)/$",
        f"api/pricemanager/v2/admin/{SEGMENT}prices/.+/preview/$",
        "api/deliverypoints/v2/admin/geocode/search/$",
        f"api/suppliers/v2/admin/suppliers/{_FEED_CHECKS}",
        f"api/atlas/v2/admin/sources/{_FEED_CHECKS}",
        "api/munin/v2/health/check/$",
        f"api/communicator/v2/admin/{SEGMENT}templates/{SEGMENT}test-generate/$",
    ),
    *_overrides("POST", WRITE, "api/leads/v2/admin/gdpr/export/$"),
    *_overrides(
        "GET",
        WRITE,
        "api/agreements/v2/admin/marketing-subscribers/export/$",
        f"api/contact-forms/v2/admin/submissions/{SEGMENT}attachments/{SEGMENT}download/$",
        f"api/checkout/v2/admin/{SEGMENT}orders/{SEGMENT}attachments/$",
        f"api/enrichment/v2/admin/proposals/{SEGMENT}staged-file/$",
        "api/returns/attachments/(?:order_return|order_attachment)/",
        f"{_CONTENTDB_V1}(?:content|layout-extender)/.*/published{ROUTER_END}",
    ),
)
# Admin although neither the path nor the view's permission classes say so (r01 §6): munin health (local
# IsAdminUser outside /admin/), the returns session downloads, the pim staff-only viewer (pim 3.3.1).
ADMIN_ROUTES: tuple[str, ...] = (
    "api/munin/v2/health/",
    "api/returns/attachments/",
    "api-viewer/pim/",
)
# Not admin although the path says so: the Django admin site (session + model permissions, its own system) and the
# X-API-ADMIN-KEY erase routes (token routes: accounts.erase, checkout.erase). Checked before ADMIN_ROUTES.
NOT_ADMIN_ROUTES: tuple[str, ...] = (
    "admin/",
    rf"api-admin/(?:accounts|checkout)/{SEGMENT}{SEGMENT}customer/delete$",
)
