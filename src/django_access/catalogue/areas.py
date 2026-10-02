# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Permission areas: every module area a role can read or write.

A permission key is ``<area>:<level>``; write implies read. Labels are English, the CMS translates them by key.
"""

import re
from dataclasses import dataclass

READ = "read"
WRITE = "write"
READ_ONLY = (READ,)
WRITE_ONLY = (WRITE,)
READ_WRITE = (READ, WRITE)
LEVEL_SETS = (READ_ONLY, WRITE_ONLY, READ_WRITE)

PII = "pii"
MONEY = "money"
SECRET = "secret"  # noqa: S105 — a sensitivity flag, not a credential
AI_COST = "ai_cost"
CONFIG = "config"
SENSITIVE_FLAGS = frozenset({PII, MONEY, SECRET, AI_COST, CONFIG})

AREA_KEY_RE = re.compile(r"^[a-z_]+\.[a-z_]+$")

# Pseudo-area of routes every active staff user reaches without a grant; never grantable.
STAFF_BASELINE = "staff.baseline"
# Roles, grants, tokens, audit and the Django admin site; only the built-in Administrator role holds it.
ACCESS_MANAGE = "access.manage"


@dataclass(frozen=True)
class Area:
    key: str
    module: str
    label: str
    levels: tuple[str, ...] = READ_WRITE
    sensitive: tuple[str, ...] = ()


def _module(label: str, *areas: tuple) -> tuple[Area, ...]:
    """Areas of one app label: ``(key, label, levels, sensitive)`` with levels and sensitive optional."""
    return tuple(Area(key, label, text, *rest) for key, text, *rest in areas)


DEFAULT_AREAS: tuple[Area, ...] = (
    *_module(
        "django_pim",
        ("pim.products", "Products and media"),
        ("pim.categories", "Categories and positions"),
        ("pim.schema", "Features, attributes, sets and link types"),
        ("pim.quality", "Quality gaps"),
    ),
    *_module(
        "django_pim_translator", ("pim_translator.translate", "AI translation (catalogue)", READ_WRITE, (AI_COST,))
    ),
    *_module(
        "django_pricemanager",
        ("pricemanager.prices", "Prices", READ_WRITE, (MONEY,)),
        ("pricemanager.settings", "Price channels and tax classes"),
    ),
    *_module(
        "django_pricefighter",
        ("pricefighter.decisions", "Repricing decisions and apply", READ_WRITE, (MONEY,)),
        ("pricefighter.rules", "Repricing rules"),
    ),
    *_module("django_qms", ("qms.stock", "Warehouses and stock")),
    *_module(
        "django_suppliers",
        ("suppliers.sources", "Suppliers, feeds, mappings and logs"),
        ("suppliers.products", "Supplier product queue and links"),
        ("suppliers.credentials", "Supplier credentials", READ_WRITE, (SECRET,)),
    ),
    *_module(
        "django_atlas",
        ("atlas.sources", "Sources, suppliers, competitors, feeds and mappings"),
        ("atlas.products", "Source products, links and observations"),
        ("atlas.credentials", "Source credentials", READ_WRITE, (SECRET,)),
    ),
    *_module(
        "django_enrichment",
        ("enrichment.rules", "Enrichment spawn rules"),
        ("enrichment.proposals", "Enrichment tasks and proposals"),
    ),
    *_module("django_lookup", ("lookup.search", "Product lookup", READ_ONLY)),
    *_module(
        "django_contentdb",
        ("content.pages", "Pages, layouts, routes and blog"),
        ("content.publish", "Publish and unpublish content", WRITE_ONLY),
        ("content.media", "Images and image tags"),
        ("content.schema", "Content types, sets, attributes and languages"),
    ),
    *_module(
        "django_contentdb_translator",
        ("contentdb_translator.translate", "AI translation (content)", READ_WRITE, (AI_COST,)),
    ),
    *_module("django_faq", ("faq.faq", "FAQ")),
    *_module("django_deliverypoints", ("deliverypoints.points", "Delivery points and types")),
    *_module("django_email", ("email.templates", "E-mail templates and sender configuration")),
    *_module(
        "django_agreements",
        ("agreements.definitions", "Agreement texts and versions"),
        ("agreements.consents", "Consents, people and subscribers", READ_WRITE, (PII,)),
    ),
    *_module("django_accounts", ("accounts.customers", "Customers and customer groups", READ_ONLY, (PII,))),
    *_module(
        "django_checkout",
        ("checkout.orders", "Orders", READ_WRITE, (PII, MONEY)),
        ("checkout.discounts", "Discounts and discount codes", READ_WRITE, (MONEY,)),
    ),
    *_module("django_returns", ("returns.attachments", "Return documents", WRITE_ONLY, (PII,))),
    *_module(
        "django_contact_forms",
        ("contact_forms.submissions", "Form submissions and bookings", READ_WRITE, (PII,)),
        ("contact_forms.leads", "Form leads and ad conversions", READ_WRITE, (PII,)),
        ("contact_forms.settings", "Form notifications and integrations"),
    ),
    *_module(
        "django_leads",
        ("leads.companies", "Companies, contacts and imports", READ_WRITE, (PII,)),
        ("leads.settings", "Pipeline stages, lead types, rules and profiles"),
        ("leads.gdpr", "GDPR export and erasure", READ_WRITE, (PII,)),
    ),
    *_module(
        "django_communicator",
        ("communicator.review", "Draft review queue"),
        ("communicator.content", "Templates, sequences and footers", READ_WRITE, (AI_COST,)),
        ("communicator.conversations", "Outbox, threads, replies and suppressions", READ_WRITE, (PII,)),
        ("communicator.settings", "Channel, send policy and mailbox", READ_WRITE, (SECRET,)),
    ),
    *_module("django_siteintel", ("siteintel.audits", "Site audits")),
    *_module("django_notifications", ("notifications.inbox", "Staff notifications")),
    *_module("django_munin", ("munin.config", "Runtime configuration and health", READ_WRITE, (CONFIG,))),
    *_module(
        "django_access",
        (ACCESS_MANAGE, "Roles, grants, application tokens and audit", READ_WRITE, (SECRET, CONFIG)),
        ("platform.devtools", "Development-only test endpoints", WRITE_ONLY),
    ),
)
