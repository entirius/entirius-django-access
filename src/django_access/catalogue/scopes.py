# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Token scopes: what an application token may call on the key-protected (non-admin) routes.

``publishable`` scopes reach browsers by design (storefronts, widgets). ``routes`` are human-readable patterns for
docs and OpenAPI, not matching rules.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class TokenScope:
    key: str
    module: str
    label: str
    publishable: bool = False
    routes: tuple[str, ...] = ()


DEFAULT_SCOPES: tuple[TokenScope, ...] = (
    TokenScope(
        "checkout.storefront",
        "django_checkout",
        "Storefront carts and orders",
        publishable=True,
        routes=(
            "/api/checkout/v2/{channel_idx}/carts/**",
            "/api/checkout/v2/{channel_idx}/orders/**",
            "/api/checkout/v2/{channel_idx}/countries/",
            "/api/checkout/{version}/{channel_idx}/carts/**",
            "/api/checkout/{version}/{channel_idx}/orders/**",
            "/api/checkout/{version}/{channel_idx}/customer/cart/",
        ),
    ),
    TokenScope(
        "checkout.erase",
        "django_checkout",
        "Anonymise a customer's orders (GDPR)",
        routes=("/api-admin/checkout/{version}/{channel_idx}/customer/delete",),
    ),
    TokenScope(
        "accounts.erase",
        "django_accounts",
        "Delete a customer account (GDPR)",
        routes=("/api-admin/accounts/{version}/{channel_idx}/customer/delete",),
    ),
    TokenScope(
        "contact_forms.submit",
        "django_contact_forms",
        "Submit contact forms",
        publishable=True,
        routes=(
            "/api/contact/{version}/{channel_idx}/contact_form/**",
            "/api/contact-forms/v2/{channel_idx}/form-types/",
            "/api/contact-forms/v2/{channel_idx}/submit/**",
        ),
    ),
    TokenScope(
        "contact_forms.booking",
        "django_contact_forms",
        "Booking slots and bookings",
        publishable=True,
        routes=("/api/contact-forms/v2/{channel_idx}/bookings/**",),
    ),
    TokenScope(
        "returns.api",
        "django_returns",
        "Order returns",
        routes=(
            "/api/returns/{version}/{channel_idx}/orders/{order_id}/returns",
            "/api/returns/{version}/{channel_idx}/orders/{order_id}/returns_extra",
            "/api/returns/{version}/{channel_idx}/returns/**",
        ),
    ),
    TokenScope(
        "reviews.moderate",
        "django_reviews",
        "Review moderation",
        routes=("/api/reviews/{version}/{channel_idx}/reviews/{uuid}/",),
    ),
    TokenScope(
        "vault.api",
        "django_vault",
        "Stored payment cards",
        routes=("/api/vault/{version}/{channel_idx}/payment_card/**",),
    ),
    TokenScope(
        "agreements.subscribe",
        "django_agreements",
        "Newsletter subscription",
        publishable=True,
        routes=("/api/agreements/v2/{channel_idx}/newsletter/subscribe/",),
    ),
)
