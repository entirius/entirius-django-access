# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Request schemas of the access admin API v2: format and shape only — every access rule is the service's call."""

from typing import Annotated

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StringConstraints, field_validator, model_validator

from django_access.catalogue import registry
from django_access.services.tokens import MAX_OVERLAP_HOURS

ROLE_KEY_PATTERN = r"^[a-z][a-z0-9_-]{1,49}$"
MAX_PAGE_SIZE = 100
PermissionKey = Annotated[str, StringConstraints(max_length=128)]
ScopeKey = Annotated[str, StringConstraints(max_length=64)]
EXPIRY_DESCRIPTION = (
    "When the token stops working, or null for never; must be in the future. Optional for every scope and without a "
    "maximum: an old token is flagged `rotation_due` instead (`ACCESS_TOKEN_ROTATION_DAYS`)."
)


def _check_permission_count(value: list[str] | None) -> list[str] | None:
    """At most two keys per area (read and write) — bounds the work of one request."""
    limit = 2 * len(registry.areas())
    if value is not None and len(value) > limit:
        raise ValueError(f"at most {limit} permissions")
    return value


class PageQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")  # a misspelt filter is a 400, never the unfiltered list

    page: int = Field(default=1, ge=1, description="Page number.")
    page_size: int = Field(default=20, ge=1, le=MAX_PAGE_SIZE, description="Rows per page.")


class RoleCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key: str = Field(pattern=ROLE_KEY_PATTERN, description="Unique slug.", examples=["warehouse"])
    name: str = Field(min_length=1, max_length=100, description="Display name.", examples=["Warehouse"])
    description: str = Field(default="", max_length=1000, description="What the role is for.")
    permissions: list[PermissionKey] = Field(
        default_factory=list, description="Permission keys `<area>:<level>`.", examples=[["qms.stock:write"]]
    )

    _permission_count = field_validator("permissions")(_check_permission_count)


class RoleUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=100, description="Display name.")
    description: str | None = Field(default=None, max_length=1000, description="What the role is for.")
    permissions: list[PermissionKey] | None = Field(default=None, description="Replaces the whole permission set.")

    _permission_count = field_validator("permissions")(_check_permission_count)

    @model_validator(mode="after")
    def some_field_not_null(self) -> "RoleUpdateRequest":
        _check_update_fields(self)
        return self


class GrantCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: str = Field(pattern=ROLE_KEY_PATTERN, description="Role key.", examples=["viewer"])
    user_id: int | None = Field(default=None, ge=1, description="An active staff user; or `group_id`.")
    group_id: int | None = Field(default=None, ge=1, description="An `auth.Group`; or `user_id`.")

    @model_validator(mode="after")
    def one_holder(self) -> "GrantCreateRequest":
        if (self.user_id is None) == (self.group_id is None):
            raise ValueError("exactly one of user_id or group_id is required")
        return self


class GrantListQuery(PageQuery):
    role: str | None = Field(default=None, pattern=ROLE_KEY_PATTERN, description="Role key filter.")
    user_id: int | None = Field(default=None, ge=1, description="Grants held by this user directly.")
    group_id: int | None = Field(default=None, ge=1, description="Grants held by this group.")


class StaffListQuery(PageQuery):
    search: str = Field(default="", max_length=100, description="Substring of username, email or name.")


class AuditListQuery(PageQuery):
    action: str | None = Field(default=None, max_length=64, description="Exact action, e.g. `role.create`.")
    actor: int | None = Field(default=None, ge=1, description="Actor user id.")
    from_: AwareDatetime | None = Field(default=None, alias="from", description="Created at or after.")
    to: AwareDatetime | None = Field(default=None, description="Created at or before.")


def _check_update_fields(request: BaseModel) -> None:
    """A PATCH body names at least one field and sets none of them to null."""
    if not request.model_fields_set:
        raise ValueError("at least one field is required")
    if any(getattr(request, name) is None for name in request.model_fields_set):
        raise ValueError("fields may not be null")


class ApplicationCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=128, description="Unique display name.", examples=["Storefront"])
    description: str = Field(default="", max_length=1000, description="What the application is for.")


class ApplicationUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=128, description="Unique display name.")
    description: str | None = Field(default=None, max_length=1000, description="What the application is for.")
    is_active: bool | None = Field(default=None, description="False stops every token of the application.")

    @model_validator(mode="after")
    def some_field_not_null(self) -> "ApplicationUpdateRequest":
        _check_update_fields(self)
        return self


class TokenCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(default="", max_length=128, description="What the token is used for.", examples=["Shop"])
    scopes: list[ScopeKey] = Field(
        min_length=1,
        max_length=32,
        description="Token scope keys from the catalogue; publishable and secret scopes never share a token.",
        examples=[["checkout.storefront"]],
    )
    channel_idx: str | None = Field(
        default=None,
        min_length=1,
        max_length=64,
        description="Pin to one channel (null = every channel). Not validated here: channels live in other modules.",
        examples=["emporium"],
    )
    expires_at: AwareDatetime | None = Field(default=None, description=EXPIRY_DESCRIPTION)


class TokenRotateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    overlap_hours: int = Field(
        default=24, ge=0, le=MAX_OVERLAP_HOURS, description="Hours the old token keeps working (0 = stops at once)."
    )
    expires_at: AwareDatetime | None = Field(
        default=None, description=f"Default: none — the successor inherits no expiry. {EXPIRY_DESCRIPTION}"
    )


class TokenExpiryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expires_at: AwareDatetime | None = Field(
        description="The new expiry (in the future: else 400 `EXPIRY_IN_PAST`), or null to clear it. Every token "
        "takes any future date or null. A revoked token → 409."
    )
