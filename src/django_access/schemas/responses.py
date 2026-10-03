# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Response schemas of the access API v2 (`me` and admin). Every label is plain data — the API never renders HTML."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class AreaResponse(BaseModel):
    key: str = Field(description="Area key.", examples=["pim.products"])
    label: str = Field(description="English label; the CMS translates by key.", examples=["Products and media"])
    levels: list[str] = Field(description="Levels the area offers.", examples=[["read", "write"]])
    sensitive: list[str] = Field(description="Sensitivity flags.", examples=[["pii"]])
    assignable: bool = Field(description="A custom role may hold it (false only for access.manage).")


class ModuleAreasResponse(BaseModel):
    module: str = Field(description="App label of the owning module.", examples=["django_pim"])
    areas: list[AreaResponse]


class BuiltinRoleResponse(BaseModel):
    key: str = Field(examples=["viewer"])
    name: str = Field(examples=["Viewer"])
    description: str
    permissions: dict[str, str] = Field(description="`{area: read | write}` computed from the catalogue.")


class ScopeResponse(BaseModel):
    key: str = Field(description="Token scope key.", examples=["checkout.storefront"])
    label: str = Field(
        description="English label; the CMS translates by key.", examples=["Storefront carts and orders"]
    )
    module: str = Field(description="App label of the owning module.", examples=["django_checkout"])
    publishable: bool = Field(description="Reaches browsers by design; publishable and secret never share a token.")
    routes: list[str] = Field(description="Route patterns for docs, not matching rules.")


class CatalogueResponse(BaseModel):
    modules: list[ModuleAreasResponse]
    roles: list[BuiltinRoleResponse]
    scopes: list[ScopeResponse]
    token_rotation_days: int = Field(
        description="`ACCESS_TOKEN_ROTATION_DAYS`: a token this many days old is `rotation_due` (0 = never).",
        examples=[365],
    )


class RoleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int = Field(examples=[5])
    key: str = Field(examples=["warehouse"])
    name: str = Field(examples=["Warehouse"])
    description: str
    builtin: bool = Field(description="Built-in roles are neither editable nor deletable.")
    grant_count: int = Field(description="Grants to users and groups.", examples=[3])
    created_at: datetime
    updated_at: datetime


class RoleDetailResponse(RoleResponse):
    permissions: dict[str, str] = Field(description="Effective `{area: read | write}`.")


class RoleListResponse(BaseModel):
    count: int
    next: str | None
    previous: str | None
    results: list[RoleResponse]


class RoleRef(BaseModel):
    id: int
    key: str
    name: str


class UserRef(BaseModel):
    id: int
    username: str


class GroupRef(BaseModel):
    id: int
    name: str


class GrantResponse(BaseModel):
    id: int = Field(examples=[12])
    role: RoleRef
    user: UserRef | None = Field(description="The holder, or null for a group grant.")
    group: GroupRef | None = Field(description="The holder, or null for a user grant.")
    created_at: datetime


class GrantListResponse(BaseModel):
    count: int
    next: str | None
    previous: str | None
    results: list[GrantResponse]


class StaffRoleResponse(BaseModel):
    key: str = Field(examples=["editor"])
    name: str = Field(examples=["Editor"])
    via_group: str | None = Field(description="The group it comes through, or null when granted directly.")


class StaffResponse(BaseModel):
    id: int
    username: str
    email: str
    name: str = Field(description="First and last name.")
    is_superuser: bool
    roles: list[StaffRoleResponse]


class StaffDetailResponse(StaffResponse):
    groups: list[GroupRef]
    grants: list[GrantResponse] = Field(description="Grants to the user and to their groups.")


class StaffListResponse(BaseModel):
    count: int
    next: str | None
    previous: str | None
    results: list[StaffResponse]


class GroupResponse(BaseModel):
    id: int
    name: str
    member_count: int
    grants: list[GrantResponse]


class GroupListResponse(BaseModel):
    count: int
    next: str | None
    previous: str | None
    results: list[GroupResponse]


class AuditEntryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    actor_id: int | None
    actor_label: str = Field(examples=["admin"])
    action: str = Field(examples=["grant.create"])
    target_type: str = Field(examples=["django_access.grant"])
    target_id: str
    target_label: str
    detail: dict[str, Any]
    ip: str | None = Field(description="Client address by the NUM_PROXIES rule.")


class AuditListResponse(BaseModel):
    count: int
    next: str | None
    previous: str | None
    results: list[AuditEntryResponse]


class MeUserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: str
    first_name: str
    last_name: str
    is_staff: bool
    is_superuser: bool


class MeRoleResponse(BaseModel):
    key: str
    name: str


class MeResponse(BaseModel):
    user: MeUserResponse
    gate_mode: str | None = Field(description="enforce, observe or off; null for a non-staff user.")
    manages_access: bool
    roles: list[MeRoleResponse]
    permissions: dict[str, str] = Field(description="`{area: read | write}`; `{}` for a non-staff user.")


class ApplicationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int = Field(examples=[3])
    name: str = Field(examples=["Storefront"])
    description: str
    is_active: bool = Field(description="False stops every token of the application.")
    created_at: datetime


class ApplicationListResponse(BaseModel):
    count: int
    next: str | None
    previous: str | None
    results: list[ApplicationResponse]


class TokenResponse(BaseModel):
    """A token as it is shown after issue: identified by ``prefix`` and ``last_four``, never by its value."""

    model_config = ConfigDict(from_attributes=True)

    id: int = Field(examples=[7])
    name: str = Field(examples=["Shop"])
    prefix: str = Field(
        description="The first 12 characters; 6 for a legacy key, `legacy` for a short one.",
        examples=["ent_api_Ab3d"],
    )
    last_four: str = Field(description="The last 4 characters; empty for a short legacy secret.", examples=["x9Q2"])
    scopes: list[str] = Field(examples=[["checkout.storefront"]])
    channel_idx: str | None = Field(description="The pinned channel, or null for every channel.")
    expires_at: datetime | None
    last_used_at: datetime | None
    revoked_at: datetime | None
    legacy: bool = Field(description="Imported from a module's legacy key table.")
    legacy_source: str = Field(
        description="`<app>.<Model>#<pk>` of the legacy key (comma-separated when one secret had several rows), "
        "empty for an issued token."
    )
    state: Literal["active", "expired", "revoked"] = Field(
        description="The token's own state; an inactive application stops its active tokens too (`is_active`)."
    )
    age_days: int = Field(description="Whole days since the token was issued (or imported).", examples=[12])
    rotation_due: bool = Field(
        description="Active and at least `token_rotation_days` old: rotate it. A recommendation — nothing is refused."
    )


class TokenSecretResponse(TokenResponse):
    raw: str = Field(
        description="The token value — in this response only; store it now, it is never shown again.",
        examples=["ent_api_<shown once>"],
    )


class TokenListResponse(BaseModel):
    count: int
    next: str | None
    previous: str | None
    results: list[TokenResponse]
