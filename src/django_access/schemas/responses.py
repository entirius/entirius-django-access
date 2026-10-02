# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Response schemas of the access API v2 (`me` and admin). Every label is plain data — the API never renders HTML."""

from datetime import datetime
from typing import Any

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


class CatalogueResponse(BaseModel):
    modules: list[ModuleAreasResponse]
    roles: list[BuiltinRoleResponse]


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
