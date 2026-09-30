# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
import pytest
from django.db import IntegrityError, transaction

from django_access.models import Grant, Role, RolePermission

pytestmark = pytest.mark.django_db


def test_builtin_roles_exist_after_migrate():
    assert set(Role.objects.filter(builtin=True).values_list("key", flat=True)) == {
        "administrator",
        "manager",
        "editor",
        "viewer",
    }
    assert not RolePermission.objects.exists()


def test_grant_needs_exactly_one_holder(make_user, role, group):
    viewer = role("viewer")
    for holder in ({}, {"user": make_user(), "group": group}):
        with pytest.raises(IntegrityError), transaction.atomic():
            Grant.objects.create(role=viewer, **holder)


@pytest.mark.parametrize("holder", ["user", "group"])
def test_grant_unique_per_role_and_holder(holder, make_user, role, group):
    target = {"user": make_user(), "group": group}[holder]
    Grant.objects.create(role=role("viewer"), **{holder: target})
    with pytest.raises(IntegrityError), transaction.atomic():
        Grant.objects.create(role=role("viewer"), **{holder: target})


def test_role_permission_unique(db):
    custom = Role.objects.create(key="custom", name="Custom")
    RolePermission.objects.create(role=custom, permission="faq.faq:read")
    with pytest.raises(IntegrityError), transaction.atomic():
        RolePermission.objects.create(role=custom, permission="faq.faq:read")
