# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
import importlib

import pytest
from django.db import connection
from django.db.migrations.executor import MigrationExecutor

from django_access.models import AuditEntry, Grant
from django_access.services.permissions import BUILTIN_ROLES

pytestmark = pytest.mark.django_db
NAME = "0002_builtin_roles_and_staff_administrators"
migration = importlib.import_module(f"django_access.migrations.{NAME}")


@pytest.fixture
def historical_apps():
    return MigrationExecutor(connection).loader.project_state(("django_access", NAME)).apps


def test_staff_become_managers_once(make_user, historical_apps):
    staff = make_user()
    others = [make_user(is_staff=False), make_user(is_active=False), make_user(is_superuser=True)]
    migration.grant_manager_to_staff(historical_apps, None)
    migration.grant_manager_to_staff(historical_apps, None)
    grant = Grant.objects.get()
    assert (grant.user, grant.role.key) == (staff, "manager")
    assert not Grant.objects.filter(user__in=others).exists()
    entry = AuditEntry.objects.get()
    assert (entry.action, entry.actor, entry.actor_label) == ("grant.migrate", None, "system")
    assert (entry.target_id, entry.detail["role"]) == (str(grant.pk), "manager")


def test_frozen_roles_match_the_code():
    assert migration.BUILTIN_ROLES == BUILTIN_ROLES
