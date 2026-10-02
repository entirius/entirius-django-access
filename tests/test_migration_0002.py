# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
import importlib

import pytest
from django.db import connection
from django.db.migrations.executor import MigrationExecutor

from django_access.models import AuditEntry, Grant, Role
from django_access.services import access_service
from django_access.services.permissions import BUILTIN_ROLES, VIEWER

pytestmark = pytest.mark.django_db
NAME = "0002_builtin_roles_and_staff_managers"
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


def test_frozen_roles_cover_the_code_keys():
    """Keys only: a later label change ships as a new data migration, never as an edit of 0002."""
    assert migration.BUILTIN_ROLES.keys() == BUILTIN_ROLES.keys()


def migrate_to(target: str | None) -> None:
    """``None`` = the app's latest migration."""
    executor = MigrationExecutor(connection)
    [latest] = executor.loader.graph.leaf_nodes("django_access")
    executor.migrate([("django_access", target)] if target else [latest])


def snapshot() -> tuple:
    grants = sorted(Grant.objects.values_list("role__key", "user_id", "group_id"), key=str)
    migrated = AuditEntry.objects.filter(action="grant.migrate").count()
    return grants, migrated, sorted(Role.objects.values_list("key", flat=True))


@pytest.mark.django_db(transaction=True, serialized_rollback=True)
def test_back_to_0001_and_forward_changes_nothing(make_user, role, system):
    """Reverse is a no-op and re-applying never re-grants a revoked user: the grants and audit rows stay as they are."""
    kept, revoked = make_user(), make_user()
    access_service.grant_role(role(VIEWER), user=kept, actor=system)
    access_service.revoke_grant(access_service.grant_role(role(VIEWER), user=revoked, actor=system), system)
    before = snapshot()
    migrate_to("0001_initial")
    assert snapshot() == before
    migrate_to(None)
    assert snapshot() == before
    assert not Grant.objects.filter(user=revoked).exists()
