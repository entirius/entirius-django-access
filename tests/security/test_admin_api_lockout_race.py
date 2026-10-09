# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Lockout race: the last two Administrators revoke each other's grant at the same time — exactly one succeeds, the
other answers 409. The race needs real concurrent transactions: it runs whenever ``DATABASE_URL`` is set (CI, zeno
``make module-test``) and fails there on anything but Postgres; only the local sqlite run skips it (``-rs`` names the
skip). The row lock itself is pinned on every database by ``test_the_guard_locks_the_administrator_row``."""

import os
import threading
import time

import pytest
from django.db import connection
from django.db.models import QuerySet

from django_access.models import Grant, Role
from django_access.services import access_service
from django_access.services.permissions import ADMINISTRATOR

URL = "/api/access/v2/admin/grants/"
FIRST = "first-revoke"
TIMEOUT_S = 10
needs_database_url = pytest.mark.skipif(not os.environ.get("DATABASE_URL"), reason="the race needs Postgres")


def lock_waiters() -> int:
    """Backends of this database waiting on a row lock right now."""
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'"
        )
        return cursor.fetchone()[0]


def hold_first_before_commit(monkeypatch) -> tuple[threading.Event, threading.Event]:
    """The first revoke stops after its own lockout check, before its commit: the second runs while it holds."""
    checked, release = threading.Event(), threading.Event()
    original, calls = access_service.has_access_manager, []

    def held() -> bool:
        result = original()
        calls.append(threading.current_thread().name)
        if calls[-1] == FIRST and calls.count(FIRST) == 2:  # the check after its delete
            checked.set()
            release.wait(TIMEOUT_S)
        return result

    monkeypatch.setattr(access_service, "has_access_manager", held)
    return checked, release


def revoke(client, grant_id: int, statuses: dict, name: str) -> threading.Thread:
    def run() -> None:
        try:
            statuses[name] = client.delete(f"{URL}{grant_id}/").status_code
        finally:
            connection.close()

    thread = threading.Thread(target=run, name=name)
    thread.start()
    return thread


def wait_until(condition) -> None:
    deadline = time.monotonic() + TIMEOUT_S
    while not condition() and time.monotonic() < deadline:
        time.sleep(0.01)


@needs_database_url
@pytest.mark.django_db(transaction=True, serialized_rollback=True)  # the flush drops the built-in roles
def test_two_administrators_revoking_each_other(person, api_as, monkeypatch):
    assert connection.vendor == "postgresql", "the lockout race must run on Postgres"
    first, second = person("administrator"), person("administrator")
    first_grant, second_grant = (Grant.objects.get(user=user, role__key=ADMINISTRATOR) for user in (first, second))
    checked, release = hold_first_before_commit(monkeypatch)
    statuses: dict[str, int] = {}
    one = revoke(api_as(first), second_grant.pk, statuses, FIRST)
    assert checked.wait(TIMEOUT_S)
    other = revoke(api_as(second), first_grant.pk, statuses, "second-revoke")
    wait_until(lambda: not other.is_alive() or lock_waiters())
    blocked = other.is_alive()
    release.set()
    one.join(), other.join()
    assert blocked, "the second revoke must wait on the first one's row lock"
    assert (statuses[FIRST], statuses["second-revoke"]) == (204, 409)
    assert Grant.objects.filter(role__key=ADMINISTRATOR).count() == 1


@pytest.mark.django_db
def test_the_guard_locks_the_administrator_row(admin_grant, make_user, role, system, monkeypatch):
    locked = []
    original = QuerySet.select_for_update

    def spy(self, *args, **kwargs):
        locked.append(self.model)
        return original(self, *args, **kwargs)

    monkeypatch.setattr(QuerySet, "select_for_update", spy)
    grant = access_service.grant_role(role(ADMINISTRATOR), user=make_user(), actor=system)
    access_service.revoke_grant(grant, system)
    assert Role in locked
