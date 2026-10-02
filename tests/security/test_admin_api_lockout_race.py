# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Lockout race: the last two Administrators revoke each other's grant at the same time — exactly one succeeds, the
other answers 409. Needs real concurrent transactions: Postgres only (``make module-test``)."""

import threading

import pytest
from django.db import connection

from django_access.models import Grant
from django_access.services.permissions import ADMINISTRATOR

pytestmark = [
    pytest.mark.django_db(transaction=True, serialized_rollback=True),  # the flush drops the built-in roles
    pytest.mark.skipif(connection.vendor != "postgresql", reason="row locks need Postgres"),
]

URL = "/api/access/v2/admin/grants/"


def revoke_concurrently(requests: list[tuple]) -> list[int]:
    """Run each ``(client, grant_id)`` revoke in its own thread and connection, released together."""
    barrier = threading.Barrier(len(requests))
    statuses: list[int] = []

    def run(client, grant_id: int) -> None:
        try:
            barrier.wait()
            statuses.append(client.delete(f"{URL}{grant_id}/").status_code)
        finally:
            connection.close()

    threads = [threading.Thread(target=run, args=request) for request in requests]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return statuses


@pytest.mark.parametrize("attempt", range(5))
def test_two_administrators_revoking_each_other(person, api_as, attempt):
    first, second = person("administrator"), person("administrator")
    first_grant, second_grant = (Grant.objects.get(user=user, role__key=ADMINISTRATOR) for user in (first, second))
    statuses = revoke_concurrently([(api_as(first), second_grant.pk), (api_as(second), first_grant.pk)])
    assert sorted(statuses) == [204, 409]
    assert Grant.objects.filter(role__key=ADMINISTRATOR).count() == 1
