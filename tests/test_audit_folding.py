# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""``GET admin/audit/?fold_bypass=true``: ``gate.bypass`` rows folded per actor and day before paging, the filters
before folding, a constant query count, and the unchanged response without the parameter."""

from datetime import UTC, datetime, timedelta

import pytest

from django_access.models import AuditAction, AuditEntry
from tests.helpers import STAFF_GET_QUERIES

pytestmark = pytest.mark.django_db

URL = "/api/access/v2/admin/audit/"
FOLDED = {"fold_bypass": "true", "action": AuditAction.GATE_BYPASS}
NOON = datetime(2026, 3, 10, 12, tzinfo=UTC)
PLAIN_FIELDS = [
    "id",
    "created_at",
    "actor_id",
    "actor_label",
    "action",
    "target_type",
    "target_id",
    "target_label",
    "detail",
    "ip",
]


@pytest.fixture
def bypasses():
    """``bypasses(actor, at, count=1)`` → that many ``gate.bypass`` rows of ``actor`` created at ``at``, oldest first."""

    def make(actor, at: datetime, count: int = 1) -> list[AuditEntry]:
        fields = {"actor": actor, "actor_label": actor.username, "action": AuditAction.GATE_BYPASS}
        target = {"target_type": "route", "target_id": "", "target_label": "api/pim/v2/admin/products/"}
        rows = [AuditEntry(**fields, **target, detail={"method": "POST", "status": 201}) for _ in range(count)]
        ids = [row.pk for row in AuditEntry.objects.bulk_create(rows)]
        AuditEntry.objects.filter(pk__in=ids).update(created_at=at)  # auto_now_add ignores a given value
        return list(AuditEntry.objects.filter(pk__in=ids).order_by("pk"))

    return make


@pytest.fixture
def root(make_user):
    return make_user(is_superuser=True)


def test_bypass_rows_of_several_raw_pages_fold_into_one_row(admin_api, bypasses, root):
    rows = bypasses(root, NOON, count=120)
    others = AuditEntry.objects.exclude(action=AuditAction.GATE_BYPASS).count()
    assert admin_api.get(URL, {"page_size": 50}).json()["count"] == others + 120

    page = admin_api.get(URL, {"fold_bypass": "true", "page_size": 50}).json()
    assert page["count"] == others + 1 and page["next"] is None
    folded = next(row for row in page["results"] if row["action"] == AuditAction.GATE_BYPASS)
    assert (folded["id"], folded["folded"], folded["detail"]) == (rows[-1].pk, 120, {})
    assert folded["first_at"] == folded["last_at"] == folded["created_at"] == "2026-03-10T12:00:00Z"
    ordinary = [row for row in page["results"] if row != folded]
    assert ordinary and all(row["folded"] == 1 and row["first_at"] == row["created_at"] for row in ordinary)


def test_folded_rows_page_newest_first(admin_api, bypasses, root):
    days = [NOON - timedelta(days=back) for back in range(5)]
    for day in days:
        bypasses(root, day, count=3)
    first = admin_api.get(URL, {**FOLDED, "page_size": 2}).json()
    second = admin_api.get(URL, {**FOLDED, "page_size": 2, "page": 2}).json()
    assert first["count"] == 5 and first["next"] is not None
    stamps = [row["created_at"] for row in first["results"] + second["results"]]
    assert stamps == [day.isoformat().replace("+00:00", "Z") for day in days[:4]]


def test_each_actor_folds_separately(admin_api, bypasses, root, make_user):
    other = make_user(is_superuser=True)
    bypasses(root, NOON, count=3)
    bypasses(other, NOON + timedelta(minutes=1), count=2)
    rows = admin_api.get(URL, FOLDED).json()["results"]
    assert [(row["actor_id"], row["folded"]) for row in rows] == [(other.pk, 2), (root.pk, 3)]


def test_the_day_ends_at_midnight_of_the_service_time_zone(admin_api, bypasses, root, settings):
    settings.TIME_ZONE = "Europe/Warsaw"  # UTC+1 in January: 23:00 UTC is the next day
    evening = datetime(2026, 1, 10, 22, 10, tzinfo=UTC)
    for minutes in (0, 20, 60, 80):  # Warsaw: 23:10 and 23:30 on the 10th, 00:10 and 00:30 on the 11th
        bypasses(root, evening + timedelta(minutes=minutes))
    rows = admin_api.get(URL, FOLDED).json()["results"]
    assert [(row["folded"], row["first_at"], row["last_at"]) for row in rows] == [
        (2, "2026-01-10T23:10:00Z", "2026-01-10T23:30:00Z"),
        (2, "2026-01-10T22:10:00Z", "2026-01-10T22:30:00Z"),
    ]


def test_filters_apply_before_folding(admin_api, bypasses, root, make_user):
    bypasses(root, NOON, count=2)
    late = bypasses(root, NOON + timedelta(hours=2), count=3)
    bypasses(make_user(is_superuser=True), NOON, count=4)
    since = (NOON + timedelta(hours=1)).isoformat()
    [row] = admin_api.get(URL, {**FOLDED, "actor": root.pk, "from": since}).json()["results"]
    assert (row["id"], row["folded"], row["first_at"]) == (late[-1].pk, 3, "2026-03-10T14:00:00Z")
    rows = admin_api.get(URL, FOLDED).json()["results"]
    assert {row["action"] for row in rows} == {AuditAction.GATE_BYPASS} and sorted(row["folded"] for row in rows) == [
        4,
        5,
    ]
    assert admin_api.get(URL, {"fold_bypass": "true", "action": "role.create"}).json()["count"] == 0


def test_a_group_of_one_is_an_ordinary_row(admin_api, bypasses, root):
    [entry] = bypasses(root, NOON)
    [row] = admin_api.get(URL, FOLDED).json()["results"]
    assert (row["id"], row["folded"], row["detail"]) == (entry.pk, 1, {"method": "POST", "status": 201})
    assert row["first_at"] == row["last_at"] == row["created_at"]


@pytest.mark.parametrize("count", [3, 150])
def test_a_folded_page_costs_two_queries_whatever_the_bypass_count(
    admin_api, bypasses, root, count, django_assert_num_queries
):
    bypasses(root, NOON, count=count)
    admin_api.get(URL)  # warm the permission cache
    with django_assert_num_queries(STAFF_GET_QUERIES + 2):  # the count and the page
        assert admin_api.get(URL, {"fold_bypass": "true", "page_size": 50}).status_code == 200


def test_without_fold_bypass_the_response_is_the_one_before(admin_api, bypasses, root):
    bypasses(root, NOON, count=3)
    plain = admin_api.get(URL)
    assert plain.content == admin_api.get(URL, {"fold_bypass": "false"}).content
    rows = plain.json()["results"]
    assert plain.json()["count"] == AuditEntry.objects.count()
    assert all(list(row) == PLAIN_FIELDS for row in rows)
    entry = AuditEntry.objects.order_by("-created_at", "-id").first()
    assert rows[0] == {
        "id": entry.pk,
        "created_at": entry.created_at.isoformat().replace("+00:00", "Z"),
        "actor_id": entry.actor_id,
        "actor_label": entry.actor_label,
        "action": entry.action,
        "target_type": entry.target_type,
        "target_id": entry.target_id,
        "target_label": entry.target_label,
        "detail": entry.detail,
        "ip": entry.ip,
    }


def test_fold_bypass_takes_a_boolean_only(admin_api):
    assert admin_api.get(URL, {"fold_bypass": "daily"}).status_code == 400
