# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Verify is timing-safe by construction: one indexed lookup by SHA-256, the raw value never reaches SQL, no oracle."""

from datetime import timedelta

import pytest
from django.db import connection
from django.test.utils import CaptureQueriesContext

from django_access.models import ApiToken, Application
from django_access.services import tokens

pytestmark = pytest.mark.django_db

STOREFRONT = "checkout.storefront"
TABLE = ApiToken._meta.db_table


def captured(request, scope=STOREFRONT, channel_idx=None):
    with CaptureQueriesContext(connection) as queries:
        answer = tokens.verify_api_key(request, scope, channel_idx)
    return answer, [query["sql"] for query in queries.captured_queries]


def selects(sqls: list[str]) -> list[str]:
    return [sql for sql in sqls if sql.startswith("SELECT") and TABLE in sql]


@pytest.mark.parametrize("hit", [True, False])
def test_one_select_by_hash_and_no_raw_value_in_sql(issue, key_request, hit):
    _, raw = issue()
    presented = raw if hit else tokens.TOKEN_PREFIX + "x" * 43
    answer, sqls = captured(key_request(HTTP_X_API_KEY=presented))
    assert (answer is not None) is hit
    lookups = selects(sqls)
    assert len(lookups) == 1 and len([sql for sql in sqls if sql.startswith("SELECT")]) == 1
    hashed = tokens.hash_key(presented) in lookups[0]
    raw_in_sql = any(presented in sql for sql in sqls)
    assert hashed and not raw_in_sql, "the lookup must carry the hash and never the raw value"


@pytest.mark.parametrize("length", [257, 259, 4096])
def test_over_long_values_run_no_query(key_request, length):
    answer, sqls = captured(key_request(HTTP_X_API_KEY="x" * length))
    assert (answer, sqls) == (None, [])


def test_empty_value_runs_no_query(key_request):
    assert captured(key_request(HTTP_X_API_KEY=""))[1] == []


def test_success_adds_one_conditional_update_per_interval(issue, key_request, clock):
    token, raw = issue()
    stale = ApiToken.objects.get(pk=token.pk)
    first = captured(key_request(HTTP_X_API_KEY=raw))[1]
    second = captured(key_request(HTTP_X_API_KEY=raw))[1]
    assert [sql.split()[0] for sql in first] == ["SELECT", "UPDATE"]
    assert [sql.split()[0] for sql in second] == ["SELECT"]
    written = ApiToken.objects.get(pk=token.pk).last_used_at
    clock.advance(seconds=10)
    tokens._touch(stale, clock.now)  # a second process that read the row before the first write
    assert ApiToken.objects.get(pk=token.pk).last_used_at == written


@pytest.fixture
def failures(issue, application, system, clock):
    """``kind → (raw, scope, channel_idx)`` for every way a presented value can fail."""
    _, expired = issue(expires_at=clock.now + timedelta(seconds=1))
    revoked_token, revoked = issue()
    tokens.revoke_token(revoked_token, actor=system)
    empty_token, empty = issue()
    ApiToken.objects.filter(pk=empty_token.pk).update(scopes=[])
    _, valid = issue(channel_idx="emporium")
    other_app = Application.objects.create(name="disabled", is_active=False)
    _, inactive = issue(application=other_app)
    clock.advance(seconds=1)
    return {
        "unknown": (tokens.TOKEN_PREFIX + "y" * 43, STOREFRONT, None),
        "expired": (expired, STOREFRONT, None),
        "revoked": (revoked, STOREFRONT, None),
        "inactive application": (inactive, STOREFRONT, None),
        "wrong scope": (valid, "contact_forms.submit", None),
        "empty scopes": (empty, STOREFRONT, None),
        "channel mismatch": (valid, STOREFRONT, "other"),
    }


def test_every_failure_is_the_same_none_after_the_same_single_query(failures, key_request):
    for kind, (raw, scope, channel_idx) in failures.items():
        request = key_request(HTTP_X_API_KEY=raw)
        answer, sqls = captured(request, scope, channel_idx)
        assert answer is None, kind
        assert len(sqls) == 1 and len(selects(sqls)) == 1, kind
        assert not hasattr(request, "access_token"), kind
