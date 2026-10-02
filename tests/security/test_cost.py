# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""The cost the gate adds: a public request runs no query, no authentication and no cache access; ``decide()`` on a
non-admin route stays far below the per-call budget; a staff GET with a warm cache runs memo 04's query count."""

import time
from contextlib import ExitStack
from unittest import mock

import pytest
from django.core.cache.backends.locmem import LocMemCache
from django.db import connection
from django.test import RequestFactory
from django.test.utils import CaptureQueriesContext
from django.urls import resolve
from rest_framework_simplejwt.authentication import JWTAuthentication

from django_access.services import gate
from tests.security import urls
from tests.test_gate import STAFF_GET_QUERIES

pytestmark = [pytest.mark.django_db, pytest.mark.urls("tests.security.urls")]

CALLS = 10_000
BUDGET_S = 0.5  # ~50 µs per call: loose on purpose, CI is noisy; the query and mock assertions are the strict part
CACHE_METHODS = ("get", "set", "add", "get_or_set", "get_many", "delete", "incr")


@pytest.mark.parametrize("path", [urls.PUBLIC, urls.KEY])
def test_non_admin_request_runs_no_query_no_jwt_no_cache(client, path, django_assert_num_queries):
    """Through the full chain with a Bearer header and a key header (the views authenticate with Session + Basic)."""
    headers = {"HTTP_AUTHORIZATION": "Bearer not.a.token", "HTTP_X_API_KEY": "ent_api_not-a-key"}
    with ExitStack() as stack:
        authenticate = stack.enter_context(mock.patch.object(JWTAuthentication, "authenticate", autospec=True))
        cache_calls = [stack.enter_context(mock.patch.object(LocMemCache, name)) for name in CACHE_METHODS]
        stack.enter_context(django_assert_num_queries(0))
        response = client.get(path, **headers)
    assert response.status_code == 200
    assert response.wsgi_request._access_decision is gate.ALLOW
    assert not hasattr(response.wsgi_request, "_access_principal")
    authenticate.assert_not_called()
    assert [name for name, mocked in zip(CACHE_METHODS, cache_calls, strict=True) if mocked.called] == []


def test_decide_on_a_non_admin_route_stays_in_budget():
    request = RequestFactory().get(urls.PUBLIC, HTTP_AUTHORIZATION="Bearer not.a.token")
    request.resolver_match = resolve(urls.PUBLIC)
    view = request.resolver_match.func
    gate.decide(request, view)  # warm the route memo, as every request after the first finds it
    started = time.perf_counter()
    for _ in range(CALLS):
        gate.decide(request, view)
    elapsed = time.perf_counter() - started
    assert elapsed < BUDGET_S, f"{CALLS} decide() calls took {elapsed:.3f} s"


def test_staff_get_with_a_warm_cache_stays_at_the_recorded_query_count(client, principal):
    viewer = principal("viewer")
    assert client.get(urls.RW_READ, **viewer).status_code == 200
    with CaptureQueriesContext(connection) as queries:
        assert client.get(urls.RW_READ, **viewer).status_code == 200
    assert len(queries) <= STAFF_GET_QUERIES
