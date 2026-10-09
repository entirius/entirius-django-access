# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
import pytest
from django.core.cache import cache
from rest_framework.exceptions import Throttled
from rest_framework.parsers import JSONParser
from rest_framework.request import Request

from django_access.services import login_guard

ADDRESS, OTHER_ADDRESS = "192.0.2.10", "192.0.2.99"


@pytest.fixture(autouse=True)
def limits(settings):
    settings.AUTH_TOKEN_FAILURE_WINDOW_S = 60
    settings.AUTH_TOKEN_MAX_FAILURES_PER_USER_IP = 3
    settings.AUTH_TOKEN_MAX_FAILURES_PER_IP = 5
    settings.AUTH_TOKEN_MAX_FAILURES_PER_USER = 50
    settings.AUTH_TOKEN_USER_FAILURE_WINDOW_S = 3600
    cache.clear()
    yield
    cache.clear()


@pytest.fixture
def at(rf):
    return lambda address=ADDRESS: rf.post("/login/", REMOTE_ADDR=address)


def _fail(request, username: str, times: int) -> None:
    for _ in range(times):
        login_guard.refuse_when_blocked(request, username)
        login_guard.record_failure(request, username)


def _wait(request, username: str) -> float | None:
    """The ``Throttled.wait`` of a blocked login, None when it may try."""
    try:
        login_guard.refuse_when_blocked(request, username)
    except Throttled as exc:
        return exc.wait
    return None


def _blocked(request, username: str) -> bool:
    wait = _wait(request, username)
    assert wait in (None, 60)
    return wait is not None


def _spread(at, username: str, addresses: int) -> None:
    """One failure of ``username`` from each of ``addresses`` distinct addresses."""
    for i in range(addresses):
        _fail(at(f"198.51.100.{i + 1}"), username, 1)


def test_failures_block_the_user_on_that_address_only(at):
    _fail(at(), "staffer", 3)
    assert _blocked(at(), "staffer")
    assert not _blocked(at(OTHER_ADDRESS), "staffer")
    assert not _blocked(at(), "someone")


def test_failures_over_usernames_block_the_address(at):
    for i in range(5):
        _fail(at(), f"guess{i}", 1)
    assert _blocked(at(), "staffer")
    assert not _blocked(at(OTHER_ADDRESS), "staffer")


def test_clear_resets_the_user_address_counter_only(at):
    _fail(at(), "staffer", 2)
    login_guard.clear(at(), "staffer")
    _fail(at(), "staffer", 2)
    assert not _blocked(at(), "staffer")
    _fail(at(), "staffer", 1)
    assert _blocked(at(), "staffer")


def test_failures_spread_over_addresses_block_the_username_everywhere(at):
    _spread(at, "staffer", 49)
    assert _wait(at(OTHER_ADDRESS), "staffer") is None
    _spread(at, "staffer", 1)
    assert _wait(at(OTHER_ADDRESS), "staffer") == 3600
    assert _wait(at(OTHER_ADDRESS), "someone") is None


def test_the_longest_window_answers_when_several_counters_block(at):
    _spread(at, "staffer", 47)
    _fail(at(), "staffer", 3)
    assert _wait(at(), "staffer") == 3600


def test_a_success_clears_the_user_address_counter_not_the_per_login_one(at):
    _spread(at, "staffer", 50)
    login_guard.clear(at("198.51.100.1"), "staffer")
    assert _wait(at("198.51.100.1"), "staffer") == 3600


def test_keys_are_hashes_without_username_or_address(at):
    keys = login_guard.failure_keys(at(), "staffer")
    assert keys[0].startswith("auth:fail:ui:") and keys[1].startswith("auth:fail:ip:")
    assert keys[2].startswith("auth:fail:u:") and keys[2] == login_guard.failure_keys(at(OTHER_ADDRESS), "staffer")[2]
    assert not any("staffer" in key or ADDRESS in key for key in keys)
    assert keys != login_guard.failure_keys(at(OTHER_ADDRESS), "staffer")


def test_login_username_is_stripped_like_the_serializer(rf):
    raw = rf.post("/login/", {"username": " staffer ", "password": "x"}, content_type="application/json")
    assert login_guard.login_username(Request(raw, parsers=[JSONParser()])) == "staffer"
    listed = rf.post("/login/", [1], content_type="application/json")
    assert login_guard.login_username(Request(listed, parsers=[JSONParser()])) == ""
