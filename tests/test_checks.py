# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""W002: a per-process default cache delays permission changes in the other processes."""

import pytest
from django.test import override_settings

from django_access.checks import permission_cache_is_shared

LOCMEM = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
DUMMY = {"default": {"BACKEND": "django.core.cache.backends.dummy.DummyCache"}}
REDIS = {"default": {"BACKEND": "django.core.cache.backends.redis.RedisCache", "LOCATION": "redis://cache:6379/0"}}


@pytest.mark.parametrize("caches", [LOCMEM, DUMMY])
def test_w002_on_a_per_process_cache_without_debug(caches):
    with override_settings(DEBUG=False, CACHES=caches):
        [message] = permission_cache_is_shared()
    assert message.id == "django_access.W002"
    assert "Redis" in message.hint


@pytest.mark.parametrize(("debug", "caches"), [(False, REDIS), (True, LOCMEM)])
def test_w002_silent_on_a_shared_cache_or_debug(debug, caches):
    with override_settings(DEBUG=debug, CACHES=caches):
        assert permission_cache_is_shared() == []
