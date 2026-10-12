# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""W002 / E012: a per-process default cache delays permission changes in the other processes — a warning in the
plain check, an error under ``check --deploy``."""

import pytest
from django.core import checks
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


def _ids(*, deploy: bool) -> list[str]:
    messages = checks.run_checks(tags=["entirius_config"], include_deployment_checks=deploy)
    return [message.id for message in messages]


@pytest.mark.parametrize("caches", [LOCMEM, DUMMY])
@pytest.mark.parametrize("debug", [False, True])
def test_e012_refuses_a_per_process_cache_under_deploy_in_any_debug(caches, debug):
    with override_settings(DEBUG=debug, CACHES=caches):
        deploy = checks.run_checks(tags=["entirius_config"], include_deployment_checks=True)
    [error] = [message for message in deploy if message.id == "django_access.E012"]
    assert error.level == checks.ERROR and "Redis" in error.hint


def test_e012_is_a_deployment_check_only_and_w002_stays_a_warning():
    with override_settings(DEBUG=False, CACHES=LOCMEM):
        plain = checks.run_checks(tags=["entirius_config"])
    assert "django_access.E012" not in [message.id for message in plain]
    [warning] = [message for message in plain if message.id == "django_access.W002"]
    assert warning.level == checks.WARNING


def test_e012_silent_on_a_shared_cache():
    with override_settings(DEBUG=False, CACHES=REDIS):
        assert "django_access.E012" not in _ids(deploy=True)
