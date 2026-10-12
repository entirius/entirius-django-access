# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""The kill switch: an invalid mode is enforced and fails ``E010``; ``observe``/``off`` warn ``W010`` without DEBUG;
``off`` never calls ``decide()``."""

from unittest import mock

import pytest
from django.test import override_settings

from django_access.checks import gate_mode_is_valid
from django_access.services import gate
from tests.security import urls
from tests.security.contract import GATE401, METHODS, assert_answer

pytestmark = [pytest.mark.django_db, pytest.mark.urls("tests.security.urls")]

INVALID_MODES = ["of", "OFF", "Observe", " enforce", "", None, 0, ["off"], {"mode": "off"}]


@pytest.mark.parametrize("value", INVALID_MODES)
def test_an_invalid_mode_is_enforced_and_fails_e010(client, ran, value):
    with override_settings(ACCESS_GATE_MODE=value, DEBUG=False):
        assert_answer(client.post(urls.FUNCTION), GATE401, ran, urls.FUNCTION, "POST")
        assert [message.id for message in gate_mode_is_valid()] == ["django_access.E010"]


@pytest.mark.parametrize(
    ("mode", "debug", "ids"),
    [
        ("observe", False, ["django_access.W010"]),
        ("off", False, ["django_access.W010"]),
        ("observe", True, []),
        ("off", True, []),
        ("enforce", False, []),
    ],
)
def test_w010_only_without_debug(mode, debug, ids):
    with override_settings(ACCESS_GATE_MODE=mode, DEBUG=debug):
        assert [message.id for message in gate_mode_is_valid()] == ids


@override_settings(ACCESS_GATE_MODE="off")
def test_off_never_calls_decide(client, principal, ran):
    superuser = principal("superuser")
    with mock.patch.object(gate, "decide", autospec=True) as decide:
        for method in METHODS:
            client.generic(method, urls.FUNCTION)
            client.generic(method, urls.RW_READ, **superuser)
    decide.assert_not_called()
    assert len(ran) == 2 * len(METHODS)
