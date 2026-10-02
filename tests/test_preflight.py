# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Upgrade preflight (D29): ``access_routes --unmapped`` and the deploy check ``E011``."""

import json
from io import StringIO

import pytest
from django.conf import settings
from django.core.management import call_command
from django.core.management.base import CommandError, SystemCheckError
from django.test import override_settings

UNMAPPED = "tests.ownership_urls"  # django_widgets: two admin routes without a rule

pytestmark = pytest.mark.django_db  # the check command runs the database checks too


@pytest.fixture(autouse=True)
def module_apps():
    with override_settings(INSTALLED_APPS=[*settings.INSTALLED_APPS, "tests.faq_stub", "tests.widgets_stub"]):
        yield


def run(*args: str) -> tuple[str, CommandError | None]:
    out = StringIO()
    try:
        call_command(*args, stdout=out, stderr=StringIO())
    except CommandError as exc:
        return out.getvalue(), exc
    return out.getvalue(), None


@override_settings(ROOT_URLCONF=UNMAPPED)
def test_unmapped_lists_route_owner_and_methods_and_fails(tmp_path):
    report = tmp_path / "routes.json"
    out, error = run("access_routes", "--unmapped", "--json", str(report))
    assert error is not None
    assert out.splitlines() == [
        "UNMAPPED api/widgets/v2/admin/things/$\towner=django_widgets\tmethods=GET",
        "UNMAPPED api/widgets/v2/admin/things/(?P<pk>[^/.]+)/$\towner=django_widgets\tmethods=GET",
    ]
    assert len(json.loads(report.read_text())["unmapped_admin"]) == 2


def test_unmapped_passes_with_full_coverage():
    out, error = run("access_routes", "--unmapped")
    assert error is None and out == "no unmapped admin routes\n"


def deploy_check() -> SystemCheckError | None:
    try:
        call_command("check", "--deploy", "--fail-level", "ERROR", stdout=StringIO(), stderr=StringIO())
    except SystemCheckError as exc:
        return exc
    return None


@override_settings(ROOT_URLCONF=UNMAPPED, ACCESS_GATE_MODE="enforce")
def test_e011_stops_an_enforcing_deploy_over_unmapped_routes():
    error = deploy_check()
    assert error is not None and "django_access.E011" in str(error)
    assert "2 admin route(s)" in str(error) and "access_routes --unmapped" in str(error)


@override_settings(ROOT_URLCONF=UNMAPPED, ACCESS_GATE_MODE="observe")
def test_e011_silent_in_observe():
    assert deploy_check() is None


@override_settings(ACCESS_GATE_MODE="enforce")
def test_e011_silent_with_full_coverage():
    assert deploy_check() is None


@override_settings(ROOT_URLCONF=UNMAPPED, ACCESS_GATE_MODE="enforce")
def test_e011_runs_under_deploy_only():
    call_command("check", stdout=StringIO(), stderr=StringIO())
