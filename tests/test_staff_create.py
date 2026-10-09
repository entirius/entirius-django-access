# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""``POST api/access/v2/admin/staff/``: an active staff account with one role, the generated password shown once, the
``staff_user_created`` signal inside the transaction, no password value in any audit row or log."""

import logging

import pytest
from django.contrib.auth import get_user_model

from django_access.models import AuditAction, AuditEntry, Grant
from django_access.services.permissions import EDITOR, VIEWER
from django_access.signals import staff_user_created

pytestmark = pytest.mark.django_db

URL = "/api/access/v2/admin/staff/"
GIVEN = "Corr3ct-h0rse-battery-staple"  # noqa: S105 — a test password
WEAK = "password"  # noqa: S105 — the validators refuse it
VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
]


def body(**fields) -> dict:
    return {"username": "jdoe", "email": "jdoe@example.com", "role": EDITOR, **fields}


def create(client, **fields):
    return client.post(URL, body(**fields), format="json")


def issue(response) -> str:
    return response.json()["details"][0]["issue"]


def field_errors(response) -> set[str]:
    return {detail["field"] for detail in response.json()["details"]}


def test_administrator_creates_an_active_staff_account_with_the_role(admin_api):
    response = create(admin_api)
    assert response.status_code == 201, response.content
    user = get_user_model().objects.get(username="jdoe")
    assert (user.is_staff, user.is_active, user.is_superuser) == (True, True, False)
    assert Grant.objects.filter(user=user, role__key=EDITOR).exists()
    answer = response.json()
    assert (answer["id"], answer["email"], answer["is_superuser"]) == (user.pk, "jdoe@example.com", False)
    assert [role["key"] for role in answer["roles"]] == [EDITOR]
    actions = set(AuditEntry.objects.filter(target_id=str(user.pk)).values_list("action", flat=True))
    assert AuditAction.STAFF_CREATE in actions
    assert AuditEntry.objects.filter(action=AuditAction.GRANT_CREATE, detail__user_id=user.pk).exists()


def test_a_generated_password_is_returned_once_and_signs_in(admin_api):
    response = create(admin_api)
    password = response.json()["password"]
    assert password and get_user_model().objects.get(username="jdoe").check_password(password)
    assert (response["Cache-Control"], response["Pragma"]) == ("no-store", "no-cache")
    entry = AuditEntry.objects.get(action=AuditAction.STAFF_CREATE)
    assert entry.detail == {"username": "jdoe", "email": "jdoe@example.com", "role": EDITOR, "password": "generated"}


def test_a_given_password_is_never_echoed(admin_api):
    response = create(admin_api, password=GIVEN)
    assert response.status_code == 201
    assert response.json()["password"] is None and GIVEN not in response.content.decode()
    assert get_user_model().objects.get(username="jdoe").check_password(GIVEN)
    assert AuditEntry.objects.get(action=AuditAction.STAFF_CREATE).detail["password"] == "given"


@pytest.mark.parametrize("name", ["manager", "editor"])
def test_only_access_managers_create(name, person, api_as):
    response = create(api_as(person(name)))
    assert response.status_code == 403 and issue(response) == "ACCESS_DENIED"
    assert not get_user_model().objects.filter(username="jdoe").exists()


def test_a_customer_is_refused_as_not_staff(person, api_as):
    response = create(api_as(person("customer")))
    assert response.status_code == 403 and issue(response) == "STAFF_ONLY"


@pytest.mark.parametrize("taken", [{"username": "JDOE"}, {"email": "JDoe@Example.com"}])
def test_a_taken_username_or_email_in_any_case_is_409(admin_api, make_user, taken):
    make_user(username="jdoe", email="jdoe@example.com")
    response = create(admin_api, **{**body(username="other", email="other@example.com"), **taken})
    assert response.status_code == 409 and response.json()["error"] == "CONFLICT"


def test_a_weak_password_is_400_on_password(admin_api, settings):
    settings.AUTH_PASSWORD_VALIDATORS = VALIDATORS
    response = create(admin_api, password=WEAK)
    assert response.status_code == 400 and field_errors(response) == {"password"}
    assert not get_user_model().objects.filter(username="jdoe").exists()


@pytest.mark.parametrize(
    ("fields", "field"),
    [
        ({"role": "nosuchrole"}, "role"),
        ({"username": "no spaces!"}, "username"),
        ({"email": "not-an-address"}, "email"),
        ({"is_superuser": True}, "is_superuser"),
        ({"is_staff": False}, "is_staff"),
    ],
)
def test_invalid_fields_are_400_on_that_field(admin_api, fields, field):
    response = create(admin_api, **fields)
    assert response.status_code == 400 and field in field_errors(response), response.content
    assert not get_user_model().objects.filter(username=body(**fields)["username"]).exists()


def test_the_signal_carries_user_and_actor_and_a_failing_receiver_rolls_back(admin_api):
    seen = []

    def receiver(sender, user, actor, **kwargs):
        seen.append((sender, user.username, actor.label))
        raise RuntimeError("no customer row")

    staff_user_created.connect(receiver, dispatch_uid="test_failing_receiver")
    try:
        assert create(admin_api).status_code == 500
    finally:
        staff_user_created.disconnect(dispatch_uid="test_failing_receiver")
    assert seen and seen[0][:2] == (get_user_model(), "jdoe")
    assert not get_user_model().objects.filter(username="jdoe").exists()
    assert not AuditEntry.objects.filter(action=AuditAction.STAFF_CREATE).exists()


def test_no_password_reaches_an_audit_row_or_a_log(admin_api, caplog, settings):
    settings.AUTH_PASSWORD_VALIDATORS = VALIDATORS
    caplog.set_level(logging.DEBUG)
    generated = create(admin_api).json()["password"]
    create(admin_api, username="weak", email="weak@example.com", password=WEAK)
    create(admin_api, username="given", email="given@example.com", password=GIVEN, role=VIEWER)
    audit = str(list(AuditEntry.objects.values()))
    for secret in (generated, GIVEN, f'"{WEAK}"'):
        assert secret not in audit and secret not in caplog.text
