# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""The service user of an application: one per application, staff only while a live admin-scoped token exists."""

from datetime import timedelta

import pytest
from django.contrib.auth import authenticate, get_user_model
from django.core import checks

from django_access.exceptions import AccessConflict
from django_access.services import access_service, directory, service_users, tokens
from django_access.services.permissions import EDITOR

pytestmark = pytest.mark.django_db

ADMIN = ["pim.products:write"]


def service_user(application):
    application.refresh_from_db()
    user = application.service_user
    if user is not None:
        user.refresh_from_db()
    return user


def flags(application) -> tuple[bool, bool]:
    user = service_user(application)
    return user.is_staff, user.is_active


def test_key_route_tokens_create_no_user(issue, application):
    issue(["vault.api"])
    assert service_user(application) is None


def test_first_admin_token_creates_one_service_user(issue, application):
    issue(ADMIN)
    issue(["pim.schema:read"])
    user = service_user(application)
    assert user.username == f"access-app-{application.pk}"
    assert (user.is_staff, user.is_active, user.is_superuser) == (True, True, False)
    assert not user.has_usable_password()
    assert get_user_model().objects.filter(username__startswith="access-app-").count() == 1


def test_password_login_is_refused(issue, application):
    issue(ADMIN)
    user = service_user(application)
    assert authenticate(username=user.username, password="") is None
    assert not user.check_password("")


def test_revoking_the_last_admin_token_drops_staff(issue, application, system):
    first, _ = issue(ADMIN)
    second, _ = issue(ADMIN)
    tokens.revoke_token(first, actor=system)
    assert flags(application) == (True, True)
    tokens.revoke_token(second, actor=system)
    assert flags(application) == (False, True)


def test_a_new_admin_token_after_revoking_all_restores_the_same_user(issue, application, system):
    token, _ = issue(ADMIN)
    before = service_user(application).pk
    tokens.revoke_token(token, actor=system)
    issue(ADMIN)
    assert (service_user(application).pk, flags(application)) == (before, (True, True))


def test_the_grant_api_refuses_the_service_user(issue, application, admin_api):
    issue(ADMIN)
    body = {"role": EDITOR, "user_id": service_user(application).pk}
    assert admin_api.post("/api/access/v2/admin/grants/", body, format="json").status_code in (400, 404)


def test_a_key_route_token_does_not_keep_staff(issue, application, system):
    admin, _ = issue(ADMIN)
    issue(["vault.api"])
    tokens.revoke_token(admin, actor=system)
    assert flags(application) == (False, True)


def test_rotation_keeps_staff_and_the_same_user(issue, application, system):
    token, _ = issue(ADMIN)
    before = service_user(application).pk
    successor, _ = tokens.rotate_token(token, actor=system, overlap_hours=0)
    assert service_user(application).pk == before
    assert flags(application) == (True, True)
    tokens.revoke_token(successor, actor=system)
    assert flags(application) == (False, True)


def test_expiry_change_recomputes(issue, application, system, clock):
    token, _ = issue(ADMIN)
    tokens.set_token_expiry(token, expires_at=clock.now + timedelta(hours=1), actor=system)
    assert flags(application) == (True, True)
    other, _ = issue(ADMIN, expires_at=clock.now + timedelta(hours=2))
    clock.advance(hours=3)
    tokens.revoke_token(other, actor=system)  # the first expired meanwhile
    assert flags(application) == (False, True)


def test_deactivating_the_application_drops_staff_and_reactivating_restores(issue, application, system):
    issue(ADMIN)
    tokens.update_application(application, {"is_active": False}, actor=system)
    assert flags(application) == (False, True)
    tokens.update_application(application, {"is_active": True}, actor=system)
    assert flags(application) == (True, True)


def test_an_unlinked_user_with_the_service_name_is_a_conflict(make_user, issue, application):
    make_user(username=f"access-app-{application.pk}")
    with pytest.raises(AccessConflict, match="already exists"):
        issue(ADMIN)


def test_the_service_user_never_gets_a_grant(issue, application, role, system):
    issue(ADMIN)
    with pytest.raises(ValueError, match="service account"):
        access_service.grant_role(role(EDITOR), user=service_user(application), actor=system)


def test_the_service_user_is_not_in_the_staff_list(issue, application, make_user):
    person = make_user()
    issue(ADMIN)
    assert list(directory.staff_users()) == [person]


def test_is_service_user(issue, application, make_user):
    issue(ADMIN)
    assert service_users.is_service_user(service_user(application))
    assert not service_users.is_service_user(make_user())


def service_checks() -> list[str]:
    return [message.id for message in checks.run_checks(databases=["default"]) if message.id == "django_access.E013"]


def test_check_is_quiet_for_healthy_service_users(issue):
    issue(ADMIN)
    assert service_checks() == []


def test_check_runs_only_with_a_database(issue, application):
    issue(ADMIN)
    get_user_model().objects.filter(pk=service_user(application).pk).update(is_superuser=True)
    assert [m.id for m in checks.run_checks() if m.id == "django_access.E013"] == []
    assert service_checks() == ["django_access.E013"]


@pytest.mark.parametrize("change", ["superuser", "password", "group", "permission"])
def test_check_flags_anything_but_a_machine(issue, application, group, change):
    from django.contrib.auth.models import Permission

    issue(ADMIN)
    user = service_user(application)
    if change == "superuser":
        user.is_superuser = True
    elif change == "password":
        user.set_password("a password someone set")
    elif change == "group":
        user.groups.add(group)
    else:
        user.user_permissions.add(Permission.objects.first())
    user.save()
    assert service_checks() == ["django_access.E013"]
