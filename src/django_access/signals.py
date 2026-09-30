# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Cache invalidation for changes made outside ``access_service``: group membership, user flags, cascaded grants."""

from django.contrib.auth import get_user_model
from django.db.models.signals import m2m_changed, post_delete, pre_save

from django_access.models import Grant
from django_access.services.permissions import bump_version

ACCESS_FLAGS = ("is_staff", "is_superuser", "is_active")
MEMBERSHIP_ACTIONS = frozenset({"post_add", "post_remove", "post_clear"})


def _membership_changed(sender, action: str, **kwargs) -> None:
    if action in MEMBERSHIP_ACTIONS:
        bump_version()


def _flags_changed(instance) -> bool:
    stored = type(instance)._default_manager.filter(pk=instance.pk).values(*ACCESS_FLAGS).first()
    return stored is not None and any(stored[flag] != getattr(instance, flag) for flag in ACCESS_FLAGS)


def _user_saving(sender, instance, update_fields=None, **kwargs) -> None:
    if update_fields is not None and not set(update_fields) & set(ACCESS_FLAGS):
        return
    if instance.pk is not None and _flags_changed(instance):
        bump_version()


def _grant_deleted(sender, **kwargs) -> None:
    bump_version()


def connect() -> None:
    user_model = get_user_model()
    m2m_changed.connect(_membership_changed, sender=user_model.groups.through, dispatch_uid="django_access_groups")
    pre_save.connect(_user_saving, sender=user_model, dispatch_uid="django_access_user_flags")
    post_delete.connect(_grant_deleted, sender=Grant, dispatch_uid="django_access_grant_deleted")
