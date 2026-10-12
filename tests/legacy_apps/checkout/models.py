# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
from django.db import models


class Channel(models.Model):
    idx = models.CharField(max_length=128, unique=True)


class APIAdminKey(models.Model):
    channel = models.ForeignKey(Channel, null=True, on_delete=models.CASCADE)
    key = models.CharField(max_length=128, editable=False)


class APIKey(models.Model):
    channel = models.ForeignKey(Channel, null=True, on_delete=models.CASCADE)
    key = models.CharField(max_length=128, editable=False)
