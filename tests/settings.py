# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Standalone test settings: DATABASE_URL when set (CI / zeno), else sqlite in memory."""

import dj_database_url

SECRET_KEY = "not so secret test secret, long enough for HS256"  # noqa: S105 — test-only
DEBUG = True
ALLOWED_HOSTS = ["*"]
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "rest_framework",
    "rest_framework_simplejwt",
    "drf_spectacular",
    "django_access",
]
# The service's order (without corsheaders / allauth), the gate appended.
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "django_access.middleware.AccessGateMiddleware",
]
APPEND_SLASH = True  # Django's default, as in the service: path fuzzing relies on the redirect
ROOT_URLCONF = "tests.urls"
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ]
        },
    }
]
REST_FRAMEWORK = {
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "EXCEPTION_HANDLER": "django_utils.api.v2_errors.v2_exception_handler",
}
SPECTACULAR_SETTINGS = {"TITLE": "django-access Admin API v2", "VERSION": "2.0.0", "OAS_VERSION": "3.1.0"}
DATABASES = {"default": dj_database_url.config(default="sqlite://:memory:")}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
USE_TZ = True
CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
