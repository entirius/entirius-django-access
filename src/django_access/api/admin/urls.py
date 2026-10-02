# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Access admin API URL routing — manual `path()` per Volkanos convention (applications and tokens: plan 07)."""

from django.urls import path

from django_access.api.admin.views import audit, catalogue, grants, roles, staff

urlpatterns = [
    path("catalogue/", catalogue.CatalogueView.as_view(), name="admin-access-catalogue"),
    path("roles/", roles.RoleListView.as_view(), name="admin-access-roles"),
    path("roles/<int:pk>/", roles.RoleDetailView.as_view(), name="admin-access-role"),
    path("grants/", grants.GrantListView.as_view(), name="admin-access-grants"),
    path("grants/<int:pk>/", grants.GrantDetailView.as_view(), name="admin-access-grant"),
    path("staff/", staff.StaffListView.as_view(), name="admin-access-staff"),
    path("staff/<int:user_id>/", staff.StaffDetailView.as_view(), name="admin-access-staff-user"),
    path("groups/", staff.GroupListView.as_view(), name="admin-access-groups"),
    path("audit/", audit.AuditListView.as_view(), name="admin-access-audit"),
]
