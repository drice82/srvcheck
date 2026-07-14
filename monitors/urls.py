from django.urls import path

from . import api, views

urlpatterns = [
    path("api/v1/client/manifest", api.manifest, name="client-manifest"),
    path("api/v1/client/tasks", api.tasks, name="client-tasks"),
    path("api/v1/client/results", api.results, name="client-results"),
    path("", views.dashboard, name="dashboard"),
    path("partials/dashboard/", views.dashboard_partial, name="dashboard-partial"),
    path("subscriptions/", views.subscription_list, name="subscriptions"),
    path("subscriptions/new/", views.subscription_form, name="subscription-new"),
    path("subscriptions/<int:pk>/edit/", views.subscription_form, name="subscription-edit"),
    path("subscriptions/<int:pk>/delete/", views.subscription_delete, name="subscription-delete"),
    path("subscriptions/<int:pk>/sync/", views.subscription_sync, name="subscription-sync"),
    path("nodes/<int:pk>/edit/", views.node_form, name="node-edit"),
    path("nodes/<int:pk>/check/", views.check_now, name="check-now"),
    path("test-points/", views.test_point_list, name="test-points"),
    path("test-points/new/", views.test_point_form, name="test-point-new"),
    path("test-points/<int:pk>/edit/", views.test_point_form, name="test-point-edit"),
    path("test-points/<int:pk>/delete/", views.test_point_delete, name="test-point-delete"),
    path("settings/", views.settings_view, name="settings"),
]
