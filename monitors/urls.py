from django.urls import path
from . import views
urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("partials/dashboard/", views.dashboard_partial, name="dashboard-partial"),
    path("monitors/<str:kind>/", views.monitor_list, name="monitor-list"),
    path("monitors/<str:kind>/new/", views.monitor_form, name="monitor-new"),
    path("monitors/<str:kind>/<int:pk>/edit/", views.monitor_form, name="monitor-edit"),
    path("monitors/<str:kind>/<int:pk>/delete/", views.monitor_delete, name="monitor-delete"),
    path("monitors/<str:kind>/<int:pk>/check/", views.check_now, name="check-now"),
    path("subscriptions/", views.subscription_list, name="subscriptions"),
    path("subscriptions/new/", views.subscription_form, name="subscription-new"),
    path("subscriptions/<int:pk>/edit/", views.subscription_form, name="subscription-edit"),
    path("subscriptions/<int:pk>/delete/", views.subscription_delete, name="subscription-delete"),
    path("subscriptions/<int:pk>/sync/", views.subscription_sync, name="subscription-sync"),
    path("nodes/<int:pk>/edit/", views.node_form, name="node-edit"),
    path("settings/", views.settings_view, name="settings"),
]
