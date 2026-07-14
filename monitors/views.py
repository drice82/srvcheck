import asyncio
from datetime import timedelta
from types import SimpleNamespace

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Prefetch
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from .forms import NotificationSettingForm, TestPointForm, XrayNodeForm, XraySubscriptionForm
from .models import ClientResult, NotificationSetting, TestPoint, XrayNode, XrayNodeSnapshot, XraySubscription
from .services import (
    aggregate_all_nodes,
    create_manual_check,
    save_subscription_result,
    synchronize_subscription,
)


@login_required
def dashboard(request):
    return render(request, "monitors/dashboard.html", dashboard_context())


def dashboard_context():
    nodes = list(XrayNode.objects.filter(active_in_subscription=True).select_related("subscription"))
    return {
        "nodes": nodes,
        "test_points": TestPoint.objects.all(),
        "counts": {key: sum(node.status == key for node in nodes) for key in ["up", "down", "unknown", "disabled"]},
    }


@login_required
def dashboard_partial(request):
    return render(request, "monitors/_dashboard_content.html", dashboard_context())


@login_required
def subscription_list(request):
    subscriptions = list(
        XraySubscription.objects.prefetch_related(
            Prefetch(
                "nodes",
                queryset=XrayNode.objects.filter(active_in_subscription=True).select_related("subscription"),
                to_attr="active_nodes",
            )
        )
    )
    nodes = [node for subscription in subscriptions for node in subscription.active_nodes]
    prepare_xray_status_bars(nodes, timezone.now())
    return render(
        request,
        "monitors/subscriptions.html",
        {"objects": subscriptions, "test_points": list(TestPoint.objects.filter(enabled=True))},
    )


def prepare_xray_status_bars(nodes, now):
    points = list(TestPoint.objects.filter(enabled=True))
    node_ids = [node.pk for node in nodes]
    current_hour = now.replace(minute=0, second=0, microsecond=0)
    # The rightmost column is reserved for the live/latest result. The hourly
    # columns therefore end at the previous completed hour.
    hourly_starts = [current_hour - timedelta(hours=offset) for offset in range(23, 0, -1)]
    today = timezone.localdate(now)
    daily_dates = [today - timedelta(days=offset) for offset in range(7, 0, -1)]
    cutoff = timezone.localtime(now).replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=7)
    snapshots = XrayNodeSnapshot.objects.filter(node_id__in=node_ids, bucket_start__gte=cutoff).select_related("test_point")
    hourly, daily = {}, {}
    for snapshot in snapshots:
        if snapshot.kind == XrayNodeSnapshot.Kind.HOURLY:
            hourly[(snapshot.node_id, snapshot.test_point_id, snapshot.bucket_start)] = snapshot
        else:
            daily[(snapshot.node_id, snapshot.test_point_id, timezone.localtime(snapshot.bucket_start).date())] = snapshot

    recent = ClientResult.objects.filter(node_id__in=node_ids).select_related("test_point").order_by("node_id", "test_point_id", "-received_at")
    latest = {}
    for result in recent:
        latest.setdefault((result.node_id, result.test_point_id), result)

    for node in nodes:
        daily_bars = [make_bucket(node.pk, points, daily, day, day.strftime("%Y-%m-%d"), "daily") for day in daily_dates]
        hourly_bars = [
            make_bucket(node.pk, points, hourly, start, timezone.localtime(start).strftime("%m-%d %H:00"), "hourly")
            for start in hourly_starts
        ]
        latest_bar = make_latest_bucket(node.pk, points, latest)
        node.status_bars = daily_bars + hourly_bars + [latest_bar]
        mark_ip_changes(node.status_bars, points)
        node.latest_results = [latest[(node.pk, point.pk)] for point in points if (node.pk, point.pk) in latest]


def make_bucket(node_id, points, source, bucket, label, kind):
    segments = []
    for point in points:
        snapshot = source.get((node_id, point.pk, bucket))
        segments.append(
            SimpleNamespace(
                test_point=point,
                snapshot=snapshot,
                status="unknown" if snapshot is None else "up" if snapshot.success else "down",
            )
        )
    return SimpleNamespace(label=label, kind=kind, segments=segments)


def make_latest_bucket(node_id, points, latest):
    segments = []
    for point in points:
        result = latest.get((node_id, point.pk))
        segments.append(
            SimpleNamespace(
                test_point=point,
                snapshot=result,
                status="unknown" if result is None else "up" if result.success else "down",
            )
        )
    return SimpleNamespace(label="最近一次", kind="latest", segments=segments)


def mark_ip_changes(bars, points):
    previous = {point.pk: None for point in points}
    for bar in bars:
        for segment in bar.segments:
            snapshot = segment.snapshot
            if segment.status != "up" or not snapshot.proxy_ip:
                continue
            old_ip = previous[segment.test_point.pk]
            if old_ip is not None and snapshot.proxy_ip != old_ip:
                segment.status = "changed"
            previous[segment.test_point.pk] = snapshot.proxy_ip


@login_required
def subscription_form(request, pk=None):
    obj = get_object_or_404(XraySubscription, pk=pk) if pk else None
    form = XraySubscriptionForm(request.POST or None, instance=obj)
    if request.method == "POST" and form.is_valid():
        saved = form.save()
        saved.next_sync_at = timezone.now()
        saved.save(update_fields=["next_sync_at"])
        aggregate_all_nodes()
        return redirect("subscriptions")
    return render(request, "monitors/form.html", {"form": form, "title": "Xray 订阅", "kind": "xray"})


@login_required
def subscription_delete(request, pk):
    obj = get_object_or_404(XraySubscription, pk=pk)
    if request.method == "POST":
        obj.delete()
    return redirect("subscriptions")


@login_required
def subscription_sync(request, pk):
    obj = get_object_or_404(XraySubscription, pk=pk)
    if request.method == "POST":
        nodes, error = asyncio.run(synchronize_subscription(obj))
        save_subscription_result(obj, nodes, error)
        messages.success(request, "同步完成" if not error else f"同步失败：{error}")
    return redirect("subscriptions")


@login_required
def check_now(request, pk):
    if request.method != "POST":
        return HttpResponse(status=405)
    node = get_object_or_404(XrayNode, pk=pk, active_in_subscription=True, enabled=True)
    task = create_manual_check(node)
    count = task.assignments.count()
    messages.success(request, f"已向 {count} 个测试点下发检查任务")
    return redirect(request.META.get("HTTP_REFERER") or "subscriptions")


@login_required
def node_form(request, pk):
    node = get_object_or_404(XrayNode, pk=pk, active_in_subscription=True)
    form = XrayNodeForm(request.POST or None, instance=node)
    if request.method == "POST" and form.is_valid():
        saved = form.save(commit=False)
        # Keep the subscription fingerprint as the stable identity. The next
        # subscription sync will match it and naturally overwrite this edit.
        saved.protocol = form.parsed_node["protocol"]
        saved.enabled = True
        saved.status = XrayNode.Status.UNKNOWN
        saved.incident_open = False
        saved.last_checked_at = None
        saved.last_changed_at = timezone.now()
        saved.save()
        # Historical buckets remain visible, but pre-edit raw results must not
        # participate in consensus for the newly edited endpoint.
        ClientResult.objects.filter(node=saved).delete()
        task = create_manual_check(saved)
        messages.success(request, f"节点已保存，并已向 {task.assignments.count()} 个测试点下发检查任务")
        return redirect("subscriptions")
    return render(request, "monitors/form.html", {"form": form, "title": f"编辑节点：{node.name}", "kind": "xray"})


@login_required
def test_point_list(request):
    return render(request, "monitors/test_points.html", {"objects": TestPoint.objects.all()})


@login_required
def test_point_form(request, pk=None):
    obj = get_object_or_404(TestPoint, pk=pk) if pk else None
    form = TestPointForm(request.POST or None, instance=obj)
    if request.method == "POST" and form.is_valid():
        form.save()
        aggregate_all_nodes()
        messages.success(request, "测试点已保存")
        return redirect("test-points")
    return render(request, "monitors/form.html", {"form": form, "title": "测试点", "kind": "test-point"})


@login_required
def test_point_delete(request, pk):
    point = get_object_or_404(TestPoint, pk=pk)
    if request.method == "POST":
        point.delete()
        aggregate_all_nodes()
    return redirect("test-points")


@login_required
def settings_view(request):
    obj = NotificationSetting.get_solo()
    form = NotificationSettingForm(request.POST or None, instance=obj)
    if request.method == "POST" and form.is_valid():
        form.save()
        messages.success(request, "设置已保存")
        return redirect("settings")
    return render(request, "monitors/form.html", {"form": form, "title": "通知设置", "kind": "settings"})
