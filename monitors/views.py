import asyncio
from datetime import timedelta
from types import SimpleNamespace

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Prefetch
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from .forms import (
    HTTPSMonitorForm,
    NotificationSettingForm,
    TCPMonitorForm,
    TestPointForm,
    XrayNodeForm,
    XraySubscriptionForm,
)
from .models import (
    ClientResult,
    ManualCheckTask,
    MonitorSnapshot,
    NotificationSetting,
    TestPoint,
    XrayNode,
    XrayNodeSnapshot,
    XraySubscription,
    target_model_for_kind,
)
from .services import (
    aggregate_all,
    aggregate_all_nodes,
    create_manual_check,
    save_subscription_result,
    synchronize_subscription,
)


@login_required
def dashboard(request):
    return render(request, "monitors/dashboard.html", dashboard_context())


def dashboard_context():
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
    return {
        "nodes": nodes,
        "objects": subscriptions,
        "test_points": list(TestPoint.objects.filter(enabled=True)),
        "counts": {key: sum(node.status == key for node in nodes) for key in ["up", "down", "unknown", "disabled"]},
    }


@login_required
def dashboard_partial(request):
    return render(request, "monitors/_dashboard_content.html", dashboard_context())


@login_required
def subscription_list(request):
    return redirect("dashboard")


def prepare_xray_status_bars(nodes, now):
    prepare_status_bars(nodes, now, "xray")


def prepare_status_bars(targets, now, kind):
    points = list(TestPoint.objects.filter(enabled=True))
    target_ids = [target.pk for target in targets]
    current_hour = now.replace(minute=0, second=0, microsecond=0)
    # The rightmost column is reserved for the live/latest result. The hourly
    # columns therefore end at the previous completed hour.
    hourly_starts = [current_hour - timedelta(hours=offset) for offset in range(23, 0, -1)]
    today = timezone.localdate(now)
    daily_dates = [today - timedelta(days=offset) for offset in range(7, 0, -1)]
    cutoff = timezone.localtime(now).replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=7)
    if kind == "xray":
        snapshots = XrayNodeSnapshot.objects.filter(
            node_id__in=target_ids, bucket_start__gte=cutoff
        ).select_related("test_point")
        target_key = lambda snapshot: snapshot.node_id
        recent = ClientResult.objects.filter(
            node_id__in=target_ids, result_type=ClientResult.ResultType.CHECK
        ).select_related("test_point").order_by("node_id", "test_point_id", "-received_at")
        result_key = lambda result: result.node_id
    else:
        fk = f"{kind}_monitor"
        snapshots = MonitorSnapshot.objects.filter(
            **{f"{fk}_id__in": target_ids}, bucket_start__gte=cutoff
        ).select_related("test_point")
        target_key = lambda snapshot: getattr(snapshot, f"{fk}_id")
        recent = ClientResult.objects.filter(**{f"{fk}_id__in": target_ids}).select_related("test_point").order_by(f"{fk}_id", "test_point_id", "-received_at")
        result_key = lambda result: getattr(result, f"{fk}_id")
    hourly, daily = {}, {}
    for snapshot in snapshots:
        if snapshot.kind == XrayNodeSnapshot.Kind.HOURLY:
            hourly[(target_key(snapshot), snapshot.test_point_id, snapshot.bucket_start)] = snapshot
        else:
            daily[(target_key(snapshot), snapshot.test_point_id, timezone.localtime(snapshot.bucket_start).date())] = snapshot

    latest = {}
    for result in recent:
        latest.setdefault((result_key(result), result.test_point_id), result)

    for target in targets:
        daily_bars = [make_bucket(target.pk, points, daily, day, day.strftime("%Y-%m-%d"), "daily") for day in daily_dates]
        hourly_bars = [
            make_bucket(target.pk, points, hourly, start, timezone.localtime(start).strftime("%m-%d %H:00"), "hourly")
            for start in hourly_starts
        ]
        latest_bar = make_latest_bucket(target.pk, points, latest)
        target.status_bars = daily_bars + hourly_bars + [latest_bar]
        if kind == "xray":
            mark_ip_changes(target.status_bars, points)
        target.latest_results = [latest[(target.pk, point.pk)] for point in points if (target.pk, point.pk) in latest]

    if kind == "xray":
        latest_speed = {}
        speed_results = ClientResult.objects.filter(
            node_id__in=target_ids, result_type=ClientResult.ResultType.SPEED
        ).select_related("test_point").order_by("node_id", "test_point_id", "-received_at")
        for result in speed_results:
            latest_speed.setdefault((result.node_id, result.test_point_id), result)
        for target in targets:
            target.latest_speed_results = [
                latest_speed[(target.pk, point.pk)]
                for point in points if (target.pk, point.pk) in latest_speed
            ]


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
        return redirect("dashboard")
    return render(request, "monitors/form.html", {"form": form, "title": "Xray 订阅", "kind": "xray"})


@login_required
def subscription_delete(request, pk):
    obj = get_object_or_404(XraySubscription, pk=pk)
    if request.method == "POST":
        obj.delete()
    return redirect("dashboard")


@login_required
def subscription_sync(request, pk):
    obj = get_object_or_404(XraySubscription, pk=pk)
    if request.method == "POST":
        nodes, error = asyncio.run(synchronize_subscription(obj))
        save_subscription_result(obj, nodes, error)
        messages.success(request, "同步完成" if not error else f"同步失败：{error}")
    return redirect("dashboard")


@login_required
def check_now(request, pk):
    if request.method != "POST":
        return HttpResponse(status=405)
    node = get_object_or_404(
        XrayNode, pk=pk, active_in_subscription=True, enabled=True, subscription__enabled=True
    )
    task = create_manual_check(node)
    count = task.assignments.count()
    messages.success(request, f"已向 {count} 个测试点下发检查任务")
    return redirect(request.META.get("HTTP_REFERER") or "dashboard")


@login_required
def speed_test_now(request, pk):
    if request.method != "POST":
        return HttpResponse(status=405)
    node = get_object_or_404(
        XrayNode, pk=pk, active_in_subscription=True, enabled=True, subscription__enabled=True
    )
    task = create_manual_check(node, ManualCheckTask.TaskType.SPEED)
    messages.success(request, f"已向 {task.assignments.count()} 个测试点下发该节点的测速任务")
    return redirect(request.META.get("HTTP_REFERER") or "dashboard")


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
        return redirect("dashboard")
    return render(request, "monitors/form.html", {"form": form, "title": f"编辑节点：{node.name}", "kind": "xray"})


MONITOR_PAGE_META = {
    "tcp": {"title": "TCP 监控", "form": TCPMonitorForm},
    "https": {"title": "HTTPS 监控", "form": HTTPSMonitorForm},
}


def monitor_page_context(kind):
    model = target_model_for_kind(kind)
    objects = list(model.objects.all())
    prepare_status_bars(objects, timezone.now(), kind)
    return {
        "kind": kind,
        "objects": objects,
        "test_points": list(TestPoint.objects.filter(enabled=True)),
        "counts": {key: sum(obj.status == key for obj in objects) for key in ["up", "down", "unknown", "disabled"]},
        "page_title": MONITOR_PAGE_META[kind]["title"],
        "new_url": f"{kind}-new",
        "edit_url": f"{kind}-edit",
        "delete_url": f"{kind}-delete",
        "check_url": f"{kind}-check",
        "partial_url": f"{kind}-partial",
    }


@login_required
def monitor_page(request, kind):
    return render(request, "monitors/monitor_page.html", monitor_page_context(kind))


@login_required
def monitor_partial(request, kind):
    return render(request, "monitors/_monitor_content.html", monitor_page_context(kind))


@login_required
def monitor_form(request, kind, pk=None):
    model = target_model_for_kind(kind)
    obj = get_object_or_404(model, pk=pk) if pk else None
    form = MONITOR_PAGE_META[kind]["form"](request.POST or None, instance=obj)
    if request.method == "POST" and form.is_valid():
        saved = form.save(commit=False)
        if obj:
            # Same rule as node edits: previous raw results must not take part
            # in consensus for the changed endpoint, buckets stay visible.
            saved.status = model.Status.UNKNOWN
            saved.incident_open = False
            saved.last_checked_at = None
            saved.last_changed_at = timezone.now()
        saved.save()
        if obj:
            ClientResult.objects.filter(**{f"{kind}_monitor": saved}).delete()
        task = create_manual_check(saved)
        messages.success(request, f"监控已保存，并已向 {task.assignments.count()} 个测试点下发检查任务")
        return redirect(f"{kind}-monitors")
    title = MONITOR_PAGE_META[kind]["title"]
    return render(request, "monitors/form.html", {"form": form, "title": title, "kind": kind})


@login_required
def monitor_delete(request, kind, pk):
    obj = get_object_or_404(target_model_for_kind(kind), pk=pk)
    if request.method == "POST":
        obj.delete()
    return redirect(f"{kind}-monitors")


@login_required
def monitor_check_now(request, kind, pk):
    if request.method != "POST":
        return HttpResponse(status=405)
    monitor = get_object_or_404(target_model_for_kind(kind), pk=pk, enabled=True)
    task = create_manual_check(monitor)
    messages.success(request, f"已向 {task.assignments.count()} 个测试点下发检查任务")
    return redirect(request.META.get("HTTP_REFERER") or f"{kind}-monitors")


@login_required
def test_point_list(request):
    return render(request, "monitors/test_points.html", {"objects": TestPoint.objects.all()})


@login_required
def test_point_form(request, pk=None):
    obj = get_object_or_404(TestPoint, pk=pk) if pk else None
    form = TestPointForm(request.POST or None, instance=obj)
    if request.method == "POST" and form.is_valid():
        form.save()
        aggregate_all()
        messages.success(request, "测试点已保存")
        return redirect("test-points")
    return render(request, "monitors/form.html", {"form": form, "title": "测试点", "kind": "test-point"})


@login_required
def test_point_delete(request, pk):
    point = get_object_or_404(TestPoint, pk=pk)
    if request.method == "POST":
        point.delete()
        aggregate_all()
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
