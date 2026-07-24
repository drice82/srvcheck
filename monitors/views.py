import asyncio
from datetime import timedelta
from types import SimpleNamespace

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Max, Prefetch
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


def latest_client_results(fk, target_ids, result_type=None):
    """Fetch only the newest result per (target, test_point) group.

    The subquery groups on the covering client_result_*_idx indexes, so the
    page never has to load the full result history into Python.
    """
    filters = {f"{fk}_id__in": target_ids}
    if result_type is not None:
        filters["result_type"] = result_type
    latest_ids = (
        ClientResult.objects.filter(**filters)
        .values(f"{fk}_id", "test_point_id")
        .order_by()
        .annotate(latest_id=Max("id"))
        .values_list("latest_id", flat=True)
    )
    return ClientResult.objects.filter(pk__in=latest_ids).select_related("test_point")


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
    local_tz = timezone.get_current_timezone()
    hourly_columns = [(start, start.astimezone(local_tz).strftime("%m-%d %H:00")) for start in hourly_starts]
    daily_columns = [(day, day.strftime("%Y-%m-%d")) for day in daily_dates]
    if kind == "xray":
        snapshots = XrayNodeSnapshot.objects.filter(
            node_id__in=target_ids, bucket_start__gte=cutoff
        )
        target_key = lambda snapshot: snapshot.node_id
        recent = latest_client_results("node", target_ids, ClientResult.ResultType.CHECK)
        result_key = lambda result: result.node_id
    else:
        fk = f"{kind}_monitor"
        snapshots = MonitorSnapshot.objects.filter(
            **{f"{fk}_id__in": target_ids}, bucket_start__gte=cutoff
        )
        target_key = lambda snapshot: getattr(snapshot, f"{fk}_id")
        recent = latest_client_results(fk, target_ids)
        result_key = lambda result: getattr(result, f"{fk}_id")
    hourly, daily = {}, {}
    for snapshot in snapshots:
        if snapshot.kind == XrayNodeSnapshot.Kind.HOURLY:
            hourly[(target_key(snapshot), snapshot.test_point_id, snapshot.bucket_start)] = snapshot
        else:
            daily[(target_key(snapshot), snapshot.test_point_id, snapshot.bucket_start.astimezone(local_tz).date())] = snapshot

    latest = {}
    for result in recent:
        latest.setdefault((result_key(result), result.test_point_id), result)

    latest_speed = {}
    if kind == "xray":
        speed_results = latest_client_results("node", target_ids, ClientResult.ResultType.SPEED)
        for result in speed_results:
            latest_speed.setdefault((result.node_id, result.test_point_id), result)

    for target in targets:
        daily_bars = [make_bucket(target.pk, points, daily, day, label, "daily") for day, label in daily_columns]
        hourly_bars = [
            make_bucket(target.pk, points, hourly, start, label, "hourly")
            for start, label in hourly_columns
        ]
        latest_bar = make_latest_bucket(target.pk, points, latest)
        target.status_bars = daily_bars + hourly_bars + [latest_bar]
        if kind == "xray":
            mark_ip_changes(target.status_bars, points)
        finalize_status_bars(target.status_bars, local_tz)
        # One fixed-height summary line per test point, so every node card has
        # the same height and speed results never add extra lines.
        target.point_summaries = [
            build_point_summary(
                point,
                latest.get((target.pk, point.pk)),
                latest_speed.get((target.pk, point.pk)),
                local_tz,
                kind,
            )
            for point in points
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


SEGMENT_CSS = {"up": "bg-emerald-500", "changed": "bg-amber-400", "down": "bg-red-500"}
SEGMENT_TEXT = {"up": "正常", "changed": "正常，IP 变化", "down": "异常"}


def finalize_status_bars(bars, local_tz):
    # Pre-render the per-segment CSS class and tooltip. The template loops over
    # thousands of segments, so doing this here keeps the hot loop cheap.
    for bar in bars:
        for segment in bar.segments:
            segment.css_class = SEGMENT_CSS.get(segment.status, "bg-slate-300")
            title = f"{bar.label} · {segment.test_point.name} · {SEGMENT_TEXT.get(segment.status, '暂无数据')}"
            snapshot = segment.snapshot
            if snapshot is not None:
                checked = snapshot.checked_at.astimezone(local_tz).strftime("%H:%M")
                proxy_ip = getattr(snapshot, "proxy_ip", None) or "无"
                latency = snapshot.latency_ms if snapshot.latency_ms is not None else "-"
                title += f" · {checked} · IP {proxy_ip} · {latency} ms"
                if snapshot.message:
                    title += f" · {snapshot.message}"
            segment.title = title


def build_point_summary(point, check, speed, local_tz, kind):
    summary = SimpleNamespace(
        point=point, check=check, speed=speed, status="unknown", detail="", speed_text=""
    )
    lines = []
    if check is None:
        lines.append(f"{point.name} · 暂无检查数据")
    else:
        summary.status = "up" if check.success else "down"
        status_text = "正常" if check.success else "异常"
        checked = check.checked_at.astimezone(local_tz).strftime("%H:%M")
        latency = check.latency_ms if check.latency_ms is not None else "-"
        if kind == "xray":
            summary.detail = check.proxy_ip or "—"
            lines.append(f"{point.name} · 检查{status_text} · {checked} · IP {summary.detail} · {latency} ms")
        else:
            summary.detail = f"{latency} ms"
            lines.append(f"{point.name} · 检查{status_text} · {checked} · {latency} ms")
        if check.message:
            lines[-1] += f" · {check.message}"
    if speed is not None:
        checked = speed.checked_at.astimezone(local_tz).strftime("%H:%M")
        ok = speed.success and speed.download_mbps is not None
        summary.speed_text = f"{speed.download_mbps:.2f} Mbps" if ok else "失败"
        lines.append(f"{point.name} · 测速 {summary.speed_text} · {checked}")
    summary.title = "\n".join(lines)
    return summary


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
