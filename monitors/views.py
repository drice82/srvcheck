import asyncio
from datetime import timedelta
from types import SimpleNamespace
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Prefetch
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from .checkers import check_http, check_tcp, check_xray
from .forms import HTTPMonitorForm, NotificationSettingForm, TCPMonitorForm, XrayNodeForm, XraySubscriptionForm
from .models import CheckResult, HTTPMonitor, NotificationSetting, TCPMonitor, XrayNode, XrayNodeSnapshot, XraySubscription
from .services import save_outcome, save_subscription_result, synchronize_subscription

@login_required
def dashboard(request):
    context = dashboard_context()
    return render(request, "monitors/dashboard.html", context)

def dashboard_context():
    monitors = list(TCPMonitor.objects.all()) + list(HTTPMonitor.objects.all()) + list(XrayNode.objects.filter(active_in_subscription=True))
    return {
        "monitors": monitors,
        "counts": {key: sum(m.status == key for m in monitors) for key in ["up", "down", "unknown", "disabled"]},
        "recent": CheckResult.objects.all()[:10],
    }

@login_required
def dashboard_partial(request):
    return render(request, "monitors/_dashboard_content.html", dashboard_context())

@login_required
def monitor_list(request, kind):
    config = type_config(kind)
    objects = list(config[0].objects.all())
    prepare_check_result_status_bars(objects, kind, timezone.now())
    return render(request, "monitors/list.html", {"kind": kind, "title": config[2], "objects": objects})

@login_required
def monitor_form(request, kind, pk=None):
    model, form_class, title = type_config(kind)
    obj = get_object_or_404(model, pk=pk) if pk else None
    form = form_class(request.POST or None, instance=obj)
    if request.method == "POST" and form.is_valid():
        saved = form.save(commit=False)
        if not saved.enabled: saved.status = "disabled"
        elif saved.status == "disabled": saved.status = "unknown"
        saved.next_check_at = timezone.now()
        saved.save()
        messages.success(request, "配置已保存")
        return redirect("monitor-list", kind=kind)
    return render(request, "monitors/form.html", {"form": form, "title": f"{'编辑' if obj else '添加'}{title}", "kind": kind})

@login_required
def monitor_delete(request, kind, pk):
    model, _, _ = type_config(kind)
    obj = get_object_or_404(model, pk=pk)
    if request.method == "POST": obj.delete(); messages.success(request, "已删除")
    return redirect("monitor-list", kind=kind)

@login_required
def check_now(request, kind, pk):
    if request.method != "POST": return HttpResponse(status=405)
    model, checker = {"tcp": (TCPMonitor, check_tcp), "http": (HTTPMonitor, check_http), "xray": (XrayNode, check_xray)}[kind]
    obj = get_object_or_404(model, pk=pk)
    outcome = asyncio.run(checker(obj)); save_outcome(kind, obj, outcome)
    messages.success(request, "检查完成")
    return redirect(request.META.get("HTTP_REFERER") or "dashboard")

@login_required
def subscription_list(request):
    subscriptions = list(XraySubscription.objects.prefetch_related(
        Prefetch(
            "nodes",
            queryset=XrayNode.objects.filter(active_in_subscription=True),
            to_attr="active_nodes",
        )
    ))
    nodes = [node for subscription in subscriptions for node in subscription.active_nodes]
    now = timezone.now()
    prepare_xray_status_bars(nodes, now)
    return render(request, "monitors/subscriptions.html", {"objects": subscriptions})

def prepare_xray_status_bars(nodes, now):
    node_ids = [node.pk for node in nodes]
    current_hour = now.replace(minute=0, second=0, microsecond=0)
    hourly_starts = [current_hour - timedelta(hours=offset) for offset in range(23, -1, -1)]
    today = timezone.localdate(now)
    daily_dates = [today - timedelta(days=offset) for offset in range(7, 0, -1)]
    snapshots = XrayNodeSnapshot.objects.filter(
        node_id__in=node_ids,
        bucket_start__gte=timezone.localtime(now).replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=7),
    )
    hourly = {}
    daily = {}
    latest = {}
    for snapshot in snapshots:
        if snapshot.kind == "hourly":
            hourly[(snapshot.node_id, snapshot.bucket_start)] = snapshot
            if snapshot.node_id not in latest or snapshot.checked_at > latest[snapshot.node_id].checked_at:
                latest[snapshot.node_id] = snapshot
        else:
            daily[(snapshot.node_id, timezone.localtime(snapshot.bucket_start).date())] = snapshot
    for node in nodes:
        node.latest_snapshot = latest.get(node.pk)
        daily_bars = [
            status_bar(daily.get((node.pk, day)), day.strftime("%Y-%m-%d"), kind="daily")
            for day in daily_dates
        ]
        hourly_bars = [
            status_bar(hourly.get((node.pk, start)), timezone.localtime(start).strftime("%m-%d %H:00"), kind="hourly")
            for start in hourly_starts
        ]
        mark_ip_changes(daily_bars)
        mark_ip_changes(hourly_bars)
        node.status_bars = daily_bars + hourly_bars

def status_bar(snapshot, label, kind):
    status = "unknown" if snapshot is None else ("up" if snapshot.success else "down")
    return SimpleNamespace(snapshot=snapshot, label=label, kind=kind, status=status)

def prepare_check_result_status_bars(objects, kind, now):
    current_hour = now.replace(minute=0, second=0, microsecond=0)
    hourly_starts = [current_hour - timedelta(hours=offset) for offset in range(23, -1, -1)]
    today = timezone.localdate(now)
    daily_dates = [today - timedelta(days=offset) for offset in range(7, 0, -1)]
    cutoff = timezone.localtime(now).replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=7)
    results = CheckResult.objects.filter(
        monitor_type=kind, monitor_id__in=[obj.pk for obj in objects], checked_at__gte=cutoff,
    ).only("monitor_id", "success", "checked_at").order_by("checked_at")
    hourly = {}
    daily = {}
    for result in results:
        hour = result.checked_at.replace(minute=0, second=0, microsecond=0)
        hourly[(result.monitor_id, hour)] = result
        daily[(result.monitor_id, timezone.localtime(result.checked_at).date())] = result
    for obj in objects:
        obj.status_bars = [
            status_bar(daily.get((obj.pk, day)), day.strftime("%Y-%m-%d"), "daily")
            for day in daily_dates
        ] + [
            status_bar(hourly.get((obj.pk, start)), timezone.localtime(start).strftime("%m-%d %H:00"), "hourly")
            for start in hourly_starts
        ]

def mark_ip_changes(bars):
    previous_ip = None
    for bar in bars:
        if bar.status != "up" or not bar.snapshot.proxy_ip:
            continue
        if previous_ip is not None and bar.snapshot.proxy_ip != previous_ip:
            bar.status = "changed"
        previous_ip = bar.snapshot.proxy_ip

@login_required
def node_form(request, pk):
    obj = get_object_or_404(XrayNode, pk=pk)
    form = XrayNodeForm(request.POST or None, instance=obj)
    if request.method == "POST" and form.is_valid():
        node = form.save(commit=False)
        node.status = "unknown" if node.enabled else "disabled"
        node.next_check_at = timezone.now() if node.enabled else None
        node.consecutive_successes = node.consecutive_failures = 0
        node.save()
        messages.success(request, "节点已保存；下次订阅更新会按订阅内容覆盖")
        return redirect("subscriptions")
    return render(request, "monitors/form.html", {"form": form, "title": f"编辑节点：{obj.name}", "kind": "xray"})

@login_required
def subscription_form(request, pk=None):
    obj = get_object_or_404(XraySubscription, pk=pk) if pk else None
    form = XraySubscriptionForm(request.POST or None, instance=obj)
    if request.method == "POST" and form.is_valid():
        saved = form.save(); saved.next_sync_at = timezone.now(); saved.save(update_fields=["next_sync_at"])
        return redirect("subscriptions")
    return render(request, "monitors/form.html", {"form": form, "title": "Xray 订阅", "kind": "xray"})

@login_required
def subscription_delete(request, pk):
    obj = get_object_or_404(XraySubscription, pk=pk)
    if request.method == "POST": obj.delete()
    return redirect("subscriptions")

@login_required
def subscription_sync(request, pk):
    obj = get_object_or_404(XraySubscription, pk=pk)
    if request.method == "POST":
        nodes, error = asyncio.run(synchronize_subscription(obj)); save_subscription_result(obj, nodes, error)
        messages.success(request, "同步完成" if not error else f"同步失败：{error}")
    return redirect("subscriptions")

@login_required
def settings_view(request):
    obj = NotificationSetting.get_solo(); form = NotificationSettingForm(request.POST or None, instance=obj)
    if request.method == "POST" and form.is_valid(): form.save(); messages.success(request, "设置已保存"); return redirect("settings")
    return render(request, "monitors/form.html", {"form": form, "title": "通知设置", "kind": "settings"})

def type_config(kind):
    return {"tcp": (TCPMonitor, TCPMonitorForm, "TCP 监控"), "http": (HTTPMonitor, HTTPMonitorForm, "HTTPS 监控")}[kind]
