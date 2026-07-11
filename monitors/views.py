import asyncio
from datetime import timedelta
from types import SimpleNamespace
from django.contrib import messages
from django.contrib.auth.decorators import login_required
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
    return render(request, "monitors/list.html", {"kind": kind, "title": config[2], "objects": config[0].objects.all()})

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
    subscriptions = list(XraySubscription.objects.prefetch_related("nodes"))
    nodes = [node for subscription in subscriptions for node in subscription.nodes.all()]
    now = timezone.now()
    hourly_by_node = {node.pk: [] for node in nodes}
    if hourly_by_node:
        hourly = XrayNodeSnapshot.objects.filter(
            node_id__in=hourly_by_node, kind="hourly", bucket_start__gte=now - timedelta(hours=15),
        ).order_by("-checked_at")
        for snapshot in hourly: hourly_by_node[snapshot.node_id].append(snapshot)
    targets = [("最近一次检查", None), ("约 6 小时前", now - timedelta(hours=6)), ("约 12 小时前", now - timedelta(hours=12))]
    for node in nodes:
        snapshots = hourly_by_node[node.pk]
        samples = []
        for label, target in targets:
            snapshot = snapshots[0] if snapshots and target is None else closest_snapshot(snapshots, target)
            samples.append(SimpleNamespace(label=label, snapshot=snapshot))
        node.sample_checks = samples
    yesterday = timezone.localdate() - timedelta(days=1)
    day_before = yesterday - timedelta(days=1)
    daily_ips = {node.pk: {} for node in nodes}
    if daily_ips:
        daily_results = XrayNodeSnapshot.objects.filter(
            node_id__in=daily_ips, kind="daily", bucket_start__gte=now - timedelta(days=3),
        )
        for result in daily_results:
            result_date = timezone.localtime(result.bucket_start).date()
            if result_date in {yesterday, day_before}: daily_ips[result.node_id][result_date] = result.proxy_ip
    for node in nodes:
        node.yesterday_ip = daily_ips[node.pk].get(yesterday)
        node.day_before_ip = daily_ips[node.pk].get(day_before)
    return render(request, "monitors/subscriptions.html", {"objects": subscriptions})

def closest_snapshot(snapshots, target):
    if not snapshots or target is None: return None
    closest = min(snapshots, key=lambda item: abs((item.checked_at - target).total_seconds()))
    return closest if abs((closest.checked_at - target).total_seconds()) <= 5400 else None

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
