import asyncio
import hashlib
import json
from datetime import timedelta, timezone as datetime_timezone
from urllib.parse import quote

import httpx
from django.conf import settings
from django.db import transaction
from django.utils import timezone

from .checkers import decode_subscription
from .models import (
    ClientResult,
    HTTPSMonitor,
    ManualCheckAssignment,
    ManualCheckTask,
    MonitorSnapshot,
    NotificationLog,
    NotificationSetting,
    TCPMonitor,
    TestPoint,
    XrayNode,
    XrayNodeSnapshot,
    XraySubscription,
    target_model_for_kind,
)


async def synchronize_subscription(subscription):
    try:
        async with httpx.AsyncClient(
            timeout=subscription.timeout_seconds,
            follow_redirects=True,
            headers={"User-Agent": "SrvCheck/2.0"},
        ) as client:
            response = await client.get(subscription.url)
            response.raise_for_status()
        nodes = decode_subscription(response.text)[1:]
        if not nodes:
            raise ValueError("订阅去掉首个信息节点后没有可用节点")
        return nodes, ""
    except Exception as exc:
        return [], f"{type(exc).__name__}: {str(exc)[:400]}"


@transaction.atomic
def save_subscription_result(subscription, nodes, error):
    XraySubscription.objects.select_for_update().get(pk=subscription.pk)
    now = timezone.now()
    subscription.last_synced_at = now
    subscription.next_sync_at = now + timedelta(minutes=subscription.update_interval_minutes)
    subscription.last_error = error
    subscription.save(update_fields=["last_synced_at", "next_sync_at", "last_error"])
    if error:
        return

    existing = list(subscription.nodes.select_for_update())
    unused = {obj.pk: obj for obj in existing}
    incoming_identity_counts = {}
    for data in nodes:
        identity = (data["protocol"], data["name"])
        incoming_identity_counts[identity] = incoming_identity_counts.get(identity, 0) + 1

    matched = []
    for data in nodes:
        obj = next((item for item in unused.values() if item.fingerprint == data["fingerprint"]), None)
        identity = (data["protocol"], data["name"])
        if obj is None and incoming_identity_counts[identity] == 1:
            candidates = [item for item in unused.values() if (item.protocol, item.name) == identity]
            if len(candidates) == 1:
                obj = candidates[0]
        if obj is None:
            obj = XrayNode(subscription=subscription)
        else:
            unused.pop(obj.pk, None)
        obj.name = data["name"]
        obj.share_link = data["share_link"]
        obj.protocol = data["protocol"]
        obj.fingerprint = data["fingerprint"]
        obj.active_in_subscription = True
        obj.enabled = True
        if obj.status == XrayNode.Status.DISABLED:
            obj.status = XrayNode.Status.UNKNOWN
        obj.save()
        matched.append(obj.pk)

    subscription.nodes.exclude(pk__in=matched).update(
        active_in_subscription=False, enabled=False, status=XrayNode.Status.DISABLED, incident_open=False
    )


def manifest_payload():
    nodes = XrayNode.objects.filter(
        active_in_subscription=True, enabled=True, subscription__enabled=True
    ).select_related("subscription").order_by("pk")
    items = [
        {
            "id": node.pk,
            "kind": "xray",
            "fingerprint": node.fingerprint,
            "name": node.name,
            "protocol": node.protocol,
            "share_link": node.share_link,
            "check_interval_seconds": node.subscription.check_interval_seconds,
            "timeout_seconds": node.subscription.timeout_seconds,
        }
        for node in nodes
    ]
    tcp_items = [
        {
            "id": monitor.pk,
            "kind": "tcp",
            "name": monitor.name,
            "host": monitor.host,
            "port": monitor.port,
            "check_interval_seconds": monitor.check_interval_seconds,
            "timeout_seconds": monitor.timeout_seconds,
        }
        for monitor in TCPMonitor.objects.filter(enabled=True).order_by("pk")
    ]
    https_items = [
        {
            "id": monitor.pk,
            "kind": "https",
            "name": monitor.name,
            "url": monitor.url,
            "expected_status_min": monitor.expected_status_min,
            "expected_status_max": monitor.expected_status_max,
            "keyword": monitor.keyword,
            "verify_tls": monitor.verify_tls,
            "follow_redirects": monitor.follow_redirects,
            "check_interval_seconds": monitor.check_interval_seconds,
            "timeout_seconds": monitor.timeout_seconds,
        }
        for monitor in HTTPSMonitor.objects.filter(enabled=True).order_by("pk")
    ]
    canonical = json.dumps(
        {"nodes": items, "tcp_monitors": tcp_items, "https_monitors": https_items},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    version = hashlib.sha256(canonical.encode()).hexdigest()
    return {
        "version": version,
        "generated_at": timezone.now().isoformat(),
        "nodes": items,
        "tcp_monitors": tcp_items,
        "https_monitors": https_items,
    }


def create_manual_check(target, task_type=ManualCheckTask.TaskType.CHECK):
    if task_type == ManualCheckTask.TaskType.SPEED and target.target_kind != "xray":
        raise ValueError("speed tests are only supported for Xray nodes")
    now = timezone.now()
    task = ManualCheckTask.objects.create(
        **target_fk(target), task_type=task_type, expires_at=now + timedelta(minutes=10)
    )
    ManualCheckAssignment.objects.bulk_create(
        [ManualCheckAssignment(task=task, test_point=point) for point in TestPoint.objects.filter(enabled=True)]
    )
    return task


def target_fk(target):
    if target.target_kind == "xray":
        return {"node": target}
    return {f"{target.target_kind}_monitor": target}


@transaction.atomic
def save_client_result(test_point, data):
    existing = ClientResult.objects.filter(result_id=data["result_id"]).first()
    if existing:
        if existing.test_point_id != test_point.pk:
            raise ValueError("result_id belongs to another test point")
        return existing, False
    kind = data.get("target_kind", "xray")
    target_id = data.get("target_id", data.get("node_id"))
    if kind == "xray":
        target = XrayNode.objects.select_related("subscription").get(
            pk=target_id, active_in_subscription=True, enabled=True, subscription__enabled=True
        )
    else:
        target = target_model_for_kind(kind).objects.get(pk=target_id, enabled=True)
    fk = target_fk(target)
    task = None
    if data.get("task_id"):
        task = ManualCheckTask.objects.get(pk=data["task_id"], **fk, expires_at__gt=timezone.now())
        assignment = ManualCheckAssignment.objects.select_for_update().get(task=task, test_point=test_point)
        if assignment.completed_at is None:
            assignment.completed_at = timezone.now()
            assignment.save(update_fields=["completed_at"])
    result = ClientResult.objects.create(
        result_id=data["result_id"],
        **fk,
        test_point=test_point,
        task=task,
        result_type=task.task_type if task else ClientResult.ResultType.CHECK,
        success=data["success"],
        latency_ms=data.get("latency_ms"),
        download_mbps=data.get("download_mbps"),
        transferred_bytes=data.get("transferred_bytes"),
        proxy_ip=data.get("proxy_ip") if kind == "xray" else None,
        message=data.get("message", "")[:500],
        checked_at=data["checked_at"],
    )
    if kind == "xray" and result.result_type == ClientResult.ResultType.CHECK:
        save_xray_snapshots(result)
        transaction.on_commit(lambda: aggregate_node(target.pk))
    elif kind != "xray":
        save_monitor_snapshots(result)
        transaction.on_commit(lambda: aggregate_monitor(target))
    return result, True


def save_xray_snapshots(result):
    checked_at = result.checked_at
    hourly_bucket = checked_at.astimezone(datetime_timezone.utc).replace(minute=0, second=0, microsecond=0)
    local_checked = timezone.localtime(checked_at)
    daily_bucket = local_checked.replace(hour=0, minute=0, second=0, microsecond=0)
    defaults = {
        "success": result.success,
        "proxy_ip": result.proxy_ip if result.success else None,
        "latency_ms": result.latency_ms,
        "message": result.message,
        "checked_at": checked_at,
    }
    for kind, bucket in ((XrayNodeSnapshot.Kind.HOURLY, hourly_bucket), (XrayNodeSnapshot.Kind.DAILY, daily_bucket)):
        current = XrayNodeSnapshot.objects.filter(
            node=result.node, test_point=result.test_point, kind=kind, bucket_start=bucket
        ).first()
        if current is None or checked_at >= current.checked_at:
            XrayNodeSnapshot.objects.update_or_create(
                node=result.node,
                test_point=result.test_point,
                kind=kind,
                bucket_start=bucket,
                defaults=defaults,
            )


def save_monitor_snapshots(result):
    checked_at = result.checked_at
    hourly_bucket = checked_at.astimezone(datetime_timezone.utc).replace(minute=0, second=0, microsecond=0)
    local_checked = timezone.localtime(checked_at)
    daily_bucket = local_checked.replace(hour=0, minute=0, second=0, microsecond=0)
    fk = {"tcp_monitor": result.tcp_monitor} if result.tcp_monitor_id else {"https_monitor": result.https_monitor}
    defaults = {
        "success": result.success,
        "latency_ms": result.latency_ms,
        "message": result.message,
        "checked_at": checked_at,
    }
    for kind, bucket in ((MonitorSnapshot.Kind.HOURLY, hourly_bucket), (MonitorSnapshot.Kind.DAILY, daily_bucket)):
        current = MonitorSnapshot.objects.filter(
            **fk, test_point=result.test_point, kind=kind, bucket_start=bucket
        ).first()
        if current is None or checked_at >= current.checked_at:
            MonitorSnapshot.objects.update_or_create(
                **fk,
                test_point=result.test_point,
                kind=kind,
                bucket_start=bucket,
                defaults=defaults,
            )


def latest_fresh_results(node, now=None):
    now = now or timezone.now()
    cutoff = now - timedelta(seconds=node.subscription.check_interval_seconds * 2)
    latest = {}
    results = ClientResult.objects.filter(
        node=node, result_type=ClientResult.ResultType.CHECK,
        test_point__enabled=True, received_at__gte=cutoff
    ).select_related("test_point").order_by("test_point_id", "-received_at")
    for result in results:
        latest.setdefault(result.test_point_id, result)
    return latest


def latest_fresh_monitor_results(monitor, now=None):
    now = now or timezone.now()
    cutoff = now - timedelta(seconds=monitor.check_interval_seconds * 2)
    latest = {}
    results = ClientResult.objects.filter(
        **target_fk(monitor), result_type=ClientResult.ResultType.CHECK,
        test_point__enabled=True, received_at__gte=cutoff
    ).select_related("test_point").order_by("test_point_id", "-received_at")
    for result in results:
        latest.setdefault(result.test_point_id, result)
    return latest


def consensus_status(enabled_points, latest):
    if len(enabled_points) == 1:
        result = latest.get(enabled_points[0])
        return (
            XrayNode.Status.UNKNOWN
            if result is None
            else XrayNode.Status.UP if result.success else XrayNode.Status.DOWN
        )
    if len(enabled_points) >= 2:
        if len(latest) < 2:
            return XrayNode.Status.UNKNOWN
        failures = sum(not result.success for result in latest.values())
        return XrayNode.Status.DOWN if failures >= 2 else XrayNode.Status.UP
    return XrayNode.Status.UNKNOWN


def persist_status(target, new_status, enabled_points, latest, now):
    old_status = target.status
    old_incident_open = target.incident_open
    old_last_checked_at = target.last_checked_at
    old_last_changed_at = target.last_changed_at
    target.status = new_status
    if latest:
        target.last_checked_at = max(result.received_at for result in latest.values())
    if new_status != old_status:
        target.last_changed_at = now
    action = None
    all_points_down = bool(enabled_points) and len(latest) == len(enabled_points) and all(
        not result.success for result in latest.values()
    )
    recovered_points = sum(result.success for result in latest.values())
    if new_status == XrayNode.Status.DISABLED:
        target.incident_open = False
    elif all_points_down and not target.incident_open:
        target.incident_open = True
        action = "down"
    elif recovered_points >= 2 and target.incident_open:
        target.incident_open = False
        action = "up"
    update_fields = []
    if target.status != old_status:
        update_fields.append("status")
    if target.incident_open != old_incident_open:
        update_fields.append("incident_open")
    if target.last_checked_at != old_last_checked_at:
        update_fields.append("last_checked_at")
    if target.last_changed_at != old_last_changed_at:
        update_fields.append("last_changed_at")
    if update_fields:
        target.save(update_fields=[*update_fields, "updated_at"])
    return action


def aggregate_node(node_id, now=None):
    now = now or timezone.now()
    with transaction.atomic():
        node = XrayNode.objects.select_for_update().select_related("subscription").get(pk=node_id)
        enabled_points = []
        if not node.enabled or not node.active_in_subscription or not node.subscription.enabled:
            new_status = XrayNode.Status.DISABLED
            latest = {}
        else:
            enabled_points = list(TestPoint.objects.filter(enabled=True).values_list("pk", flat=True))
            latest = latest_fresh_results(node, now)
            new_status = consensus_status(enabled_points, latest)
        action = persist_status(node, new_status, enabled_points, latest, now)
    if action:
        notify_status_change(node, action, latest)
    return new_status


def aggregate_monitor(monitor, now=None):
    now = now or timezone.now()
    with transaction.atomic():
        target = type(monitor).objects.select_for_update().get(pk=monitor.pk)
        enabled_points = []
        if not target.enabled:
            new_status = XrayNode.Status.DISABLED
            latest = {}
        else:
            enabled_points = list(TestPoint.objects.filter(enabled=True).values_list("pk", flat=True))
            latest = latest_fresh_monitor_results(target, now)
            new_status = consensus_status(enabled_points, latest)
        action = persist_status(target, new_status, enabled_points, latest, now)
    if action:
        notify_status_change(target, action, latest)
    return new_status


def aggregate_all_nodes():
    for node_id in XrayNode.objects.values_list("pk", flat=True):
        aggregate_node(node_id)


def aggregate_all():
    aggregate_all_nodes()
    for model in (TCPMonitor, HTTPSMonitor):
        for monitor in model.objects.all():
            aggregate_monitor(monitor)


def _send_bark(bark_url, title, body, group):
    url = f"{bark_url.rstrip('/')}/{quote(title, safe='')}/{quote(body, safe='')}"
    response = httpx.get(url, params={"group": group}, timeout=10)
    response.raise_for_status()
    return True, ""


def _notification_title(setting, title):
    server_name = setting.server_name.strip() or "SrvCheck服务器"
    return f"[{server_name}] {title}"


def notify_status_change(node, action, latest):
    setting = NotificationSetting.get_solo()
    if not setting.enabled or not setting.bark_url:
        return
    recovering = action == "up"
    status_icon = "✅" if recovering else "❌"
    title = _notification_title(
        setting, f"{status_icon} {node.name} {'恢复正常' if recovering else '发生故障'}"
    )
    lines = [
        f"类型: {node.monitor_type_label}",
        f"地址: {node.server_host}",
        f"状态: {status_icon} {'正常' if recovering else '异常/故障'}",
    ]
    for result in sorted(latest.values(), key=lambda value: value.test_point.name):
        result_icon = "✅" if result.success else "❌"
        lines.append(f"{result.test_point.name}: {result_icon} {'正常' if result.success else '异常'}")
    body = "\n".join(lines)
    success, error = False, ""
    try:
        success, error = _send_bark(setting.bark_url, title, body, setting.group)
    except Exception as exc:
        error = f"{type(exc).__name__}: {str(exc)[:400]}"
    NotificationLog.objects.create(title=title, body=body, success=success, error=error)


def cleanup_history(days=30):
    now = timezone.now()
    ClientResult.objects.filter(received_at__lt=now - timedelta(days=days)).delete()
    current_hour = now.replace(minute=0, second=0, microsecond=0)
    hourly_cutoff = current_hour - timedelta(hours=23)
    XrayNodeSnapshot.objects.filter(
        kind=XrayNodeSnapshot.Kind.HOURLY, bucket_start__lt=hourly_cutoff
    ).delete()
    MonitorSnapshot.objects.filter(
        kind=MonitorSnapshot.Kind.HOURLY, bucket_start__lt=hourly_cutoff
    ).delete()
    local_now = timezone.localtime(now)
    daily_cutoff = local_now.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=7)
    XrayNodeSnapshot.objects.filter(
        kind=XrayNodeSnapshot.Kind.DAILY, bucket_start__lt=daily_cutoff
    ).delete()
    MonitorSnapshot.objects.filter(
        kind=MonitorSnapshot.Kind.DAILY, bucket_start__lt=daily_cutoff
    ).delete()
    ManualCheckTask.objects.filter(expires_at__lt=now - timedelta(days=1)).delete()


SUMMARY_HOURS = (8, 20)


def send_summary_report():
    setting = NotificationSetting.get_solo()
    groups = [
        ("Xray", list(XrayNode.objects.filter(active_in_subscription=True))),
        ("TCP", list(TCPMonitor.objects.all())),
        ("HTTPS", list(HTTPSMonitor.objects.all())),
    ]
    title = _notification_title(setting, "SrvCheck 监控概况")
    lines = []
    for label, items in groups:
        counts = {key: sum(item.status == key for item in items) for key in ["up", "down", "unknown", "disabled"]}
        lines.append(
            f"{label} 正常: {counts['up']}  异常: {counts['down']}  未知: {counts['unknown']}  停用: {counts['disabled']}"
        )
    down_items = [
        f"{label}/{item.name}"
        for label, items in groups
        for item in items
        if item.status == XrayNode.Status.DOWN
    ]
    if down_items:
        lines.append("异常目标:\n" + "\n".join(down_items[:20]))
    lines.append("测试点:")
    for point in TestPoint.objects.all():
        seen = timezone.localtime(point.last_seen_at).strftime("%m-%d %H:%M") if point.last_seen_at else "从未在线"
        lines.append(f"{point.name}: {seen}")
    lines.append(f"时间: {timezone.localtime(timezone.now()).strftime('%Y-%m-%d %H:%M')}")
    body = "\n".join(lines)
    success, error = False, ""
    try:
        success, error = _send_bark(setting.bark_url, title, body, setting.group)
    except Exception as exc:
        error = f"{type(exc).__name__}: {str(exc)[:400]}"
    NotificationLog.objects.create(title=title, body=body, success=success, error=error)
    return success, error


def maybe_send_summary():
    setting = NotificationSetting.get_solo()
    if not (setting.enabled and setting.summary_enabled and setting.bark_url):
        return
    local = timezone.localtime(timezone.now())
    if local.hour not in SUMMARY_HOURS or local.minute >= 5:
        return
    hour_bucket = local.replace(minute=0, second=0, microsecond=0)
    if setting.summary_last_sent_at and timezone.localtime(setting.summary_last_sent_at) >= hour_bucket:
        return
    send_summary_report()
    setting.summary_last_sent_at = timezone.now()
    setting.save(update_fields=["summary_last_sent_at"])
