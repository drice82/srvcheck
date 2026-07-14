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
    ManualCheckAssignment,
    ManualCheckTask,
    NotificationLog,
    NotificationSetting,
    TestPoint,
    XrayNode,
    XrayNodeSnapshot,
    XraySubscription,
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
            "fingerprint": node.fingerprint,
            "name": node.name,
            "protocol": node.protocol,
            "share_link": node.share_link,
            "check_interval_seconds": node.subscription.check_interval_seconds,
            "timeout_seconds": node.subscription.timeout_seconds,
        }
        for node in nodes
    ]
    canonical = json.dumps(items, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    version = hashlib.sha256(canonical.encode()).hexdigest()
    return {"version": version, "generated_at": timezone.now().isoformat(), "nodes": items}


def create_manual_check(node):
    now = timezone.now()
    task = ManualCheckTask.objects.create(node=node, expires_at=now + timedelta(minutes=10))
    ManualCheckAssignment.objects.bulk_create(
        [ManualCheckAssignment(task=task, test_point=point) for point in TestPoint.objects.filter(enabled=True)]
    )
    return task


@transaction.atomic
def save_client_result(test_point, data):
    existing = ClientResult.objects.filter(result_id=data["result_id"]).first()
    if existing:
        if existing.test_point_id != test_point.pk:
            raise ValueError("result_id belongs to another test point")
        return existing, False
    node = XrayNode.objects.select_related("subscription").get(
        pk=data["node_id"], active_in_subscription=True, enabled=True, subscription__enabled=True
    )
    task = None
    if data.get("task_id"):
        task = ManualCheckTask.objects.get(pk=data["task_id"], node=node, expires_at__gt=timezone.now())
        assignment = ManualCheckAssignment.objects.select_for_update().get(task=task, test_point=test_point)
        if assignment.completed_at is None:
            assignment.completed_at = timezone.now()
            assignment.save(update_fields=["completed_at"])
    result = ClientResult.objects.create(
        result_id=data["result_id"],
        node=node,
        test_point=test_point,
        task=task,
        success=data["success"],
        latency_ms=data.get("latency_ms"),
        proxy_ip=data.get("proxy_ip"),
        message=data.get("message", "")[:500],
        checked_at=data["checked_at"],
    )
    save_xray_snapshots(result)
    transaction.on_commit(lambda: aggregate_node(node.pk))
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


def latest_fresh_results(node, now=None):
    now = now or timezone.now()
    cutoff = now - timedelta(seconds=node.subscription.check_interval_seconds * 2)
    latest = {}
    results = ClientResult.objects.filter(
        node=node, test_point__enabled=True, received_at__gte=cutoff
    ).select_related("test_point").order_by("test_point_id", "-received_at")
    for result in results:
        latest.setdefault(result.test_point_id, result)
    return latest


def aggregate_node(node_id, now=None):
    now = now or timezone.now()
    with transaction.atomic():
        node = XrayNode.objects.select_for_update().select_related("subscription").get(pk=node_id)
        if not node.enabled or not node.active_in_subscription or not node.subscription.enabled:
            new_status = XrayNode.Status.DISABLED
            latest = {}
        else:
            enabled_points = list(TestPoint.objects.filter(enabled=True).values_list("pk", flat=True))
            latest = latest_fresh_results(node, now)
            if len(enabled_points) == 1:
                result = latest.get(enabled_points[0])
                new_status = (
                    XrayNode.Status.UNKNOWN
                    if result is None
                    else XrayNode.Status.UP if result.success else XrayNode.Status.DOWN
                )
            elif len(enabled_points) >= 2:
                if len(latest) < 2:
                    new_status = XrayNode.Status.UNKNOWN
                else:
                    failures = sum(not result.success for result in latest.values())
                    new_status = XrayNode.Status.DOWN if failures >= 2 else XrayNode.Status.UP
            else:
                new_status = XrayNode.Status.UNKNOWN

        old_status = node.status
        node.status = new_status
        if latest:
            node.last_checked_at = max(result.received_at for result in latest.values())
        if new_status != old_status:
            node.last_changed_at = now
        action = None
        if new_status == XrayNode.Status.DISABLED:
            node.incident_open = False
        elif new_status == XrayNode.Status.DOWN and not node.incident_open:
            node.incident_open = True
            action = "down"
        elif new_status == XrayNode.Status.UP and node.incident_open:
            node.incident_open = False
            action = "up"
        node.save(update_fields=["status", "incident_open", "last_checked_at", "last_changed_at", "updated_at"])
    if action:
        notify_status_change(node, action, latest)
    return new_status


def aggregate_all_nodes():
    for node_id in XrayNode.objects.values_list("pk", flat=True):
        aggregate_node(node_id)


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
    status_icon = "✅" if recovering else "🚨"
    title = _notification_title(
        setting, f"{status_icon} {node.name} {'恢复正常' if recovering else '发生故障'}"
    )
    lines = [
        f"类型: {node.monitor_type_label}",
        f"地址: {node.server_host}",
        f"状态: {status_icon} {'正常' if recovering else '异常/故障'}",
    ]
    for result in sorted(latest.values(), key=lambda value: value.test_point.name):
        lines.append(f"{result.test_point.name}: {'正常' if result.success else '异常'}")
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
    XrayNodeSnapshot.objects.filter(
        kind=XrayNodeSnapshot.Kind.HOURLY, bucket_start__lt=current_hour - timedelta(hours=23)
    ).delete()
    local_now = timezone.localtime(now)
    daily_cutoff = local_now.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=7)
    XrayNodeSnapshot.objects.filter(
        kind=XrayNodeSnapshot.Kind.DAILY, bucket_start__lt=daily_cutoff
    ).delete()
    ManualCheckTask.objects.filter(expires_at__lt=now - timedelta(days=1)).delete()


SUMMARY_HOURS = (8, 20)


def send_summary_report():
    setting = NotificationSetting.get_solo()
    nodes = list(XrayNode.objects.filter(active_in_subscription=True))
    counts = {key: sum(node.status == key for node in nodes) for key in ["up", "down", "unknown", "disabled"]}
    title = _notification_title(setting, "SrvCheck Xray 监控概况")
    body = f"正常: {counts['up']}  异常: {counts['down']}  未知: {counts['unknown']}  停用: {counts['disabled']}"
    down_items = [node.name for node in nodes if node.status == XrayNode.Status.DOWN]
    if down_items:
        body += "\n异常节点:\n" + "\n".join(down_items[:20])
    body += "\n测试点:"
    for point in TestPoint.objects.all():
        seen = timezone.localtime(point.last_seen_at).strftime("%m-%d %H:%M") if point.last_seen_at else "从未在线"
        body += f"\n{point.name}: {seen}"
    body += f"\n时间: {timezone.localtime(timezone.now()).strftime('%Y-%m-%d %H:%M')}"
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
