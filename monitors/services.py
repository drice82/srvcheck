import asyncio
from datetime import timedelta
from urllib.parse import quote

import httpx
from django.conf import settings
from django.db import transaction
from django.utils import timezone

from .checkers import check_http, check_tcp, check_xray, decode_subscription
from .models import CheckResult, HTTPMonitor, NotificationLog, NotificationSetting, TCPMonitor, XrayNode, XrayNodeSnapshot, XraySubscription

MODEL_TYPES = {"tcp": TCPMonitor, "http": HTTPMonitor, "xray": XrayNode}

async def synchronize_subscription(subscription):
    try:
        async with httpx.AsyncClient(timeout=subscription.timeout_seconds, follow_redirects=True, headers={"User-Agent": "SrvCheck/1.0"}) as client:
            response = await client.get(subscription.url)
            response.raise_for_status()
        nodes = decode_subscription(response.text)
        # Providers commonly use the first pseudo-node for traffic/quota text.
        # It is not a proxy endpoint; keep every subsequent entry as-is,
        # including repeated fingerprints.
        nodes = nodes[1:]
        if not nodes:
            raise ValueError("订阅去掉首个信息节点后没有可用节点")
        return nodes, ""
    except Exception as exc:
        return [], f"{type(exc).__name__}: {str(exc)[:400]}"

@transaction.atomic
def save_subscription_result(subscription, nodes, error):
    # Serialize manual and scheduled syncs for the same subscription.
    XraySubscription.objects.select_for_update().get(pk=subscription.pk)
    now = timezone.now()
    subscription.last_synced_at = now
    subscription.next_sync_at = now + timedelta(minutes=subscription.update_interval_minutes)
    subscription.last_error = error
    subscription.save(update_fields=["last_synced_at", "next_sync_at", "last_error"])
    if error: return

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

        obj.name, obj.share_link, obj.protocol = data["name"], data["share_link"], data["protocol"]
        obj.fingerprint, obj.active_in_subscription = data["fingerprint"], True
        obj.interval_seconds, obj.timeout_seconds = subscription.check_interval_seconds, subscription.timeout_seconds
        if obj.status == "disabled": obj.status, obj.enabled = "unknown", True
        obj.save()
        matched.append(obj.pk)

    subscription.nodes.exclude(pk__in=matched).update(
        active_in_subscription=False, enabled=False, status="disabled", next_check_at=None,
    )

def due_monitors(limit=100):
    now = timezone.now()
    result = []
    for kind, model in MODEL_TYPES.items():
        query = model.objects.filter(enabled=True)
        if kind == "xray": query = query.filter(active_in_subscription=True)
        query = query.filter(next_check_at__isnull=True) | query.filter(next_check_at__lte=now)
        for obj in query[:limit]:
            obj.next_check_at = now + timedelta(seconds=obj.interval_seconds)
            obj.save(update_fields=["next_check_at"])
            result.append((kind, obj))
    return result

async def execute_checks(items, concurrency=20):
    semaphore = asyncio.Semaphore(concurrency)
    xray_semaphore = asyncio.Semaphore(settings.XRAY_CONCURRENCY)
    async def one(kind, obj):
        async with semaphore:
            checker = {"tcp": check_tcp, "http": check_http, "xray": check_xray}[kind]
            if kind == "xray":
                async with xray_semaphore:
                    return kind, obj, await checker(obj)
            return kind, obj, await checker(obj)
    return await asyncio.gather(*(one(*item) for item in items))

def save_outcome(kind, obj, outcome):
    setting = NotificationSetting.get_solo()
    now, old_status = timezone.now(), obj.status
    obj.last_checked_at, obj.last_latency_ms = now, outcome.latency_ms
    if outcome.success:
        obj.consecutive_successes += 1; obj.consecutive_failures = 0; obj.last_error = ""
        if old_status == "unknown" or (old_status == "down" and obj.consecutive_successes >= setting.recovery_threshold):
            obj.status = "up"
    else:
        obj.consecutive_failures += 1; obj.consecutive_successes = 0; obj.last_error = outcome.message
        if old_status in {"unknown", "up"} and obj.consecutive_failures >= setting.failure_threshold:
            obj.status = "down"
    changed = obj.status != old_status
    if changed: obj.last_changed_at = now
    obj.save()
    CheckResult.objects.create(monitor_type=kind, monitor_id=obj.pk, success=outcome.success, latency_ms=outcome.latency_ms, proxy_ip=None if kind == "xray" else outcome.proxy_ip, message=outcome.message)
    if kind == "xray": save_xray_snapshots(obj, outcome, now)
    if changed and not (old_status == "unknown" and obj.status == "up"):
        notify_status_change(kind, obj, old_status, outcome.message)

def _send_bark(bark_url, title, body, group):
    url = f"{bark_url.rstrip('/')}/{quote(title, safe='')}/{quote(body, safe='')}"
    response = httpx.get(url, params={"group": group}, timeout=10)
    response.raise_for_status()
    return True, ""

def notify_status_change(kind, obj, old_status, message):
    setting = NotificationSetting.get_solo()
    if not setting.enabled or not setting.bark_url: return
    title = f"{obj.name} {'恢复正常' if obj.status == 'up' else '发生故障'}"
    monitor_type = obj.monitor_type_label
    address = obj.server_host if kind == "xray" else obj.endpoint
    body = f"类型: {monitor_type}\n地址: {address}\n状态: {obj.get_status_display()}"
    success, error = False, ""
    try:
        success, error = _send_bark(setting.bark_url, title, body, setting.group)
    except Exception as exc:
        error = f"{type(exc).__name__}: {str(exc)[:400]}"
    NotificationLog.objects.create(title=title, body=body, success=success, error=error)

def cleanup_history(days=30):
    CheckResult.objects.filter(checked_at__lt=timezone.now() - timedelta(days=days)).delete()
    now = timezone.now()
    current_hour = now.replace(minute=0, second=0, microsecond=0)
    XrayNodeSnapshot.objects.filter(kind="hourly", bucket_start__lt=current_hour - timedelta(hours=23)).delete()
    local_now = timezone.localtime(now)
    daily_cutoff = local_now.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=7)
    XrayNodeSnapshot.objects.filter(kind="daily", bucket_start__lt=daily_cutoff).delete()

def save_xray_snapshots(node, outcome, checked_at):
    hourly_bucket = checked_at.replace(minute=0, second=0, microsecond=0)
    local_checked = timezone.localtime(checked_at)
    daily_bucket = local_checked.replace(hour=0, minute=0, second=0, microsecond=0)
    common = {"success": outcome.success, "latency_ms": outcome.latency_ms, "checked_at": checked_at}
    XrayNodeSnapshot.objects.update_or_create(
        node=node, kind="hourly", bucket_start=hourly_bucket,
        defaults={**common, "proxy_ip": outcome.proxy_ip},
    )
    XrayNodeSnapshot.objects.update_or_create(
        node=node, kind="daily", bucket_start=daily_bucket,
        defaults={**common, "proxy_ip": outcome.proxy_ip if outcome.success else None},
    )

SUMMARY_HOURS = (8, 20)

def send_summary_report():
    setting = NotificationSetting.get_solo()
    monitors = list(TCPMonitor.objects.all()) + list(HTTPMonitor.objects.all()) + list(XrayNode.objects.filter(active_in_subscription=True))
    counts = {key: sum(m.status == key for m in monitors) for key in ["up", "down", "unknown", "disabled"]}
    down_items = [m.name for m in monitors if m.status == "down"]
    title = "SrvCheck 监控概况"
    body = f"正常: {counts['up']}  异常: {counts['down']}  未知: {counts['unknown']}  停用: {counts['disabled']}"
    if down_items:
        body += "\n异常项:\n" + "\n".join(down_items[:20])
        if len(down_items) > 20: body += f"\n…及其他 {len(down_items) - 20} 项"
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
    if not (setting.enabled and setting.summary_enabled and setting.bark_url): return
    local = timezone.localtime(timezone.now())
    if local.hour not in SUMMARY_HOURS or local.minute >= 5: return
    hour_bucket = local.replace(minute=0, second=0, microsecond=0)
    if setting.summary_last_sent_at and timezone.localtime(setting.summary_last_sent_at) >= hour_bucket: return
    send_summary_report()
    setting.summary_last_sent_at = timezone.now()
    setting.save(update_fields=["summary_last_sent_at"])
