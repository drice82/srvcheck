import base64
import json
import uuid
from urllib.parse import parse_qs, urlparse

from django.core.validators import MinValueValidator
from django.db import models


class XraySubscription(models.Model):
    name = models.CharField("名称", max_length=120)
    url = models.URLField("订阅 URL", max_length=2000)
    enabled = models.BooleanField("启用", default=True)
    update_interval_minutes = models.PositiveIntegerField(
        "订阅更新间隔（分钟）", default=60, validators=[MinValueValidator(5)]
    )
    check_interval_seconds = models.PositiveIntegerField(
        "节点检查间隔（秒）", default=300, validators=[MinValueValidator(30)]
    )
    timeout_seconds = models.PositiveIntegerField("超时（秒）", default=15)
    last_synced_at = models.DateTimeField(null=True, blank=True, editable=False)
    next_sync_at = models.DateTimeField(null=True, blank=True, db_index=True, editable=False)
    last_error = models.TextField(blank=True, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class XrayNode(models.Model):
    class Status(models.TextChoices):
        UNKNOWN = "unknown", "未知"
        UP = "up", "正常"
        DOWN = "down", "异常"
        DISABLED = "disabled", "停用"

    subscription = models.ForeignKey(XraySubscription, related_name="nodes", on_delete=models.CASCADE)
    name = models.CharField("名称", max_length=120)
    protocol = models.CharField(max_length=20)
    fingerprint = models.CharField(max_length=64, db_index=True)
    share_link = models.TextField()
    enabled = models.BooleanField("启用", default=True)
    active_in_subscription = models.BooleanField(default=True)
    status = models.CharField(max_length=10, choices=Status.choices, default=Status.UNKNOWN, editable=False)
    incident_open = models.BooleanField(default=False, editable=False)
    last_checked_at = models.DateTimeField(null=True, blank=True, editable=False)
    last_changed_at = models.DateTimeField(null=True, blank=True, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["subscription", "name"]

    def __str__(self):
        return self.name

    @property
    def monitor_type_label(self):
        if self.protocol == "vless":
            security = parse_qs(urlparse(self.share_link).query).get("security", [""])[-1].lower()
            return "Reality" if security == "reality" else "VLESS"
        return {"trojan": "Trojan", "vmess": "VMess", "ss": "Shadowsocks"}.get(
            self.protocol, self.protocol.upper()
        )

    @property
    def server_address(self):
        try:
            if self.protocol == "vmess":
                raw = self.share_link.split("://", 1)[1].split("#", 1)[0]
                data = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
                return format_host_port(data.get("add"), data.get("port"))
            parsed = urlparse(self.share_link)
            return format_host_port(parsed.hostname, parsed.port)
        except (ValueError, TypeError, KeyError, json.JSONDecodeError):
            return "—"

    @property
    def server_host(self):
        try:
            if self.protocol == "vmess":
                raw = self.share_link.split("://", 1)[1].split("#", 1)[0]
                data = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
                return str(data.get("add") or "—")
            return urlparse(self.share_link).hostname or "—"
        except (ValueError, TypeError, KeyError, json.JSONDecodeError):
            return "—"


class TestPoint(models.Model):
    name = models.CharField("测试点名称", max_length=120, unique=True)
    enabled = models.BooleanField("启用", default=True)
    last_seen_at = models.DateTimeField(null=True, blank=True, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


class ManualCheckTask(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    node = models.ForeignKey(XrayNode, related_name="manual_tasks", on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(db_index=True)

    class Meta:
        ordering = ["-created_at"]


class ManualCheckAssignment(models.Model):
    task = models.ForeignKey(ManualCheckTask, related_name="assignments", on_delete=models.CASCADE)
    test_point = models.ForeignKey(TestPoint, related_name="manual_assignments", on_delete=models.CASCADE)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["task", "test_point"], name="unique_manual_task_test_point")
        ]


class ClientResult(models.Model):
    result_id = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)
    node = models.ForeignKey(XrayNode, related_name="client_results", on_delete=models.CASCADE)
    test_point = models.ForeignKey(TestPoint, related_name="results", on_delete=models.CASCADE)
    task = models.ForeignKey(
        ManualCheckTask, related_name="results", on_delete=models.SET_NULL, null=True, blank=True
    )
    success = models.BooleanField()
    latency_ms = models.PositiveIntegerField(null=True, blank=True)
    proxy_ip = models.GenericIPAddressField(null=True, blank=True)
    message = models.CharField(max_length=500, blank=True)
    checked_at = models.DateTimeField()
    received_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-received_at"]
        indexes = [models.Index(fields=["node", "test_point", "-received_at"], name="client_result_latest_idx")]


class XrayNodeSnapshot(models.Model):
    class Kind(models.TextChoices):
        HOURLY = "hourly", "小时"
        DAILY = "daily", "每日"

    node = models.ForeignKey(XrayNode, related_name="snapshots", on_delete=models.CASCADE)
    test_point = models.ForeignKey(TestPoint, related_name="snapshots", on_delete=models.CASCADE)
    kind = models.CharField(max_length=10, choices=Kind.choices)
    bucket_start = models.DateTimeField(db_index=True)
    success = models.BooleanField()
    proxy_ip = models.GenericIPAddressField(null=True, blank=True)
    latency_ms = models.PositiveIntegerField(null=True, blank=True)
    message = models.CharField(max_length=500, blank=True)
    checked_at = models.DateTimeField()

    class Meta:
        ordering = ["-bucket_start"]
        constraints = [
            models.UniqueConstraint(
                fields=["node", "test_point", "kind", "bucket_start"],
                name="unique_xray_client_snapshot_bucket",
            )
        ]
        indexes = [models.Index(fields=["kind", "bucket_start"], name="xray_client_snap_bucket_idx")]


class NotificationSetting(models.Model):
    bark_url = models.URLField(
        "Bark 地址", max_length=1000, blank=True, help_text="例如 https://api.day.app/设备Key"
    )
    enabled = models.BooleanField("启用通知", default=False)
    server_name = models.CharField(
        "服务器标识", max_length=80, default="SrvCheck服务器", help_text="例如：中心服务器"
    )
    group = models.CharField("通知分组", max_length=80, default="SrvCheck", blank=True)
    summary_enabled = models.BooleanField(
        "定时概况通知", default=True, help_text="每天 8:00 与 20:00 发送整体监控概况"
    )
    summary_last_sent_at = models.DateTimeField(null=True, blank=True, editable=False)

    @classmethod
    def get_solo(cls):
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj


class NotificationLog(models.Model):
    title = models.CharField(max_length=200)
    body = models.TextField()
    success = models.BooleanField(default=False)
    error = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]


def format_host_port(host, port):
    if not host:
        return "—"
    host = f"[{host}]" if ":" in str(host) and not str(host).startswith("[") else host
    return f"{host}:{port}" if port else str(host)
