import base64
import json
from urllib.parse import parse_qs, urlparse

from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models

class MonitorBase(models.Model):
    class Status(models.TextChoices):
        UNKNOWN = "unknown", "未知"
        UP = "up", "正常"
        DOWN = "down", "异常"
        DISABLED = "disabled", "停用"
    name = models.CharField("名称", max_length=120)
    enabled = models.BooleanField("启用", default=True)
    interval_seconds = models.PositiveIntegerField("检查间隔（秒）", default=60, validators=[MinValueValidator(10)])
    timeout_seconds = models.PositiveIntegerField("超时（秒）", default=10, validators=[MinValueValidator(1), MaxValueValidator(120)])
    status = models.CharField(max_length=10, choices=Status.choices, default=Status.UNKNOWN, editable=False)
    last_checked_at = models.DateTimeField(null=True, blank=True, editable=False)
    next_check_at = models.DateTimeField(null=True, blank=True, db_index=True, editable=False)
    last_changed_at = models.DateTimeField(null=True, blank=True, editable=False)
    last_latency_ms = models.PositiveIntegerField(null=True, blank=True, editable=False)
    last_error = models.TextField(blank=True, editable=False)
    consecutive_successes = models.PositiveIntegerField(default=0, editable=False)
    consecutive_failures = models.PositiveIntegerField(default=0, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    class Meta:
        abstract = True
        ordering = ["name"]

class TCPMonitor(MonitorBase):
    host = models.CharField("主机", max_length=255)
    port = models.PositiveIntegerField("端口", validators=[MinValueValidator(1), MaxValueValidator(65535)])
    def __str__(self): return self.name
    @property
    def endpoint(self): return f"{self.host}:{self.port}"
    @property
    def monitor_type_label(self): return "TCP"

class HTTPMonitor(MonitorBase):
    url = models.URLField("URL", max_length=1000)
    expected_status_min = models.PositiveIntegerField("最小状态码", default=200)
    expected_status_max = models.PositiveIntegerField("最大状态码", default=399)
    keyword = models.CharField("响应关键词", max_length=200, blank=True)
    verify_tls = models.BooleanField("验证 TLS 证书", default=True)
    follow_redirects = models.BooleanField("跟随重定向", default=True)
    def __str__(self): return self.name
    @property
    def endpoint(self): return self.url
    @property
    def monitor_type_label(self): return "HTTPS" if self.url.lower().startswith("https://") else "HTTP"

class XraySubscription(models.Model):
    name = models.CharField("名称", max_length=120)
    url = models.URLField("订阅 URL", max_length=2000)
    enabled = models.BooleanField("启用", default=True)
    update_interval_minutes = models.PositiveIntegerField("订阅更新间隔（分钟）", default=60, validators=[MinValueValidator(5)])
    check_interval_seconds = models.PositiveIntegerField("节点检查间隔（秒）", default=300, validators=[MinValueValidator(30)])
    timeout_seconds = models.PositiveIntegerField("超时（秒）", default=15)
    last_synced_at = models.DateTimeField(null=True, blank=True, editable=False)
    next_sync_at = models.DateTimeField(null=True, blank=True, db_index=True, editable=False)
    last_error = models.TextField(blank=True, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    def __str__(self): return self.name

class XrayNode(MonitorBase):
    subscription = models.ForeignKey(XraySubscription, related_name="nodes", on_delete=models.CASCADE)
    protocol = models.CharField(max_length=20)
    fingerprint = models.CharField(max_length=64, db_index=True)
    share_link = models.TextField()
    active_in_subscription = models.BooleanField(default=True)
    class Meta:
        ordering = ["subscription", "name"]
        constraints = [models.UniqueConstraint(fields=["subscription", "fingerprint"], name="unique_subscription_node")]
    def __str__(self): return self.name
    @property
    def endpoint(self): return f"{self.protocol}://{self.name}"
    @property
    def monitor_type_label(self):
        if self.protocol == "vless":
            security = parse_qs(urlparse(self.share_link).query).get("security", [""])[-1].lower()
            return "Reality" if security == "reality" else "VLESS"
        return {"trojan": "Trojan", "vmess": "VMess", "ss": "Shadowsocks"}.get(self.protocol, self.protocol.upper())
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

def format_host_port(host, port):
    if not host: return "—"
    host = f"[{host}]" if ":" in str(host) and not str(host).startswith("[") else host
    return f"{host}:{port}" if port else str(host)

class CheckResult(models.Model):
    monitor_type = models.CharField(max_length=20, db_index=True)
    monitor_id = models.PositiveIntegerField(db_index=True)
    success = models.BooleanField()
    latency_ms = models.PositiveIntegerField(null=True, blank=True)
    proxy_ip = models.GenericIPAddressField(null=True, blank=True)
    message = models.CharField(max_length=500, blank=True)
    checked_at = models.DateTimeField(auto_now_add=True, db_index=True)
    class Meta:
        ordering = ["-checked_at"]

class XrayNodeSnapshot(models.Model):
    class Kind(models.TextChoices):
        HOURLY = "hourly", "小时"
        DAILY = "daily", "每日"
    node = models.ForeignKey(XrayNode, related_name="snapshots", on_delete=models.CASCADE)
    kind = models.CharField(max_length=10, choices=Kind.choices)
    bucket_start = models.DateTimeField(db_index=True)
    success = models.BooleanField()
    proxy_ip = models.GenericIPAddressField(null=True, blank=True)
    latency_ms = models.PositiveIntegerField(null=True, blank=True)
    checked_at = models.DateTimeField()
    class Meta:
        ordering = ["-bucket_start"]
        constraints = [models.UniqueConstraint(fields=["node", "kind", "bucket_start"], name="unique_xray_snapshot_bucket")]
        indexes = [models.Index(fields=["kind", "bucket_start"], name="xray_snap_kind_bucket_idx")]

class NotificationSetting(models.Model):
    bark_url = models.URLField("Bark 地址", max_length=1000, blank=True, help_text="例如 https://api.day.app/设备Key")
    enabled = models.BooleanField("启用通知", default=False)
    failure_threshold = models.PositiveIntegerField("连续失败阈值", default=2, validators=[MinValueValidator(1)])
    recovery_threshold = models.PositiveIntegerField("连续成功阈值", default=2, validators=[MinValueValidator(1)])
    group = models.CharField("通知分组", max_length=80, default="SrvCheck", blank=True)
    summary_enabled = models.BooleanField("定时概况通知", default=True, help_text="每天 8:00 与 20:00 发送整体监控概况")
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
