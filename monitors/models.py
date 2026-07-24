import base64
import json
import uuid
from urllib.parse import parse_qs, urlparse

from django.core.validators import MaxValueValidator, MinValueValidator
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
    target_kind = "xray"

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
    exit_ip = models.GenericIPAddressField("出口 IP", null=True, blank=True, editable=False)
    country_code = models.CharField("国家代码", max_length=2, blank=True, editable=False)
    company_name = models.CharField("公司名", max_length=255, blank=True, editable=False)
    ip_info_checked_at = models.DateTimeField(null=True, blank=True, editable=False)
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


class MonitorBase(models.Model):
    class Status(models.TextChoices):
        UNKNOWN = "unknown", "未知"
        UP = "up", "正常"
        DOWN = "down", "异常"
        DISABLED = "disabled", "停用"

    name = models.CharField("名称", max_length=120)
    enabled = models.BooleanField("启用", default=True)
    check_interval_seconds = models.PositiveIntegerField(
        "检查间隔（秒）", default=60, validators=[MinValueValidator(30)]
    )
    timeout_seconds = models.PositiveIntegerField(
        "超时（秒）", default=10, validators=[MinValueValidator(1), MaxValueValidator(120)]
    )
    status = models.CharField(max_length=10, choices=Status.choices, default=Status.UNKNOWN, editable=False)
    incident_open = models.BooleanField(default=False, editable=False)
    last_checked_at = models.DateTimeField(null=True, blank=True, editable=False)
    last_changed_at = models.DateTimeField(null=True, blank=True, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True
        ordering = ["name"]

    def __str__(self):
        return self.name


class TCPMonitor(MonitorBase):
    target_kind = "tcp"

    host = models.CharField("主机", max_length=255)
    port = models.PositiveIntegerField("端口", validators=[MinValueValidator(1), MaxValueValidator(65535)])

    @property
    def monitor_type_label(self):
        return "TCP"

    @property
    def server_host(self):
        return self.host

    @property
    def endpoint(self):
        return format_host_port(self.host, self.port)


class HTTPSMonitor(MonitorBase):
    target_kind = "https"

    url = models.URLField("URL", max_length=1000)
    expected_status_min = models.PositiveIntegerField("最小状态码", default=200)
    expected_status_max = models.PositiveIntegerField("最大状态码", default=399)
    keyword = models.CharField("响应关键词", max_length=200, blank=True)
    verify_tls = models.BooleanField("验证 TLS 证书", default=True)
    follow_redirects = models.BooleanField("跟随重定向", default=True)
    timeout_seconds = models.PositiveIntegerField(
        "超时（秒）", default=15, validators=[MinValueValidator(1), MaxValueValidator(120)]
    )

    @property
    def monitor_type_label(self):
        return "HTTPS" if self.url.lower().startswith("https://") else "HTTP"

    @property
    def server_host(self):
        return urlparse(self.url).hostname or "—"

    @property
    def endpoint(self):
        return self.url


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
    class TaskType(models.TextChoices):
        CHECK = "check", "检查"
        SPEED = "speed", "测速"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    node = models.ForeignKey(
        XrayNode, related_name="manual_tasks", on_delete=models.CASCADE, null=True, blank=True
    )
    tcp_monitor = models.ForeignKey(
        TCPMonitor, related_name="manual_tasks", on_delete=models.CASCADE, null=True, blank=True
    )
    https_monitor = models.ForeignKey(
        HTTPSMonitor, related_name="manual_tasks", on_delete=models.CASCADE, null=True, blank=True
    )
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(db_index=True)
    task_type = models.CharField(max_length=10, choices=TaskType.choices, default=TaskType.CHECK)

    class Meta:
        ordering = ["-created_at"]
        constraints = [
            models.CheckConstraint(
                condition=(
                    models.Q(node__isnull=False, tcp_monitor__isnull=True, https_monitor__isnull=True)
                    | models.Q(node__isnull=True, tcp_monitor__isnull=False, https_monitor__isnull=True)
                    | models.Q(node__isnull=True, tcp_monitor__isnull=True, https_monitor__isnull=False)
                ),
                name="manual_task_exactly_one_target",
            )
        ]

    @property
    def target(self):
        return self.node or self.tcp_monitor or self.https_monitor

    @property
    def target_kind(self):
        if self.node_id:
            return "xray"
        if self.tcp_monitor_id:
            return "tcp"
        return "https"


class ManualCheckAssignment(models.Model):
    task = models.ForeignKey(ManualCheckTask, related_name="assignments", on_delete=models.CASCADE)
    test_point = models.ForeignKey(TestPoint, related_name="manual_assignments", on_delete=models.CASCADE)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["task", "test_point"], name="unique_manual_task_test_point")
        ]


class ClientResult(models.Model):
    class ResultType(models.TextChoices):
        CHECK = "check", "检查"
        SPEED = "speed", "测速"

    result_id = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)
    node = models.ForeignKey(
        XrayNode, related_name="client_results", on_delete=models.CASCADE, null=True, blank=True
    )
    tcp_monitor = models.ForeignKey(
        TCPMonitor, related_name="client_results", on_delete=models.CASCADE, null=True, blank=True
    )
    https_monitor = models.ForeignKey(
        HTTPSMonitor, related_name="client_results", on_delete=models.CASCADE, null=True, blank=True
    )
    test_point = models.ForeignKey(TestPoint, related_name="results", on_delete=models.CASCADE)
    task = models.ForeignKey(
        ManualCheckTask, related_name="results", on_delete=models.SET_NULL, null=True, blank=True
    )
    result_type = models.CharField(max_length=10, choices=ResultType.choices, default=ResultType.CHECK)
    success = models.BooleanField()
    latency_ms = models.PositiveIntegerField(null=True, blank=True)
    download_mbps = models.FloatField(null=True, blank=True)
    transferred_bytes = models.PositiveBigIntegerField(null=True, blank=True)
    proxy_ip = models.GenericIPAddressField(null=True, blank=True)
    message = models.CharField(max_length=500, blank=True)
    checked_at = models.DateTimeField()
    received_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-received_at"]
        constraints = [
            models.CheckConstraint(
                condition=(
                    models.Q(node__isnull=False, tcp_monitor__isnull=True, https_monitor__isnull=True)
                    | models.Q(node__isnull=True, tcp_monitor__isnull=False, https_monitor__isnull=True)
                    | models.Q(node__isnull=True, tcp_monitor__isnull=True, https_monitor__isnull=False)
                ),
                name="client_result_exactly_one_target",
            )
        ]
        indexes = [
            models.Index(fields=["node", "test_point", "-received_at"], name="client_result_latest_idx"),
            models.Index(fields=["tcp_monitor", "test_point", "-received_at"], name="client_result_tcp_idx"),
            models.Index(fields=["https_monitor", "test_point", "-received_at"], name="client_result_https_idx"),
        ]


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


class MonitorSnapshot(models.Model):
    class Kind(models.TextChoices):
        HOURLY = "hourly", "小时"
        DAILY = "daily", "每日"

    tcp_monitor = models.ForeignKey(
        TCPMonitor, related_name="snapshots", on_delete=models.CASCADE, null=True, blank=True
    )
    https_monitor = models.ForeignKey(
        HTTPSMonitor, related_name="snapshots", on_delete=models.CASCADE, null=True, blank=True
    )
    test_point = models.ForeignKey(TestPoint, related_name="monitor_snapshots", on_delete=models.CASCADE)
    kind = models.CharField(max_length=10, choices=Kind.choices)
    bucket_start = models.DateTimeField(db_index=True)
    success = models.BooleanField()
    latency_ms = models.PositiveIntegerField(null=True, blank=True)
    message = models.CharField(max_length=500, blank=True)
    checked_at = models.DateTimeField()

    class Meta:
        ordering = ["-bucket_start"]
        constraints = [
            models.CheckConstraint(
                condition=(
                    models.Q(tcp_monitor__isnull=False, https_monitor__isnull=True)
                    | models.Q(tcp_monitor__isnull=True, https_monitor__isnull=False)
                ),
                name="monitor_snapshot_exactly_one_target",
            ),
            models.UniqueConstraint(
                fields=["tcp_monitor", "test_point", "kind", "bucket_start"],
                condition=models.Q(tcp_monitor__isnull=False),
                name="unique_tcp_snapshot_bucket",
            ),
            models.UniqueConstraint(
                fields=["https_monitor", "test_point", "kind", "bucket_start"],
                condition=models.Q(https_monitor__isnull=False),
                name="unique_https_snapshot_bucket",
            ),
        ]
        indexes = [models.Index(fields=["kind", "bucket_start"], name="monitor_snap_bucket_idx")]


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


TARGET_MODELS = {"xray": XrayNode, "tcp": TCPMonitor, "https": HTTPSMonitor}


def target_model_for_kind(kind):
    try:
        return TARGET_MODELS[kind]
    except KeyError:
        raise ValueError(f"unknown target kind: {kind}") from None
