import asyncio
import base64
import httpx
from unittest.mock import Mock, patch
from datetime import timedelta
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.test import TestCase
from .checkers import decode_subscription, parse_proxy_ip, xray_config_from_link
from .models import NotificationLog, NotificationSetting, TCPMonitor, XrayNode, XrayNodeSnapshot, XraySubscription
from .services import cleanup_history, notify_status_change, save_outcome, save_xray_snapshots
from .views import closest_snapshot
from .checkers import Outcome

class SubscriptionParserTests(TestCase):
    def test_decodes_base64_subscription(self):
        text = "vless://uuid@example.com:443?security=tls#Hong%20Kong\ntrojan://secret@example.org:443#Tokyo"
        encoded = base64.b64encode(text.encode()).decode()
        nodes = decode_subscription(encoded)
        self.assertEqual([n["protocol"] for n in nodes], ["vless", "trojan"])
        self.assertEqual(nodes[0]["name"], "Hong Kong")

    def test_vless_reality_config_has_required_fields_and_no_allow_insecure(self):
        link = "vless://00000000-0000-4000-8000-000000000001@example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.example.com&fp=chrome&pbk=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG&sid=0123456789abcdef&type=tcp#Reality"
        config = xray_config_from_link(link, 1080)
        stream = config["outbounds"][0]["streamSettings"]
        self.assertEqual(stream["network"], "raw")
        self.assertEqual(stream["realitySettings"]["fingerprint"], "chrome")
        self.assertNotIn("allowInsecure", str(config))

    def test_shadowsocks_sip002_config(self):
        credentials = base64.urlsafe_b64encode(b"aes-256-gcm:password").decode().rstrip("=")
        config = xray_config_from_link(f"ss://{credentials}@example.com:8388#SS", 1080)
        server = config["outbounds"][0]["settings"]["servers"][0]
        self.assertEqual(server["method"], "aes-256-gcm")
        self.assertEqual(server["password"], "password")

    def test_tls_certificate_pin_replaces_allow_insecure(self):
        link = "trojan://password@example.com:443?security=tls&sni=example.com&type=tcp&pcs=001122aabbcc#Pinned"
        config = xray_config_from_link(link, 1080)
        tls = config["outbounds"][0]["streamSettings"]["tlsSettings"]
        self.assertEqual(tls["pinnedPeerCertSha256"], "001122aabbcc")
        self.assertNotIn("allowInsecure", str(config))

    def test_parses_proxy_ip_response(self):
        response = httpx.Response(200, json={"ip": "203.0.113.9"})
        self.assertEqual(parse_proxy_ip(response), "203.0.113.9")

    def test_reality_type_and_server_address(self):
        subscription = XraySubscription.objects.create(name="sub", url="https://example.com/sub")
        node = XrayNode.objects.create(
            subscription=subscription, name="reality", protocol="vless", fingerprint="a" * 64,
            share_link="vless://uuid@203.0.113.10:443?security=reality&type=tcp#node",
        )
        self.assertEqual(node.monitor_type_label, "Reality")
        self.assertEqual(node.server_address, "203.0.113.10:443")
        self.assertEqual(node.server_host, "203.0.113.10")

    @patch("monitors.services.httpx.get")
    def test_bark_uses_specific_type_host_and_current_status(self, http_get):
        http_get.return_value = Mock(raise_for_status=Mock())
        setting = NotificationSetting.get_solo()
        setting.enabled, setting.bark_url = True, "https://api.day.app/device"
        setting.save()
        subscription = XraySubscription.objects.create(name="sub2", url="https://example.com/sub2")
        node = XrayNode.objects.create(
            subscription=subscription, name="node", protocol="trojan", fingerprint="b" * 64,
            share_link="trojan://password@cdn1.cugon.cn:443?security=tls#node", status="down",
        )
        notify_status_change("xray", node, "up", "ignored")
        self.assertEqual(NotificationLog.objects.first().body, "类型: Trojan\n地址: cdn1.cugon.cn\n状态: 异常")

class StateTransitionTests(TestCase):
    def test_failure_and_recovery_thresholds(self):
        setting = NotificationSetting.get_solo()
        setting.failure_threshold = setting.recovery_threshold = 2
        setting.save()
        monitor = TCPMonitor.objects.create(name="test", host="127.0.0.1", port=9)
        save_outcome("tcp", monitor, Outcome(False, 1, "failed")); monitor.refresh_from_db()
        self.assertEqual(monitor.status, "unknown")
        save_outcome("tcp", monitor, Outcome(False, 1, "failed")); monitor.refresh_from_db()
        self.assertEqual(monitor.status, "down")
        save_outcome("tcp", monitor, Outcome(True, 1, "ok")); monitor.refresh_from_db()
        self.assertEqual(monitor.status, "down")
        save_outcome("tcp", monitor, Outcome(True, 1, "ok")); monitor.refresh_from_db()
        self.assertEqual(monitor.status, "up")

class SnapshotTests(TestCase):
    def setUp(self):
        subscription = XraySubscription.objects.create(name="snap", url="https://example.com/snap")
        self.node = XrayNode.objects.create(subscription=subscription, name="node", protocol="trojan", fingerprint="c" * 64, share_link="trojan://p@example.com:443")

    def test_hour_bucket_is_updated_not_duplicated(self):
        now = timezone.now().replace(minute=5, second=0, microsecond=0)
        save_xray_snapshots(self.node, Outcome(True, 10, "ok", "203.0.113.1"), now)
        save_xray_snapshots(self.node, Outcome(False, 20, "down", None), now + timedelta(minutes=20))
        hourly = XrayNodeSnapshot.objects.get(kind="hourly")
        self.assertEqual(XrayNodeSnapshot.objects.filter(kind="hourly").count(), 1)
        self.assertFalse(hourly.success)
        self.assertIsNone(hourly.proxy_ip)

    def test_daily_snapshot_keeps_last_successful_ip(self):
        now = timezone.now()
        save_xray_snapshots(self.node, Outcome(True, 10, "ok", "203.0.113.2"), now)
        save_xray_snapshots(self.node, Outcome(False, 20, "down", None), now + timedelta(minutes=5))
        daily = XrayNodeSnapshot.objects.get(kind="daily")
        self.assertEqual(daily.proxy_ip, "203.0.113.2")

    def test_closest_snapshot_has_ninety_minute_tolerance(self):
        target = timezone.now() - timedelta(hours=6)
        close = XrayNodeSnapshot(node=self.node, kind="hourly", bucket_start=target, checked_at=target + timedelta(minutes=45), success=True)
        far = XrayNodeSnapshot(node=self.node, kind="hourly", bucket_start=target, checked_at=target + timedelta(hours=2), success=True)
        self.assertIs(closest_snapshot([close], target), close)
        self.assertIsNone(closest_snapshot([far], target))

class AuthenticationTests(TestCase):
    def test_dashboard_requires_login(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login/", response.url)
