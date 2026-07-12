import asyncio
import base64
import httpx
from unittest.mock import Mock, patch
from datetime import timedelta
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.test import TestCase
from .checkers import decode_subscription, parse_proxy_ip, xray_config_from_link
from .models import CheckResult, NotificationLog, NotificationSetting, TCPMonitor, XrayNode, XrayNodeSnapshot, XraySubscription
from .services import cleanup_history, notify_status_change, save_outcome, save_subscription_result, save_xray_snapshots
from .views import mark_ip_changes, prepare_check_result_status_bars, prepare_xray_status_bars, status_bar
from .checkers import Outcome

class SubscriptionParserTests(TestCase):
    def test_decodes_base64_subscription(self):
        text = "vless://uuid@example.com:443?security=tls#Hong%20Kong\ntrojan://secret@example.org:443#Tokyo"
        encoded = base64.b64encode(text.encode()).decode()
        nodes = decode_subscription(encoded)
        self.assertEqual([n["protocol"] for n in nodes], ["vless", "trojan"])
        self.assertEqual(nodes[0]["name"], "Hong Kong")

class SubscriptionSyncTests(TestCase):
    def setUp(self):
        self.subscription = XraySubscription.objects.create(name="sub", url="https://example.com/sub")

    def node_data(self, name, fingerprint, host="old.example.com", protocol="vless"):
        return {
            "name": name,
            "protocol": protocol,
            "fingerprint": fingerprint,
            "share_link": f"{protocol}://uuid@{host}:443#{name}",
        }

    def test_address_change_reuses_node_and_preserves_history(self):
        save_subscription_result(self.subscription, [self.node_data("Hong Kong", "a" * 64)], "")
        node = self.subscription.nodes.get()
        snapshot = XrayNodeSnapshot.objects.create(
            node=node, kind="hourly", bucket_start=timezone.now(),
            checked_at=timezone.now(), success=True,
        )

        save_subscription_result(
            self.subscription,
            [self.node_data("Hong Kong", "b" * 64, host="new.example.com")],
            "",
        )

        self.assertEqual(self.subscription.nodes.count(), 1)
        updated = self.subscription.nodes.get()
        self.assertEqual(updated.pk, node.pk)
        self.assertEqual(updated.fingerprint, "b" * 64)
        self.assertIn("new.example.com", updated.share_link)
        self.assertEqual(snapshot.node_id, updated.pk)

    def test_removed_nodes_are_inactive_and_not_scheduled(self):
        save_subscription_result(self.subscription, [
            self.node_data("A", "a" * 64),
            self.node_data("B", "b" * 64),
        ], "")
        save_subscription_result(self.subscription, [self.node_data("A", "a" * 64)], "")

        self.assertEqual(self.subscription.nodes.filter(active_in_subscription=True).count(), 1)
        removed = self.subscription.nodes.get(name="B")
        self.assertFalse(removed.enabled)
        self.assertIsNone(removed.next_check_at)

    def test_sync_error_keeps_current_nodes(self):
        save_subscription_result(self.subscription, [self.node_data("A", "a" * 64)], "")
        save_subscription_result(self.subscription, [], "download failed")
        self.assertEqual(self.subscription.nodes.filter(active_in_subscription=True).count(), 1)

    def test_duplicate_fingerprints_in_feed_are_ignored(self):
        duplicate = self.node_data("A duplicate", "a" * 64)
        save_subscription_result(self.subscription, [
            self.node_data("A", "a" * 64),
            duplicate,
            self.node_data("B", "b" * 64),
        ], "")

        self.assertEqual(self.subscription.nodes.count(), 2)
        self.assertEqual(self.subscription.nodes.get(fingerprint="a" * 64).name, "A duplicate")

    def test_subscription_page_only_contains_active_nodes(self):
        user = get_user_model().objects.create_user(username="admin", password="secret")
        XrayNode.objects.create(
            subscription=self.subscription, name="Current", protocol="vless",
            fingerprint="a" * 64, share_link="vless://uuid@current.example.com:443#Current",
        )
        XrayNode.objects.create(
            subscription=self.subscription, name="Obsolete", protocol="vless",
            fingerprint="b" * 64, share_link="vless://uuid@old.example.com:443#Obsolete",
            active_in_subscription=False, enabled=False, status="disabled",
        )
        self.client.force_login(user)

        response = self.client.get("/subscriptions/")

        self.assertContains(response, "节点 1")
        self.assertContains(response, "Current")
        self.assertNotContains(response, "Obsolete")

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

    def test_daily_snapshot_uses_latest_check_and_clears_ip_on_failure(self):
        now = timezone.now()
        save_xray_snapshots(self.node, Outcome(True, 10, "ok", "203.0.113.2"), now)
        save_xray_snapshots(self.node, Outcome(False, 20, "down", None), now + timedelta(minutes=5))
        daily = XrayNodeSnapshot.objects.get(kind="daily")
        self.assertFalse(daily.success)
        self.assertIsNone(daily.proxy_ip)
        self.assertEqual(daily.checked_at, now + timedelta(minutes=5))

    def test_status_bars_have_seven_days_and_twenty_four_hours(self):
        now = timezone.now().replace(minute=30, second=0, microsecond=0)
        save_xray_snapshots(self.node, Outcome(True, 10, "ok", "203.0.113.3"), now)
        prepare_xray_status_bars([self.node], now)
        self.assertEqual(len(self.node.status_bars), 31)
        self.assertEqual([bar.kind for bar in self.node.status_bars[:7]], ["daily"] * 7)
        self.assertEqual([bar.kind for bar in self.node.status_bars[7:]], ["hourly"] * 24)
        self.assertEqual(self.node.status_bars[-1].status, "up")
        self.assertEqual(self.node.latest_snapshot.proxy_ip, "203.0.113.3")
        self.assertEqual(self.node.status_bars[-2].status, "unknown")

    def test_ip_change_is_marked_as_normal_variant(self):
        now = timezone.now().replace(minute=0, second=0, microsecond=0)
        snapshots = [
            XrayNodeSnapshot(node=self.node, kind="hourly", bucket_start=now, checked_at=now, success=True, proxy_ip="203.0.113.1"),
            XrayNodeSnapshot(node=self.node, kind="hourly", bucket_start=now + timedelta(hours=1), checked_at=now + timedelta(hours=1), success=True, proxy_ip="203.0.113.2"),
        ]
        bars = [status_bar(snapshot, "hour", "hourly") for snapshot in snapshots]
        mark_ip_changes(bars)
        self.assertEqual([bar.status for bar in bars], ["up", "changed"])

    def test_cleanup_keeps_24_hour_buckets_and_eight_daily_buckets(self):
        now = timezone.now()
        current_hour = now.replace(minute=0, second=0, microsecond=0)
        local_midnight = timezone.localtime(now).replace(hour=0, minute=0, second=0, microsecond=0)
        for offset in range(25):
            XrayNodeSnapshot.objects.create(
                node=self.node, kind="hourly", bucket_start=current_hour - timedelta(hours=offset),
                checked_at=current_hour - timedelta(hours=offset), success=True,
            )
        for offset in range(9):
            XrayNodeSnapshot.objects.create(
                node=self.node, kind="daily", bucket_start=local_midnight - timedelta(days=offset),
                checked_at=local_midnight - timedelta(days=offset), success=True,
            )
        cleanup_history()
        self.assertEqual(XrayNodeSnapshot.objects.filter(kind="hourly").count(), 24)
        self.assertEqual(XrayNodeSnapshot.objects.filter(kind="daily").count(), 8)

    def test_tcp_status_bars_use_last_result_in_each_bucket(self):
        monitor = TCPMonitor.objects.create(name="tcp-bars", host="example.com", port=443)
        now = timezone.now().replace(minute=30, second=0, microsecond=0)
        CheckResult.objects.create(monitor_type="tcp", monitor_id=monitor.pk, success=True)
        result = CheckResult.objects.get(monitor_type="tcp", monitor_id=monitor.pk)
        CheckResult.objects.filter(pk=result.pk).update(checked_at=now)
        prepare_check_result_status_bars([monitor], "tcp", now)
        self.assertEqual(len(monitor.status_bars), 31)
        self.assertEqual(monitor.status_bars[-1].status, "up")
        self.assertEqual(monitor.status_bars[-2].status, "unknown")

class AuthenticationTests(TestCase):
    def test_dashboard_requires_login(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login/", response.url)
