import asyncio
import base64
import http.server
import json
import threading
import uuid
from datetime import timedelta
from io import StringIO
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import OperationalError
from django.test import TestCase, override_settings
from django.utils import timezone

from .checkers import (
    Outcome,
    check_https,
    check_tcp,
    decode_subscription,
    parse_proxy_ip,
    xray_config_from_link,
)
from .management.commands.run_scheduler import Command as SchedulerCommand
from .models import (
    ClientResult,
    HTTPSMonitor,
    ManualCheckAssignment,
    MonitorSnapshot,
    NotificationLog,
    NotificationSetting,
    TCPMonitor,
    TestPoint,
    XrayNode,
    XrayNodeSnapshot,
    XraySubscription,
)
from .services import (
    aggregate_monitor,
    aggregate_node,
    cleanup_history,
    consensus_proxy_ip,
    create_manual_check,
    lookup_ip_info,
    manifest_payload,
    refresh_node_ip_info,
    save_client_result,
    save_subscription_result,
    send_summary_report,
    synchronize_subscription,
)
from .views import prepare_status_bars, prepare_xray_status_bars


class BaseNodeTest(TestCase):
    def setUp(self):
        self.subscription = XraySubscription.objects.create(name="sub", url="https://example.com/sub")
        self.node = XrayNode.objects.create(
            subscription=self.subscription,
            name="Hong Kong",
            protocol="vless",
            fingerprint="a" * 64,
            share_link="vless://uuid@example.com:443?security=tls#Hong%20Kong",
        )

    def result(self, point, success, received_at=None, proxy_ip=None, task=None):
        result = ClientResult.objects.create(
            result_id=uuid.uuid4(),
            node=self.node,
            test_point=point,
            task=task,
            success=success,
            latency_ms=20,
            proxy_ip=proxy_ip,
            message="ok" if success else "failed",
            checked_at=timezone.now(),
        )
        if received_at:
            ClientResult.objects.filter(pk=result.pk).update(received_at=received_at)
            result.refresh_from_db()
        return result


class ParserTests(TestCase):
    def test_decodes_base64_subscription(self):
        text = "vless://uuid@example.com:443?security=tls#Hong%20Kong\ntrojan://secret@example.org:443#Tokyo"
        encoded = base64.b64encode(text.encode()).decode()
        nodes = decode_subscription(encoded)
        self.assertEqual([node["protocol"] for node in nodes], ["vless", "trojan"])
        self.assertEqual(nodes[0]["name"], "Hong Kong")

    def test_reality_config(self):
        link = "vless://00000000-0000-4000-8000-000000000001@example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.example.com&fp=chrome&pbk=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG&sid=0123456789abcdef&type=tcp#Reality"
        config = xray_config_from_link(link, 1080)
        stream = config["outbounds"][0]["streamSettings"]
        self.assertEqual(stream["realitySettings"]["fingerprint"], "chrome")
        self.assertNotIn("allowInsecure", str(config))

    def test_proxy_ip_json(self):
        import httpx

        self.assertEqual(parse_proxy_ip(httpx.Response(200, json={"ip": "203.0.113.9"})), "203.0.113.9")


class SubscriptionTests(BaseNodeTest):
    @patch("monitors.services.httpx.AsyncClient")
    def test_sync_discards_first_information_entry(self, async_client):
        response = Mock(text="vless://info@example.com:443#Info\nvless://id@example.com:443#A")
        response.raise_for_status = Mock()
        client = AsyncMock()
        client.get.return_value = response
        context = AsyncMock()
        context.__aenter__.return_value = client
        async_client.return_value = context
        import asyncio

        nodes, error = asyncio.run(synchronize_subscription(self.subscription))
        self.assertEqual(error, "")
        self.assertEqual([node["name"] for node in nodes], ["A"])

    def test_address_change_preserves_node_identity(self):
        data = [{"name": "Hong Kong", "protocol": "vless", "fingerprint": "b" * 64, "share_link": "vless://uuid@new.example.com:443#Hong%20Kong"}]
        save_subscription_result(self.subscription, data, "")
        self.node.refresh_from_db()
        self.assertEqual(self.node.fingerprint, "b" * 64)
        self.assertIn("new.example.com", self.node.share_link)

    def test_manifest_version_changes_with_configuration(self):
        first = manifest_payload()
        self.subscription.check_interval_seconds = 600
        self.subscription.save()
        second = manifest_payload()
        self.assertNotEqual(first["version"], second["version"])
        self.assertEqual(second["nodes"][0]["check_interval_seconds"], 600)

    def test_removed_node_is_disabled_and_reenabled_when_it_returns(self):
        save_subscription_result(self.subscription, [], "")
        self.node.refresh_from_db()
        self.assertFalse(self.node.enabled)
        data = [{
            "name": self.node.name,
            "protocol": self.node.protocol,
            "fingerprint": self.node.fingerprint,
            "share_link": self.node.share_link,
        }]
        save_subscription_result(self.subscription, data, "")
        self.node.refresh_from_db()
        self.assertTrue(self.node.enabled)
        self.assertEqual(self.node.status, "unknown")


@override_settings(CLIENT_API_TOKEN="shared-secret")
class ClientApiTests(BaseNodeTest):
    def setUp(self):
        super().setUp()
        self.point = TestPoint.objects.create(name="深圳测试点")
        self.headers = {"HTTP_AUTHORIZATION": "Bearer shared-secret", "HTTP_X_CLIENT_NAME": self.point.name}

    def test_manifest_requires_token_and_registered_name(self):
        self.assertEqual(self.client.get("/api/v1/client/manifest").status_code, 401)
        response = self.client.get("/api/v1/client/manifest", **self.headers)
        self.assertEqual(response.status_code, 200)
        etag = response["ETag"]
        response = self.client.get("/api/v1/client/manifest", HTTP_IF_NONE_MATCH=etag, **self.headers)
        self.assertEqual(response.status_code, 304)

    def test_result_submission_is_idempotent(self):
        result_id = str(uuid.uuid4())
        payload = {"results": [{
            "result_id": result_id,
            "node_id": self.node.pk,
            "checked_at": timezone.now().isoformat(),
            "success": True,
            "latency_ms": 12,
            "proxy_ip": "203.0.113.5",
            "message": "ok",
        }]}
        first = self.client.post("/api/v1/client/results", json.dumps(payload), content_type="application/json", **self.headers)
        second = self.client.post("/api/v1/client/results", json.dumps(payload), content_type="application/json", **self.headers)
        self.assertEqual(first.json()["accepted"], [result_id])
        self.assertEqual(second.json()["duplicates"], [result_id])
        self.assertEqual(ClientResult.objects.count(), 1)

    def test_manual_task_is_returned_and_completed(self):
        task = create_manual_check(self.node)
        response = self.client.get("/api/v1/client/tasks", **self.headers)
        self.assertEqual(response.json()["tasks"][0]["id"], str(task.pk))
        data = {
            "result_id": uuid.uuid4(), "node_id": self.node.pk, "task_id": task.pk,
            "checked_at": timezone.now(), "success": True, "latency_ms": 1,
            "proxy_ip": None, "message": "ok",
        }
        save_client_result(self.point, data)
        self.assertIsNotNone(ManualCheckAssignment.objects.get(task=task, test_point=self.point).completed_at)

    def test_speed_task_is_explicit_and_does_not_update_health_history(self):
        task = create_manual_check(self.node, task_type="speed")
        response = self.client.get("/api/v1/client/tasks", **self.headers)
        item = response.json()["tasks"][0]
        self.assertEqual(item["task_type"], "speed")
        self.assertEqual(item["target_type"], "xray")
        self.assertEqual(item["target_id"], self.node.pk)

        result, created = save_client_result(self.point, {
            "result_id": uuid.uuid4(), "target_kind": "xray", "target_id": self.node.pk,
            "task_id": task.pk, "checked_at": timezone.now(), "success": True,
            "latency_ms": 1500, "download_mbps": 123.45, "transferred_bytes": 25_000_000,
            "message": "下载 123.45 Mbps",
        })
        self.assertTrue(created)
        self.assertEqual(result.result_type, "speed")
        self.assertEqual(result.download_mbps, 123.45)
        self.assertFalse(XrayNodeSnapshot.objects.filter(node=self.node).exists())
        self.node.refresh_from_db()
        self.assertEqual(self.node.status, "unknown")


class AggregationTests(BaseNodeTest):
    def test_unchanged_status_does_not_write_node(self):
        with patch.object(XrayNode, "save", autospec=True) as save:
            self.assertEqual(aggregate_node(self.node.pk), "unknown")
        save.assert_not_called()

    @patch("monitors.services._send_bark")
    def test_single_client_uses_direct_result(self, send_bark):
        point = TestPoint.objects.create(name="深圳")
        self.result(point, False)
        setting = NotificationSetting.get_solo()
        setting.enabled, setting.bark_url = True, "https://api.day.app/key"
        setting.save()
        self.assertEqual(aggregate_node(self.node.pk), "down")
        self.node.refresh_from_db()
        self.assertTrue(self.node.incident_open)
        self.assertEqual(NotificationLog.objects.count(), 1)
        notification = NotificationLog.objects.get()
        self.assertIn("❌", notification.title)
        self.assertIn("状态: ❌ 异常/故障", notification.body)
        self.assertIn("深圳: ❌ 异常", notification.body)

    def test_two_failures_required_with_multiple_clients(self):
        a = TestPoint.objects.create(name="深圳")
        b = TestPoint.objects.create(name="上海")
        c = TestPoint.objects.create(name="北京")
        self.result(a, False)
        self.result(b, True)
        self.assertEqual(aggregate_node(self.node.pk), "up")
        self.result(c, False)
        self.assertEqual(aggregate_node(self.node.pk), "down")

    @patch("monitors.services._send_bark")
    def test_failure_notification_requires_every_enabled_point_to_be_down(self, send_bark):
        a = TestPoint.objects.create(name="深圳")
        b = TestPoint.objects.create(name="上海")
        c = TestPoint.objects.create(name="北京")
        setting = NotificationSetting.get_solo()
        setting.enabled, setting.bark_url = True, "https://api.day.app/key"
        setting.save()
        self.result(a, False)
        self.result(b, False)
        self.result(c, True)
        self.assertEqual(aggregate_node(self.node.pk), "down")
        self.node.refresh_from_db()
        self.assertFalse(self.node.incident_open)
        self.assertFalse(NotificationLog.objects.exists())
        self.result(c, False)
        aggregate_node(self.node.pk)
        self.node.refresh_from_db()
        self.assertTrue(self.node.incident_open)
        self.assertEqual(NotificationLog.objects.count(), 1)

    def test_insufficient_fresh_reports_is_unknown(self):
        a = TestPoint.objects.create(name="深圳")
        TestPoint.objects.create(name="上海")
        self.result(a, False)
        self.assertEqual(aggregate_node(self.node.pk), "unknown")

    def test_stale_reports_do_not_count(self):
        a = TestPoint.objects.create(name="深圳")
        b = TestPoint.objects.create(name="上海")
        stale = timezone.now() - timedelta(seconds=self.subscription.check_interval_seconds * 2 + 1)
        self.result(a, False, received_at=stale)
        self.result(b, False)
        self.assertEqual(aggregate_node(self.node.pk), "unknown")

    @patch("monitors.services._send_bark")
    def test_unknown_does_not_close_incident_and_recovery_notifies_once(self, send_bark):
        a = TestPoint.objects.create(name="深圳")
        b = TestPoint.objects.create(name="上海")
        c = TestPoint.objects.create(name="北京")
        setting = NotificationSetting.get_solo()
        setting.enabled, setting.bark_url = True, "https://api.day.app/key"
        setting.save()
        self.result(a, False)
        self.result(b, False)
        self.result(c, False)
        aggregate_node(self.node.pk)
        b.enabled = False
        b.save()
        a.enabled = False
        a.save()
        c.enabled = False
        c.save()
        aggregate_node(self.node.pk)
        self.node.refresh_from_db()
        self.assertTrue(self.node.incident_open)
        a.enabled = True
        a.save()
        self.result(a, True)
        aggregate_node(self.node.pk)
        self.node.refresh_from_db()
        self.assertTrue(self.node.incident_open)
        self.assertEqual(NotificationLog.objects.count(), 1)
        b.enabled = True
        b.save()
        self.result(b, True)
        aggregate_node(self.node.pk)
        self.node.refresh_from_db()
        self.assertFalse(self.node.incident_open)
        self.assertEqual(NotificationLog.objects.count(), 2)
        titles = list(NotificationLog.objects.values_list("title", flat=True))
        self.assertTrue(any("❌" in title for title in titles))
        self.assertTrue(any("✅" in title for title in titles))
        recovery = NotificationLog.objects.filter(title__contains="恢复正常").get()
        self.assertIn("上海: ✅ 正常", recovery.body)
        self.assertIn("深圳: ✅ 正常", recovery.body)


class NodeIpInfoTests(BaseNodeTest):
    def test_consensus_proxy_ip_uses_most_common_successful_ip(self):
        points = [TestPoint.objects.create(name=name) for name in ("深圳", "上海", "北京")]
        older = timezone.now() - timedelta(minutes=1)
        a = self.result(points[0], True, received_at=older, proxy_ip="8.8.8.8")
        b = self.result(points[1], True, received_at=older, proxy_ip="8.8.8.8")
        c = self.result(points[2], True, proxy_ip="1.1.1.1")

        self.assertEqual(
            consensus_proxy_ip({a.test_point_id: a, b.test_point_id: b, c.test_point_id: c}),
            "8.8.8.8",
        )

    def test_consensus_proxy_ip_uses_newest_report_to_break_tie(self):
        a = TestPoint.objects.create(name="深圳")
        b = TestPoint.objects.create(name="上海")
        older = timezone.now() - timedelta(minutes=1)
        old_result = self.result(a, True, received_at=older, proxy_ip="8.8.8.8")
        new_result = self.result(b, True, proxy_ip="1.1.1.1")

        self.assertEqual(
            consensus_proxy_ip({a.pk: old_result, b.pk: new_result}),
            "1.1.1.1",
        )

    @override_settings(
        IPINFO_URL="https://ipinfo.example/{ip}/json",
        IPINFO_TOKEN="token",
        IPINFO_TIMEOUT_SECONDS=3,
    )
    @patch("monitors.services.httpx.get")
    def test_refresh_stores_consensus_ip_country_and_company(self, get):
        response = Mock()
        response.raise_for_status = Mock()
        response.json.return_value = {"country": "US", "org": "AS15169 Google LLC"}
        get.return_value = response
        points = [TestPoint.objects.create(name=name) for name in ("深圳", "上海", "北京")]
        self.result(points[0], True, proxy_ip="8.8.8.8")
        self.result(points[1], True, proxy_ip="8.8.8.8")
        self.result(points[2], True, proxy_ip="1.1.1.1")

        self.assertEqual(refresh_node_ip_info(self.node.pk), "8.8.8.8")

        self.node.refresh_from_db()
        self.assertEqual(self.node.exit_ip, "8.8.8.8")
        self.assertEqual(self.node.country_code, "US")
        self.assertEqual(self.node.company_name, "Google LLC")
        get.assert_called_once_with(
            "https://ipinfo.example/8.8.8.8/json",
            params={"token": "token"},
            timeout=3,
            headers={"User-Agent": "SrvCheck/2.0"},
        )

    @override_settings(
        IPINFO_URL="https://ipinfo.example/{ip}/json",
        IPINFO_TOKEN="",
        IPINFO_TIMEOUT_SECONDS=5,
    )
    @patch("monitors.services.httpx.get")
    def test_lookup_supports_structured_company(self, get):
        response = Mock()
        response.raise_for_status = Mock()
        response.json.return_value = {
            "country_code": "de",
            "company": {"name": "Example Hosting GmbH"},
        }
        get.return_value = response

        self.assertEqual(
            lookup_ip_info("8.8.4.4"),
            ("DE", "Example Hosting GmbH"),
        )


class SnapshotAndViewTests(BaseNodeTest):
    def test_snapshot_is_per_test_point_and_latest_wins(self):
        point = TestPoint.objects.create(name="深圳")
        first = self.result(point, True, proxy_ip="203.0.113.1")
        from .services import save_xray_snapshots
        save_xray_snapshots(first)
        second = self.result(point, False)
        save_xray_snapshots(second)
        self.assertEqual(XrayNodeSnapshot.objects.filter(kind="hourly").count(), 1)
        self.assertFalse(XrayNodeSnapshot.objects.get(kind="hourly").success)

    def test_status_bars_contain_a_segment_per_point(self):
        TestPoint.objects.create(name="上海")
        TestPoint.objects.create(name="深圳")
        prepare_xray_status_bars([self.node], timezone.now())
        self.assertEqual(len(self.node.status_bars), 31)
        self.assertEqual(len(self.node.status_bars[0].segments), 2)
        self.assertEqual([segment.test_point.name for segment in self.node.status_bars[-1].segments], ["上海", "深圳"])

    def test_rightmost_bar_is_latest_and_previous_bar_is_last_completed_hour(self):
        point = TestPoint.objects.create(name="深圳")
        now = timezone.now().replace(minute=5, second=0, microsecond=0)
        current_hour = now.replace(minute=0)
        previous_hour = current_hour - timedelta(hours=1)
        XrayNodeSnapshot.objects.create(
            node=self.node, test_point=point, kind="hourly", bucket_start=previous_hour,
            success=False, checked_at=previous_hour + timedelta(minutes=50),
        )
        XrayNodeSnapshot.objects.create(
            node=self.node, test_point=point, kind="hourly", bucket_start=current_hour,
            success=True, checked_at=now,
        )
        self.result(point, True, proxy_ip="203.0.113.8")

        prepare_xray_status_bars([self.node], now)

        self.assertEqual(self.node.status_bars[-1].kind, "latest")
        self.assertEqual(self.node.status_bars[-1].segments[0].status, "up")
        self.assertEqual(self.node.status_bars[-2].kind, "hourly")
        self.assertEqual(self.node.status_bars[-2].segments[0].status, "down")

    def test_cleanup_history(self):
        point = TestPoint.objects.create(name="深圳")
        result = self.result(point, True)
        from .services import save_xray_snapshots
        save_xray_snapshots(result)
        cleanup_history()
        self.assertTrue(XrayNodeSnapshot.objects.exists())


class BaseMonitorTest(TestCase):
    def setUp(self):
        self.tcp = TCPMonitor.objects.create(name="SSH", host="example.com", port=22)
        self.https = HTTPSMonitor.objects.create(name="官网", url="https://example.com")

    def monitor_result(self, monitor, point, success, received_at=None, checked_at=None):
        fk = {"tcp_monitor": monitor} if isinstance(monitor, TCPMonitor) else {"https_monitor": monitor}
        result = ClientResult.objects.create(
            result_id=uuid.uuid4(),
            **fk,
            test_point=point,
            success=success,
            latency_ms=15,
            message="ok" if success else "failed",
            checked_at=checked_at or timezone.now(),
        )
        if received_at:
            ClientResult.objects.filter(pk=result.pk).update(received_at=received_at)
            result.refresh_from_db()
        return result


class MonitorManifestTests(BaseMonitorTest):
    def test_manifest_includes_tcp_and_https_monitors(self):
        payload = manifest_payload()
        self.assertEqual(
            payload["tcp_monitors"],
            [{
                "id": self.tcp.pk, "kind": "tcp", "name": "SSH", "host": "example.com", "port": 22,
                "check_interval_seconds": 60, "timeout_seconds": 10,
            }],
        )
        entry = payload["https_monitors"][0]
        self.assertEqual(entry["kind"], "https")
        self.assertEqual(entry["url"], "https://example.com")
        self.assertEqual(entry["expected_status_min"], 200)
        self.assertEqual(entry["expected_status_max"], 399)

    def test_manifest_version_changes_and_disabled_monitors_are_excluded(self):
        first = manifest_payload()
        self.tcp.port = 2222
        self.tcp.save()
        second = manifest_payload()
        self.assertNotEqual(first["version"], second["version"])
        self.https.enabled = False
        self.https.save()
        self.assertEqual(manifest_payload()["https_monitors"], [])


@override_settings(CLIENT_API_TOKEN="shared-secret")
class MonitorClientApiTests(BaseMonitorTest):
    def setUp(self):
        super().setUp()
        self.point = TestPoint.objects.create(name="深圳测试点")
        self.headers = {"HTTP_AUTHORIZATION": "Bearer shared-secret", "HTTP_X_CLIENT_NAME": self.point.name}

    def post_results(self, items):
        return self.client.post(
            "/api/v1/client/results", json.dumps({"results": items}),
            content_type="application/json", **self.headers,
        )

    def result_item(self, monitor, kind, result_id=None, task_id=None):
        item = {
            "result_id": result_id or str(uuid.uuid4()),
            "target_type": kind,
            "target_id": monitor.pk,
            "checked_at": timezone.now().isoformat(),
            "success": True,
            "latency_ms": 9,
            "message": "ok",
        }
        if task_id:
            item["task_id"] = str(task_id)
        return item

    def test_tcp_result_submission_is_idempotent(self):
        item = self.result_item(self.tcp, "tcp")
        first = self.post_results([item])
        second = self.post_results([item])
        self.assertEqual(first.json()["accepted"], [item["result_id"]])
        self.assertEqual(second.json()["duplicates"], [item["result_id"]])
        result = ClientResult.objects.get()
        self.assertEqual(result.tcp_monitor, self.tcp)
        self.assertIsNone(result.proxy_ip)

    def test_https_result_triggers_aggregation_and_snapshot(self):
        with self.captureOnCommitCallbacks(execute=True):
            response = self.post_results([self.result_item(self.https, "https")])
        self.assertEqual(len(response.json()["accepted"]), 1)
        self.https.refresh_from_db()
        self.assertEqual(self.https.status, "up")
        self.assertEqual(
            MonitorSnapshot.objects.filter(https_monitor=self.https, test_point=self.point).count(), 2
        )

    def test_unknown_target_and_kind_are_rejected(self):
        missing = self.result_item(self.tcp, "tcp")
        missing["target_id"] = 99999
        wrong_kind = self.result_item(self.tcp, "dns")
        response = self.post_results([missing, wrong_kind])
        self.assertEqual(len(response.json()["rejected"]), 2)
        self.assertFalse(ClientResult.objects.exists())

    def test_manual_task_for_tcp_monitor_is_returned_and_completed(self):
        task = create_manual_check(self.tcp)
        response = self.client.get("/api/v1/client/tasks", **self.headers)
        entry = response.json()["tasks"][0]
        self.assertEqual(entry["id"], str(task.pk))
        self.assertEqual(entry["target_type"], "tcp")
        self.assertEqual(entry["target_id"], self.tcp.pk)
        save_client_result(self.point, {
            "result_id": uuid.uuid4(), "target_kind": "tcp", "target_id": self.tcp.pk,
            "task_id": task.pk, "checked_at": timezone.now(), "success": True,
            "latency_ms": 1, "proxy_ip": None, "message": "ok",
        })
        self.assertIsNotNone(ManualCheckAssignment.objects.get(task=task, test_point=self.point).completed_at)

    def test_task_for_disabled_monitor_is_not_returned(self):
        self.tcp.enabled = False
        self.tcp.save()
        create_manual_check(self.tcp)
        response = self.client.get("/api/v1/client/tasks", **self.headers)
        self.assertEqual(response.json()["tasks"], [])


class MonitorAggregationTests(BaseMonitorTest):
    def test_single_point_uses_direct_result(self):
        point = TestPoint.objects.create(name="深圳")
        self.monitor_result(self.tcp, point, False)
        self.assertEqual(aggregate_monitor(self.tcp), "down")
        self.tcp.refresh_from_db()
        self.assertTrue(self.tcp.incident_open)

    def test_two_failures_required_with_multiple_points(self):
        a = TestPoint.objects.create(name="深圳")
        b = TestPoint.objects.create(name="上海")
        c = TestPoint.objects.create(name="北京")
        self.monitor_result(self.https, a, False)
        self.monitor_result(self.https, b, True)
        self.assertEqual(aggregate_monitor(self.https), "up")
        self.monitor_result(self.https, c, False)
        self.assertEqual(aggregate_monitor(self.https), "down")

    def test_stale_reports_do_not_count(self):
        point = TestPoint.objects.create(name="深圳")
        stale = timezone.now() - timedelta(seconds=self.tcp.check_interval_seconds * 2 + 10)
        self.monitor_result(self.tcp, point, False, received_at=stale)
        self.assertEqual(aggregate_monitor(self.tcp), "unknown")

    def test_disabled_monitor_is_disabled(self):
        self.tcp.enabled = False
        self.tcp.save()
        self.assertEqual(aggregate_monitor(self.tcp), "disabled")

    @patch("monitors.services._send_bark")
    def test_failure_notification_mentions_monitor(self, send_bark):
        point = TestPoint.objects.create(name="深圳")
        self.monitor_result(self.tcp, point, False)
        setting = NotificationSetting.get_solo()
        setting.enabled, setting.bark_url = True, "https://api.day.app/key"
        setting.save()
        aggregate_monitor(self.tcp)
        notification = NotificationLog.objects.get()
        self.assertIn("SSH", notification.title)
        self.assertIn("类型: TCP", notification.body)
        self.assertIn("地址: example.com", notification.body)


class MonitorSnapshotTests(BaseMonitorTest):
    def test_snapshot_is_per_test_point_and_latest_wins(self):
        a = TestPoint.objects.create(name="深圳")
        b = TestPoint.objects.create(name="上海")
        checked_at = timezone.now().replace(second=0, microsecond=0)
        save_client_result(a, {
            "result_id": uuid.uuid4(), "target_kind": "tcp", "target_id": self.tcp.pk,
            "checked_at": checked_at - timedelta(minutes=5), "success": False, "latency_ms": 5, "message": "old",
        })
        save_client_result(a, {
            "result_id": uuid.uuid4(), "target_kind": "tcp", "target_id": self.tcp.pk,
            "checked_at": checked_at, "success": True, "latency_ms": 7, "message": "new",
        })
        save_client_result(b, {
            "result_id": uuid.uuid4(), "target_kind": "tcp", "target_id": self.tcp.pk,
            "checked_at": checked_at, "success": False, "latency_ms": 9, "message": "peer",
        })
        snapshot = MonitorSnapshot.objects.get(
            tcp_monitor=self.tcp, test_point=a, kind=MonitorSnapshot.Kind.HOURLY
        )
        self.assertTrue(snapshot.success)
        self.assertEqual(snapshot.message, "new")
        self.assertEqual(MonitorSnapshot.objects.filter(tcp_monitor=self.tcp).count(), 4)

    def test_status_bars_contain_a_segment_per_point(self):
        a = TestPoint.objects.create(name="深圳")
        TestPoint.objects.create(name="上海")
        self.monitor_result(self.https, a, True)
        prepare_status_bars([self.https], timezone.now(), "https")
        self.assertEqual(len(self.https.status_bars), 7 + 23 + 1)
        latest_bar = self.https.status_bars[-1]
        by_point = {segment.test_point.name: segment.status for segment in latest_bar.segments}
        self.assertEqual(by_point, {"深圳": "up", "上海": "unknown"})
        by_point_summary = {s.point.name: s.status for s in self.https.point_summaries}
        self.assertEqual(by_point_summary, {"深圳": "up", "上海": "unknown"})

    def test_cleanup_history_removes_old_monitor_snapshots(self):
        point = TestPoint.objects.create(name="深圳")
        checked_at = timezone.now() - timedelta(days=2)
        save_client_result(point, {
            "result_id": uuid.uuid4(), "target_kind": "tcp", "target_id": self.tcp.pk,
            "checked_at": checked_at, "success": True, "latency_ms": 5, "message": "old",
        })
        save_client_result(point, {
            "result_id": uuid.uuid4(), "target_kind": "tcp", "target_id": self.tcp.pk,
            "checked_at": timezone.now(), "success": True, "latency_ms": 5, "message": "new",
        })
        cleanup_history()
        remaining = MonitorSnapshot.objects.filter(tcp_monitor=self.tcp)
        # Hourly buckets are trimmed after 23 hours; daily buckets survive 7 days.
        self.assertEqual(remaining.filter(kind=MonitorSnapshot.Kind.HOURLY).count(), 1)
        self.assertEqual(remaining.filter(kind=MonitorSnapshot.Kind.DAILY).count(), 2)
        self.assertTrue(all(snapshot.checked_at > checked_at for snapshot in remaining.filter(kind=MonitorSnapshot.Kind.HOURLY)))


class MonitorCheckerTests(TestCase):
    def test_check_tcp_success_and_failure(self):
        async def run():
            server = await asyncio.start_server(lambda reader, writer: None, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            async with server:
                ok = await check_tcp(SimpleNamespace(host="127.0.0.1", port=port, timeout_seconds=2))
                refused = await check_tcp(SimpleNamespace(host="127.0.0.1", port=1, timeout_seconds=2))
            return ok, refused

        ok, refused = asyncio.run(run())
        self.assertTrue(ok.success)
        self.assertIsNotNone(ok.latency_ms)
        self.assertFalse(refused.success)

    def test_check_https_status_range_and_keyword(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/fail":
                    self.send_response(500)
                    self.end_headers()
                    return
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"hello world")

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{server.server_port}"
            probe = lambda **overrides: SimpleNamespace(
                **{
                    "url": base, "expected_status_min": 200, "expected_status_max": 299,
                    "keyword": "", "verify_tls": False, "follow_redirects": False,
                    "timeout_seconds": 5, **overrides,
                }
            )
            ok = asyncio.run(check_https(probe(keyword="hello")))
            missing_keyword = asyncio.run(check_https(probe(keyword="absent")))
            bad_status = asyncio.run(check_https(probe(url=f"{base}/fail")))
        finally:
            server.shutdown()
            thread.join()
        self.assertTrue(ok.success)
        self.assertEqual(ok.message, "HTTP 200")
        self.assertFalse(missing_keyword.success)
        self.assertIn("关键词", missing_keyword.message)
        self.assertFalse(bad_status.success)
        self.assertIn("500", bad_status.message)


class SummaryReportTests(BaseMonitorTest):
    @patch("monitors.services._send_bark")
    def test_summary_covers_all_monitor_kinds(self, send_bark):
        TCPMonitor.objects.filter(pk=self.tcp.pk).update(status="up")
        HTTPSMonitor.objects.filter(pk=self.https.pk).update(status="down")
        send_summary_report()
        body = NotificationLog.objects.get().body
        self.assertIn("Xray 正常:", body)
        self.assertIn("TCP 正常: 1", body)
        self.assertIn("HTTPS 正常: 0", body)
        self.assertIn("HTTPS/官网", body)


class SchedulerTests(TestCase):
    @patch("monitors.management.commands.run_scheduler.maybe_send_summary")
    @patch("monitors.management.commands.run_scheduler.aggregate_all")
    @patch("monitors.management.commands.run_scheduler.time.monotonic")
    def test_locked_aggregate_does_not_block_tick_or_retry_immediately(
        self, monotonic, aggregate_all, maybe_summary
    ):
        command = SchedulerCommand()
        command.stderr = StringIO()
        command.last_cleanup = 100
        command.last_aggregate = 0
        monotonic.return_value = 100
        aggregate_all.side_effect = OperationalError("database is locked")

        command.tick()
        monotonic.return_value = 102
        command.tick()

        self.assertEqual(command.last_aggregate, 100)
        aggregate_all.assert_called_once_with()
        self.assertEqual(maybe_summary.call_count, 2)
        self.assertIn(
            "scheduler aggregate failed: OperationalError: database is locked",
            command.stderr.getvalue(),
        )


class SqliteConfigurationTests(TestCase):
    def test_write_concurrency_options_are_enabled(self):
        options = settings.DATABASES["default"]["OPTIONS"]
        self.assertEqual(options["timeout"], 20)
        self.assertEqual(options["transaction_mode"], "IMMEDIATE")
        self.assertIn("PRAGMA journal_mode=WAL", options["init_command"])
        self.assertIn("PRAGMA synchronous=NORMAL", options["init_command"])
        self.assertIn("PRAGMA busy_timeout=20000", options["init_command"])


class PageTests(BaseNodeTest):
    def setUp(self):
        super().setUp()
        self.user = get_user_model().objects.create_user(username="admin", password="secret")

    def test_dashboard_requires_login(self):
        self.assertEqual(self.client.get("/").status_code, 302)

    def test_pages_only_expose_xray_and_test_points(self):
        self.client.force_login(self.user)
        response = self.client.get("/")
        self.assertContains(response, "Xray 服务总览")
        self.assertContains(response, "Xray 订阅")
        self.assertContains(response, ">测试</button>")
        self.assertContains(response, ">测速</button>")
        self.assertNotContains(response, "全部测试点立即检查")
        self.assertNotContains(response, ">TCP<")
        self.assertNotContains(response, ">HTTPS<")

    def test_speed_button_creates_one_node_only_speed_task(self):
        TestPoint.objects.create(name="深圳")
        other = XrayNode.objects.create(
            subscription=self.subscription, name="Tokyo", protocol="trojan", fingerprint="b" * 64,
            share_link="trojan://secret@example.org:443#Tokyo",
        )
        self.client.force_login(self.user)
        response = self.client.post(f"/nodes/{self.node.pk}/speed-test/")
        self.assertRedirects(response, "/")
        task = self.node.manual_tasks.get()
        self.assertEqual(task.task_type, "speed")
        self.assertEqual(task.assignments.count(), 1)
        self.assertFalse(other.manual_tasks.exists())

    def test_legacy_subscription_page_redirects_to_dashboard(self):
        self.client.force_login(self.user)
        self.assertRedirects(self.client.get("/subscriptions/"), "/")

    def test_editing_node_keeps_subscription_identity_and_dispatches_to_all_points(self):
        TestPoint.objects.create(name="深圳")
        TestPoint.objects.create(name="上海")
        old_fingerprint = self.node.fingerprint
        ClientResult.objects.create(
            node=self.node, test_point=TestPoint.objects.get(name="深圳"), success=True,
            checked_at=timezone.now(), result_id=uuid.uuid4(),
        )
        self.client.force_login(self.user)
        response = self.client.post(
            f"/nodes/{self.node.pk}/edit/",
            {"name": "临时节点", "share_link": "trojan://password@edited.example.com:443#Temporary"},
        )
        self.assertRedirects(response, "/")
        self.node.refresh_from_db()
        self.assertEqual(self.node.name, "临时节点")
        self.assertEqual(self.node.protocol, "trojan")
        self.assertEqual(self.node.fingerprint, old_fingerprint)
        self.assertEqual(self.node.status, "unknown")
        self.assertFalse(ClientResult.objects.filter(node=self.node).exists())
        task = self.node.manual_tasks.get()
        self.assertEqual(task.assignments.count(), 2)

        save_subscription_result(self.subscription, [{
            "name": "Hong Kong", "protocol": "vless", "fingerprint": old_fingerprint,
            "share_link": "vless://uuid@example.com:443?security=tls#Hong%20Kong",
        }], "")
        self.node.refresh_from_db()
        self.assertEqual(self.node.name, "Hong Kong")
        self.assertEqual(self.node.protocol, "vless")

    def test_latest_result_displays_client_test_hour_and_minute(self):
        point = TestPoint.objects.create(name="深圳")
        checked_at = timezone.now().replace(second=0, microsecond=0)
        ClientResult.objects.create(
            node=self.node, test_point=point, success=True, checked_at=checked_at,
            proxy_ip="203.0.113.9", result_id=uuid.uuid4(),
        )
        self.client.force_login(self.user)
        response = self.client.get("/")
        self.assertContains(response, timezone.localtime(checked_at).strftime("%H:%M"))
        self.assertContains(response, "203.0.113.9")

    def test_dashboard_displays_consensus_ip_country_and_company(self):
        XrayNode.objects.filter(pk=self.node.pk).update(
            exit_ip="8.8.8.8", country_code="US", company_name="Google LLC"
        )
        self.client.force_login(self.user)
        response = self.client.get("/")
        self.assertContains(response, "8.8.8.8")
        self.assertContains(response, "US")
        self.assertContains(response, "Google LLC")


class MonitorPageTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="admin", password="secret")
        self.tcp = TCPMonitor.objects.create(name="SSH", host="example.com", port=22)
        self.https = HTTPSMonitor.objects.create(name="官网", url="https://example.com")

    def test_monitor_pages_require_login(self):
        self.assertEqual(self.client.get("/tcp/").status_code, 302)
        self.assertEqual(self.client.get("/https/").status_code, 302)

    def test_tcp_page_lists_monitors(self):
        self.client.force_login(self.user)
        response = self.client.get("/tcp/")
        self.assertContains(response, "TCP 监控")
        self.assertContains(response, "SSH")
        self.assertContains(response, "example.com:22")
        self.assertContains(response, ">TCP<")
        self.assertContains(response, ">测试</button>")

    def test_https_page_lists_monitors(self):
        self.client.force_login(self.user)
        response = self.client.get("/https/")
        self.assertContains(response, "HTTPS 监控")
        self.assertContains(response, "官网")
        self.assertContains(response, "https://example.com")
        self.assertContains(response, ">HTTPS<")

    def test_partial_endpoints_refresh_independently(self):
        self.client.force_login(self.user)
        self.assertContains(self.client.get("/partials/tcp/"), "SSH")
        self.assertNotContains(self.client.get("/partials/tcp/"), "官网")
        self.assertContains(self.client.get("/partials/https/"), "官网")
        self.assertNotContains(self.client.get("/partials/https/"), "SSH")

    def test_create_tcp_monitor_dispatches_tasks(self):
        TestPoint.objects.create(name="深圳")
        self.client.force_login(self.user)
        response = self.client.post("/tcp/new/", {
            "name": "数据库", "host": "db.internal", "port": 5432,
            "check_interval_seconds": 60, "timeout_seconds": 10, "enabled": "on",
        })
        self.assertRedirects(response, "/tcp/")
        monitor = TCPMonitor.objects.get(name="数据库")
        self.assertEqual(monitor.manual_tasks.get().assignments.count(), 1)

    def test_edit_monitor_resets_status_and_clears_results(self):
        point = TestPoint.objects.create(name="深圳")
        ClientResult.objects.create(
            tcp_monitor=self.tcp, test_point=point, success=True,
            checked_at=timezone.now(), result_id=uuid.uuid4(),
        )
        TCPMonitor.objects.filter(pk=self.tcp.pk).update(status="up", incident_open=True)
        self.client.force_login(self.user)
        response = self.client.post(f"/tcp/{self.tcp.pk}/edit/", {
            "name": "SSH", "host": "new.example.com", "port": 2222,
            "check_interval_seconds": 60, "timeout_seconds": 10, "enabled": "on",
        })
        self.assertRedirects(response, "/tcp/")
        self.tcp.refresh_from_db()
        self.assertEqual(self.tcp.status, "unknown")
        self.assertFalse(self.tcp.incident_open)
        self.assertFalse(ClientResult.objects.filter(tcp_monitor=self.tcp).exists())
        self.assertEqual(self.tcp.manual_tasks.count(), 1)

    def test_https_form_rejects_inverted_status_range(self):
        self.client.force_login(self.user)
        response = self.client.post("/https/new/", {
            "name": "bad", "url": "https://example.com", "expected_status_min": 400,
            "expected_status_max": 200, "keyword": "", "verify_tls": "on",
            "follow_redirects": "on", "check_interval_seconds": 60, "timeout_seconds": 15,
            "enabled": "on",
        })
        self.assertEqual(response.status_code, 200)
        self.assertFalse(HTTPSMonitor.objects.filter(name="bad").exists())

    def test_check_now_dispatches_manual_task(self):
        TestPoint.objects.create(name="深圳")
        self.client.force_login(self.user)
        response = self.client.post(f"/https/{self.https.pk}/check/")
        self.assertRedirects(response, "/https/")
        task = self.https.manual_tasks.get()
        self.assertEqual(task.assignments.count(), 1)
        self.assertEqual(task.target_kind, "https")

    def test_delete_monitor_cascades_results(self):
        point = TestPoint.objects.create(name="深圳")
        ClientResult.objects.create(
            tcp_monitor=self.tcp, test_point=point, success=True,
            checked_at=timezone.now(), result_id=uuid.uuid4(),
        )
        self.client.force_login(self.user)
        response = self.client.post(f"/tcp/{self.tcp.pk}/delete/")
        self.assertRedirects(response, "/tcp/")
        self.assertFalse(TCPMonitor.objects.exists())
        self.assertFalse(ClientResult.objects.exists())
