import base64
import json
import uuid
from datetime import timedelta
from unittest.mock import AsyncMock, Mock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone

from .checkers import Outcome, decode_subscription, parse_proxy_ip, xray_config_from_link
from .models import (
    ClientResult,
    ManualCheckAssignment,
    NotificationLog,
    NotificationSetting,
    TestPoint,
    XrayNode,
    XrayNodeSnapshot,
    XraySubscription,
)
from .services import (
    aggregate_node,
    cleanup_history,
    create_manual_check,
    manifest_payload,
    save_client_result,
    save_subscription_result,
    synchronize_subscription,
)
from .views import prepare_xray_status_bars


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


class AggregationTests(BaseNodeTest):
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
        self.assertIn("🚨", notification.title)
        self.assertIn("状态: 🚨 异常/故障", notification.body)

    def test_two_failures_required_with_multiple_clients(self):
        a = TestPoint.objects.create(name="深圳")
        b = TestPoint.objects.create(name="上海")
        c = TestPoint.objects.create(name="北京")
        self.result(a, False)
        self.result(b, True)
        self.assertEqual(aggregate_node(self.node.pk), "up")
        self.result(c, False)
        self.assertEqual(aggregate_node(self.node.pk), "down")

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
        setting = NotificationSetting.get_solo()
        setting.enabled, setting.bark_url = True, "https://api.day.app/key"
        setting.save()
        self.result(a, False)
        self.result(b, False)
        aggregate_node(self.node.pk)
        b.enabled = False
        b.save()
        a.enabled = False
        a.save()
        aggregate_node(self.node.pk)
        self.node.refresh_from_db()
        self.assertTrue(self.node.incident_open)
        a.enabled = True
        a.save()
        self.result(a, True)
        aggregate_node(self.node.pk)
        self.node.refresh_from_db()
        self.assertFalse(self.node.incident_open)
        self.assertEqual(NotificationLog.objects.count(), 2)
        titles = list(NotificationLog.objects.values_list("title", flat=True))
        self.assertTrue(any("🚨" in title for title in titles))
        self.assertTrue(any("✅" in title for title in titles))


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
        self.assertNotContains(response, ">TCP<")
        self.assertNotContains(response, ">HTTPS<")

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
        self.assertRedirects(response, "/subscriptions/")
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
        response = self.client.get("/subscriptions/")
        self.assertContains(response, timezone.localtime(checked_at).strftime("%H:%M"))
        self.assertContains(response, "203.0.113.9")
