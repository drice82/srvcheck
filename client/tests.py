import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from monitors.checkers import Outcome

from .main import ClientAgent, atomic_json, load_json


class PersistenceTests(unittest.TestCase):
    def test_atomic_json_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            atomic_json(path, {"节点": [1, 2]})
            self.assertEqual(load_json(path, {}), {"节点": [1, 2]})

    def test_invalid_cache_uses_default(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            path.write_text("not json", encoding="utf-8")
            self.assertEqual(load_json(path, {"nodes": []}), {"nodes": []})


class AgentQueueTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.environment = patch.dict(os.environ, {
            "SERVER_URL": "https://server.example.com",
            "CLIENT_NAME": "深圳测试点",
            "CLIENT_API_TOKEN": "secret",
            "CLIENT_DATA_DIR": self.directory.name,
        })
        self.environment.start()
        self.agent = ClientAgent()
        self.node = {
            "id": 1,
            "kind": "xray",
            "name": "node",
            "share_link": "vless://id@example.com:443#node",
            "timeout_seconds": 10,
            "check_interval_seconds": 60,
        }

    async def asyncTearDown(self):
        await self.agent.http.aclose()
        self.environment.stop()
        self.directory.cleanup()

    @patch("client.main.check_xray", new_callable=AsyncMock)
    async def test_scheduled_result_keeps_only_latest_per_node(self, check):
        check.return_value = Outcome(True, 12, "ok", "203.0.113.1")
        await self.agent.test_target(self.node)
        first_id = self.agent.pending["xray:1"]["result_id"]
        await self.agent.test_target(self.node)
        self.assertEqual(list(self.agent.pending), ["xray:1"])
        self.assertNotEqual(first_id, self.agent.pending["xray:1"]["result_id"])
        self.assertEqual(self.agent.pending["xray:1"]["target_type"], "xray")
        self.assertEqual(self.agent.pending["xray:1"]["proxy_ip"], "203.0.113.1")

    @patch("client.main.check_xray", new_callable=AsyncMock)
    async def test_manual_result_has_separate_durable_key(self, check):
        check.return_value = Outcome(False, 12, "failed", None)
        await self.agent.test_target(self.node, task_id="task-id")
        self.assertIn("task:task-id", load_json(self.agent.pending_path, {}))

    @patch("client.main.check_xray_speed", new_callable=AsyncMock)
    async def test_speed_result_only_runs_for_explicit_speed_task(self, speed_check):
        speed_check.return_value = Outcome(
            True, 1500, "下载 100.00 Mbps", download_mbps=100.0,
            transferred_bytes=25_000_000,
        )
        await self.agent.test_target(self.node, task_id="speed-task", task_type="speed")
        result = self.agent.pending["task:speed-task"]
        self.assertEqual(result["download_mbps"], 100.0)
        self.assertEqual(result["transferred_bytes"], 25_000_000)
        speed_check.assert_awaited_once()

    @patch("client.main.check_tcp", new_callable=AsyncMock)
    async def test_tcp_target_reports_target_type(self, check):
        check.return_value = Outcome(True, 5, "TCP 连接成功")
        target = {"id": 7, "kind": "tcp", "name": "ssh", "host": "example.com", "port": 22,
                  "timeout_seconds": 5, "check_interval_seconds": 60}
        await self.agent.test_target(target)
        result = self.agent.pending["tcp:7"]
        self.assertEqual(result["target_type"], "tcp")
        self.assertEqual(result["target_id"], 7)
        self.assertNotIn("proxy_ip", result)
        probe = check.await_args.args[0]
        self.assertEqual((probe.host, probe.port, probe.timeout_seconds), ("example.com", 22, 5))

    @patch("client.main.check_https", new_callable=AsyncMock)
    async def test_https_target_reports_target_type(self, check):
        check.return_value = Outcome(False, 30, "HTTP 500 不在期望范围")
        target = {"id": 3, "kind": "https", "name": "site", "url": "https://example.com",
                  "expected_status_min": 200, "expected_status_max": 299, "keyword": "ok",
                  "verify_tls": False, "follow_redirects": True,
                  "timeout_seconds": 8, "check_interval_seconds": 60}
        await self.agent.test_target(target, task_id="t-1")
        result = self.agent.pending["task:t-1"]
        self.assertEqual(result["target_type"], "https")
        self.assertFalse(result["success"])
        probe = check.await_args.args[0]
        self.assertEqual((probe.url, probe.keyword, probe.verify_tls), ("https://example.com", "ok", False))

    def test_iter_targets_covers_all_manifest_sections(self):
        self.agent.manifest = {
            "version": "v1",
            "nodes": [{"id": 1, "kind": "xray"}],
            "tcp_monitors": [{"id": 2, "kind": "tcp"}],
            "https_monitors": [{"id": 3, "kind": "https"}],
        }
        self.assertEqual(
            sorted((kind, item["id"]) for kind, item in self.agent.iter_targets()),
            [("https", 3), ("tcp", 2), ("xray", 1)],
        )


if __name__ == "__main__":
    unittest.main()
