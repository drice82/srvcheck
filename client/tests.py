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
        await self.agent.test_node(self.node)
        first_id = self.agent.pending["node:1"]["result_id"]
        await self.agent.test_node(self.node)
        self.assertEqual(list(self.agent.pending), ["node:1"])
        self.assertNotEqual(first_id, self.agent.pending["node:1"]["result_id"])

    @patch("client.main.check_xray", new_callable=AsyncMock)
    async def test_manual_result_has_separate_durable_key(self, check):
        check.return_value = Outcome(False, 12, "failed", None)
        await self.agent.test_node(self.node, task_id="task-id")
        self.assertIn("task:task-id", load_json(self.agent.pending_path, {}))


if __name__ == "__main__":
    unittest.main()
