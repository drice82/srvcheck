import asyncio
import json
import os
import signal
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import quote

import httpx

from monitors.checkers import check_xray


class ClientAgent:
    def __init__(self):
        self.server_url = required_env("SERVER_URL").rstrip("/")
        self.client_name = required_env("CLIENT_NAME")
        self.token = required_env("CLIENT_API_TOKEN")
        self.data_dir = Path(os.getenv("CLIENT_DATA_DIR", "/app/data"))
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_path = self.data_dir / "manifest.json"
        self.pending_path = self.data_dir / "pending.json"
        self.manifest = load_json(self.manifest_path, {"version": "", "nodes": []})
        self.pending = load_json(self.pending_path, {})
        if not isinstance(self.manifest, dict) or not isinstance(self.manifest.get("nodes"), list):
            self.manifest = {"version": "", "nodes": []}
        if not isinstance(self.pending, dict):
            self.pending = {}
        self.next_due = {}
        self.running = True
        self.semaphore = asyncio.Semaphore(int(os.getenv("XRAY_CONCURRENCY", "4")))
        self.http = httpx.AsyncClient(
            timeout=20,
            headers={
                "Authorization": f"Bearer {self.token}",
                "X-Client-Name": quote(self.client_name, safe=""),
            },
        )

    async def run(self):
        print(f"SrvCheck client started: {self.client_name}", flush=True)
        await self.refresh_manifest(force=True)
        loops = [
            asyncio.create_task(self.manifest_loop()),
            asyncio.create_task(self.schedule_loop()),
            asyncio.create_task(self.task_loop()),
            asyncio.create_task(self.upload_loop()),
        ]
        try:
            await asyncio.gather(*loops)
        finally:
            for task in loops:
                task.cancel()
            await self.http.aclose()

    async def manifest_loop(self):
        while self.running:
            await asyncio.sleep(60)
            await self.refresh_manifest()

    async def refresh_manifest(self, force=False):
        headers = {}
        if self.manifest.get("version") and not force:
            headers["If-None-Match"] = f'"{self.manifest["version"]}"'
        try:
            response = await self.http.get(f"{self.server_url}/api/v1/client/manifest", headers=headers)
            if response.status_code == 304:
                return True
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload.get("nodes"), list) or not payload.get("version"):
                raise ValueError("invalid manifest")
            if payload["version"] != self.manifest.get("version"):
                self.manifest = payload
                atomic_json(self.manifest_path, payload)
                valid_ids = {str(node["id"]) for node in payload["nodes"]}
                self.next_due = {key: value for key, value in self.next_due.items() if key in valid_ids}
                print(f"manifest updated: {len(payload['nodes'])} nodes", flush=True)
            return True
        except Exception as exc:
            print(f"manifest refresh failed: {type(exc).__name__}: {exc}", flush=True)
        return False

    async def schedule_loop(self):
        while self.running:
            now = asyncio.get_running_loop().time()
            due = []
            for node in self.manifest.get("nodes", []):
                key = str(node["id"])
                if self.next_due.get(key, 0) <= now:
                    self.next_due[key] = now + max(30, int(node["check_interval_seconds"]))
                    due.append(node)
            if due:
                await asyncio.gather(*(self.test_node(node) for node in due))
            await asyncio.sleep(1)

    async def task_loop(self):
        while self.running:
            try:
                response = await self.http.get(f"{self.server_url}/api/v1/client/tasks")
                response.raise_for_status()
                tasks = response.json().get("tasks", [])
                if tasks and not await self.refresh_manifest(force=True):
                    await asyncio.sleep(5)
                    continue
                for task in tasks:
                    pending_key = f"task:{task['id']}"
                    if pending_key in self.pending:
                        continue
                    node = next((item for item in self.manifest.get("nodes", []) if item["id"] == task["node_id"]), None)
                    if node:
                        await self.test_node(node, task_id=task["id"])
            except Exception as exc:
                print(f"task poll failed: {type(exc).__name__}: {exc}", flush=True)
            await asyncio.sleep(5)

    async def test_node(self, node, task_id=None):
        async with self.semaphore:
            checked_at = datetime.now(timezone.utc).isoformat()
            probe_node = SimpleNamespace(
                share_link=node["share_link"], timeout_seconds=int(node["timeout_seconds"])
            )
            outcome = await check_xray(
                probe_node,
                xray_executable=os.getenv("XRAY_EXECUTABLE", "/usr/local/bin/xray"),
                ip_check_url=os.getenv("XRAY_IP_CHECK_URL", "https://api.ipify.org?format=json"),
            )
            result = {
                "result_id": str(uuid.uuid4()),
                "node_id": node["id"],
                "checked_at": checked_at,
                "success": outcome.success,
                "latency_ms": outcome.latency_ms,
                "proxy_ip": outcome.proxy_ip,
                "message": outcome.message,
            }
            key = f"node:{node['id']}"
            if task_id:
                result["task_id"] = task_id
                key = f"task:{task_id}"
            self.pending[key] = result
            atomic_json(self.pending_path, self.pending)
            print(f"checked {node['name']}: {'up' if outcome.success else 'down'}", flush=True)

    async def upload_loop(self):
        while self.running:
            if self.pending:
                batch = list(self.pending.values())
                try:
                    response = await self.http.post(
                        f"{self.server_url}/api/v1/client/results", json={"results": batch}
                    )
                    response.raise_for_status()
                    payload = response.json()
                    finished = set(payload.get("accepted", [])) | set(payload.get("duplicates", []))
                    rejected = {item.get("result_id") for item in payload.get("rejected", [])}
                    remove = finished | rejected
                    self.pending = {
                        key: value for key, value in self.pending.items() if value["result_id"] not in remove
                    }
                    atomic_json(self.pending_path, self.pending)
                except Exception as exc:
                    print(f"result upload failed: {type(exc).__name__}: {exc}", flush=True)
            await asyncio.sleep(3)


def required_env(name):
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"missing required environment variable: {name}")
    return value


def load_json(path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return default


def atomic_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    temporary.replace(path)


async def main():
    agent = ClientAgent()
    loop = asyncio.get_running_loop()
    for name in ("SIGINT", "SIGTERM"):
        if hasattr(signal, name):
            loop.add_signal_handler(getattr(signal, name), lambda: setattr(agent, "running", False))
    await agent.run()


if __name__ == "__main__":
    asyncio.run(main())
