import asyncio
import base64
import hashlib
import ipaddress
import json
import os
import socket
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

import httpx

@dataclass
class Outcome:
    success: bool
    latency_ms: int | None = None
    message: str = ""
    proxy_ip: str | None = None

def safe_error(exc):
    return f"{type(exc).__name__}: {str(exc)[:350]}"

async def check_tcp(monitor):
    started = time.monotonic()
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(monitor.host, monitor.port), monitor.timeout_seconds
        )
        writer.close()
        await writer.wait_closed()
        return Outcome(True, int((time.monotonic() - started) * 1000), "TCP 连接成功")
    except Exception as exc:
        return Outcome(False, int((time.monotonic() - started) * 1000), safe_error(exc))

async def check_https(monitor):
    started = time.monotonic()
    try:
        async with httpx.AsyncClient(
            verify=monitor.verify_tls,
            follow_redirects=monitor.follow_redirects,
            timeout=monitor.timeout_seconds,
        ) as client:
            response = await client.get(monitor.url)
        latency = int((time.monotonic() - started) * 1000)
        if not monitor.expected_status_min <= response.status_code <= monitor.expected_status_max:
            return Outcome(False, latency, f"HTTP {response.status_code} 不在期望范围")
        if monitor.keyword and monitor.keyword not in response.text:
            return Outcome(False, latency, "响应中未找到关键词")
        return Outcome(True, latency, f"HTTP {response.status_code}")
    except Exception as exc:
        return Outcome(False, int((time.monotonic() - started) * 1000), safe_error(exc))

def decode_subscription(content: str):
    text = content.strip()
    if "://" not in text:
        try:
            text = base64.b64decode(text + "=" * (-len(text) % 4)).decode("utf-8")
        except Exception:
            pass
    links = [line.strip() for line in text.replace("\r", "").split("\n") if line.strip()]
    nodes = []
    for link in links:
        protocol = link.split("://", 1)[0].lower() if "://" in link else ""
        if protocol not in {"vmess", "vless", "trojan", "ss"}:
            continue
        name = parse_node_name(link, protocol)
        fingerprint = hashlib.sha256(link.split("#", 1)[0].encode()).hexdigest()
        nodes.append({"protocol": protocol, "name": name[:120] or f"{protocol}-{fingerprint[:8]}", "fingerprint": fingerprint, "share_link": link})
    return nodes

def parse_node_name(link, protocol):
    if protocol == "vmess":
        try:
            raw = link.split("://", 1)[1]
            data = json.loads(base64.b64decode(raw + "=" * (-len(raw) % 4)))
            return str(data.get("ps") or data.get("add") or "")
        except Exception:
            return "VMess 节点"
    return unquote(urlparse(link).fragment) or unquote(urlparse(link).hostname or "")

def xray_config_from_link(link, socks_port):
    protocol = link.split("://", 1)[0].lower()
    if protocol == "vmess":
        d = decode_vmess(link)
        stream = stream_settings(
            d.get("net", "tcp"), d.get("tls", ""), d.get("host", ""),
            d.get("path", ""), d.get("sni", ""), d.get("fp", ""),
            d.get("alpn", ""), d,
        )
        outbound = {"protocol": "vmess", "settings": {"vnext": [{"address": d["add"], "port": int(d["port"]), "users": [{"id": d["id"], "alterId": int(d.get("aid") or 0), "security": d.get("scy") or "auto"}]}]}, "streamSettings": stream}
    elif protocol in {"vless", "trojan"}:
        u, q = urlparse(link), query_values(link)
        if not u.hostname or not u.port:
            raise ValueError("节点缺少服务器地址或端口")
        user = unquote(u.username or "")
        if protocol == "vless":
            settings_data = {"vnext": [{"address": u.hostname, "port": u.port, "users": [compact({"id": user, "encryption": q.get("encryption", "none"), "flow": q.get("flow", "")})]}]}
        else:
            settings_data = {"servers": [{"address": u.hostname, "port": u.port, "password": user}]}
        outbound = {"protocol": protocol, "settings": settings_data, "streamSettings": stream_settings(q.get("type", "tcp"), q.get("security", ""), q.get("host", ""), q.get("path", q.get("serviceName", "")), q.get("sni", ""), q.get("fp", ""), q.get("alpn", ""), q)}
    elif protocol == "ss":
        host, port, method, password = parse_shadowsocks(link)
        outbound = {"protocol": "shadowsocks", "settings": {"servers": [{"address": host, "port": port, "method": method, "password": password}]}}
    else:
        raise ValueError(f"不支持的 Xray 协议: {protocol}")
    outbound["tag"] = "proxy"
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{"tag": "probe-in", "listen": "127.0.0.1", "port": socks_port, "protocol": "socks", "settings": {"auth": "noauth", "udp": False}}],
        "outbounds": [outbound, {"tag": "direct", "protocol": "freedom"}],
        "routing": {"domainStrategy": "AsIs", "rules": [{"type": "field", "inboundTag": ["probe-in"], "outboundTag": "proxy"}]},
    }

def stream_settings(network, security, host, path, sni, fingerprint="", alpn="", params=None):
    params = params or {}
    network = {"tcp": "raw", "ws": "websocket", "http": "xhttp", "h2": "xhttp"}.get((network or "tcp").lower(), (network or "raw").lower())
    security = (security or "none").lower()
    result = {"network": network, "security": security}
    if network == "websocket":
        result["wsSettings"] = compact({"path": path or "/", "host": host, "headers": {"Host": host} if host else None})
    elif network == "grpc":
        result["grpcSettings"] = compact({"serviceName": path, "multiMode": truthy(params.get("mode") == "multi")})
    elif network == "httpupgrade":
        result["httpupgradeSettings"] = compact({"path": path or "/", "host": host})
    elif network == "xhttp":
        result["xhttpSettings"] = compact({"path": path or "/", "host": host, "mode": params.get("mode"), "extra": parse_json_value(params.get("extra"))})
    elif network == "raw" and params.get("headerType") == "http":
        result["rawSettings"] = {"header": {"type": "http", "request": {"path": [path or "/"], "headers": {"Host": [host]} if host else {}}}}
    if security == "tls":
        # Do not emit allowInsecure: certificate verification remains enabled.
        result["tlsSettings"] = compact({
            "serverName": sni or host,
            "verifyPeerCertByName": params.get("verifyPeerCertByName") or params.get("vcn"),
            "fingerprint": fingerprint,
            "alpn": split_csv(alpn),
            "pinnedPeerCertSha256": params.get("pcs") or params.get("pinnedPeerCertSha256"),
        })
    elif security == "reality":
        public_key = params.get("pbk") or params.get("publicKey")
        if not public_key:
            raise ValueError("REALITY 节点缺少 publicKey/pbk")
        result["realitySettings"] = compact({
            "serverName": sni or host,
            "fingerprint": fingerprint or "chrome",
            # Current Xray renamed the client-side publicKey field to password.
            "password": public_key,
            "shortId": params.get("sid") or params.get("shortId", ""),
            "spiderX": params.get("spx") or params.get("spiderX", ""),
        })
    return result

def decode_vmess(link):
    raw = link.split("://", 1)[1].split("#", 1)[0]
    try:
        return json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
    except Exception as exc:
        raise ValueError("无效的 VMess 分享链接") from exc

def query_values(link):
    return {key: values[-1] for key, values in parse_qs(urlparse(link).query, keep_blank_values=True).items()}

def parse_shadowsocks(link):
    raw = link.split("ss://", 1)[1].split("#", 1)[0].split("?", 1)[0]
    if "@" not in raw:
        try: raw = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)).decode()
        except Exception as exc: raise ValueError("无效的 Shadowsocks 分享链接") from exc
    credentials, address = raw.rsplit("@", 1)
    if ":" not in credentials:
        try: credentials = base64.urlsafe_b64decode(credentials + "=" * (-len(credentials) % 4)).decode()
        except Exception as exc: raise ValueError("无效的 Shadowsocks 认证信息") from exc
    method, password = credentials.split(":", 1)
    parsed = urlparse(f"ss://x@{address}")
    if not parsed.hostname or not parsed.port: raise ValueError("Shadowsocks 节点缺少地址或端口")
    return parsed.hostname, parsed.port, unquote(method), unquote(password)

def compact(value):
    return {k: v for k, v in value.items() if v not in (None, "", [], {})}

def split_csv(value):
    return [item.strip() for item in str(value).replace("|", ",").split(",") if item.strip()]

def truthy(value):
    return value if value else None

def parse_json_value(value):
    if not value: return None
    try: return json.loads(unquote(value))
    except (ValueError, TypeError): return None

def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]

async def check_xray(node, xray_executable=None, ip_check_url=None):
    started, port = time.monotonic(), free_port()
    process = None
    try:
        config = xray_config_from_link(node.share_link, port)
        with tempfile.TemporaryDirectory(prefix="srvcheck-xray-") as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            os.chmod(path, 0o600)
            executable = xray_executable or os.getenv("XRAY_EXECUTABLE", "xray")
            check_url = ip_check_url or os.getenv("XRAY_IP_CHECK_URL", "https://api.ipify.org?format=json")
            process = await asyncio.create_subprocess_exec(executable, "run", "-c", str(path), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            await wait_port(port, min(node.timeout_seconds, 5), process)
            async with httpx.AsyncClient(proxy=f"socks5://127.0.0.1:{port}", timeout=node.timeout_seconds) as client:
                response = await client.get(check_url)
            if response.status_code >= 400:
                raise RuntimeError(f"探测地址返回 HTTP {response.status_code}")
            proxy_ip = parse_proxy_ip(response)
            return Outcome(True, int((time.monotonic() - started) * 1000), "Xray 代理可用", proxy_ip)
    except Exception as exc:
        detail = safe_error(exc)
        if process:
            runtime_error = await stop_xray_process(process)
            process = None
            if runtime_error:
                detail = f"{detail} | Xray: {runtime_error}"
        return Outcome(False, int((time.monotonic() - started) * 1000), detail[:500])
    finally:
        if process and process.returncode is None:
            await stop_xray_process(process)

async def stop_xray_process(process):
    if process.returncode is None:
        process.terminate()
        try: await asyncio.wait_for(process.wait(), 2)
        except asyncio.TimeoutError:
            process.kill(); await process.wait()
    try:
        stdout, stderr = await process.communicate()
        output = stdout.decode(errors="replace") + "\n" + stderr.decode(errors="replace")
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        return lines[-1][-350:] if lines else ""
    except Exception:
        return ""

def parse_proxy_ip(response):
    candidate = None
    try:
        payload = response.json()
        if isinstance(payload, dict): candidate = payload.get("ip") or payload.get("query")
    except (ValueError, TypeError):
        pass
    if not candidate: candidate = response.text.strip()
    try: return str(ipaddress.ip_address(candidate))
    except (ValueError, TypeError): return None

async def wait_port(port, timeout, process=None):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process and process.returncode is not None:
            _, stderr = await process.communicate()
            detail = stderr.decode(errors="replace").strip()[-500:]
            raise RuntimeError(f"Xray 配置或启动失败: {detail or '进程已退出'}")
        try:
            _, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.close(); await writer.wait_closed(); return
        except OSError:
            await asyncio.sleep(.1)
    raise TimeoutError("Xray 本地入站启动超时")
