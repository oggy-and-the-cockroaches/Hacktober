"""Local-only runtime security proxy for developer-started APIs."""

import asyncio
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib import request as urlrequest
from urllib.error import HTTPError
from urllib.parse import unquote_plus, urlparse

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response

from backend.database.schema import get_db
from backend.services.native_inspector import native_inspector
from backend.services.runtime_monitoring import RuntimeMonitoringService

router = APIRouter(prefix="/api/proxy", tags=["runtime-proxy"])
_targets: dict[str, str] = {}
_servers: dict[str, ThreadingHTTPServer] = {}
_cloudflared_processes: dict[str, subprocess.Popen] = {}
_cloudflared_urls: dict[str, str] = {}
_request_windows: dict[tuple[str, str, str], list[float]] = {}
RATE_LIMIT_REQUESTS = int(os.environ.get("SHIPCHECK_PROXY_RATE_LIMIT", "60"))
RATE_LIMIT_WINDOW_SECONDS = 2
ROUTE_BURST_REQUESTS = 120

SUSPICIOUS_PATTERNS = {
    # Time-delay/database workload functions are typically used to infer data without a response body.
    "Blind SQL injection": r"(?i)(?:\b(?:sleep|pg_sleep|benchmark)\s*\(|\bwaitfor\s+delay\b|\bif\s*\([^)]{0,200}\bsleep\s*\()",
    "SQL injection": r"(?i)(\bunion\s+select\b|\bdrop\s+table\b|\bor\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?|--\s*$)",
    "XSS payload": r"(?i)(<script\b|javascript:|onerror\s*=|onload\s*=)",
    # Markup tags in untrusted request data can become HTML injection if reflected unsafely.
    "HTML injection": r"(?is)<\s*(?:iframe|object|embed|form|img|svg|style|meta|link)\b[^>]*>",
    "Server-side includes injection": r"(?is)<!--\s*#\s*(?:include|exec|echo|set|config)\b",
    "Server-side template injection": r"(?is)(?:\{\{\s*[^}]{1,200}\}\}|\$\{\s*[^}]{1,200}\}|<%[=\-]?\s*[^%]{1,200}%>)",
    "XPath injection": r"(?i)(?:/\*/\[|//\*\[|\]\s*\|\s*//|\bor\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?\s*\])",
    "Path traversal": r"(?:\.\./|\.\.\\)",
    # CRLF followed by a header-shaped value is a response/request splitting payload.
    "CRLF injection": r"(?:\r\n|\r|\n)[A-Za-z0-9-]+\s*:",
    # Command separators/interpreters are high-risk when they reach an execution sink.
    "Remote code execution": r"(?i)(?:;\s*(?:curl|wget|bash|sh|cmd(?:\.exe)?|powershell)\b|&&\s*(?:curl|wget|bash|sh|cmd(?:\.exe)?|powershell)\b|\$\([^)]*\)|`[^`]+`|\b(?:cmd\.exe|powershell(?:\.exe)?|/bin/(?:ba)?sh)\b)",
    "OS command injection": r"(?i)(?:[;&|]{1,2}\s*(?:whoami|id|uname|dir|ls|cat|type|net\s+user|ipconfig)\b|\$\([^)]{1,200}\)|`[^`]{1,200}`)",
    # External entity declarations are the actionable XML injection/XXE indicator.
    "XML injection": r"(?is)<!DOCTYPE[^>]*(?:\[[\s\S]*?<!ENTITY|SYSTEM|PUBLIC)|<!ENTITY\s+[^>]+(?:SYSTEM|PUBLIC)",
    # LDAP filter metacharacter combinations rather than an ordinary wildcard.
    "LDAP injection": r"(?i)(?:\)\s*\(\||\)\s*\(&|\(\||\(&|\*\)\s*\(|\x00)",
}


def _event_type_for(label: str) -> str:
    return {
        "Blind SQL injection": "BLIND_SQL_INJECTION",
        "SQL injection": "DB_QUERY",
        "XSS payload": "HTML_RENDER",
        "HTML injection": "HTML_INJECTION",
        "Server-side includes injection": "SSI_INJECTION",
        "Server-side template injection": "SSTI_INJECTION",
        "XPath injection": "XPATH_INJECTION",
        "CRLF injection": "CRLF_INJECTION",
        "Remote code execution": "PROCESS_EXEC",
        "OS command injection": "OS_COMMAND_INJECTION",
        "Path traversal": "PATH_TRAVERSAL",
        "XML injection": "XML_INJECTION",
        "LDAP injection": "LDAP_INJECTION",
    }.get(label, "REQUEST")


def _inspect_attack(probe_text: str) -> str | None:
    """Use native signatures first; keep complete regex coverage as a safe fallback."""
    decoded_once = unquote_plus(probe_text)
    decoded_twice = unquote_plus(decoded_once)
    for text_candidate in (probe_text, decoded_once, decoded_twice):
        for label in native_inspector.inspect(text_candidate.encode("utf-8", errors="ignore")):
            return label
        for label, pattern in SUSPICIOUS_PATTERNS.items():
            if re.search(pattern, text_candidate):
                return label
    return None


def _prune_window(key: tuple[str, str, str], now: float) -> list[float]:
    window = [stamp for stamp in _request_windows.get(key, []) if now - stamp < RATE_LIMIT_WINDOW_SECONDS]
    _request_windows[key] = window
    return window


def _rate_limit_reason(project_id: str, client_id: str, path: str) -> str | None:
    """Identify client abuse separately from route-wide traffic bursts."""
    route = path.split("?", 1)[0]
    now = time.monotonic()
    client_key = (project_id, client_id, route)
    route_key = (project_id, "__all_clients__", route)
    client_window = _prune_window(client_key, now)
    route_window = _prune_window(route_key, now)
    if len(client_window) >= RATE_LIMIT_REQUESTS:
        return "client_limit"
    if len(route_window) >= ROUTE_BURST_REQUESTS:
        return "route_burst"
    client_window.append(now)
    route_window.append(now)
    _request_windows[client_key] = client_window
    _request_windows[route_key] = route_window
    return None


def _local_url(value: str) -> str:
    if not value or not str(value).strip():
        raise HTTPException(400, "Please provide a valid application URL (e.g. http://127.0.0.1:8001).")
    parsed = urlparse(value.strip())
    if parsed.scheme not in {"http", "https"} or parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise HTTPException(400, "Only a localhost API URL is allowed (for example http://127.0.0.1:8001).")
    if parsed.username or parsed.password:
        raise HTTPException(400, "URLs with credentials are not allowed.")

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    # Prevent self-forwarding to Shipcheck Dashboard / API server on port 8000
    if port == 8000:
        raise HTTPException(400, "Target URL cannot point to the Shipcheck dashboard/API server on port 8000. Point to your application server (e.g. http://127.0.0.1:8001).")

    # Prevent forwarding loops to active proxy listeners
    active_ports = {srv.server_address[1] for srv in _servers.values() if srv and hasattr(srv, "server_address")}
    if port in active_ports:
        raise HTTPException(400, f"Target URL cannot point to an active proxy port ({port}). Point to your application server (e.g. http://127.0.0.1:8001).")

    return value.rstrip("/")


def _fetch_json(url: str) -> dict[str, Any]:
    with urlrequest.urlopen(url, timeout=8) as response:
        return json.loads(response.read().decode("utf-8"))


def _find_cloudflared() -> str | None:
    path = shutil.which("cloudflared") or shutil.which("cloudflared.exe")
    if path:
        return path
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        bundle_path = os.path.join(sys._MEIPASS, "cloudflared.exe")
        if os.path.exists(bundle_path):
            return bundle_path
    local_path = os.path.abspath("cloudflared.exe")
    if os.path.exists(local_path):
        return local_path
    parent_local = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "cloudflared.exe")
    if os.path.exists(parent_local):
        return parent_local
    user_downloads = os.path.expanduser("~/Downloads")
    for name in ["cloudflared.exe", "cloudflared-windows-amd64.exe"]:
        dl_path = os.path.join(user_downloads, name)
        if os.path.exists(dl_path):
            return dl_path
    return None


def _start_cloudflared_tunnel(project_id: str, port: int) -> str | None:
    proc = _cloudflared_processes.pop(project_id, None)
    if proc:
        try:
            proc.terminate()
            proc.wait(timeout=1.5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
    _cloudflared_urls.pop(project_id, None)

    exe_path = _find_cloudflared()
    if not exe_path:
        return None

    try:
        creation_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        proc = subprocess.Popen(
            [exe_path, "tunnel", "--url", f"http://127.0.0.1:{port}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            creationflags=creation_flags
        )
        _cloudflared_processes[project_id] = proc

        public_url = None
        connection_registered = False

        def read_stderr():
            nonlocal public_url, connection_registered
            for line in proc.stderr:
                if not public_url:
                    match = re.search(r"https://[a-zA-Z0-9-]+\.trycloudflare\.com", line)
                    if match:
                        public_url = match.group(0)
                        _cloudflared_urls[project_id] = public_url
                if "Registered tunnel connection" in line or "connection registered" in line.lower():
                    connection_registered = True
                    break

        t = threading.Thread(target=read_stderr, daemon=True)
        t.start()
        t.join(timeout=3.0)

        # Verify process is still alive and didn't crash
        if proc.poll() is not None:
            _cloudflared_processes.pop(project_id, None)
            _cloudflared_urls.pop(project_id, None)
            return None

        return public_url or _cloudflared_urls.get(project_id)
    except Exception as exc:
        print(f"Cloudflared tunnel startup failed: {exc}")
        return None


@router.post("/create")
async def create_proxy_endpoint(payload: dict):
    """Start a protected proxy forwarding to a local application."""
    raw_target = payload.get("target_url") or payload.get("url") or "http://127.0.0.1:8001"
    target = _local_url(str(raw_target))

    raw_project_id = payload.get("project_id")
    project_id = None
    if raw_project_id and str(raw_project_id).strip() not in {"undefined", "null", ""}:
        with get_db() as conn:
            row = conn.execute("SELECT id FROM projects WHERE id = ?", (str(raw_project_id).strip(),)).fetchone()
            if row:
                project_id = row[0]

    if not project_id:
        with get_db() as conn:
            row = conn.execute("SELECT id FROM projects ORDER BY created_at DESC LIMIT 1").fetchone()
            if row:
                project_id = row[0]
            else:
                project_id = "default-runtime"
                conn.execute("INSERT OR IGNORE INTO projects (id, name) VALUES (?, ?)", (project_id, "Local Runtime App"))

    _targets[project_id] = target
    port = _start_proxy(project_id, target)
    public_url = await asyncio.to_thread(_start_cloudflared_tunnel, project_id, port)
    proxy_url = f"http://127.0.0.1:{port}"

    return {
        "success": True,
        "proxy_url": proxy_url,
        "proxy_base_url": proxy_url,
        "target_url": target,
        "port": port,
        "project_id": project_id,
        "active": True,
        "status": "active",
        "public_url": public_url,
        "waf_engine": "Hyperion C++ Engine" if native_inspector.available else "Python Signature Engine",
        "rate_limit": {"requests": RATE_LIMIT_REQUESTS, "window_seconds": RATE_LIMIT_WINDOW_SECONDS},
        "message": f"Protected proxy active on port {port} forwarding to {target}. Route traffic through {proxy_url} to enable real-time WAF inspection and RASP blocking."
    }


@router.post("/{project_id}/connect")
async def connect_proxy(project_id: str, payload: dict):
    """Discover a local OpenAPI service (optional) and register it as a proxy target."""
    with get_db() as conn:
        if not conn.execute("SELECT 1 FROM projects WHERE id = ?", (project_id,)).fetchone():
            conn.execute("INSERT OR IGNORE INTO projects (id, name) VALUES (?, ?)", (project_id, "Local Runtime App"))

    raw_target = payload.get("target_url") or payload.get("url") or "http://127.0.0.1:8001"
    target = _local_url(str(raw_target))

    endpoints = []
    title = "Local API"
    try:
        document = await asyncio.to_thread(_fetch_json, f"{target}/openapi.json")
        paths = document.get("paths", {})
        endpoints = [
            {"path": path, "methods": [method.upper() for method in spec if method.lower() in {"get", "post", "put", "patch", "delete", "head", "options"}]}
            for path, spec in paths.items()
        ]
        title = document.get("info", {}).get("title", "Local API")
    except Exception:
        pass

    _targets[project_id] = target
    port = _start_proxy(project_id, target)
    public_url = await asyncio.to_thread(_start_cloudflared_tunnel, project_id, port)
    proxy_url = f"http://127.0.0.1:{port}"

    return {
        "success": True,
        "proxy_url": proxy_url,
        "proxy_base_url": proxy_url,
        "target_url": target,
        "title": title,
        "endpoints": endpoints,
        "port": port,
        "project_id": project_id,
        "active": True,
        "status": "active",
        "public_url": public_url,
        "waf_engine": "Hyperion C++ Engine" if native_inspector.available else "Python Signature Engine",
        "rate_limit": {"requests": RATE_LIMIT_REQUESTS, "window_seconds": RATE_LIMIT_WINDOW_SECONDS},
        "message": f"Point your frontend API base URL to the protected localhost proxy URL {proxy_url} shown above."
    }


@router.get("/status")
@router.get("/{project_id}/status")
async def get_proxy_status(project_id: str = None):
    """Get active proxy status for the specified or default project."""
    if not project_id or project_id not in _servers:
        if _servers:
            project_id = next(iter(_servers.keys()))
        else:
            return {"active": False, "proxy_url": None, "proxy_base_url": None, "target_url": None, "port": None}

    server = _servers.get(project_id)
    port = server.server_address[1] if server else None
    proxy_url = f"http://127.0.0.1:{port}" if port else None
    return {
        "active": bool(server is not None),
        "project_id": project_id,
        "proxy_url": proxy_url,
        "proxy_base_url": proxy_url,
        "target_url": _targets.get(project_id),
        "port": port,
        "waf_engine": "Hyperion C++ Engine" if native_inspector.available else "Python Signature Engine"
    }


@router.delete("/disconnect")
@router.post("/disconnect")
@router.delete("/{project_id}/disconnect")
@router.post("/{project_id}/disconnect")
async def disconnect_proxy(project_id: str = None):
    """Stop proxy listener and clean up running processes."""
    targets_to_remove = [project_id] if project_id and project_id in _servers else list(_servers.keys())
    if not targets_to_remove and project_id:
        targets_to_remove = [project_id]

    for pid in targets_to_remove:
        _targets.pop(pid, None)
        server = _servers.pop(pid, None)
        if server:
            try:
                server.shutdown()
                server.server_close()
            except Exception:
                pass
        proc = _cloudflared_processes.pop(pid, None)
        if proc:
            try:
                proc.terminate()
                proc.wait(timeout=1.5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        _cloudflared_urls.pop(pid, None)
        for key in [key for key in _request_windows if key[0] == pid]:
            del _request_windows[key]
    return {"disconnected": True, "active": False, "message": "Proxy listener disconnected."}


def _forward(method: str, url: str, body: bytes, headers: dict[str, str]):
    hop_by_hop = {"host", "content-length", "connection", "transfer-encoding", "upgrade", "keep-alive"}
    forwarded = {key: value for key, value in headers.items() if key.lower() not in hop_by_hop}
    request = urlrequest.Request(url, data=body or None, headers=forwarded, method=method)
    try:
        with urlrequest.urlopen(request, timeout=15) as upstream:
            return upstream.status, upstream.read(), dict(upstream.headers.items())
    except HTTPError as upstream:
        return upstream.code, upstream.read(), dict(upstream.headers.items())


def _header(headers: dict[str, str], name: str, default: str = "") -> str:
    """Read stdlib HTTP headers case-insensitively."""
    return next((value for key, value in headers.items() if key.lower() == name.lower()), default)


def _make_handler(project_id: str, target: str):
    """Create a dedicated localhost proxy handler for one selected project."""
    class ProtectedProxyHandler(BaseHTTPRequestHandler):
        def log_message(self, _format, *_args):
            return

        def _cors(self):
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, Accept, X-Shipcheck-Client")

        def do_OPTIONS(self):
            self.send_response(204)
            self._cors()
            self.end_headers()

        def _handle(self):
            try:
                length = max(0, int(self.headers.get("Content-Length", "0")))
            except (ValueError, TypeError):
                length = 0
            body = self.rfile.read(length) if length else b""
            probe_text = (unquote_plus(self.path) + "\n" + unquote_plus(body.decode("utf-8", errors="ignore")))[:200_000]
            monitoring = RuntimeMonitoringService(project_id)
            client_id = self.headers.get("X-Shipcheck-Client", self.client_address[0])[:128]
            rate_reason = _rate_limit_reason(project_id, client_id, self.path)
            if rate_reason:
                evidence = (f"Client {client_id} exceeded {RATE_LIMIT_REQUESTS} requests per {RATE_LIMIT_WINDOW_SECONDS} seconds."
                            if rate_reason == "client_limit" else
                            f"Route traffic exceeded {ROUTE_BURST_REQUESTS} requests per {RATE_LIMIT_WINDOW_SECONDS} seconds; possible DDoS burst.")
                monitoring.record_event({"event_type": "RATE_ANOMALY", "endpoint": self.path, "action": "BLOCKED", "confidence": "HIGH", "evidence": evidence})
                self.send_response(429)
                self._cors()
                self.send_header("X-Shipcheck-Proxy", "active")
                self.send_header("X-Shipcheck-Rate-Limit", f"client={RATE_LIMIT_REQUESTS}, route={ROUTE_BURST_REQUESTS}/{RATE_LIMIT_WINDOW_SECONDS}s")
                self.send_header("Content-Type", "application/json")
                self.send_header("Retry-After", str(RATE_LIMIT_WINDOW_SECONDS))
                self.end_headers()
                self.wfile.write(json.dumps({"detail": "Rate limit exceeded. Try again in a minute."}).encode())
                return
            label = _inspect_attack(probe_text)
            if label:
                source = "native engine" if native_inspector.available else "signature engine"
                monitoring.record_event({"event_type": _event_type_for(label), "endpoint": self.path, "action": "BLOCKED", "confidence": "HIGH", "evidence": f"Blocked {label} pattern by Shipcheck {source} before forwarding."})
                self.send_response(403)
                self._cors()
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"detail": "Request blocked by Shipcheck", "reason": label}).encode())
                return
            try:
                status, response_body, response_headers = _forward(self.command, f"{target}{self.path}", body, dict(self.headers))
                monitoring.record_event({"event_type": "REQUEST", "endpoint": self.path, "action": "LOGGED", "confidence": "HIGH", "evidence": f"{self.command} forwarded with response {status}."})
                self.send_response(status)
                self._cors()
                self.send_header("X-Shipcheck-Proxy", "active")
                self.send_header("X-Shipcheck-Rate-Limit", f"client={RATE_LIMIT_REQUESTS}, route={ROUTE_BURST_REQUESTS}/{RATE_LIMIT_WINDOW_SECONDS}s")
                self.send_header("Content-Type", _header(response_headers, "Content-Type", "application/octet-stream"))
                self.end_headers()
                self.wfile.write(response_body)
            except Exception as exc:
                monitoring.record_event({"event_type": "PROXY", "endpoint": self.path, "action": "SUSPICIOUS", "confidence": "HIGH", "evidence": str(exc)})
                self.send_response(502)
                self._cors()
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"detail": f"Upstream unavailable: {exc}"}).encode())

        do_GET = _handle
        do_POST = _handle
        do_PUT = _handle
        do_PATCH = _handle
        do_DELETE = _handle
        do_HEAD = _handle
    return ProtectedProxyHandler


def _start_proxy(project_id: str, target: str) -> int:
    import socket
    existing = _servers.pop(project_id, None)
    if existing:
        try:
            existing.shutdown()
            existing.server_close()
        except Exception:
            pass
    # Port 0 delegates collision-free random-port selection to the OS.
    server = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(project_id, target))
    port = server.server_address[1]
    _servers[project_id] = server
    threading.Thread(target=server.serve_forever, name=f"shipcheck-proxy-{project_id[:8]}", daemon=True).start()

    # Verify listener is active and accepting connections
    reachable = False
    for _ in range(20):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                reachable = True
                break
        except Exception:
            time.sleep(0.05)

    if not reachable:
        _servers.pop(project_id, None)
        try:
            server.shutdown()
            server.server_close()
        except Exception:
            pass
        raise HTTPException(500, f"Failed to start and verify reachability of proxy listener on port {port}.")

    return port


@router.api_route("/{project_id}/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
async def proxy_request(project_id: str, path: str, request: Request):
    target = _targets.get(project_id)
    if not target:
        raise HTTPException(409, "No local API connected. Connect it in Runtime first.")

    body = await request.body()
    probe_text = (unquote_plus(path + "?" + request.url.query) + "\n" + unquote_plus(body.decode("utf-8", errors="ignore")))[:200_000]
    monitoring = RuntimeMonitoringService(project_id)
    label = _inspect_attack(probe_text)
    if label:
        source = "native engine" if native_inspector.available else "signature engine"
        monitoring.record_event({
            "event_type": _event_type_for(label), "endpoint": "/" + path, "action": "BLOCKED", "confidence": "HIGH",
            "evidence": f"Blocked {label} pattern by Shipcheck {source} before forwarding to local API."
        })
        return Response(content=json.dumps({"detail": "Request blocked by Shipcheck runtime proxy", "reason": label}), status_code=403, media_type="application/json")

    query = request.url.query
    upstream_url = f"{target}/{path}" + (f"?{query}" if query else "")
    try:
        status, response_body, response_headers = await asyncio.to_thread(_forward, request.method, upstream_url, body, dict(request.headers))
    except Exception as exc:
        monitoring.record_event({"event_type": "PROXY", "endpoint": "/" + path, "action": "SUSPICIOUS", "confidence": "HIGH", "evidence": str(exc)})
        raise HTTPException(502, f"Local API could not be reached: {exc}")

    monitoring.record_event({"event_type": "REQUEST", "endpoint": "/" + path, "action": "LOGGED", "confidence": "HIGH", "evidence": f"{request.method} forwarded with response {status}."})
    content_type = _header(response_headers, "Content-Type", "application/octet-stream")
    return Response(content=response_body, status_code=status, media_type=content_type)
