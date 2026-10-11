"""Regression and integration tests for Shipcheck Runtime Monitoring and Protected Proxy."""

import asyncio
import json
import sqlite3
import time
import urllib.request
import urllib.error
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import pytest
from fastapi import HTTPException

import backend.database.schema as db_schema
from backend.api.proxy import (
    create_proxy_endpoint,
    disconnect_proxy,
    get_proxy_status,
    _servers,
    _targets,
    _inspect_attack,
    _local_url
)
from backend.api.runtime import (
    get_all_runtime_stats,
    get_all_runtime_events,
    scan_direct_runtime
)
from backend.services.native_inspector import native_inspector


@pytest.fixture(autouse=True)
def _isolate_db(tmp_path, monkeypatch):
    """Isolate SQLite database per test."""
    db_path = str(tmp_path / "test_runtime.db")
    monkeypatch.setenv("SHIPCHECK_DB_PATH", db_path)
    db_schema.DATABASE_PATH = db_path
    db_schema.init_db()
    yield
    # Clean up active servers
    for pid in list(_servers.keys()):
        srv = _servers.pop(pid, None)
        if srv:
            try:
                srv.shutdown()
                srv.server_close()
            except Exception:
                pass
    _targets.clear()


@pytest.fixture
def dummy_upstream():
    """Start a lightweight mock HTTP upstream on a dynamic port."""
    class DummyHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def do_GET(self):
            if self.path in ("/", "/api/data", "/api/data?"):
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status": "ok", "source": "dummy_upstream"}')
            elif self.path.startswith("/api/data"):
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status": "ok", "source": "dummy_upstream"}')
            elif self.path.startswith("/openapi.json"):
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"openapi": "3.0.0", "info": {"title": "Test Upstream API"}, "paths": {"/api/data": {"get": {}}}}')
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b'{"detail": "Not found"}')

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b""
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"received": body.decode("utf-8", errors="ignore")}).encode())

    server = ThreadingHTTPServer(("127.0.0.1", 0), DummyHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    server.server_close()


def test_proxy_create_schema_and_reachability(dummy_upstream):
    """Verify POST /api/proxy/create returns valid proxy_url and starts reachable listener."""
    data = asyncio.run(create_proxy_endpoint({"target_url": dummy_upstream}))

    assert data["success"] is True
    assert data["active"] is True
    assert "proxy_url" in data
    assert data["proxy_url"].startswith("http://127.0.0.1:")
    assert data["proxy_base_url"] == data["proxy_url"]
    assert data["target_url"] == dummy_upstream
    assert isinstance(data["port"], int)

    # Verify listener is reachable and forwards benign requests
    proxy_url = data["proxy_url"]
    with urllib.request.urlopen(f"{proxy_url}/api/data") as resp:
        assert resp.status == 200
        body = json.loads(resp.read().decode("utf-8"))
        assert body["source"] == "dummy_upstream"


def test_proxy_blocks_sqli_and_xss(dummy_upstream):
    """Verify malicious payloads are intercepted by WAF with HTTP 403 and logged in runtime_events."""
    data = asyncio.run(create_proxy_endpoint({"target_url": dummy_upstream}))
    proxy_url = data["proxy_url"]

    # 1. Test SQL Injection blocking
    q_sqli = urllib.parse.quote("' UNION SELECT * FROM users--")
    sqli_url = f"{proxy_url}/api/data?q={q_sqli}"
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(sqli_url)
    assert exc_info.value.code == 403
    err_body = json.loads(exc_info.value.read().decode("utf-8"))
    assert "blocked by Shipcheck" in err_body["detail"]

    # 2. Test XSS blocking
    q_xss = urllib.parse.quote("<script>alert('pwn')</script>")
    xss_url = f"{proxy_url}/api/data?input={q_xss}"
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(xss_url)
    assert exc_info.value.code == 403

    # 3. Verify events were persisted in SQLite
    stats = asyncio.run(get_all_runtime_stats())
    assert stats["total_events"] >= 2
    assert stats["blocked"] >= 2


def test_proxy_self_forwarding_loop_prevention():
    """Verify proxy rejects targeting port 8000 (Shipcheck itself) or an active proxy port."""
    with pytest.raises(HTTPException) as exc_info:
        _local_url("http://127.0.0.1:8000")
    assert exc_info.value.status_code == 400
    assert "dashboard/API server on port 8000" in exc_info.value.detail


def test_proxy_invalid_target_rejection():
    """Verify non-localhost URLs and empty targets are rejected."""
    with pytest.raises(HTTPException) as exc1:
        _local_url("http://evil.attacker.com")
    assert exc1.value.status_code == 400

    with pytest.raises(HTTPException) as exc2:
        _local_url("")
    assert exc2.value.status_code == 400


def test_repeated_proxy_creation_replaces_cleanly(dummy_upstream):
    """Verify repeatedly creating proxy shuts down previous listener without port leak."""
    res1 = asyncio.run(create_proxy_endpoint({"target_url": dummy_upstream, "project_id": "proj-1"}))
    port1 = res1["port"]

    res2 = asyncio.run(create_proxy_endpoint({"target_url": dummy_upstream, "project_id": "proj-1"}))
    port2 = res2["port"]

    # Status check
    status = asyncio.run(get_proxy_status("proj-1"))
    assert status["active"] is True
    assert status["port"] == port2


def test_proxy_disconnect_and_status(dummy_upstream):
    """Verify proxy status and clean shutdown."""
    res = asyncio.run(create_proxy_endpoint({"target_url": dummy_upstream}))
    proxy_url = res["proxy_url"]

    # Status is active
    status_active = asyncio.run(get_proxy_status())
    assert status_active["active"] is True
    assert status_active["proxy_url"] == proxy_url

    # Disconnect
    disc = asyncio.run(disconnect_proxy())
    assert disc["disconnected"] is True

    # Status is now inactive
    status_inactive = asyncio.run(get_proxy_status())
    assert status_inactive["active"] is False
    assert status_inactive["proxy_url"] is None


def test_direct_scan_local_runtime(dummy_upstream):
    """Verify direct runtime probe endpoint works against local apps."""
    res = asyncio.run(scan_direct_runtime({"url": dummy_upstream}))
    assert res["success"] is True
    assert res["status_code"] == 200
    assert "missing_headers" in res
    assert res["not_found_status"] == 404
