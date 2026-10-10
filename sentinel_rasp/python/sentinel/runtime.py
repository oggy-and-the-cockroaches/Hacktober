import contextvars
import json
import logging
import re
import sqlite3
import subprocess
from pathlib import Path
from threading import Lock
from urllib.parse import urlparse
from uuid import uuid4

from .engine import NativeEngine
from .events import EventType, SecurityEvent
from .policy import load_policy

_request_id = contextvars.ContextVar("sentinel_request_id", default="")
_runtime = None
_original_request = None
_original_sqlite_connect = None
_original_subprocess_run = None
log = logging.getLogger("sentinel.security")

class _JsonSecurityLog:
    """Small durable JSON event store for the demo; no payload values are recorded."""
    def __init__(self, path):
        self.path = Path(path)
        self._lock = Lock()

    def append(self, record):
        with self._lock:
            events = []
            if self.path.exists():
                try:
                    events = json.loads(self.path.read_text(encoding="utf-8"))
                    if not isinstance(events, list): events = []
                except (OSError, json.JSONDecodeError):
                    # Preserve enforcement even if an operator has corrupted the log.
                    events = []
            events.append(record)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.path.with_suffix(self.path.suffix + ".tmp")
            temporary.write_text(json.dumps(events, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            temporary.replace(self.path)

    def read(self):
        if not self.path.exists(): return []
        try:
            contents = json.loads(self.path.read_text(encoding="utf-8"))
            return contents if isinstance(contents, list) else []
        except (OSError, json.JSONDecodeError):
            return []

    def clear(self):
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text("[]\n", encoding="utf-8")

class SentinelBlocked(RuntimeError):
    def __init__(self, policy, reason, destination):
        self.policy, self.reason, self.destination = policy, reason, destination
        super().__init__(f"Sentinel blocked outbound request: {reason}")

class SensitiveValue(str):
    """Explicit marker; string-compatible so supported HTTP clients can send it."""
    pass

def secret(value, resource="SECRET"):
    return SensitiveValue(str(value))

def _contains_secret(value):
    if isinstance(value, SensitiveValue): return True
    if isinstance(value, dict): return any(_contains_secret(v) for v in value.values())
    if isinstance(value, (tuple, list)): return any(_contains_secret(v) for v in value)
    return False

def _destination(url):
    host = (urlparse(url).hostname or "").lower()
    # Explicitly local hosts form the MVP trusted set for deterministic tests/demo.
    return "TRUSTED" if host in {"localhost", "127.0.0.1", "::1"} else "UNTRUSTED"

def _patched_request(session, method, url, **kwargs):
    sensitive = _contains_secret(kwargs.get("data")) or _contains_secret(kwargs.get("json"))
    event = SecurityEvent(EventType.NETWORK_SEND, request_id=_request_id.get(), destination=_destination(url),
                          data_classification="SECRET" if sensitive else "PUBLIC", operation_id=str(uuid4()))
    decision, reason = _runtime.engine.evaluate(event)
    if decision == "BLOCK":
        record = {"event": "SECURITY_VIOLATION", "policy": _runtime.policy.name,
                  "event_type": event.event_type.value, "data": event.data_classification,
                  "destination": event.destination, "decision": "BLOCKED", "reason": reason}
        log.warning(json.dumps(record, sort_keys=True))
        _runtime.security_log.append(record)
        raise SentinelBlocked(_runtime.policy.name, reason, event.destination)
    return _original_request(session, method, url, **kwargs)

def _unsafe_sql(statement):
    """Conservative MVP detector for injection syntax in dynamically built SQL."""
    normalized = statement.lower()
    return ("--" in normalized or "/*" in normalized or ";" in normalized or
            bool(re.search(r"\bunion\s+select\b|\bor\s+['\"]?[0-9a-z]+['\"]?\s*=", normalized)))

def _evaluate_sql(statement):
    if not _unsafe_sql(statement): return
    event = SecurityEvent(EventType.DB_QUERY, request_id=_request_id.get(), resource="sqlite3",
                          data_classification="UNSAFE_SQL", operation_id=str(uuid4()))
    decision, reason = _runtime.engine.evaluate(event)
    if decision == "BLOCK":
        record = {"event": "SECURITY_VIOLATION", "policy": _runtime.policy.name,
                  "event_type": event.event_type.value, "resource": event.resource,
                  "decision": "BLOCKED", "reason": reason}
        log.warning(json.dumps(record, sort_keys=True))
        _runtime.security_log.append(record)
        raise SentinelBlocked(_runtime.policy.name, reason, "LOCAL_DATABASE")

def _unsafe_html(value):
    normalized = value.lower()
    return bool(re.search(r"<\s*(script|svg|img|iframe|object)\b|\bon\w+\s*=|javascript:\s*", normalized))

def _evaluate_html(value, resource="html"):
    if not _unsafe_html(value): return
    event = SecurityEvent(EventType.HTML_RENDER, request_id=_request_id.get(), resource=resource,
                          data_classification="UNSAFE_HTML", operation_id=str(uuid4()))
    decision, reason = _runtime.engine.evaluate(event)
    if decision == "BLOCK":
        record = {"event": "SECURITY_VIOLATION", "policy": _runtime.policy.name,
                  "event_type": event.event_type.value, "resource": event.resource,
                  "decision": "BLOCKED", "reason": reason}
        log.warning(json.dumps(record, sort_keys=True))
        _runtime.security_log.append(record)
        raise SentinelBlocked(_runtime.policy.name, reason, "LOCAL_BROWSER")

def _unsafe_command(command):
    return isinstance(command, str) and bool(re.search(r"[;&|`]|$\(|\r|\n", command))

def _patched_subprocess_run(command, *args, **kwargs):
    if _unsafe_command(command):
        event = SecurityEvent(EventType.PROCESS_EXEC, request_id=_request_id.get(), resource="subprocess",
                              data_classification="UNSAFE_COMMAND", operation_id=str(uuid4()))
        decision, reason = _runtime.engine.evaluate(event)
        if decision == "BLOCK":
            record = {"event": "SECURITY_VIOLATION", "policy": _runtime.policy.name,
                      "event_type": event.event_type.value, "resource": "subprocess",
                      "decision": "BLOCKED", "reason": reason}
            log.warning(json.dumps(record, sort_keys=True)); _runtime.security_log.append(record)
            raise SentinelBlocked(_runtime.policy.name, reason, "LOCAL_PROCESS")
    return _original_subprocess_run(command, *args, **kwargs)

class _CursorProxy:
    def __init__(self, cursor): self._cursor = cursor
    def execute(self, statement, *args, **kwargs):
        _evaluate_sql(statement)
        return self._cursor.execute(statement, *args, **kwargs)
    def __getattr__(self, name): return getattr(self._cursor, name)

class _ConnectionProxy:
    def __init__(self, connection): self._connection = connection
    def __enter__(self):
        self._connection.__enter__()
        return self
    def __exit__(self, *args): return self._connection.__exit__(*args)
    def execute(self, statement, *args, **kwargs):
        _evaluate_sql(statement)
        return self._connection.execute(statement, *args, **kwargs)
    def cursor(self, *args, **kwargs): return _CursorProxy(self._connection.cursor(*args, **kwargs))
    def __getattr__(self, name): return getattr(self._connection, name)

def _protected_sqlite_connect(*args, **kwargs):
    return _ConnectionProxy(_original_sqlite_connect(*args, **kwargs))

class _Runtime:
    def __init__(self, policy, security_log):
        self.policy = policy
        self.engine = NativeEngine(policy)
        self.security_log = _JsonSecurityLog(security_log)

def protect(app, policy, security_log=None):
    """Install Sentinel hooks and its SDK-hosted audit-log interface on an app."""
    global _runtime, _original_request, _original_sqlite_connect, _original_subprocess_run
    # Audit data belongs to the SDK, rather than to the application being protected.
    if security_log is None:
        security_log = Path(__file__).with_name("_logs") / "security-events.json"
    _runtime = _Runtime(load_policy(policy), security_log)
    import requests
    if _original_request is None:
        _original_request = requests.sessions.Session.request
        requests.sessions.Session.request = _patched_request
    if _original_sqlite_connect is None:
        _original_sqlite_connect = sqlite3.connect
        sqlite3.connect = _protected_sqlite_connect
    if _original_subprocess_run is None:
        _original_subprocess_run = subprocess.run
        subprocess.run = _patched_subprocess_run

    @app.middleware("http")
    async def sentinel_request_context(request, call_next):
        token = _request_id.set(request.headers.get("x-request-id", str(uuid4())))
        try:
            # Guard untrusted request input before it reaches an HTML-rendering route.
            if request.url.path in {"/search", "/lab/xss-preview"}:
                _evaluate_html(request.query_params.get("query", request.query_params.get("comment", "")), request.url.path)
            return await call_next(request)
        except SentinelBlocked as exc:
            # Exceptions raised by middleware do not reach FastAPI's route-level
            # exception handler, so return the enforcement result here.
            from fastapi.responses import JSONResponse
            return JSONResponse(status_code=403, content={
                "error": "security_operation_blocked", "reason": exc.reason, "policy": exc.policy,
            })
        finally: _request_id.reset(token)

    @app.exception_handler(SentinelBlocked)
    async def sentinel_blocked_handler(request, exc):
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=403, content={"error": "security_operation_blocked", "reason": exc.reason, "policy": exc.policy})

    @app.get("/logs", include_in_schema=False)
    async def sentinel_logs_interface():
        """SDK-owned UI; the protected app exposes it through its own URL."""
        from fastapi.responses import HTMLResponse
        return HTMLResponse(Path(__file__).with_name("logs.html").read_text(encoding="utf-8"))

    @app.get("/logs/events", include_in_schema=False)
    async def sentinel_log_events():
        from fastapi.responses import JSONResponse
        return JSONResponse({"events": _runtime.security_log.read()})
    return _runtime
