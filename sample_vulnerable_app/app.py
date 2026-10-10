"""Unprotected local baseline for comparing the Sentinel demo.

This app intentionally has no Sentinel dependency or runtime hook. It contains
only fake local data and the same login/search training exercises.
"""
from pathlib import Path
import sqlite3
import subprocess
import secrets
from fastapi import Cookie, Depends, HTTPException, Request, Response

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI(title="Northstar Knowledge — unprotected baseline", version="0.1.0")
LAB_DATABASE = Path(__file__).with_name("vuln-lab.sqlite3")
_sessions: set[str] = set()

def initialise_lab_database():
    with sqlite3.connect(LAB_DATABASE) as db:
        db.execute("CREATE TABLE IF NOT EXISTS documents (id INTEGER PRIMARY KEY, title TEXT, body TEXT)")
        db.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)")
        if not db.execute("SELECT 1 FROM documents LIMIT 1").fetchone():
            db.executemany("INSERT INTO documents(title, body) VALUES (?, ?)", [
                ("Public status", "All local demo systems nominal."),
                ("Engineering notes", "Local proof-of-concept checklist."),
                ("Internal demo record", "Fake record for local SQL injection exercise."),
            ])
        db.executemany("INSERT OR IGNORE INTO users(username, password, role) VALUES (?, ?, ?)", [("Ajay", "ajay123", "analyst"), ("Hansika", "hansika123", "analyst"), ("Sunny", "sunny123", "analyst"), ("Syam", "syam123", "analyst")])

initialise_lab_database()

UNTRUSTED_DEFAULT = "https://attacker.example/collect"
TRUSTED_DEFAULT = "http://127.0.0.1:8001/receiver"

def local_demo_login(username: str = "", password: str = ""):
    """INTENTIONALLY VULNERABLE local training endpoint: SQL concatenation."""
    sql = f"SELECT username, role FROM users WHERE username = '{username}' AND password = '{password}'"
    try:
        with sqlite3.connect(LAB_DATABASE) as db:
            user = db.execute(sql).fetchone()
        if user:
            return {"authenticated": True, "user": user[0], "role": user[1], "demo_only": True}
        return {"authenticated": False, "message": "Invalid username or password.", "demo_only": True}
    except sqlite3.DatabaseError as exc:
        return {"authenticated": False, "message": "Invalid username or password.", "sql_error": str(exc), "demo_only": True}

def require_login(lab_session: str | None = Cookie(default=None)):
    if not lab_session or lab_session not in _sessions:
        raise HTTPException(status_code=401, detail="Sign in to access the training lab.")

@app.get("/api/login")
def login(username: str = "", password: str = "", response: Response = None):
    """Intentionally vulnerable login used as the comparison application."""
    result = local_demo_login(username, password)
    if result.get("authenticated"):
        token = secrets.token_urlsafe(24)
        _sessions.add(token)
        response.set_cookie("lab_session", token, httponly=True, samesite="lax")
    return result

@app.get("/api/diagnostics")
def vulnerable_diagnostics(target: str = "local-service"):
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

@app.get("/cases")
def list_cases():
    return {"cases": [
        {"id": "secret-untrusted", "endpoint": "POST /cases/secret-untrusted", "expected": "baseline simulates an outbound send"},
        {"id": "public-untrusted", "endpoint": "POST /cases/public-untrusted", "expected": "baseline allows"},
        {"id": "secret-trusted", "endpoint": "POST /cases/secret-trusted", "expected": "baseline allows"},
    ]}

@app.get("/security-events")
def security_events():
    return {"events": [], "protected": False, "message": "No Sentinel security log in the baseline app."}

@app.get("/lab/status")
def lab_status():
    return {"engine": "INACTIVE", "policy": None, "violations": 0, "protected_operation": None}

@app.post("/lab/reset")
def reset_lab():
    return {"status": "reset", "message": "Baseline has no security-event log."}

@app.get("/lab/sql-search")
def vulnerable_sql_search(query: str = ""):
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
    return f"<!doctype html><html><body><h3>Community comment preview</h3><div>{comment}</div></body></html>"

@app.post("/receiver")
async def trusted_receiver(request: Request):
    return {"receiver": "trusted-local-baseline", "received_bytes": len(await request.body())}

@app.post("/cases/secret-untrusted")
def secret_to_untrusted():
    # Baseline records what would happen but never contacts the internet.
    return {"case": "secret-untrusted", "status": "sent", "simulated": True, "destination": UNTRUSTED_DEFAULT}

@app.post("/cases/public-untrusted")
def public_to_untrusted():
    return {"case": "public-untrusted", "status": "sent", "simulated": True, "destination": UNTRUSTED_DEFAULT}

@app.post("/cases/secret-trusted")
def secret_to_trusted():
    return {"case": "secret-trusted", "status": "sent", "simulated": True, "destination": TRUSTED_DEFAULT}

@app.post("/send-secret")
def send_secret():
    return secret_to_untrusted()

@app.get("/search", response_class=HTMLResponse)
def normal_search_results(query: str = ""):
    """INTENTIONALLY VULNERABLE local training endpoint: raw reflected HTML."""
    with sqlite3.connect(LAB_DATABASE) as db:
        rows = db.execute("SELECT title, body FROM documents WHERE title LIKE ?", (f"%{query}%",)).fetchall()
    results = "".join(f"<article><b>{title}</b><p>{body}</p></article>" for title, body in rows) or "<p>No documents found.</p>"
    return f"""<!doctype html><html><head><style>body{{font:14px system-ui;padding:13px;color:#172234}}article{{border-bottom:1px solid #d8dee8;padding:8px 0}}p{{margin:4px 0;color:#516176}}</style></head>
    <body><div>Search results for: <strong>{query}</strong></div>{results}</body></html>"""

@app.get("/", response_class=HTMLResponse)
def portal():
    return Path(__file__).with_name("dashboard.html").read_text(encoding="utf-8")
