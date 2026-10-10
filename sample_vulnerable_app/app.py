"""E-Commerce & Digital Asset Management Platform API.

Looks like a realistic production FastAPI application, but intentionally contains
a diverse range of security, privacy, configuration, and dependency flaws for auditing.
"""

import os
import sys
import sqlite3
import subprocess
from typing import Optional
from fastapi import FastAPI, HTTPException, Query, Form, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Dangerous hardcoded secrets & credentials
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DATABASE_URL = "postgres://admin:P@ssw0rd2026!@production-db.internal:5432/store_db"
JWT_SECRET_KEY = "super_secret_jwt_key_12345"

# Unsafe CORS configuration (wildcard origins with credentials)
app = FastAPI(
    title="NexusMart Digital Platform",
    description="E-Commerce Storefront and Merchant Analytics API",
    version="1.4.0",
    docs_url="/docs",  # Debug/docs exposed in production
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve Frontend UI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/")
def serve_ui():
    """Serve NexusMart Merchant Portal UI."""
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "NexusMart Merchant Portal API v1.4.0"}

# Unsafe database connection initialization
DB_FILE = "nexusmart.db"

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_demo_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT,
            credit_card TEXT,
            ssn TEXT,
            is_admin INTEGER DEFAULT 0
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            category TEXT,
            price REAL,
            stock INTEGER
        )
    """)
    # Seed data with exposed PII
    cursor.execute("INSERT OR IGNORE INTO users (id, username, password, email, credit_card, ssn, is_admin) VALUES (1, 'admin', 'admin123', 'admin@nexusmart.io', '4532-7100-9812-4011', '000-12-3456', 1)")
    cursor.execute("INSERT OR IGNORE INTO users (id, username, password, email, credit_card, ssn, is_admin) VALUES (2, 'john_doe', 'password123', 'john@gmail.com', '4111-2222-3333-4444', '123-45-6789', 0)")
    cursor.execute("INSERT OR IGNORE INTO products (id, name, category, price, stock) VALUES (1, 'Pro Cloud Server', 'hosting', 199.99, 50)")
    cursor.execute("INSERT OR IGNORE INTO products (id, name, category, price, stock) VALUES (2, 'SSL Certificate', 'security', 49.99, 200)")
    conn.commit()
    conn.close()

init_demo_db()

# -------------------------------------------------------------
# 1. SQL Injection Flaw
# -------------------------------------------------------------
@app.get("/api/v1/products/search")
def search_products(q: str = Query(..., description="Product search query")):
    """Search storefront product catalog."""
    conn = get_db()
    cursor = conn.cursor()
    # Direct string interpolation leading to SQL Injection
    raw_query = f"SELECT * FROM products WHERE name LIKE '%{q}%' OR category LIKE '%{q}%'"
    cursor.execute(raw_query)
    rows = cursor.fetchall()
    conn.close()
    return {"results": [dict(r) for r in rows]}

# -------------------------------------------------------------
# 2. Command Injection Flaw
# -------------------------------------------------------------
@app.post("/api/v1/system/ping-host")
def ping_service_host(host: str = Form(...)):
    """Diagnostic tool for merchant server status check."""
    # Command injection via shell=True
    cmd = f"ping -n 1 {host}" if os.name == 'nt' else f"ping -c 1 {host}"
    output = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5).stdout
    return {"status": "complete", "output": output}

# -------------------------------------------------------------
# 3. Path Traversal & Arbitrary File Access
# -------------------------------------------------------------
@app.get("/api/v1/media/download")
def download_merchant_media(filename: str = Query(...)):
    """Download merchant product invoices and media assets."""
    # Unsanitized path joining allowing relative traversal
    media_dir = os.path.join(os.getcwd(), "media")
    target_path = os.path.join(media_dir, filename)
    if not os.path.exists(target_path):
        raise HTTPException(status_code=404, detail="File not found")
    with open(target_path, "r", encoding="utf-8", errors="ignore") as f:
        data = f.read()
    return {"filename": filename, "content": data}

# -------------------------------------------------------------
# 4. Unsafe Code Evaluation (RCE)
# -------------------------------------------------------------
@app.post("/api/v1/analytics/calculate")
def evaluate_custom_formula(formula: str = Form(...)):
    """Calculate custom revenue margins and discount metrics."""
    # Arbitrary code evaluation via eval()
    try:
        result = eval(formula)
        return {"formula": formula, "calculated_result": result}
    except Exception as e:
        return {"error": str(e)}

# -------------------------------------------------------------
# 5. PII & Privacy Leak Flaw
# -------------------------------------------------------------
@app.get("/api/v1/users/profile/{user_id}")
def get_user_profile(user_id: int):
    """Retrieve merchant profile details."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="User not found")
    # Returns unredacted SSN and credit card numbers
    return dict(row)

# -------------------------------------------------------------
# 6. Hardcoded Secret & Debug Mode Info Leak
# -------------------------------------------------------------
@app.get("/api/v1/config/status")
def get_system_config():
    """Retrieve system environment metadata."""
    return {
        "app_name": "NexusMart Digital Platform",
        "debug": True,
        "environment": "production",
        "aws_region": "us-east-1",
        "aws_access_key": AWS_ACCESS_KEY_ID,
        "database_uri": DATABASE_URL
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8005)
