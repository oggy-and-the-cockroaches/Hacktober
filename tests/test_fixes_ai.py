"""Regression tests for AI fix suggestion endpoint."""

import pytest
from unittest.mock import MagicMock
from fastapi.testclient import TestClient
from backend.main import app
from backend.database.schema import get_db, init_db, DATABASE_PATH
import backend.database.schema as db_schema
from backend.services.llm import set_llm_provider, LLMProvider


class MockLLMProvider(LLMProvider):
    def __init__(self):
        self.model_name = "gemma-4-31b-it"

    def generate(self, prompt, system_prompt=None):
        return "mock response"

    def generate_json(self, prompt, system_prompt=None):
        return {
            "summary": "AI remediation patch proposal",
            "root_cause": "Vulnerable input concatenation in SQL query",
            "patch_diff": "--- app.py\n+++ app.py\n- db.execute(f'SELECT...')\n+ db.execute('SELECT...', (query,))",
            "expected_security_effect": "Prevents SQL injection attacks",
            "limitations": "Ensure parameterized queries throughout codebase"
        }

    def propose_patch(self, finding, code_context=""):
        return self.generate_json("")


@pytest.fixture(autouse=True)
def _isolate_env(tmp_path, monkeypatch):
    """Isolate database, project storage, and mock LLM provider."""
    db_path = str(tmp_path / "test_fixes.db")
    projects_dir = str(tmp_path / "projects")
    monkeypatch.setenv("SHIPCHECK_PROJECTS_DIR", projects_dir)
    monkeypatch.setenv("SHIPCHECK_DB_PATH", db_path)
    db_schema.DATABASE_PATH = db_path
    db_schema.init_db()

    mock_llm = MockLLMProvider()
    set_llm_provider(mock_llm)
    yield
    set_llm_provider(None)


def test_ai_suggest_fix_endpoint(tmp_path):
    client = TestClient(app)

    # Setup project and finding in DB
    project_id = "test-ai-fix-proj"
    project_dir = db_schema.get_project_dir(project_id)
    project_dir.mkdir(parents=True, exist_ok=True)

    test_file = project_dir / "app.py"
    test_file.write_text("import sqlite3\ndef search(query):\n    return db.execute(f'SELECT * FROM users WHERE name={query}')\n", encoding="utf-8")

    scan_id = "scan-fix-1"
    finding_id = "finding-fix-1"

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO projects (id, name) VALUES (?, ?)", (project_id, "Test App"))
        cursor.execute("INSERT INTO scans (id, project_id, status) VALUES (?, ?, ?)", (scan_id, project_id, "completed"))
        cursor.execute("""
            INSERT INTO findings (
                id, scan_id, title, file_path, line_number, severity, category,
                description, evidence, recommendation, suggested_fix
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            finding_id,
            scan_id,
            "SQL Injection in search query",
            "app.py",
            3,
            "critical",
            "security",
            "Direct string concatenation into SQL query",
            "db.execute(f'SELECT * FROM users WHERE name={query}')",
            "Use parameterized SQL queries",
            "db.execute('SELECT * FROM users WHERE name=?', (query,))"
        ))

    # Test GET /api/fixes/{finding_id}/ai-suggest
    response = client.get(f"/api/fixes/{finding_id}/ai-suggest")
    assert response.status_code == 200
    data = response.json()

    assert data["finding_id"] == finding_id
    assert "Gemma" in data["model"]
    assert "summary" in data
    assert "root_cause" in data
    assert "suggested_fix" in data
    assert len(data["suggested_fix"]) > 0
    assert "expected_security_effect" in data

    # Test POST /api/fixes/{finding_id}/ai-suggest
    post_response = client.post(f"/api/fixes/{finding_id}/ai-suggest")
    assert post_response.status_code == 200
    post_data = post_response.json()
    assert post_data["finding_id"] == finding_id


def test_ai_suggest_nonexistent_finding():
    client = TestClient(app)
    response = client.get("/api/fixes/non-existent-finding-id/ai-suggest")
    assert response.status_code == 404
