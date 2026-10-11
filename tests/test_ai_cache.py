"""Tests for SQLite AI Cache functionality."""

import pytest
import sqlite3

import backend.database.schema as db_schema
from backend.services.ai_cache import AICacheService
from backend.services.llm import GemmaProvider


@pytest.fixture(autouse=True)
def _isolate_env(tmp_path, monkeypatch):
    db_path = str(tmp_path / "test_ai_cache.db")
    projects_dir = str(tmp_path / "projects")
    monkeypatch.setenv("SHIPCHECK_PROJECTS_DIR", projects_dir)
    monkeypatch.setenv("SHIPCHECK_DB_PATH", db_path)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GEMMA_API_KEY", raising=False)
    monkeypatch.delenv("GEMMA_ENDPOINT", raising=False)
    db_schema.DATABASE_PATH = db_path
    db_schema.init_db()
    yield


def test_ai_cache_hit_and_invalidation():
    finding = {
        "id": "find-001",
        "title": "SQL Injection",
        "category": "security",
        "severity": "critical",
        "file_path": "db.py",
        "line_number": 10,
        "evidence": "SELECT * FROM users WHERE name = " + "query"
    }
    code = "def get_user(query):\n    cursor.execute('SELECT * FROM users WHERE name = ' + query)\n"
    model_id = "gemma-4-31b-it"

    # Initial get should be None
    cached = AICacheService.get("propose_patch", code, finding, model_id)
    assert cached is None

    # Put successful result
    sample_res = {
        "summary": "Use parameterized queries",
        "patch_diff": "--- db.py\n+++ db.py\n- cursor.execute('SELECT * FROM users WHERE name = ' + query)\n+ cursor.execute('SELECT * FROM users WHERE name = ?', (query,))"
    }
    stored = AICacheService.put("propose_patch", code, finding, model_id, sample_res)
    assert stored is True

    # Retrieve cached result
    cached_hit = AICacheService.get("propose_patch", code, finding, model_id)
    assert cached_hit is not None
    assert cached_hit["_cached"] is True
    assert cached_hit["summary"] == "Use parameterized queries"

    # Invalidate cache key
    cache_key = AICacheService.compute_cache_key("propose_patch", code, finding, model_id)
    AICacheService.invalidate(cache_key)

    # Subsequent fetch should return None
    assert AICacheService.get("propose_patch", code, finding, model_id) is None


def test_ai_cache_rejects_transient_failures():
    finding = {"title": "XSS", "category": "security", "evidence": "eval()"}
    code = "eval(x)"
    model_id = "gemma-4-31b-it"

    error_response = {"error": "Failed to parse JSON response", "raw_response": "Broken AI output"}
    stored = AICacheService.put("explain_finding", code, finding, model_id, error_response)
    assert stored is False
    assert AICacheService.get("explain_finding", code, finding, model_id) is None


def test_llm_provider_uses_cache():
    provider = GemmaProvider(model="gemma-4-31b-it")
    finding = {
        "id": "find-cached-1",
        "title": "Command Injection",
        "category": "security",
        "file_path": "app.py",
        "line_number": 12,
        "evidence": "os.system(user_input)"
    }
    code = "os.system(cmd)"

    # First call stores in cache
    res1 = provider.propose_patch(finding, code)
    assert res1 is not None

    # Second call uses cache
    res2 = provider.propose_patch(finding, code)
    assert res2.get("_cached") is True
    assert res2["finding_id"] == "find-cached-1"
