"""Tests for Phase 2 Context Windowing and Bounded Finding Batching."""

import pytest
import backend.database.schema as db_schema
from backend.services.context_window import extract_context_window
from backend.services.llm import GemmaProvider


@pytest.fixture(autouse=True)
def _isolate_env(tmp_path, monkeypatch):
    db_path = str(tmp_path / "test_phase2.db")
    projects_dir = str(tmp_path / "projects")
    monkeypatch.setenv("SHIPCHECK_PROJECTS_DIR", projects_dir)
    monkeypatch.setenv("SHIPCHECK_DB_PATH", db_path)
    db_schema.DATABASE_PATH = db_path
    db_schema.init_db()
    yield


def test_context_windowing_large_file():
    # Generate 100 line source file
    file_lines = [f"def func_{i}():\n    pass\n" for i in range(100)]
    full_code = "".join(file_lines)

    # Window around line 50
    windowed = extract_context_window(full_code, target_line=50, window_radius=10)
    assert len(windowed.splitlines()) < 100
    assert "50:" in windowed


def test_batch_analyze_findings_bounded():
    provider = GemmaProvider()
    findings = [
        {"id": f"find-{i}", "title": f"Vulnerability {i}", "severity": "high", "file_path": "app.py"}
        for i in range(12)
    ]

    results = provider.batch_analyze_findings(findings, max_batch_size=5)
    assert len(results) == 12
    for f in findings:
        assert f["id"] in results
        assert "summary" in results[f["id"]]
        assert "action" in results[f["id"]]


def test_batch_analyze_handles_empty():
    provider = GemmaProvider()
    results = provider.batch_analyze_findings([], max_batch_size=5)
    assert results == {}
