"""Phase 2 integration tests for scanner orchestration."""

import asyncio
import json
import os
import sqlite3
import importlib

import pytest

from backend.scanners.security import SecurityScanner
from backend.scanners.privacy import PrivacyScanner
from backend.scanners.reliability import ReliabilityScanner
from backend.scanners.production import ProductionScanner
from backend.scanners.dependency import DependencyScanner
from backend.scanners.configuration import ConfigurationScanner
from backend.scanners.base import Finding
from backend.services.scanner import ScannerService

import database.schema as db_schema
from backend.database import schema as backend_schema


@pytest.fixture(autouse=True)
def _isolate_env(tmp_path, monkeypatch):
    """Isolate database and project storage for each test."""
    db_path = str(tmp_path / "test.db")
    projects_dir = str(tmp_path / "projects")
    monkeypatch.setenv("SHIPCHECK_PROJECTS_DIR", projects_dir)
    monkeypatch.setenv("SHIPCHECK_DB_PATH", db_path)
    db_schema.DATABASE_PATH = db_path
    backend_schema.DATABASE_PATH = db_path
    db_schema.init_db()
    yield
    for conn in sqlite3.connect(db_path).execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ):
        try:
            sqlite3.connect(db_path).execute(f"DROP TABLE IF EXISTS {conn[0]}")
        except Exception:
            pass


def _create_project(tmp_path, files):
    """Create a project directory with specified files."""
    project_id = "test-project-" + str(abs(hash(str(tmp_path))))
    project_dir = db_schema.get_project_dir(project_id)
    project_dir.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        path = project_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if content is None:
            path.write_text("", encoding="utf-8")
        else:
            path.write_text(content, encoding="utf-8")

    with db_schema.get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR IGNORE INTO projects (id, name) VALUES (?, ?)",
            (project_id, "Test Project")
        )
    return project_id, project_dir


def _run_scan(project_dir, project_id):
    """Run a full scan synchronously."""
    scan_id = "scan-" + str(abs(hash(project_dir)))
    scanner = ScannerService(str(project_dir), project_id, scan_id)
    return asyncio.run(scanner.run_scan()), scan_id


def test_existing_scanners_still_run(tmp_path):
    project_id, project_dir = _create_project(tmp_path, {
        "app.py": "import os\npassword = 'hardcoded123'\n"
    })

    report, _ = _run_scan(project_dir, project_id)

    assert report is not None
    assert "summary" in report
    categories = set(report["findings_by_category"].keys())
    assert "security" in categories


def test_dependency_scanner_is_invoked(tmp_path):
    project_id, project_dir = _create_project(tmp_path, {
        "requirements.txt": "django==2.2.0\nrequests==2.30.0\n"
    })

    report, _ = _run_scan(project_dir, project_id)

    assert "dependency" in report["findings_by_category"]


def test_configuration_scanner_is_invoked(tmp_path):
    project_id, project_dir = _create_project(tmp_path, {
        "config.py": "DEBUG = True\n"
    })

    report, _ = _run_scan(project_dir, project_id)

    assert "configuration" in report["findings_by_category"]


def test_findings_are_persisted(tmp_path):
    project_id, project_dir = _create_project(tmp_path, {
        "app.py": "password = 'secret123'\n"
    })

    report, scan_id = _run_scan(project_dir, project_id)

    with db_schema.get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM findings WHERE scan_id = ?", (scan_id,))
        count = cursor.fetchone()[0]
    assert count > 0


def test_dependency_records_are_persisted(tmp_path):
    project_id, project_dir = _create_project(tmp_path, {
        "requirements.txt": "django==2.2.0\n"
    })

    _, _ = _run_scan(project_dir, project_id)

    with db_schema.get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM dependencies WHERE project_id = ?", (project_id,))
        count = cursor.fetchone()[0]
    assert count > 0


def test_detection_source_values_are_correct(tmp_path):
    project_id, project_dir = _create_project(tmp_path, {
        "requirements.txt": "django==2.2.0\n",
        "config.py": "DEBUG = True\n"
    })

    report, _ = _run_scan(project_dir, project_id)

    dep_findings = report["findings_by_category"].get("dependency", {}).get("findings", [])
    config_findings = report["findings_by_category"].get("configuration", {}).get("findings", [])

    for f in dep_findings:
        assert f.get("detection_source") == "DEPENDENCY", f"Expected DEPENDENCY, got {f.get('detection_source')}"

    for f in config_findings:
        assert f.get("detection_source") == "CONFIGURATION", f"Expected CONFIGURATION, got {f.get('detection_source')}"


def test_empty_project_does_not_crash(tmp_path):
    project_id, project_dir = _create_project(tmp_path, {})

    report, _ = _run_scan(project_dir, project_id)

    assert report is not None
    assert report["status"] in ("completed", "partial")


def test_malformed_files_do_not_crash_scan(tmp_path):
    project_id, project_dir = _create_project(tmp_path, {
        "package.json": "not valid json {{{",
        "requirements.txt": "django==2.2.0\n",
        "config.py": "DEBUG = True\n"
    })

    report, _ = _run_scan(project_dir, project_id)

    assert report is not None
    assert report["status"] in ("completed", "partial")


def test_multiple_scanners_produce_findings_for_same_project(tmp_path):
    project_id, project_dir = _create_project(tmp_path, {
        "app.py": "password = 'secret123'\n",
        "requirements.txt": "django==2.2.0\n",
        "config.py": "DEBUG = True\n"
    })

    report, _ = _run_scan(project_dir, project_id)

    categories = set(report["findings_by_category"].keys())
    assert "security" in categories
    assert "dependency" in categories
    assert "configuration" in categories
