"""Extended database schema for Shipcheck + Verified Remediation Engine."""

import sqlite3
import os
from pathlib import Path
from contextlib import contextmanager
from typing import Generator, Optional

DATABASE_PATH = os.environ.get("SHIPCHECK_DB_PATH", "shipcheck.db")


def get_db_path() -> str:
    return DATABASE_PATH


def init_db() -> None:
    """Initialize the complete database schema."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    cursor = conn.cursor()

    # Projects table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS projects (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_scan_at TIMESTAMP,
            project_context TEXT,
            security_score INTEGER,
            privacy_score INTEGER,
            production_readiness_score INTEGER,
            reliability_score INTEGER,
            sentinel_enabled INTEGER DEFAULT 0,
            sentinel_integrated_at TIMESTAMP
        )
    """)

    # Scans table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'queued',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            summary TEXT,
            FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
        )
    """)

    # Findings table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            category TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            evidence TEXT,
            file_path TEXT,
            line_number INTEGER,
            confidence TEXT,
            recommendation TEXT,
            status TEXT DEFAULT 'open',
            first_detected_scan TEXT,
            last_detected_scan TEXT,
            ai_explanation TEXT,
            suggested_fix TEXT,
            existing_solution TEXT,
            project_specific_solution TEXT,
            detection_source TEXT DEFAULT 'STATIC',
            validation_status TEXT,
            validation_result TEXT,
            fix_applied INTEGER DEFAULT 0,
            fix_validated INTEGER DEFAULT 0,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        )
    """)

    # Remediation Proposals table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS remediation_proposals (
            id TEXT PRIMARY KEY,
            finding_id TEXT NOT NULL,
            project_id TEXT NOT NULL,
            summary TEXT,
            root_cause TEXT,
            file_path TEXT NOT NULL,
            patch_diff TEXT NOT NULL,
            recommended_tests TEXT,
            expected_security_effect TEXT,
            limitations TEXT,
            model_provider TEXT DEFAULT 'gemma',
            model_identifier TEXT DEFAULT 'gemma-2-27b-it',
            status TEXT DEFAULT 'PROPOSED',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE,
            FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
        )
    """)

    # Remediation Verifications table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS remediation_verifications (
            id TEXT PRIMARY KEY,
            proposal_id TEXT NOT NULL,
            finding_id TEXT NOT NULL,
            project_id TEXT NOT NULL,
            status TEXT NOT NULL,
            baseline_test_status TEXT,
            patched_test_status TEXT,
            rescan_status TEXT,
            syntax_status TEXT,
            details TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (proposal_id) REFERENCES remediation_proposals(id) ON DELETE CASCADE,
            FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE,
            FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
        )
    """)

    # AI Analysis Cache table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ai_analysis_cache (
            cache_key TEXT PRIMARY KEY,
            cache_type TEXT NOT NULL,
            code_hash TEXT NOT NULL,
            model_identifier TEXT NOT NULL,
            prompt_version TEXT NOT NULL DEFAULT '1.0',
            schema_version TEXT NOT NULL DEFAULT '1.0',
            response_json TEXT NOT NULL,
            is_valid INTEGER NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            invalidated_at TIMESTAMP
        )
    """)

    # Dependencies table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS dependencies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id TEXT NOT NULL,
            name TEXT NOT NULL,
            version TEXT,
            ecosystem TEXT,
            is_vulnerable INTEGER DEFAULT 0,
            vulnerability_info TEXT,
            FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
        )
    """)

    # Runtime events table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS runtime_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            endpoint TEXT,
            action TEXT,
            confidence TEXT,
            evidence TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            request_id TEXT,
            FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
        )
    """)

    # Sentinel integrations table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sentinel_integrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id TEXT NOT NULL,
            enabled INTEGER DEFAULT 0,
            policy_name TEXT,
            integration_patch TEXT,
            applied_at TIMESTAMP,
            FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
        )
    """)

    # Scan comparisons table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_comparisons (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id TEXT NOT NULL,
            current_scan_id TEXT,
            previous_scan_id TEXT,
            fixed_count INTEGER DEFAULT 0,
            unresolved_count INTEGER DEFAULT 0,
            new_count INTEGER DEFAULT 0,
            reintroduced_count INTEGER DEFAULT 0,
            comparison_data TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
        )
    """)

    # Sandbox executions table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sandbox_executions (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            container_id TEXT,
            port INTEGER,
            results TEXT,
            error TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
        )
    """)

    # Fix validations table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS fix_validations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id TEXT NOT NULL,
            scan_id TEXT,
            previous_vulnerabilities INTEGER,
            current_vulnerabilities INTEGER,
            resolved_count INTEGER,
            new_count INTEGER,
            validation_result TEXT,
            validation_data TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
        )
    """)

    conn.commit()
    conn.close()


@contextmanager
def get_db() -> Generator[sqlite3.Connection, None, None]:
    """Context manager for database connections."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_connection() -> sqlite3.Connection:
    """Get a raw database connection."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row
    return conn


def get_project_dir(project_id: str) -> Path:
    """Get the project directory path."""
    base = Path(os.environ.get("SHIPCHECK_PROJECTS_DIR", "./projects"))
    base.mkdir(exist_ok=True)
    return base / project_id