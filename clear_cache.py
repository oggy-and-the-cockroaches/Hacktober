"""Clear all cached scans, findings, projects, and AI cache in Shipcheck."""

import os
import shutil
import sqlite3
from pathlib import Path

DB_PATHS = [
    Path("shipcheck.db"),
    Path("backend/shipcheck.db"),
    Path("dist/shipcheck.db"),
    Path("dist/Shipcheck/_internal/backend/shipcheck.db"),
    Path("C:/Users/Ajay/shipcheck.db"),
    Path("C:/Users/Ajay/Desktop/Shipcheck/shipcheck.db"),
    Path("C:/Users/Ajay/Desktop/Shipcheck/backend/shipcheck.db"),
]

PROJECT_DIRS = [
    Path("projects"),
    Path("dist/projects"),
    Path("dist/Shipcheck/projects"),
]

TABLES_TO_CLEAR = [
    "ai_analysis_cache",
    "remediation_verifications",
    "remediation_proposals",
    "fix_validations",
    "findings",
    "scans",
    "dependencies",
    "runtime_events",
    "sentinel_integrations",
    "scan_comparisons",
    "sandbox_executions",
    "projects",
]


def clear_databases():
    print("--- Inspecting and Clearing Databases ---")
    for db_path in DB_PATHS:
        if not db_path.exists():
            print(f"Skipping non-existent {db_path}")
            continue

        print(f"\nProcessing database: {db_path}")
        try:
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()

            # Get existing tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall() if not row[0].startswith("sqlite_")]

            # Show counts before
            print("Before clearing:")
            for table in tables:
                try:
                    cursor.execute(f"SELECT COUNT(*) FROM {table}")
                    cnt = cursor.fetchone()[0]
                    if cnt > 0:
                        print(f"  {table}: {cnt}")
                except Exception as e:
                    print(f"  Error reading {table}: {e}")

            # Clear tables
            cursor.execute("PRAGMA foreign_keys = OFF")
            for table in TABLES_TO_CLEAR:
                if table in tables:
                    cursor.execute(f"DELETE FROM {table}")
            cursor.execute("PRAGMA foreign_keys = ON")
            conn.commit()

            # Vacuum
            cursor.execute("VACUUM")
            conn.commit()

            print("Cleared and vacuumed successfully.")
            conn.close()
        except Exception as e:
            print(f"Error processing {db_path}: {e}")


def clear_project_dirs():
    print("\n--- Clearing Project Folders ---")
    for pdir in PROJECT_DIRS:
        if pdir.exists():
            print(f"Clearing folder: {pdir}")
            for item in pdir.iterdir():
                try:
                    if item.is_dir():
                        shutil.rmtree(item)
                    else:
                        item.unlink()
                    print(f"  Deleted: {item.name}")
                except Exception as e:
                    print(f"  Failed to delete {item.name}: {e}")
        else:
            print(f"Folder does not exist: {pdir}")


if __name__ == "__main__":
    clear_databases()
    clear_project_dirs()
    print("\n[SUCCESS] Cache and data memory completely cleared!")
