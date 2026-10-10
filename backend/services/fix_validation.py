"""Fix validation service for validating applied fixes."""

import uuid
import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

from backend.database.schema import get_db, get_project_dir
from backend.scanners.base import Finding


class FixValidationService:
    """Validate fixes by re-scanning and comparing results."""

    def __init__(self, project_id: str, scan_id: str):
        self.project_id = project_id
        self.scan_id = scan_id
        self.project_dir = get_project_dir(project_id)

    def validate_fix(self, finding_id: str, fix_data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate a fix by applying it and re-scanning."""
        validation_id = str(uuid.uuid4())

        # Get the finding
        finding = self._get_finding(finding_id)
        if not finding:
            return {"error": "Finding not found", "validation_id": validation_id}

        # Apply the fix
        apply_result = self._apply_fix(finding, fix_data)
        if not apply_result.get("success"):
            return {
                "error": "Fix application failed",
                "validation_id": validation_id,
                "apply_result": apply_result
            }

        # Re-scan the project
        rescan_result = self._rescan_project()

        # Compare results
        comparison = self._compare_results(rescan_result)

        # Save validation
        self._save_validation(validation_id, finding_id, comparison)

        return {
            "validation_id": validation_id,
            "finding_id": finding_id,
            "fix_applied": True,
            "rescan_result": rescan_result,
            "comparison": comparison,
            "validated": True,
            "timestamp": datetime.utcnow().isoformat()
        }

    def _get_finding(self, finding_id: str) -> Optional[Dict[str, Any]]:
        """Get finding details from database."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, title, file_path, line_number, severity, category,
                       description, evidence, recommendation, suggested_fix
                FROM findings WHERE id = ?
            """, (finding_id,))
            row = cursor.fetchone()
            if not row:
                return None

            return {
                "id": row[0],
                "title": row[1],
                "file_path": row[2],
                "line_number": row[3],
                "severity": row[4],
                "category": row[5],
                "description": row[6],
                "evidence": row[7],
                "recommendation": row[8],
                "suggested_fix": row[9],
            }

    def _apply_fix(self, finding: Dict[str, Any], fix_data: Dict[str, Any]) -> Dict[str, Any]:
        """Apply a fix to the project files."""
        file_path = finding.get("file_path")
        if not file_path:
            return {"success": False, "error": "No file path in finding"}

        full_path = self.project_dir / file_path
        if not full_path.exists():
            return {"success": False, "error": f"File not found: {file_path}"}

        try:
            content = full_path.read_text(encoding="utf-8")
            line_number = finding.get("line_number")

            # Get the fix content
            fix_content = fix_data.get("fix", fix_data.get("suggested_fix", ""))
            if not fix_content:
                return {"success": False, "error": "No fix content provided"}

            # Apply fix based on type
            fix_type = fix_data.get("fix_type", "replace_line")

            if fix_type == "replace_line" and line_number:
                lines = content.splitlines()
                if 1 <= line_number <= len(lines):
                    lines[line_number - 1] = fix_content
                    new_content = "\n".join(lines)
                else:
                    return {"success": False, "error": f"Line {line_number} out of range"}

            elif fix_type == "replace_text":
                old_text = fix_data.get("old_text", "")
                if old_text in content:
                    new_content = content.replace(old_text, fix_content)
                else:
                    return {"success": False, "error": "Text to replace not found"}

            elif fix_type == "insert_after":
                if line_number:
                    lines = content.splitlines()
                    lines.insert(line_number, fix_content)
                    new_content = "\n".join(lines)
                else:
                    return {"success": False, "error": "Line number required for insert"}

            else:
                return {"success": False, "error": f"Unknown fix type: {fix_type}"}

            # Write the fixed content
            full_path.write_text(new_content, encoding="utf-8")

            # Update finding status
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE findings SET fix_applied = 1, status = 'fixed'
                    WHERE id = ?
                """, (finding["id"],))

            return {
                "success": True,
                "file": file_path,
                "line_number": line_number,
                "fix_type": fix_type
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def _rescan_project(self) -> Dict[str, Any]:
        """Re-scan the project after fix application."""
        try:
            from backend.services.scanner import ScannerService

            new_scan_id = str(uuid.uuid4())

            # Create new scan record
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO scans (id, project_id, status)
                    VALUES (?, ?, ?)
                """, (new_scan_id, self.project_id, "completed"))

            # Run scan
            scanner = ScannerService(str(self.project_dir), self.project_id, new_scan_id)
            import asyncio
            report = asyncio.get_event_loop().run_until_complete(
                scanner.run_scan()
            )

            return {
                "scan_id": new_scan_id,
                "total_findings": report.get("summary", {}).get("total_findings", 0),
                "by_severity": report.get("summary", {}).get("by_severity", {}),
                "findings": report.get("findings_by_category", {})
            }

        except Exception as e:
            return {
                "error": f"Rescan failed: {str(e)}",
                "total_findings": -1
            }

    def _compare_results(self, rescan_result: Dict[str, Any]) -> Dict[str, Any]:
        """Compare rescan results with original scan."""
        # Get original scan summary
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT summary FROM scans WHERE id = ?", (self.scan_id,))
            row = cursor.fetchone()

        original_summary = json.loads(row[0]) if row and row[0] else {}
        original_count = original_summary.get("total_findings", 0)
        current_count = rescan_result.get("total_findings", 0)

        resolved = max(0, original_count - current_count)
        new_findings = max(0, current_count - original_count)

        return {
            "previous_vulnerabilities": original_count,
            "current_vulnerabilities": current_count,
            "resolved_count": resolved,
            "new_count": new_findings,
            "improved": current_count < original_count,
            "previous_by_severity": original_summary.get("by_severity", {}),
            "current_by_severity": rescan_result.get("by_severity", {})
        }

    def _save_validation(self, validation_id: str, finding_id: str, comparison: Dict[str, Any]):
        """Save validation results to database."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO fix_validations
                (finding_id, scan_id, previous_vulnerabilities, current_vulnerabilities,
                 resolved_count, new_count, validation_result, validation_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                finding_id,
                self.scan_id,
                comparison.get("previous_vulnerabilities", 0),
                comparison.get("current_vulnerabilities", 0),
                comparison.get("resolved_count", 0),
                comparison.get("new_count", 0),
                "passed" if comparison.get("improved") else "needs_review",
                json.dumps(comparison)
            ))


def validate_fix(project_id: str, scan_id: str, finding_id: str, fix_data: Dict[str, Any]) -> Dict[str, Any]:
    """Validate a fix for a finding."""
    service = FixValidationService(project_id, scan_id)
    return service.validate_fix(finding_id, fix_data)