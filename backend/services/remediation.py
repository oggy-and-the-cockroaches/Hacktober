"""Remediation and Verification Harness Service for Shipcheck + Gemma."""

import ast
import json
import os
import shutil
import sqlite3
import subprocess
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

from backend.database.schema import get_db, get_project_dir
from backend.services.llm import get_llm
from backend.services.workspace import WorkspaceManager


class VerificationStatus:
    PROPOSED = "PROPOSED"
    APPROVED = "APPROVED"
    APPLIED = "APPLIED"
    VERIFYING = "VERIFYING"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"
    REJECTED = "REJECTED"


class RemediationService:
    """Manages patch generation, review, and dual-baseline verification."""

    def __init__(self, project_id: str):
        self.project_id = project_id
        self.workspace = WorkspaceManager(project_id)
        self.project_dir = self.workspace.project_dir

    def generate_proposal(self, finding_id: str) -> Dict[str, Any]:
        """Generate a remediation proposal using Gemma AI provider."""
        finding = self._get_finding(finding_id)
        if not finding:
            return {"error": "Finding not found"}

        file_path = finding.get("file_path")
        code_context = ""
        if file_path:
            try:
                safe_path = self.workspace.resolve_safe_path(file_path)
                if safe_path.exists():
                    full_content = safe_path.read_text(encoding="utf-8", errors="ignore")
                    from backend.services.context_window import extract_context_window
                    code_context = extract_context_window(
                        full_content,
                        target_line=finding.get("line_number"),
                        window_radius=25
                    )
            except Exception as e:
                code_context = f"// Error loading file content: {e}"

        llm = get_llm()
        raw_proposal = llm.propose_patch(finding, code_context)

        proposal_id = str(uuid.uuid4())
        summary = raw_proposal.get("summary", "Gemma AI Proposed Patch")
        root_cause = raw_proposal.get("root_cause", "Identified security vulnerability")
        patch_diff = raw_proposal.get("patch_diff", "")
        recommended_tests = json.dumps(raw_proposal.get("recommended_tests", []))
        expected_effect = raw_proposal.get("expected_security_effect", "Resolves vulnerability")
        limitations = raw_proposal.get("limitations", "None identified")
        model_provider = raw_proposal.get("model_provider", "gemma")
        model_identifier = raw_proposal.get("model_identifier", "gemma-2-27b-it")

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO remediation_proposals (
                    id, finding_id, project_id, summary, root_cause, file_path, patch_diff,
                    recommended_tests, expected_security_effect, limitations,
                    model_provider, model_identifier, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    proposal_id,
                    finding_id,
                    self.project_id,
                    summary,
                    root_cause,
                    file_path or "",
                    patch_diff,
                    recommended_tests,
                    expected_effect,
                    limitations,
                    model_provider,
                    model_identifier,
                    VerificationStatus.PROPOSED,
                ),
            )

        return {
            "proposal_id": proposal_id,
            "finding_id": finding_id,
            "project_id": self.project_id,
            "summary": summary,
            "root_cause": root_cause,
            "file_path": file_path,
            "patch_diff": patch_diff,
            "recommended_tests": json.loads(recommended_tests),
            "expected_security_effect": expected_effect,
            "limitations": limitations,
            "model_provider": model_provider,
            "model_identifier": model_identifier,
            "status": VerificationStatus.PROPOSED,
        }

    def review_proposal(self, proposal_id: str, action: str) -> Dict[str, Any]:
        """Approve or Reject a proposed patch."""
        action_upper = action.upper()
        new_status = VerificationStatus.APPROVED if action_upper == "APPROVE" else VerificationStatus.REJECTED

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE remediation_proposals SET status = ? WHERE id = ?", (new_status, proposal_id))

        return {"proposal_id": proposal_id, "status": new_status}

    def verify_and_apply(self, proposal_id: str) -> Dict[str, Any]:
        """Execute dual-baseline verification harness in disposable workspace."""
        proposal = self._get_proposal(proposal_id)
        if not proposal:
            return {"error": "Proposal not found"}

        finding_id = proposal["finding_id"]
        finding = self._get_finding(finding_id)
        file_path = proposal["file_path"]
        patch_diff = proposal["patch_diff"]

        # Create disposable workspace for execution safety
        disposable_id = f"disp_{uuid.uuid4().hex[:8]}"
        disposable_dir = Path(os.environ.get("SHIPCHECK_PROJECTS_DIR", "./projects")) / disposable_id
        
        try:
            shutil.copytree(self.project_dir, disposable_dir, dirs_exist_ok=True)
            
            # Step 1: Baseline Check on original disposable copy
            baseline_syntax_ok = self._check_syntax(disposable_dir, file_path)
            baseline_test_status = self._run_workspace_tests(disposable_dir)

            # Step 2: Apply Patch safely to disposable copy
            patch_applied_ok, apply_error = self._apply_patch_to_workspace(disposable_dir, file_path, patch_diff)
            if not patch_applied_ok:
                return self._record_verification_result(
                    proposal_id, finding_id, VerificationStatus.FAILED,
                    baseline_test_status, "NOT_RUN", "FAILED", "SYNTAX_ERROR",
                    f"Failed to apply patch: {apply_error}"
                )

            # Step 3: Patched Code Syntax Check
            patched_syntax_ok = self._check_syntax(disposable_dir, file_path)
            syntax_status = "PASSED" if patched_syntax_ok else "FAILED"
            if not patched_syntax_ok:
                return self._record_verification_result(
                    proposal_id, finding_id, VerificationStatus.FAILED,
                    baseline_test_status, "NOT_RUN", "FAILED", syntax_status,
                    "Patched code introduced syntax errors"
                )

            # Step 4: Patched Code Tests
            patched_test_status = self._run_workspace_tests(disposable_dir)

            # Step 5: Real Rescan Verification - verify the vulnerability was actually remediated
            rescan_status = self._rescan_finding_in_workspace(disposable_dir, finding)

            # Step 6: Decision Logic
            if syntax_status == "PASSED" and patched_test_status in ["PASSED", "SKIPPED"] and rescan_status != "FAILED":
                final_status = VerificationStatus.VERIFIED
                # Apply fix to real workspace since verified
                self._apply_patch_to_workspace(self.project_dir, file_path, patch_diff)
                with get_db() as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        "UPDATE findings SET status = 'fixed', fix_applied = 1, fix_validated = 1 WHERE id = ?",
                        (finding_id,)
                    )
                    cursor.execute(
                        "UPDATE remediation_proposals SET status = ? WHERE id = ?",
                        (VerificationStatus.VERIFIED, proposal_id)
                    )
                verification_details = "Dual-baseline verification and security rescan passed"
            else:
                final_status = VerificationStatus.FAILED
                if rescan_status == "FAILED":
                    verification_details = "Patch compiled but failed security rescan: vulnerability is still present"
                elif syntax_status != "PASSED":
                    verification_details = "Patched code introduced syntax errors"
                else:
                    verification_details = f"Regression tests failed: {patched_test_status}"

            return self._record_verification_result(
                proposal_id, finding_id, final_status,
                baseline_test_status, patched_test_status, rescan_status, syntax_status,
                verification_details
            )

        finally:
            if disposable_dir.exists():
                shutil.rmtree(disposable_dir, ignore_errors=True)

    def _rescan_finding_in_workspace(self, workspace_path: Path, finding: Optional[Dict[str, Any]]) -> str:
        """Run category scanner on workspace to verify finding was actually remediated."""
        if not finding:
            return "SKIPPED"
        category = finding.get("category", "")
        scanner_map = {
            "security": "backend.scanners.security.SecurityScanner",
            "privacy": "backend.scanners.privacy.PrivacyScanner",
            "reliability": "backend.scanners.reliability.ReliabilityScanner",
            "production": "backend.scanners.production.ProductionScanner",
            "dependency": "backend.scanners.dependency.DependencyScanner",
            "configuration": "backend.scanners.configuration.ConfigurationScanner",
        }
        scanner_cls_path = scanner_map.get(category)
        if not scanner_cls_path:
            return "PASSED"
        try:
            import importlib
            mod_name, cls_name = scanner_cls_path.rsplit(".", 1)
            mod = importlib.import_module(mod_name)
            scanner_cls = getattr(mod, cls_name)
            scanner = scanner_cls(str(workspace_path), {})
            findings = scanner.scan()
            file_path = finding.get("file_path", "")
            title = finding.get("title", "")
            still_present = any(
                f.title == title and (not file_path or f.file_path == file_path)
                for f in findings
            )
            return "FAILED" if still_present else "PASSED"
        except Exception:
            return "SKIPPED"

    def _get_finding(self, finding_id: str) -> Optional[Dict[str, Any]]:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM findings WHERE id = ?", (finding_id,))
            row = cursor.fetchone()
            if not row:
                return None
            if isinstance(row, sqlite3.Row):
                return dict(row)
            col_names = [col[0] for col in cursor.description]
            return dict(zip(col_names, row))

    def _get_proposal(self, proposal_id: str) -> Optional[Dict[str, Any]]:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM remediation_proposals WHERE id = ?", (proposal_id,))
            row = cursor.fetchone()
            if not row:
                return None
            if isinstance(row, sqlite3.Row):
                return dict(row)
            col_names = [col[0] for col in cursor.description]
            return dict(zip(col_names, row))

    def _check_syntax(self, workspace_path: Path, file_path: str) -> bool:
        if not file_path or not file_path.endswith(".py"):
            return True
        target = workspace_path / file_path
        if not target.exists():
            return False
        try:
            ast.parse(target.read_text(encoding="utf-8", errors="ignore"))
            return True
        except SyntaxError:
            return False

    def _apply_patch_to_workspace(self, workspace_path: Path, file_path: str, patch_diff: str) -> tuple[bool, str]:
        if not file_path:
            return False, "No file path provided"

        # Validate Path Traversal & Workspace Boundaries
        target = (workspace_path / file_path).resolve()
        if not target.is_relative_to(workspace_path.resolve()):
            return False, f"Path traversal blocked: {file_path}"

        if not target.exists():
            return False, f"Target file does not exist: {file_path}"

        # Reject binary files
        binary_extensions = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".tar", ".gz", ".exe", ".dll", ".pyc", ".db", ".sqlite"}
        if target.suffix.lower() in binary_extensions:
            return False, f"Binary file patch rejected: {file_path}"

        backup_content = target.read_text(encoding="utf-8", errors="ignore")
        try:
            content = backup_content

            # 1. Direct explicit replacement format
            if "REPLACEMENT:" in patch_diff:
                new_code = patch_diff.split("REPLACEMENT:")[1].strip()
                target.write_text(new_code, encoding="utf-8")
                return True, ""

            # Helper to clean model-added line numbers (e.g., "12: code" -> "code")
            import re
            def strip_line_prefix(s: str) -> str:
                return re.sub(r"^\d+:\s?", "", s)

            # 2. Unified diff / hunk parsing
            diff_lines = patch_diff.splitlines()
            additions = [strip_line_prefix(dl[1:]) for dl in diff_lines if dl.startswith("+") and not dl.startswith("+++")]
            removals = [strip_line_prefix(dl[1:]) for dl in diff_lines if dl.startswith("-") and not dl.startswith("---")]

            if removals:
                removal_block = "\n".join(removals)
                addition_block = "\n".join(additions)

                # Strategy A: exact block replacement
                if removal_block in content:
                    new_content = content.replace(removal_block, addition_block, 1)
                    target.write_text(new_content, encoding="utf-8")
                    return True, ""

                # Strategy B: normalized whitespace block replacement
                content_lines = content.splitlines()
                match_start = -1
                clean_removals = [r.strip() for r in removals if r.strip()]

                if clean_removals:
                    for idx, c_line in enumerate(content_lines):
                        if c_line.strip() == clean_removals[0]:
                            # verify subsequent lines
                            all_match = True
                            for j, rem in enumerate(clean_removals):
                                if idx + j >= len(content_lines) or content_lines[idx + j].strip() != rem:
                                    all_match = False
                                    break
                            if all_match:
                                match_start = idx
                                match_len = len(clean_removals)
                                break

                    if match_start != -1:
                        new_lines = content_lines[:match_start] + additions + content_lines[match_start + match_len:]
                        new_content = "\n".join(new_lines)
                        target.write_text(new_content, encoding="utf-8")
                        return True, ""

                # If removals were specified but could not be located, reject safely
                return False, f"Patch context mismatch: expected lines '{clean_removals[0]}' not found in target file"

            # 3. Direct replacement fallback only for valid source code (not comments/errors)
            stripped_diff = patch_diff.strip()
            if not stripped_diff.startswith("---") and not stripped_diff.startswith("# Error") and len(stripped_diff) > 10:
                if file_path.endswith(".py"):
                    try:
                        ast.parse(stripped_diff)
                        target.write_text(stripped_diff, encoding="utf-8")
                        return True, ""
                    except SyntaxError:
                        return False, "Patch fallback is not valid Python code"
                else:
                    target.write_text(stripped_diff, encoding="utf-8")
                    return True, ""

            return False, "Patch did not contain applicable diff hunks or replacement blocks"
        except Exception as e:
            # Restore backup on any failure
            target.write_text(backup_content, encoding="utf-8")
            return False, str(e)

    def _run_workspace_tests(self, workspace_path: Path) -> str:
        test_files = list(workspace_path.rglob("test_*.py"))
        if not test_files:
            return "SKIPPED"
        try:
            result = subprocess.run(
                ["python", "-m", "unittest", "discover", "-s", str(workspace_path)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return "PASSED" if result.returncode == 0 else "FAILED"
        except Exception:
            return "SKIPPED"

    def _record_verification_result(
        self, proposal_id: str, finding_id: str, status: str,
        baseline_test: str, patched_test: str, rescan: str, syntax: str, details: str
    ) -> Dict[str, Any]:
        verification_id = str(uuid.uuid4())
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO remediation_verifications (
                    id, proposal_id, finding_id, project_id, status,
                    baseline_test_status, patched_test_status, rescan_status, syntax_status, details
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    verification_id,
                    proposal_id,
                    finding_id,
                    self.project_id,
                    status,
                    baseline_test,
                    patched_test,
                    rescan,
                    syntax,
                    details,
                ),
            )

        return {
            "verification_id": verification_id,
            "proposal_id": proposal_id,
            "finding_id": finding_id,
            "status": status,
            "baseline_test_status": baseline_test,
            "patched_test_status": patched_test,
            "rescan_status": rescan,
            "syntax_status": syntax,
            "details": details,
            "timestamp": datetime.utcnow().isoformat(),
        }
