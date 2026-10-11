"""API endpoints for fix management and validation."""

import uuid
import json
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, Optional, List
from datetime import datetime

from backend.database.schema import get_db, get_project_dir
from backend.services.fix_validation import FixValidationService

router = APIRouter(prefix="/api/fixes", tags=["fixes"])


class FixRequest(BaseModel):
    finding_id: str
    fix: str
    fix_type: str = "replace_line"
    old_text: Optional[str] = None


class FixValidationRequest(BaseModel):
    finding_id: str
    fix: str
    fix_type: str = "replace_line"
    old_text: Optional[str] = None


@router.post("/{project_id}/apply")
async def apply_fix(project_id: str, scan_id: str, request: FixRequest):
    """Apply a fix to a finding."""
    # Verify project exists
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM projects WHERE id = ?", (project_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="Project not found")

    # Get finding
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, file_path, line_number, title
            FROM findings WHERE id = ?
        """, (request.finding_id,))
        finding = cursor.fetchone()

        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")

    # Apply fix safely within workspace boundaries
    from backend.services.workspace import WorkspaceManager
    workspace = WorkspaceManager(project_id)
    try:
        file_path = workspace.resolve_safe_path(finding[1])
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if not file_path.exists():
        raise HTTPException(status_code=404, detail=f"File not found: {finding[1]}")

    try:
        content = file_path.read_text(encoding="utf-8")
        line_number = finding[2]

        if request.fix_type == "replace_line" and line_number:
            lines = content.splitlines()
            if 1 <= line_number <= len(lines):
                lines[line_number - 1] = request.fix
                new_content = "\n".join(lines)
            else:
                raise HTTPException(status_code=400, detail=f"Line {line_number} out of range")

        elif request.fix_type == "replace_text":
            if request.old_text and request.old_text in content:
                new_content = content.replace(request.old_text, request.fix)
            else:
                raise HTTPException(status_code=400, detail="Text to replace not found")

        else:
            raise HTTPException(status_code=400, detail=f"Unknown fix type: {request.fix_type}")

        # Write fixed content
        file_path.write_text(new_content, encoding="utf-8")

        # Update finding
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE findings SET fix_applied = 1, status = 'fixed'
                WHERE id = ?
            """, (request.finding_id,))

        return {
            "success": True,
            "finding_id": request.finding_id,
            "file": finding[1],
            "line_number": line_number,
            "fix_type": request.fix_type,
            "message": "Fix applied successfully"
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fix application failed: {str(e)}")


@router.post("/{project_id}/validate")
async def validate_fix(project_id: str, scan_id: str, request: FixValidationRequest):
    """Validate a fix by re-scanning."""
    # Verify project exists
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM projects WHERE id = ?", (project_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="Project not found")

    # Apply fix first
    apply_request = FixRequest(
        finding_id=request.finding_id,
        fix=request.fix,
        fix_type=request.fix_type,
        old_text=request.old_text
    )

    try:
        apply_result = await apply_fix(project_id, scan_id, apply_request)
    except HTTPException as e:
        raise HTTPException(status_code=400, detail=f"Fix application failed: {e.detail}")

    # Validate fix
    service = FixValidationService(project_id, scan_id)
    validation = service.validate_fix(request.finding_id, {
        "fix": request.fix,
        "fix_type": request.fix_type,
        "old_text": request.old_text
    })

    return validation


@router.get("/{finding_id}/details")
async def get_fix_details(finding_id: str):
    """Get fix details for a finding."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, title, file_path, line_number, severity, category,
                   description, evidence, recommendation, suggested_fix,
                   existing_solution, project_specific_solution, ai_explanation
            FROM findings WHERE id = ?
        """, (finding_id,))
        row = cursor.fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="Finding not found")

        suggested_fix = row[9] or row[8] or row[11] or row[10]
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
            # Older scans may predate the suggested_fix column being filled.
            # Their scanner recommendation remains valid, offline fix guidance.
            "suggested_fix": suggested_fix,
            "existing_solution": row[10],
            "project_specific_solution": row[11],
            "ai_explanation": row[12]
        }


def _synthesize_clean_code_patch(title: str, category: str, evidence: str, file_path: str, line_number: Optional[int]) -> str:
    title_lower = title.lower()
    evidence_clean = (evidence or "").strip()

    if "sql" in title_lower or "injection" in title_lower:
        if evidence_clean and ("query" in evidence_clean or "SELECT" in evidence_clean or "execute" in evidence_clean):
            return f"# ❌ Vulnerable (Direct concatenation):\n# {evidence_clean}\n\n# ✅ Secure Parameterized Replacement:\ncursor.execute(\"SELECT * FROM table WHERE param = ?\", (param_value,))"
        return "# ✅ Use parameterized query:\ncursor.execute(\"SELECT * FROM users WHERE username = ? AND is_active = 1\", (username,))"
    elif "xss" in title_lower or "script" in title_lower or "cross-site" in title_lower:
        return "# ✅ Sanitize & HTML Entity Escape user inputs before rendering:\nimport html\nsafe_output = html.escape(untrusted_user_input)"
    elif "secret" in title_lower or "key" in title_lower or "token" in title_lower or "password" in title_lower:
        return "import os\n# ✅ Load sensitive credentials securely from environment variables\nAPI_KEY = os.environ.get(\"SECRET_KEY\")\nif not API_KEY:\n    raise RuntimeError(\"Missing required environment variable: SECRET_KEY\")"
    elif "cors" in title_lower:
        return "# ✅ Restrict CORS to explicit trusted origins\napp.add_middleware(\n    CORSMiddleware,\n    allow_origins=[\"https://app.yourdomain.com\"],\n    allow_credentials=True,\n    allow_methods=[\"GET\", \"POST\"],\n    allow_headers=[\"Authorization\", \"Content-Type\"]\n)"
    elif "command" in title_lower or "exec" in title_lower or "eval" in title_lower or "rce" in title_lower:
        return "import subprocess\n# ✅ Pass arguments as safe list without shell=True\nresult = subprocess.run([\"command_executable\", safe_argument], capture_output=True, text=True, check=True)"
    elif "path" in title_lower or "traversal" in title_lower:
        return "from pathlib import Path\n# ✅ Validate and resolve file path within base workspace boundary\nsafe_file = (base_dir / user_filename).resolve()\nif not safe_file.is_relative_to(base_dir.resolve()):\n    raise ValueError(\"Path traversal detected\")"
    elif evidence_clean:
        return f"# ✅ Suggested Secure Implementation for: {title}\n# Context:\n# {evidence_clean}\n# Apply strict input validation, type coercion, and least-privilege access."
    else:
        return f"# ✅ Implement validation guards and defensive checks for: {title}"


@router.get("/{finding_id}/ai-suggest")
@router.post("/{finding_id}/ai-suggest")
async def get_ai_fix_suggestion(finding_id: str):
    """Generate an AI-powered fix suggestion, code patch, and root cause analysis for a finding."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT f.id, f.title, f.file_path, f.line_number, f.severity, f.category,
                   f.description, f.evidence, f.recommendation, f.suggested_fix,
                   f.existing_solution, f.project_specific_solution, f.ai_explanation,
                   s.project_id
            FROM findings f
            LEFT JOIN scans s ON f.scan_id = s.id
            WHERE f.id = ?
        """, (finding_id,))
        row = cursor.fetchone()

        if not row:
            cursor.execute("""
                SELECT id, title, file_path, line_number, severity, category,
                       description, evidence, recommendation, suggested_fix,
                       existing_solution, project_specific_solution, ai_explanation, '' as project_id
                FROM findings WHERE id = ?
            """, (finding_id,))
    if not row:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding_dict = {
        "id": row[0],
        "title": row[1] or "Security Finding",
        "file_path": row[2] or "",
        "line_number": row[3],
        "severity": row[4] or "medium",
        "category": row[5] or "security",
        "description": row[6] or "",
        "evidence": row[7] or "",
        "recommendation": row[8] or "",
        "suggested_fix": row[9] or "",
        "existing_solution": row[10] or "",
        "project_specific_solution": row[11] or "",
        "ai_explanation": row[12] or ""
    }

    project_id = row[13] if len(row) > 13 else None
    code_context = ""

    if project_id and finding_dict.get("file_path"):
        try:
            from backend.services.workspace import WorkspaceManager
            from backend.services.context_window import extract_context_window
            workspace = WorkspaceManager(project_id)
            safe_path = workspace.resolve_safe_path(finding_dict["file_path"])
            if safe_path.exists():
                full_content = safe_path.read_text(encoding="utf-8", errors="ignore")
                code_context = extract_context_window(
                    full_content,
                    target_line=finding_dict.get("line_number"),
                    window_radius=25
                )
        except Exception:
            pass

    from backend.services.llm import get_llm
    from backend.services.fix_synthesis import synthesize_ai_remediation
    llm = get_llm()
    
    # Propose AI patch
    raw_proposal = llm.propose_patch(finding_dict, code_context)
    synthesized = synthesize_ai_remediation(finding_dict, code_context)
    
    # Structure the AI response
    model_name = getattr(llm, "model_name", "gemma-4-31b-it")
    
    summary = raw_proposal.get("summary")
    if not summary or summary.startswith("Remediation patch proposal for"):
        summary = synthesized.get("summary") or finding_dict.get("description") or f"AI remediation guidance for {finding_dict.get('title')}"

    root_cause = raw_proposal.get("root_cause")
    if not root_cause or root_cause == "Vulnerability identified during code audit":
        root_cause = synthesized.get("root_cause") or "Vulnerable pattern detected by Shipcheck security analyzer"

    expected_security_effect = raw_proposal.get("expected_security_effect")
    if not expected_security_effect or "Remediates detected risk without side effects" in expected_security_effect:
        expected_security_effect = synthesized.get("expected_security_effect") or "Eliminates vulnerable attack surface without side effects"

    patch_code = raw_proposal.get("patch_diff") or ""
    if not patch_code or "# Fix applied for" in patch_code:
        patch_code = (
            finding_dict.get("suggested_fix")
            or finding_dict.get("project_specific_solution")
            or synthesized.get("patch_diff")
            or ""
        )
    
    return {
        "finding_id": finding_id,
        "model": f"Gemma 4 ({model_name})",
        "summary": summary,
        "root_cause": root_cause,
        "suggested_fix": patch_code,
        "expected_security_effect": expected_security_effect,
        "limitations": raw_proposal.get("limitations") or "Verify updated code with automated test suite",
        "recommendation": finding_dict.get("recommendation") or ""
    }


@router.get("/project/{project_id}/validations")
async def list_fix_validations(project_id: str):
    """List all fix validations for a project."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT fv.id, fv.finding_id, f.title, fv.previous_vulnerabilities,
                   fv.current_vulnerabilities, fv.resolved_count, fv.new_count,
                   fv.validation_result, fv.created_at
            FROM fix_validations fv
            JOIN findings f ON fv.finding_id = f.id
            JOIN scans s ON f.scan_id = s.id
            WHERE s.project_id = ?
            ORDER BY fv.created_at DESC
        """, (project_id,))

        validations = []
        for row in cursor.fetchall():
            validations.append({
                "id": row[0],
                "finding_id": row[1],
                "finding_title": row[2],
                "previous_vulnerabilities": row[3],
                "current_vulnerabilities": row[4],
                "resolved_count": row[5],
                "new_count": row[6],
                "validation_result": row[7],
                "created_at": row[8]
            })

        return {"project_id": project_id, "validations": validations}
