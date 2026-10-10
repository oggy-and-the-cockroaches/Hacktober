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
