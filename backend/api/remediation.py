"""API Router for Verified Remediation Engine."""

from fastapi import APIRouter, HTTPException, Body
from typing import Dict, Any, Optional
from pydantic import BaseModel

from backend.database.schema import get_db
from backend.services.remediation import RemediationService
from backend.services.llm import get_llm, sanitize_untrusted_input

router = APIRouter(prefix="/api/remediation", tags=["Remediation & Verification"])


class ReviewRequest(BaseModel):
    action: str  # "approve" or "reject"


@router.post("/propose/{finding_id}")
async def propose_remediation(finding_id: str):
    """Generate a Gemma-powered patch proposal for a finding."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT scan_id FROM findings WHERE id = ?", (finding_id,))
        finding_row = cursor.fetchone()
        if not finding_row:
            raise HTTPException(status_code=404, detail="Finding not found")

        scan_id = finding_row["scan_id"]
        cursor.execute("SELECT project_id FROM scans WHERE id = ?", (scan_id,))
        scan_row = cursor.fetchone()
        if not scan_row:
            raise HTTPException(status_code=404, detail="Scan not found")
        project_id = scan_row["project_id"]

    service = RemediationService(project_id)
    proposal = service.generate_proposal(finding_id)
    if "error" in proposal:
        raise HTTPException(status_code=400, detail=proposal["error"])
    return proposal


@router.get("/proposals/{finding_id}")
async def get_proposals(finding_id: str):
    """Get all patch proposals for a specific finding."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM remediation_proposals WHERE finding_id = ? ORDER BY created_at DESC",
            (finding_id,)
        )
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


@router.post("/review/{proposal_id}")
async def review_proposal(proposal_id: str, request: ReviewRequest):
    """Approve or reject a remediation patch proposal."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT project_id FROM remediation_proposals WHERE id = ?", (proposal_id,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Proposal not found")
        project_id = row["project_id"]

    service = RemediationService(project_id)
    result = service.review_proposal(proposal_id, request.action)
    return result


@router.post("/verify/{proposal_id}")
async def verify_remediation(proposal_id: str):
    """Execute dual-baseline verification harness for an approved proposal."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT project_id FROM remediation_proposals WHERE id = ?", (proposal_id,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Proposal not found")
        project_id = row["project_id"]

    service = RemediationService(project_id)
    result = service.verify_and_apply(proposal_id)
    return result


@router.get("/verifications/{proposal_id}")
async def get_verifications(proposal_id: str):
    """Get verification run history for a proposal."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM remediation_verifications WHERE proposal_id = ? ORDER BY created_at DESC",
            (proposal_id,)
        )
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
