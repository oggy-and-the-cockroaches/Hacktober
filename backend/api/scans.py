"""API endpoints for scan management."""

import uuid
import asyncio
from fastapi import APIRouter, HTTPException, BackgroundTasks, Query
from typing import Optional, Dict, Any
from datetime import datetime

from backend.models.schemas import ScanCreate, ScanResponse, ScanStatus
from backend.database.schema import get_db
from backend.services.scanner import ScannerService

router = APIRouter(prefix="/api/scans", tags=["scans"])

# In-memory scan status tracking
scan_status: Dict[str, Dict[str, Any]] = {}


@router.post("", response_model=ScanResponse)
async def create_scan(scan: ScanCreate, background_tasks: BackgroundTasks):
    """Start a new scan for a project."""
    # Verify project exists
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM projects WHERE id = ?", (scan.project_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="Project not found")

    scan_id = str(uuid.uuid4())

    # Create scan record
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scans (id, project_id, status)
            VALUES (?, ?, ?)
        """, (scan_id, scan.project_id, ScanStatus.QUEUED))

    # Initialize scan status
    scan_status[scan_id] = {
        "project_id": scan.project_id,
        "status": ScanStatus.QUEUED,
        "progress": 0,
        "message": "Queued",
        "started_at": datetime.utcnow().isoformat()
    }

    # Start background scan
    background_tasks.add_task(run_scan_background, scan_id, scan.project_id)

    return ScanResponse(
        id=scan_id,
        project_id=scan.project_id,
        status=ScanStatus.QUEUED,
        created_at=datetime.utcnow()
    )


async def run_scan_background(scan_id: str, project_id: str):
    """Background task to run the scan."""
    import traceback
    print(f"[BACKGROUND] Starting scan {scan_id} for project {project_id}")
    try:
        from backend.services.scanner import ScannerService
        from backend.database.schema import get_project_dir
    except Exception as e:
        print(f"[BACKGROUND] Import error: {e}")
        traceback.print_exc()
        scan_status[scan_id] = {
            "status": ScanStatus.FAILED,
            "progress": 0,
            "message": f"Import error: {e}",
            "error": str(e)
        }
        return

    project_dir = get_project_dir(project_id)

    if not project_dir.exists():
        print(f"[BACKGROUND] Project directory not found: {project_dir}")
        scan_status[scan_id] = {
            "status": ScanStatus.FAILED,
            "progress": 0,
            "message": "Project directory not found",
            "error": "Project directory not found"
        }
        return

    # Update status to running
    scan_status[scan_id]["status"] = ScanStatus.RUNNING
    scan_status[scan_id]["message"] = "Starting scan..."
    print(f"[BACKGROUND] Scan {scan_id} status updated to RUNNING")

    async def progress_callback(message: str, progress: int):
        scan_status[scan_id]["message"] = message
        scan_status[scan_id]["progress"] = progress
        print(f"[BACKGROUND] Progress: {progress}% - {message}")

    try:
        scanner = ScannerService(str(project_dir), project_id, scan_id)
        report = await scanner.run_scan(progress_callback)
        print(f"[BACKGROUND] Scan {scan_id} completed with {report['summary']['total_findings']} findings")

        # Update scan status in database
        with get_db() as conn:
            cursor = conn.cursor()
            import json
            cursor.execute("""
                UPDATE scans SET status = ?, completed_at = ?, summary = ?
                WHERE id = ?
            """, (ScanStatus.COMPLETED, datetime.utcnow().isoformat(), json.dumps(report.get("summary", {})), scan_id))

        scan_status[scan_id] = {
            "status": ScanStatus.COMPLETED,
            "progress": 100,
            "message": "Scan completed",
            "report": report
        }

    except Exception as e:
        print(f"[BACKGROUND] Scan {scan_id} failed: {e}")
        traceback.print_exc()
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE scans SET status = ?, completed_at = ?
                WHERE id = ?
            """, (ScanStatus.FAILED, datetime.utcnow().isoformat(), scan_id))

        scan_status[scan_id] = {
            "status": ScanStatus.FAILED,
            "progress": 0,
            "message": f"Scan failed: {str(e)}",
            "error": str(e)
        }


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str):
    """Get scan status and results."""
    # Check in-memory status first
    if scan_id in scan_status:
        status_info = scan_status[scan_id]
        started_at = status_info.get("started_at", datetime.utcnow().isoformat())
        proj_id = status_info.get("project_id", "")
        if not proj_id:
            with get_db() as conn:
                r = conn.execute("SELECT project_id FROM scans WHERE id = ?", (scan_id,)).fetchone()
                if r: proj_id = r[0]
        return ScanResponse(
            id=scan_id,
            project_id=proj_id,
            status=status_info["status"],
            created_at=datetime.fromisoformat(started_at),
            completed_at=datetime.utcnow() if status_info["status"] in [ScanStatus.COMPLETED, ScanStatus.FAILED] else None,
            summary=status_info.get("report", {}).get("summary") if status_info.get("report") else None
        )

    # Fallback to database
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, project_id, status, created_at, completed_at, summary
            FROM scans WHERE id = ?
        """, (scan_id,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Scan not found")

        import json
        return ScanResponse(
            id=row[0],
            project_id=row[1],
            status=row[2],
            created_at=row[3],
            completed_at=row[4],
            summary=json.loads(row[5]) if row[5] else None
        )


@router.get("/{scan_id}/status")
async def get_scan_status(scan_id: str):
    """Get detailed scan progress status."""
    if scan_id in scan_status:
        return scan_status[scan_id]

    # Fallback to database
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT status, created_at, completed_at FROM scans WHERE id = ?", (scan_id,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Scan not found")

        return {
            "status": row[0],
            "progress": 100 if row[0] in [ScanStatus.COMPLETED, ScanStatus.FAILED] else 0,
            "message": row[0].capitalize(),
            "started_at": row[1],
            "completed_at": row[2]
        }


@router.get("/project/{project_id}", response_model=list[ScanResponse])
async def list_project_scans(project_id: str):
    """List all scans for a project."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, project_id, status, created_at, completed_at, summary
            FROM scans WHERE project_id = ?
            ORDER BY created_at DESC
        """, (project_id,))

        scans = []
        import json
        for row in cursor.fetchall():
            scans.append(ScanResponse(
                id=row[0],
                project_id=row[1],
                status=row[2],
                created_at=row[3],
                completed_at=row[4],
                summary=json.loads(row[5]) if row[5] else None
            ))
        return scans