"""API endpoints for project management."""

import os
import uuid
import shutil
import json
import aiofiles
from pathlib import Path
from fastapi import APIRouter, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from typing import List, Optional
from datetime import datetime

from backend.models.schemas import ProjectCreate, ProjectResponse, ScanCreate, ScanResponse
from backend.database.schema import get_db, get_project_dir
from backend.services.scanner import ScannerService
from backend.services.hindsight import HindsightService
from backend.services.secure_extract import secure_extract, validate_zip_safety, ZipSecurityError

router = APIRouter(prefix="/api/projects", tags=["projects"])

# In-memory scan tracking (in production, use Redis or database)
scan_status = {}


@router.post("", response_model=ProjectResponse)
async def create_project(project: ProjectCreate):
    """Create a new project (without upload)."""
    project_id = str(uuid.uuid4())
    project_dir = get_project_dir(project_id)
    project_dir.mkdir(parents=True, exist_ok=True)

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO projects (id, name, project_context)
            VALUES (?, ?, ?)
        """, (project_id, project.name, json.dumps(project.project_context) if project.project_context else None))

    return ProjectResponse(
        id=project_id,
        name=project.name,
        created_at=datetime.utcnow(),
        project_context=project.project_context
    )


@router.post("/{project_id}/upload")
async def upload_project(
    project_id: str,
    file: UploadFile = File(...),
    background_tasks: BackgroundTasks = None
):
    """Upload a project ZIP file with secure extraction."""
    project_dir = get_project_dir(project_id)

    # Verify project exists
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM projects WHERE id = ?", (project_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="Project not found")

    # Clear existing project files
    if project_dir.exists():
        shutil.rmtree(project_dir)
    project_dir.mkdir(parents=True, exist_ok=True)

    # Save ZIP
    zip_path = project_dir / "project.zip"
    async with aiofiles.open(zip_path, 'wb') as f:
        content = await file.read()
        await f.write(content)

    # Validate ZIP safety
    try:
        validation = validate_zip_safety(str(zip_path))
        if not validation["valid"]:
            zip_path.unlink()
            raise HTTPException(
                status_code=400,
                detail=f"ZIP failed security checks: {validation['issues']}"
            )
    except ZipSecurityError as e:
        if zip_path.exists():
            zip_path.unlink()
        raise HTTPException(status_code=400, detail=str(e))

    # Secure extraction
    try:
        extract_result = secure_extract(str(zip_path), str(project_dir))
    except ZipSecurityError as e:
        if zip_path.exists():
            zip_path.unlink()
        raise HTTPException(status_code=400, detail=str(e))

    # Remove ZIP after extraction
    if zip_path.exists():
        zip_path.unlink()

    # Detect project structure
    from backend.services.project_detector import detect_project
    project_context = detect_project(str(project_dir))

    # Update project context in database
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE projects SET project_context = ? WHERE id = ?
        """, (json.dumps(project_context), project_id))

    return {
        "project_id": project_id,
        "message": "Project uploaded and extracted successfully",
        "detected_technologies": project_context,
        "extraction": extract_result
    }


@router.get("", response_model=List[ProjectResponse])
async def list_projects():
    """List all projects."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, created_at, last_scan_at, project_context FROM projects ORDER BY created_at DESC")
        projects = []
        for row in cursor.fetchall():
            projects.append(ProjectResponse(
                id=row[0],
                name=row[1],
                created_at=row[2],
                last_scan_at=row[3],
                project_context=json.loads(row[4]) if row[4] else None
            ))
        return projects


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(project_id: str):
    """Get project details."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, created_at, last_scan_at, project_context FROM projects WHERE id = ?", (project_id,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Project not found")

        return ProjectResponse(
            id=row[0],
            name=row[1],
            created_at=row[2],
            last_scan_at=row[3],
            project_context=json.loads(row[4]) if row[4] else None
        )


@router.get("/{project_id}/dashboard")
async def get_project_dashboard(project_id: str):
    """Get project dashboard data."""
    with get_db() as conn:
        cursor = conn.cursor()

        # Get project info
        cursor.execute("""
            SELECT id, name, created_at, last_scan_at, project_context,
                   security_score, privacy_score, production_readiness_score,
                   reliability_score, sentinel_enabled
            FROM projects WHERE id = ?
        """, (project_id,))
        row = cursor.fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="Project not found")

        project = {
            "id": row[0],
            "name": row[1],
            "created_at": row[2],
            "last_scan_at": row[3],
            "project_context": json.loads(row[4]) if row[4] else {},
            "security_score": row[5],
            "privacy_score": row[6],
            "production_readiness_score": row[7],
            "reliability_score": row[8],
            "sentinel_enabled": bool(row[9])
        }

        # Get latest scan
        cursor.execute("""
            SELECT id, status, created_at, completed_at, summary
            FROM scans
            WHERE project_id = ? AND status = 'completed'
            ORDER BY completed_at DESC
            LIMIT 1
        """, (project_id,))
        scan_row = cursor.fetchone()

        latest_scan = None
        if scan_row:
            latest_scan = {
                "id": scan_row[0],
                "status": scan_row[1],
                "created_at": scan_row[2],
                "completed_at": scan_row[3],
                "summary": json.loads(scan_row[4]) if scan_row[4] else {}
            }

        # Get scan history
        cursor.execute("""
            SELECT id, status, created_at, completed_at, summary
            FROM scans
            WHERE project_id = ? AND status = 'completed'
            ORDER BY completed_at DESC
            LIMIT 10
        """, (project_id,))
        scan_history = []
        for scan_row in cursor.fetchall():
            scan_history.append({
                "id": scan_row[0],
                "status": scan_row[1],
                "created_at": scan_row[2],
                "completed_at": scan_row[3],
                "summary": json.loads(scan_row[4]) if scan_row[4] else {}
            })

        # Get findings summary
        findings_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        if latest_scan:
            cursor.execute("""
                SELECT severity, COUNT(*) as count
                FROM findings
                WHERE scan_id = ?
                GROUP BY severity
            """, (latest_scan["id"],))
            for sev_row in cursor.fetchall():
                findings_summary[sev_row[0]] = sev_row[1]

        # Get runtime status
        from backend.services.runtime_monitoring import RuntimeMonitoringService
        monitoring = RuntimeMonitoringService(project_id)
        runtime_status = monitoring.get_runtime_status()

        return {
            "project": project,
            "latest_scan": latest_scan,
            "scan_history": scan_history,
            "findings_summary": findings_summary,
            "runtime_status": runtime_status,
            "timestamp": datetime.utcnow().isoformat()
        }


@router.get("/{project_id}/files")
async def list_project_files(project_id: str, path: str = ""):
    """List files in the project directory."""
    project_dir = get_project_dir(project_id)

    if not project_dir.exists():
        raise HTTPException(status_code=404, detail="Project directory not found")

    target_dir = project_dir / path if path else project_dir

    if not target_dir.exists():
        raise HTTPException(status_code=404, detail="Directory not found")

    # Security check: ensure path is within project directory
    try:
        target_dir.resolve().relative_to(project_dir.resolve())
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid path")

    files = []
    directories = []

    for item in target_dir.iterdir():
        if item.is_dir():
            directories.append({
                "name": item.name,
                "path": str(item.relative_to(project_dir)),
                "type": "directory"
            })
        else:
            files.append({
                "name": item.name,
                "path": str(item.relative_to(project_dir)),
                "type": "file",
                "size": item.stat().st_size
            })

    return {
        "path": path,
        "directories": directories,
        "files": files
    }


@router.get("/{project_id}/files/{file_path:path}")
async def get_file_content(project_id: str, file_path: str):
    """Get file content for the code editor."""
    project_dir = get_project_dir(project_id)

    if not project_dir.exists():
        raise HTTPException(status_code=404, detail="Project directory not found")

    file_full_path = project_dir / file_path

    if not file_full_path.exists():
        raise HTTPException(status_code=404, detail="File not found")

    # Security check: ensure path is within project directory
    try:
        file_full_path.resolve().relative_to(project_dir.resolve())
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid path")

    # Check file size
    if file_full_path.stat().st_size > 1024 * 1024:  # 1MB limit
        raise HTTPException(status_code=413, detail="File too large to display")

    try:
        content = file_full_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File is not a text file")

    return {
        "path": file_path,
        "content": content,
        "size": file_full_path.stat().st_size
    }


@router.put("/{project_id}/files/{file_path:path}")
async def update_file_content(project_id: str, file_path: str, content: str):
    """Update file content (code editor save)."""
    project_dir = get_project_dir(project_id)

    if not project_dir.exists():
        raise HTTPException(status_code=404, detail="Project directory not found")

    file_full_path = project_dir / file_path

    # Security check: ensure path is within project directory
    try:
        file_full_path.resolve().relative_to(project_dir.resolve())
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid path")

    # Create parent directories if needed
    file_full_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        file_full_path.write_text(content, encoding="utf-8")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to write file: {str(e)}")

    return {
        "path": file_path,
        "saved": True,
        "size": len(content)
    }


@router.delete("")
async def clear_all_projects():
    """Remove all locally stored Shipcheck projects, scans, findings, and uploads."""
    projects_root = get_project_dir("_clear_probe_").parent
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM projects")
        project_count = cursor.fetchone()[0]
        # Explicitly remove tables that are not all covered by project foreign keys
        # in databases created by early Shipcheck versions.
        for table in ("runtime_events", "sandbox_executions", "dependencies", "scan_comparisons", "hindsight_memory", "fix_validations", "findings", "scans", "sentinel_integrations", "projects"):
            cursor.execute(f"DELETE FROM {table}")

    if projects_root.exists():
        for child in projects_root.iterdir():
            if child.is_dir():
                shutil.rmtree(child)
            elif child.is_file():
                child.unlink()
    return {"message": "All local Shipcheck data cleared", "projects_deleted": project_count}


@router.delete("/{project_id}")
async def delete_project(project_id: str):
    """Delete a project and all its data."""
    project_dir = get_project_dir(project_id)

    # Delete from database (cascades to scans, findings)
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM projects WHERE id = ?", (project_id,))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Project not found")

    # Delete project files
    if project_dir.exists():
        shutil.rmtree(project_dir)

    return {"message": "Project deleted successfully"}


@router.get("/{project_id}/sentinel/status")
async def get_project_sentinel_status(project_id: str):
    """Get Sentinel integration status for a project."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT sentinel_enabled, sentinel_integrated_at
            FROM projects WHERE id = ?
        """, (project_id,))
        row = cursor.fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="Project not found")

        return {
            "project_id": project_id,
            "sentinel_enabled": bool(row[0]),
            "integrated_at": row[1]
        }


@router.get("/{project_id}/download")
async def download_project(project_id: str):
    """Download the project as a ZIP file."""
    import zipfile
    import io
    from fastapi.responses import StreamingResponse

    project_dir = get_project_dir(project_id)

    # Verify project exists
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, name FROM projects WHERE id = ?", (project_id,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Project not found")
        project_name = row["name"] or project_id[:8]

    if not project_dir.exists():
        raise HTTPException(status_code=404, detail="Project directory not found")

    # Create ZIP in memory
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        for file_path in project_dir.rglob('*'):
            if file_path.is_file():
                # Skip __pycache__, .git, .env, etc.
                rel_path = file_path.relative_to(project_dir)
                skip_dirs = {'__pycache__', '.git', 'node_modules', '.venv', 'venv'}
                if any(part in skip_dirs for part in rel_path.parts):
                    continue
                if rel_path.name == 'project.zip':
                    continue
                zf.write(file_path, str(rel_path))

    zip_buffer.seek(0)
    safe_name = "".join(c for c in project_name if c.isalnum() or c in "-_ ").strip() or "project"

    return StreamingResponse(
        zip_buffer,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{safe_name}-fixed.zip"'
        }
    )
