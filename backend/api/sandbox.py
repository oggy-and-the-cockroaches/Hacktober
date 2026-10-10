"""API endpoints for sandbox execution."""

import uuid
import asyncio
from fastapi import APIRouter, HTTPException, BackgroundTasks
from typing import Dict, Any, Optional
from datetime import datetime

from backend.database.schema import get_db, get_project_dir
from backend.services.sandbox import SandboxService

router = APIRouter(prefix="/api/sandbox", tags=["sandbox"])

# In-memory sandbox status tracking
sandbox_status: Dict[str, Dict[str, Any]] = {}


@router.post("/{project_id}/execute")
async def execute_sandbox(project_id: str, background_tasks: BackgroundTasks):
    """Execute a project in the secure sandbox."""
    # Verify project exists
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM projects WHERE id = ?", (project_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="Project not found")

    execution_id = str(uuid.uuid4())
    project_dir = get_project_dir(project_id)

    if not project_dir.exists():
        raise HTTPException(status_code=404, detail="Project directory not found")

    # Initialize status
    sandbox_status[execution_id] = {
        "status": "running",
        "progress": 0,
        "message": "Starting sandbox execution...",
        "started_at": datetime.utcnow().isoformat()
    }

    # Run sandbox in background
    background_tasks.add_task(
        _run_sandbox_background,
        execution_id,
        project_id,
        str(project_dir)
    )

    return {
        "execution_id": execution_id,
        "project_id": project_id,
        "status": "running",
        "started_at": datetime.utcnow().isoformat()
    }


async def _run_sandbox_background(execution_id: str, project_id: str, project_dir: str):
    """Background task to run sandbox execution."""
    try:
        sandbox_status[execution_id]["status"] = "running"
        sandbox_status[execution_id]["progress"] = 10
        sandbox_status[execution_id]["message"] = "Detecting project type..."

        service = SandboxService(project_dir, project_id)
        result = await service.execute()

        sandbox_status[execution_id]["status"] = "completed"
        sandbox_status[execution_id]["progress"] = 100
        sandbox_status[execution_id]["message"] = "Sandbox execution completed"
        sandbox_status[execution_id]["result"] = result

        # Save to database
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO sandbox_executions
                (id, project_id, status, results, completed_at)
                VALUES (?, ?, ?, ?, ?)
            """, (
                execution_id,
                project_id,
                result.get("status", "completed"),
                str(result),
                datetime.utcnow().isoformat()
            ))

    except Exception as e:
        sandbox_status[execution_id]["status"] = "failed"
        sandbox_status[execution_id]["error"] = str(e)

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO sandbox_executions
                (id, project_id, status, error, completed_at)
                VALUES (?, ?, ?, ?, ?)
            """, (
                execution_id,
                project_id,
                "failed",
                str(e),
                datetime.utcnow().isoformat()
            ))


@router.get("/{execution_id}/status")
async def get_sandbox_status(execution_id: str):
    """Get sandbox execution status."""
    if execution_id in sandbox_status:
        return sandbox_status[execution_id]

    # Fallback to database
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, project_id, status, results, error, created_at, completed_at
            FROM sandbox_executions WHERE id = ?
        """, (execution_id,))
        row = cursor.fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="Sandbox execution not found")

        return {
            "execution_id": row[0],
            "project_id": row[1],
            "status": row[2],
            "results": row[3],
            "error": row[4],
            "created_at": row[5],
            "completed_at": row[6]
        }


@router.get("/project/{project_id}/executions")
async def list_sandbox_executions(project_id: str):
    """List all sandbox executions for a project."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, status, created_at, completed_at
            FROM sandbox_executions
            WHERE project_id = ?
            ORDER BY created_at DESC
        """, (project_id,))

        executions = []
        for row in cursor.fetchall():
            executions.append({
                "execution_id": row[0],
                "status": row[1],
                "created_at": row[2],
                "completed_at": row[3]
            })

        return {"project_id": project_id, "executions": executions}


@router.post("/{execution_id}/stop")
async def stop_sandbox(execution_id: str):
    """Stop a running sandbox execution."""
    if execution_id in sandbox_status:
        sandbox_status[execution_id]["status"] = "stopped"
        sandbox_status[execution_id]["message"] = "Stopped by user"
        return {"execution_id": execution_id, "status": "stopped"}

    raise HTTPException(status_code=404, detail="Sandbox execution not found")