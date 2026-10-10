"""API endpoints for Hindsight Memory Engine interactions."""

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import List, Optional, Dict, Any

from backend.services.hindsight import HindsightService

router = APIRouter(prefix="/api/hindsight", tags=["hindsight"])


class RetainRequest(BaseModel):
    content: str
    project_id: Optional[str] = None
    context: Optional[str] = None
    tags: Optional[List[str]] = None
    metadata: Optional[Dict[str, str]] = None


class ReflectRequest(BaseModel):
    project_id: str
    query: Optional[str] = None


@router.get("/status")
async def get_hindsight_status():
    """Get Hindsight memory system status and connection info."""
    hindsight = HindsightService()
    try:
        return await hindsight.aget_status()
    finally:
        hindsight.close()


@router.get("/recall")
async def recall_memories(
    query: str = Query(..., description="Query to search memory bank"),
    project_id: Optional[str] = Query(None, description="Optional project ID to filter memories"),
    max_tokens: int = Query(2048, description="Max tokens of memory context")
):
    """Recall memories from Hindsight Memory bank."""
    hindsight = HindsightService()
    try:
        tags = [f"project_{project_id}"] if project_id else None
        results = await hindsight.arecall_memories(query=query, tags=tags, max_tokens=max_tokens)
        return {
            "query": query,
            "project_id": project_id,
            "count": len(results),
            "memories": results
        }
    finally:
        hindsight.close()


@router.post("/retain")
async def retain_memory(req: RetainRequest):
    """Retain a new memory into Hindsight Memory Engine."""
    hindsight = HindsightService()
    try:
        tags = list(req.tags or [])
        if req.project_id and f"project_{req.project_id}" not in tags:
            tags.append(f"project_{req.project_id}")

        meta = dict(req.metadata or {})
        if req.project_id:
            meta["project_id"] = req.project_id

        success = await hindsight.aretain_memory(
            content=req.content,
            context=req.context or (f"Project {req.project_id}" if req.project_id else None),
            tags=tags,
            metadata=meta
        )

        if not success:
            raise HTTPException(status_code=500, detail="Failed to retain memory in Hindsight engine")

        return {"status": "success", "message": "Memory retained successfully"}
    finally:
        hindsight.close()


@router.post("/reflect")
async def reflect_on_project(req: ReflectRequest):
    """Synthesize high-level reflections and historical learning for a project."""
    hindsight = HindsightService()
    try:
        reflection = await hindsight.areflect_on_project(project_id=req.project_id, query=req.query)
        return {
            "project_id": req.project_id,
            "reflection": reflection
        }
    finally:
        hindsight.close()
