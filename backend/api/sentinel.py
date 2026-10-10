"""API endpoints for Sentinel RASP integration."""

import json
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, Optional
from datetime import datetime

from backend.database.schema import get_db, get_project_dir
from backend.services.sentinel_integration import SentinelIntegrationService
from backend.services.native_inspector import native_inspector

router = APIRouter(prefix="/api/sentinel", tags=["sentinel"])


class SentinelEnableRequest(BaseModel):
    approved: bool = True
    policy_name: Optional[str] = None


@router.get("/{project_id}/preview")
async def preview_integration(project_id: str):
    """Preview Sentinel integration changes."""
    # Verify project exists
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM projects WHERE id = ?", (project_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="Project not found")

    service = SentinelIntegrationService(project_id)
    preview = service.generate_integration_preview()

    return preview


@router.post("/{project_id}/enable")
async def enable_sentinel(project_id: str, request: SentinelEnableRequest):
    """Enable Sentinel RASP protection (requires developer approval)."""
    # Verify project exists
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM projects WHERE id = ?", (project_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="Project not found")

    if not request.approved:
        raise HTTPException(
            status_code=400,
            detail="Developer approval required to enable Sentinel"
        )

    service = SentinelIntegrationService(project_id)
    result = service.apply_integration(approved=True)

    if result.get("success"):
        return result
    else:
        raise HTTPException(
            status_code=500,
            detail=result.get("error", "Failed to enable Sentinel")
        )


@router.get("/{project_id}/status")
async def get_sentinel_status(project_id: str):
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

        # Get integration details
        cursor.execute("""
            SELECT id, policy_name, applied_at
            FROM sentinel_integrations
            WHERE project_id = ?
            ORDER BY applied_at DESC
            LIMIT 1
        """, (project_id,))
        integration = cursor.fetchone()

        return {
            "project_id": project_id,
            "enabled": bool(row[0]),
            "integrated_at": row[1],
            "native_engine": {
                "available": native_inspector.available,
                "name": "Shipcheck C++ Inspector",
                "mode": "native" if native_inspector.available else "python fallback"
            },
            "integration": {
                "id": integration[0] if integration else None,
                "policy_name": integration[1] if integration else None,
                "applied_at": integration[2] if integration else None
            } if integration else None
        }


@router.get("/{project_id}/protections")
async def list_protections(project_id: str):
    """List available Sentinel protections."""
    return {
        "project_id": project_id,
        "protections": [
            {
                "name": "Blind SQL Injection Protection",
                "description": "Blocks time-delay and workload payloads used to extract database data without visible results",
                "event_type": "BLIND_SQL_INJECTION",
                "enabled": True
            },
            {
                "name": "SQL Injection Detection",
                "description": "Detects and blocks SQL injection attempts at runtime",
                "event_type": "DB_QUERY",
                "enabled": True
            },
            {
                "name": "XSS Detection",
                "description": "Detects and blocks cross-site scripting attempts",
                "event_type": "HTML_RENDER",
                "enabled": True
            },
            {
                "name": "HTML Injection Protection",
                "description": "Blocks unsafe HTML markup payloads before an application can reflect or render them",
                "event_type": "HTML_INJECTION",
                "enabled": True
            },
            {
                "name": "XPath Injection Protection",
                "description": "Blocks suspicious XPath query manipulation and predicate-bypass payloads",
                "event_type": "XPATH_INJECTION",
                "enabled": True
            },
            {
                "name": "Server-Side Includes Protection",
                "description": "Blocks SSI directives that could read files or execute commands on a web server",
                "event_type": "SSI_INJECTION",
                "enabled": True
            },
            {
                "name": "Server-Side Template Protection",
                "description": "Blocks template-expression payloads before server-side template rendering",
                "event_type": "SSTI_INJECTION",
                "enabled": True
            },
            {
                "name": "CRLF Injection Protection",
                "description": "Blocks CRLF response-splitting and injected-header payloads before forwarding requests",
                "event_type": "CRLF_INJECTION",
                "enabled": True
            },
            {
                "name": "Remote Code Execution Protection",
                "description": "Blocks command-interpreter and remote code execution payloads before forwarding requests",
                "event_type": "PROCESS_EXEC",
                "enabled": True
            },
            {
                "name": "XML / XXE Injection Protection",
                "description": "Blocks XML external-entity declarations and XML injection payloads",
                "event_type": "XML_INJECTION",
                "enabled": True
            },
            {
                "name": "LDAP Injection Protection",
                "description": "Blocks malicious LDAP filter manipulation patterns",
                "event_type": "LDAP_INJECTION",
                "enabled": True
            },
            {
                "name": "Command Injection Detection",
                "description": "Detects and blocks command injection attempts",
                "event_type": "PROCESS_EXEC",
                "enabled": True
            },
            {
                "name": "OS Command Injection Protection",
                "description": "Blocks shell metacharacters paired with common operating-system command payloads",
                "event_type": "OS_COMMAND_INJECTION",
                "enabled": True
            },
            {
                "name": "Secret Exfiltration Prevention",
                "description": "Prevents secrets from being sent to untrusted destinations",
                "event_type": "NETWORK_SEND",
                "enabled": True
            },
            {
                "name": "Request Monitoring",
                "description": "Monitors all incoming requests for suspicious patterns",
                "event_type": "REQUEST",
                "enabled": True
            },
            {
                "name": "Rate Anomaly Detection",
                "description": "Detects abnormal request rates and potential abuse",
                "event_type": "RATE_ANOMALY",
                "enabled": True
            }
        ]
    }


@router.get("/{project_id}/events")
async def get_sentinel_events(project_id: str, limit: int = 100):
    """Get Sentinel security events for a project."""
    from backend.services.runtime_monitoring import RuntimeMonitoringService

    monitoring = RuntimeMonitoringService(project_id)
    events = monitoring.get_security_events(limit)

    return {
        "project_id": project_id,
        "events": events,
        "count": len(events)
    }
