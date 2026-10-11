"""API endpoints for runtime monitoring."""

from fastapi import APIRouter, HTTPException
from typing import Optional
from datetime import datetime
from urllib.parse import urlparse
from urllib import request as urlrequest
from urllib.error import HTTPError
import asyncio

from backend.database.schema import get_db
from backend.services.runtime_monitoring import RuntimeMonitoringService

router = APIRouter(prefix="/api/runtime", tags=["runtime"])


def _validate_local_target(target_url: str) -> str:
    """Permit runtime probes only against a service on this machine."""
    parsed = urlparse(target_url.strip())
    if parsed.scheme not in {"http", "https"} or parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise HTTPException(
            status_code=400,
            detail="Only local URLs are allowed (for example http://127.0.0.1:8001)."
        )
    if parsed.username or parsed.password:
        raise HTTPException(status_code=400, detail="URLs with credentials are not allowed.")
    return target_url.rstrip("/")


def _local_get(url: str):
    """Fetch a local URL with Python's standard library only."""
    try:
        with urlrequest.urlopen(urlrequest.Request(url, method="GET"), timeout=8) as response:
            return response.status, dict(response.headers.items())
    except HTTPError as response:
        # A 404 remains a valid response for the unknown-route probe.
        return response.code, dict(response.headers.items())


@router.post("/{project_id}/scan-local")
async def scan_local_runtime(project_id: str, payload: dict):
    """Run safe HTTP checks against a developer-started local application."""
    with get_db() as conn:
        if not conn.execute("SELECT 1 FROM projects WHERE id = ?", (project_id,)).fetchone():
            raise HTTPException(status_code=404, detail="Project not found")

    target_url = _validate_local_target(str(payload.get("url", "")))
    monitoring = RuntimeMonitoringService(project_id)

    try:
        home_status, home_headers = await asyncio.to_thread(_local_get, target_url)
        header_names = {name.lower() for name in home_headers}
        missing_headers = [header for header in (
            "X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy", "Referrer-Policy"
        ) if header.lower() not in header_names]
        missing_404_status, _ = await asyncio.to_thread(_local_get, f"{target_url}/shipcheck-not-found-probe-404")

        exposed = []
        for path in ("/.env", "/admin", "/debug", "/metrics", "/backup"):
            status, _ = await asyncio.to_thread(_local_get, f"{target_url}{path}")
            if status == 200:
                exposed.append(path)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Could not reach local application: {exc}")

    events = []
    header_action = "SUSPICIOUS" if missing_headers else "LOGGED"
    events.append(monitoring.record_event({
        "event_type": "SECURITY_HEADERS", "endpoint": target_url, "action": header_action,
        "confidence": "HIGH", "evidence": "Missing headers: " + ", ".join(missing_headers) if missing_headers else "Required headers detected."
    }))
    events.append(monitoring.record_event({
        "event_type": "HTTP_404", "endpoint": f"{target_url}/shipcheck-not-found-probe-404",
        "action": "LOGGED" if missing_404_status == 404 else "SUSPICIOUS", "confidence": "HIGH",
        "evidence": f"Unknown-route response status: {missing_404_status}"
    }))
    if exposed:
        events.append(monitoring.record_event({
            "event_type": "EXPOSED_ENDPOINT", "endpoint": target_url, "action": "SUSPICIOUS",
            "confidence": "HIGH", "evidence": "Publicly reachable paths: " + ", ".join(exposed)
        }))

    return {
        "target_url": target_url, "status_code": home_status,
        "missing_headers": missing_headers, "not_found_status": missing_404_status,
        "exposed_endpoints": exposed, "events_recorded": len(events)
    }


@router.post("/scan-direct")
async def scan_direct_runtime(payload: dict):
    """Run safe HTTP checks against a developer-started local application."""
    raw_url = payload.get("url") or payload.get("target_url") or "http://127.0.0.1:8001"
    target_url = _validate_local_target(str(raw_url))

    raw_project_id = payload.get("project_id")
    project_id = None
    if raw_project_id and str(raw_project_id).strip() not in {"undefined", "null", ""}:
        with get_db() as conn:
            row = conn.execute("SELECT id FROM projects WHERE id = ?", (str(raw_project_id).strip(),)).fetchone()
            if row:
                project_id = row[0]

    if not project_id:
        with get_db() as conn:
            row = conn.execute("SELECT id FROM projects ORDER BY created_at DESC LIMIT 1").fetchone()
            if row:
                project_id = row[0]
            else:
                project_id = "default-runtime"
                conn.execute("INSERT OR IGNORE INTO projects (id, name) VALUES (?, ?)", (project_id, "Local Runtime App"))

    monitoring = RuntimeMonitoringService(project_id)
    try:
        home_status, home_headers = await asyncio.to_thread(_local_get, target_url)
        header_names = {name.lower() for name in home_headers}
        missing_headers = [header for header in (
            "X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy", "Referrer-Policy"
        ) if header.lower() not in header_names]
        missing_404_status, _ = await asyncio.to_thread(_local_get, f"{target_url}/shipcheck-not-found-probe-404")

        exposed = []
        for path in ("/.env", "/admin", "/debug", "/metrics", "/backup"):
            status, _ = await asyncio.to_thread(_local_get, f"{target_url}{path}")
            if status == 200:
                exposed.append(path)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Could not reach local application at {target_url}: {exc}")

    events = []
    header_action = "SUSPICIOUS" if missing_headers else "LOGGED"
    events.append(monitoring.record_event({
        "event_type": "SECURITY_HEADERS", "endpoint": target_url, "action": header_action,
        "confidence": "HIGH", "evidence": "Missing headers: " + ", ".join(missing_headers) if missing_headers else "Required headers detected."
    }))
    events.append(monitoring.record_event({
        "event_type": "HTTP_404", "endpoint": f"{target_url}/shipcheck-not-found-probe-404",
        "action": "LOGGED" if missing_404_status == 404 else "SUSPICIOUS", "confidence": "HIGH",
        "evidence": f"Unknown-route response status: {missing_404_status}"
    }))
    if exposed:
        events.append(monitoring.record_event({
            "event_type": "EXPOSED_ENDPOINT", "endpoint": target_url, "action": "SUSPICIOUS",
            "confidence": "HIGH", "evidence": "Publicly reachable paths: " + ", ".join(exposed)
        }))

    findings_count = len(missing_headers) + (1 if missing_404_status != 404 else 0) + len(exposed)
    return {
        "success": True,
        "target_url": target_url,
        "status_code": home_status,
        "findings_count": findings_count,
        "missing_headers": missing_headers,
        "not_found_status": missing_404_status,
        "exposed_endpoints": exposed,
        "events_recorded": len(events)
    }


@router.get("/stats")
async def get_all_runtime_stats():
    """Get aggregated runtime statistics."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM runtime_events")
        total_events = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM runtime_events WHERE action = 'BLOCKED'")
        blocked = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM runtime_events WHERE action = 'SUSPICIOUS'")
        suspicious = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM runtime_events WHERE event_type IN ('DB_QUERY', 'BLIND_SQL_INJECTION')")
        sql_injection = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM runtime_events WHERE event_type IN ('HTML_RENDER', 'HTML_INJECTION', 'XSS')")
        xss = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM runtime_events WHERE event_type = 'RATE_ANOMALY'")
        rate_abuse = cursor.fetchone()[0]

    return {
        "total_events": total_events,
        "blocked": blocked,
        "suspicious": suspicious,
        "sql_injection": sql_injection,
        "xss": xss,
        "rate_abuse": rate_abuse
    }


@router.get("/events")
async def get_all_runtime_events(limit: int = 50):
    """Get recent runtime events across projects."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, event_type, endpoint, action, confidence, evidence, timestamp, request_id, project_id
            FROM runtime_events
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,))
        events = []
        for row in cursor.fetchall():
            events.append({
                "id": row[0],
                "event_type": row[1],
                "endpoint": row[2],
                "action": row[3],
                "confidence": row[4],
                "evidence": row[5],
                "timestamp": row[6],
                "request_id": row[7],
                "project_id": row[8]
            })
    return {
        "events": events,
        "count": len(events)
    }


@router.get("/{project_id}/status")
async def get_runtime_status(project_id: str):
    """Get runtime security status for a project."""
    # Verify project exists
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM projects WHERE id = ?", (project_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="Project not found")

    monitoring = RuntimeMonitoringService(project_id)
    status = monitoring.get_runtime_status()

    return status


@router.get("/{project_id}/events")
async def get_runtime_events(project_id: str, limit: int = 100):
    """Get runtime security events."""
    monitoring = RuntimeMonitoringService(project_id)
    events = monitoring.get_security_events(limit)

    return {
        "project_id": project_id,
        "events": events,
        "count": len(events)
    }


@router.get("/{project_id}/statistics")
async def get_runtime_statistics(project_id: str, hours: int = 24):
    """Get runtime event statistics."""
    monitoring = RuntimeMonitoringService(project_id)
    stats = monitoring.get_event_statistics(hours)

    return stats


@router.post("/{project_id}/events")
async def record_runtime_event(project_id: str, event: dict):
    """Record a runtime security event."""
    monitoring = RuntimeMonitoringService(project_id)
    result = monitoring.record_event(event)

    return result


@router.post("/{project_id}/events/clear")
async def clear_runtime_events(project_id: str):
    """Clear all runtime events for a project."""
    monitoring = RuntimeMonitoringService(project_id)
    result = monitoring.clear_events()

    return result


@router.get("/{project_id}/dashboard")
async def get_runtime_dashboard(project_id: str):
    """Get comprehensive runtime dashboard data."""
    monitoring = RuntimeMonitoringService(project_id)

    # Get status
    status = monitoring.get_runtime_status()

    # Get statistics
    stats = monitoring.get_event_statistics(24)

    # Get recent events
    events = monitoring.get_security_events(20)

    return {
        "project_id": project_id,
        "status": status,
        "statistics": stats,
        "recent_events": events,
        "timestamp": datetime.utcnow().isoformat()
    }

