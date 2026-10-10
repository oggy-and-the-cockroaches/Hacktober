"""API endpoints for security reports."""

import json
import uuid
from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse
from typing import Dict, Any, Optional
from datetime import datetime

from backend.database.schema import get_db, get_project_dir
from backend.services.runtime_monitoring import RuntimeMonitoringService

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("/scan/{scan_id}")
async def get_scan_report(scan_id: str):
    """Get full scan report with all findings."""
    with get_db() as conn:
        cursor = conn.cursor()

        # Get scan info
        cursor.execute("""
            SELECT id, project_id, status, created_at, completed_at, summary
            FROM scans WHERE id = ?
        """, (scan_id,))
        scan = cursor.fetchone()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        # Get findings
        cursor.execute("""
            SELECT id, scan_id, category, severity, title, description, evidence,
                   file_path, line_number, confidence, recommendation, status,
                   first_detected_scan, last_detected_scan, ai_explanation,
                   suggested_fix, existing_solution, project_specific_solution,
                   detection_source, validation_status
            FROM findings WHERE scan_id = ?
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    WHEN 'info' THEN 5
                END
        """, (scan_id,))

        findings = []
        for row in cursor.fetchall():
            findings.append({
                "id": row[0],
                "scan_id": row[1],
                "category": row[2],
                "severity": row[3],
                "title": row[4],
                "description": row[5],
                "evidence": row[6],
                "file_path": row[7],
                "line_number": row[8],
                "confidence": row[9],
                "recommendation": row[10],
                "status": row[11],
                "first_detected_scan": row[12],
                "last_detected_scan": row[13],
                "ai_explanation": row[14],
                "suggested_fix": row[15],
                "existing_solution": row[16],
                "project_specific_solution": row[17],
                "detection_source": row[18],
                "validation_status": row[19]
            })

        return {
            "scan": {
                "id": scan[0],
                "project_id": scan[1],
                "status": scan[2],
                "created_at": scan[3],
                "completed_at": scan[4],
                "summary": json.loads(scan[5]) if scan[5] else {}
            },
            "findings": findings,
            "total_findings": len(findings)
        }


@router.get("/scan/{scan_id}/export")
async def export_report(scan_id: str, format: str = "json"):
    """Export report in various formats."""
    # Get report data
    report = await get_scan_report(scan_id)

    if format == "json":
        return JSONResponse(content=report)

    elif format == "html":
        html = _generate_html_report(report)
        return HTMLResponse(content=html)

    elif format == "pdf":
        # PDF generation requires additional libraries
        # Return HTML as fallback with print-friendly styles
        html = _generate_html_report(report, print_friendly=True)
        return HTMLResponse(content=html)

    else:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {format}")


@router.get("/project/{project_id}/full")
async def get_full_project_report(project_id: str):
    """Get comprehensive project security report."""
    with get_db() as conn:
        cursor = conn.cursor()

        # Get project info
        cursor.execute("""
            SELECT id, name, created_at, last_scan_at, project_context,
                   security_score, privacy_score, production_readiness_score,
                   reliability_score, sentinel_enabled
            FROM projects WHERE id = ?
        """, (project_id,))
        project = cursor.fetchone()

        if not project:
            raise HTTPException(status_code=404, detail="Project not found")

        # Get latest scan
        cursor.execute("""
            SELECT id, status, created_at, completed_at, summary
            FROM scans
            WHERE project_id = ? AND status = 'completed'
            ORDER BY completed_at DESC
            LIMIT 1
        """, (project_id,))
        latest_scan = cursor.fetchone()

        # Get all findings from latest scan
        findings = []
        if latest_scan:
            cursor.execute("""
                SELECT id, category, severity, title, description, evidence,
                       file_path, line_number, confidence, recommendation, status
                FROM findings WHERE scan_id = ?
                ORDER BY
                    CASE severity
                        WHEN 'critical' THEN 1
                        WHEN 'high' THEN 2
                        WHEN 'medium' THEN 3
                        WHEN 'low' THEN 4
                        WHEN 'info' THEN 5
                    END
            """, (latest_scan[0],))

            for row in cursor.fetchall():
                findings.append({
                    "id": row[0],
                    "category": row[1],
                    "severity": row[2],
                    "title": row[3],
                    "description": row[4],
                    "evidence": row[5],
                    "file_path": row[6],
                    "line_number": row[7],
                    "confidence": row[8],
                    "recommendation": row[9],
                    "status": row[10]
                })

        # Get runtime status
        monitoring = RuntimeMonitoringService(project_id)
        runtime_status = monitoring.get_runtime_status()

        # Get scan history
        cursor.execute("""
            SELECT id, status, created_at, completed_at, summary
            FROM scans
            WHERE project_id = ? AND status = 'completed'
            ORDER BY completed_at DESC
            LIMIT 10
        """, (project_id,))
        scan_history = []
        for row in cursor.fetchall():
            scan_history.append({
                "id": row[0],
                "status": row[1],
                "created_at": row[2],
                "completed_at": row[3],
                "summary": json.loads(row[4]) if row[4] else {}
            })

        return {
            "project": {
                "id": project[0],
                "name": project[1],
                "created_at": project[2],
                "last_scan_at": project[3],
                "project_context": json.loads(project[4]) if project[4] else {},
                "security_score": project[5],
                "privacy_score": project[6],
                "production_readiness_score": project[7],
                "reliability_score": project[8],
                "sentinel_enabled": bool(project[9])
            },
            "latest_scan": {
                "id": latest_scan[0],
                "status": latest_scan[1],
                "created_at": latest_scan[2],
                "completed_at": latest_scan[3],
                "summary": json.loads(latest_scan[4]) if latest_scan[4] else {}
            } if latest_scan else None,
            "findings": findings,
            "total_findings": len(findings),
            "runtime_status": runtime_status,
            "scan_history": scan_history,
            "generated_at": datetime.utcnow().isoformat()
        }


@router.get("/project/{project_id}/export")
async def export_project_report(project_id: str, format: str = "json"):
    """Export full project report."""
    report = await get_full_project_report(project_id)

    if format == "json":
        return JSONResponse(content=report)

    elif format == "html":
        html = _generate_full_html_report(report)
        return HTMLResponse(content=html)

    elif format == "pdf":
        html = _generate_full_html_report(report, print_friendly=True)
        return HTMLResponse(content=html)

    else:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {format}")


def _generate_html_report(report: Dict[str, Any], print_friendly: bool = False) -> str:
    """Generate HTML report."""
    scan = report.get("scan", {})
    findings = report.get("findings", [])
    summary = scan.get("summary", {})

    by_severity = summary.get("by_severity", {})

    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Security Report - {scan.get('id', 'Unknown')}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #f8fafc; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        h1 {{ color: #1e293b; border-bottom: 2px solid #2563eb; padding-bottom: 10px; }}
        h2 {{ color: #334155; margin-top: 30px; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 20px; margin: 20px 0; }}
        .summary-card {{ padding: 20px; border-radius: 8px; text-align: center; border-left: 4px solid; }}
        .summary-card.critical {{ border-color: #ef4444; background: #fef2f2; }}
        .summary-card.high {{ border-color: #f59e0b; background: #fffbeb; }}
        .summary-card.medium {{ border-color: #06b6d4; background: #eff6ff; }}
        .summary-card.low {{ border-color: #64748b; background: #f1f5f9; }}
        .summary-card.info {{ border-color: #2563eb; background: #f0f9ff; }}
        .summary-count {{ font-size: 2.5rem; font-weight: 700; }}
        .summary-label {{ font-size: 0.875rem; color: #64748b; text-transform: uppercase; }}
        .finding {{ border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px; margin: 15px 0; }}
        .finding-header {{ display: flex; justify-content: space-between; align-items: start; margin-bottom: 10px; }}
        .finding-title {{ font-weight: 600; font-size: 1.1rem; }}
        .badge {{ padding: 4px 12px; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }}
        .badge.critical {{ background: #fef2f2; color: #ef4444; }}
        .badge.high {{ background: #fffbeb; color: #f59e0b; }}
        .badge.medium {{ background: #eff6ff; color: #06b6d4; }}
        .badge.low {{ background: #f1f5f9; color: #64748b; }}
        .badge.info {{ background: #f0f9ff; color: #2563eb; }}
        .finding-description {{ color: #475569; margin: 10px 0; }}
        .finding-evidence {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 4px; padding: 10px; font-family: monospace; font-size: 0.85rem; margin: 10px 0; }}
        .finding-meta {{ display: flex; gap: 20px; font-size: 0.85rem; color: #64748b; margin: 10px 0; }}
        .finding-recommendation {{ background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 4px; padding: 15px; margin-top: 10px; }}
        .timestamp {{ color: #94a3b8; font-size: 0.85rem; }}
        @media print {{
            body {{ background: white; }}
            .container {{ box-shadow: none; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Security Scan Report</h1>
        <p class="timestamp">Scan ID: {scan.get('id', 'Unknown')} | Generated: {datetime.utcnow().isoformat()}</p>

        <h2>Summary</h2>
        <div class="summary-grid">
            <div class="summary-card critical">
                <div class="summary-count">{by_severity.get('critical', 0)}</div>
                <div class="summary-label">Critical</div>
            </div>
            <div class="summary-card high">
                <div class="summary-count">{by_severity.get('high', 0)}</div>
                <div class="summary-label">High</div>
            </div>
            <div class="summary-card medium">
                <div class="summary-count">{by_severity.get('medium', 0)}</div>
                <div class="summary-label">Medium</div>
            </div>
            <div class="summary-card low">
                <div class="summary-count">{by_severity.get('low', 0)}</div>
                <div class="summary-label">Low</div>
            </div>
            <div class="summary-card info">
                <div class="summary-count">{by_severity.get('info', 0)}</div>
                <div class="summary-label">Info</div>
            </div>
        </div>

        <h2>Findings ({len(findings)} total)</h2>
"""

    for finding in findings:
        severity = finding.get('severity', 'info')
        html += f"""
        <div class="finding">
            <div class="finding-header">
                <div class="finding-title">{finding.get('title', 'Unknown')}</div>
                <span class="badge {severity}">{severity}</span>
            </div>
            <div class="finding-description">{finding.get('description', '')}</div>
            {f'<div class="finding-evidence">{finding.get("evidence", "")}</div>' if finding.get('evidence') else ''}
            <div class="finding-meta">
                {f'<span>📁 {finding.get("file_path", "")}</span>' if finding.get('file_path') else ''}
                {f'<span>📍 Line {finding.get("line_number", "")}</span>' if finding.get('line_number') else ''}
                <span>🎯 Confidence: {finding.get('confidence', 'Unknown')}</span>
                <span>Category: {finding.get('category', 'Unknown')}</span>
            </div>
            {f'<div class="finding-recommendation"><strong>Recommendation:</strong><br>{finding.get("recommendation", "")}</div>' if finding.get('recommendation') else ''}
        </div>
"""

    html += """
    </div>
</body>
</html>
"""

    return html


def _generate_full_html_report(report: Dict[str, Any], print_friendly: bool = False) -> str:
    """Generate full project HTML report."""
    project = report.get("project", {})
    findings = report.get("findings", [])
    runtime_status = report.get("runtime_status", {})

    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Security Report - {project.get('name', 'Unknown Project')}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #f8fafc; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        h1 {{ color: #1e293b; border-bottom: 2px solid #2563eb; padding-bottom: 10px; }}
        h2 {{ color: #334155; margin-top: 30px; }}
        .project-info {{ background: #f8fafc; padding: 20px; border-radius: 8px; margin: 20px 0; }}
        .score-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
        .score-card {{ padding: 20px; border-radius: 8px; text-align: center; background: #f8fafc; }}
        .score-value {{ font-size: 2.5rem; font-weight: 700; color: #2563eb; }}
        .score-label {{ font-size: 0.875rem; color: #64748b; text-transform: uppercase; }}
        .finding {{ border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px; margin: 15px 0; }}
        .badge {{ padding: 4px 12px; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }}
        .badge.critical {{ background: #fef2f2; color: #ef4444; }}
        .badge.high {{ background: #fffbeb; color: #f59e0b; }}
        .badge.medium {{ background: #eff6ff; color: #06b6d4; }}
        .badge.low {{ background: #f1f5f9; color: #64748b; }}
        .badge.info {{ background: #f0f9ff; color: #2563eb; }}
        @media print {{
            body {{ background: white; }}
            .container {{ box-shadow: none; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Security Report: {project.get('name', 'Unknown Project')}</h1>
        <p class="timestamp">Generated: {datetime.utcnow().isoformat()}</p>

        <h2>Project Information</h2>
        <div class="project-info">
            <p><strong>Project ID:</strong> {project.get('id', 'Unknown')}</p>
            <p><strong>Created:</strong> {project.get('created_at', 'Unknown')}</p>
            <p><strong>Last Scan:</strong> {project.get('last_scan_at', 'Never')}</p>
            <p><strong>Sentinel Enabled:</strong> {'Yes' if project.get('sentinel_enabled') else 'No'}</p>
        </div>

        <h2>Security Scores</h2>
        <div class="score-grid">
            <div class="score-card">
                <div class="score-value">{project.get('security_score', 'N/A')}</div>
                <div class="score-label">Security Score</div>
            </div>
            <div class="score-card">
                <div class="score-value">{project.get('privacy_score', 'N/A')}</div>
                <div class="score-label">Privacy Score</div>
            </div>
            <div class="score-card">
                <div class="score-value">{project.get('production_readiness_score', 'N/A')}</div>
                <div class="score-label">Production Readiness</div>
            </div>
            <div class="score-card">
                <div class="score-value">{project.get('reliability_score', 'N/A')}</div>
                <div class="score-label">Reliability Score</div>
            </div>
        </div>

        <h2>Runtime Security Status</h2>
        <div class="project-info">
            <p><strong>Sentinel Enabled:</strong> {'Yes' if runtime_status.get('sentinel_enabled') else 'No'}</p>
            <p><strong>Total Events:</strong> {runtime_status.get('total_events', 0)}</p>
            <p><strong>Blocked:</strong> {runtime_status.get('blocked_count', 0)}</p>
            <p><strong>Suspicious:</strong> {runtime_status.get('suspicious_count', 0)}</p>
        </div>

        <h2>Findings ({len(findings)} total)</h2>
"""

    for finding in findings:
        severity = finding.get('severity', 'info')
        html += f"""
        <div class="finding">
            <div class="finding-header">
                <div class="finding-title">{finding.get('title', 'Unknown')}</div>
                <span class="badge {severity}">{severity}</span>
            </div>
            <div class="finding-description">{finding.get('description', '')}</div>
            {f'<div class="finding-evidence">{finding.get("evidence", "")}</div>' if finding.get('evidence') else ''}
            <div class="finding-meta">
                {f'<span>📁 {finding.get("file_path", "")}</span>' if finding.get('file_path') else ''}
                {f'<span>📍 Line {finding.get("line_number", "")}</span>' if finding.get('line_number') else ''}
                <span>🎯 Confidence: {finding.get('confidence', 'Unknown')}</span>
                <span>Category: {finding.get('category', 'Unknown')}</span>
            </div>
            {f'<div class="finding-recommendation"><strong>Recommendation:</strong><br>{finding.get("recommendation", "")}</div>' if finding.get('recommendation') else ''}
        </div>
"""

    html += """
    </div>
</body>
</html>
"""

    return html