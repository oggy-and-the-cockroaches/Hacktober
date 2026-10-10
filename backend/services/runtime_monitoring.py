"""Runtime monitoring service for Sentinel events."""

import json
import sqlite3
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta

from backend.database.schema import get_db, get_connection


class RuntimeMonitoringService:
    """Monitor and analyze runtime security events from Sentinel."""

    def __init__(self, project_id: str):
        self.project_id = project_id

    def get_runtime_status(self) -> Dict[str, Any]:
        """Get overall runtime security status."""
        with get_db() as conn:
            cursor = conn.cursor()

            # Check if Sentinel is enabled
            cursor.execute("""
                SELECT sentinel_enabled, sentinel_integrated_at
                FROM projects WHERE id = ?
            """, (self.project_id,))
            project = cursor.fetchone()

            if not project:
                return {"error": "Project not found"}

            sentinel_enabled = bool(project[0])
            integrated_at = project[1]

            # Get runtime events
            cursor.execute("""
                SELECT COUNT(*) FROM runtime_events WHERE project_id = ?
            """, (self.project_id,))
            total_events = cursor.fetchone()[0]

            # Get event breakdown
            cursor.execute("""
                SELECT event_type, action, COUNT(*) as count
                FROM runtime_events
                WHERE project_id = ?
                GROUP BY event_type, action
                ORDER BY count DESC
            """, (self.project_id,))
            event_breakdown = []
            for row in cursor.fetchall():
                event_breakdown.append({
                    "event_type": row[0],
                    "action": row[1],
                    "count": row[2]
                })

            # Get recent events
            cursor.execute("""
                SELECT id, event_type, endpoint, action, confidence, evidence, timestamp
                FROM runtime_events
                WHERE project_id = ?
                ORDER BY timestamp DESC
                LIMIT 50
            """, (self.project_id,))
            recent_events = []
            for row in cursor.fetchall():
                recent_events.append({
                    "id": row[0],
                    "event_type": row[1],
                    "endpoint": row[2],
                    "action": row[3],
                    "confidence": row[4],
                    "evidence": row[5],
                    "timestamp": row[6]
                })

            # Calculate statistics
            blocked_count = sum(e["count"] for e in event_breakdown if e["action"] == "BLOCKED")
            suspicious_count = sum(e["count"] for e in event_breakdown if e["action"] == "SUSPICIOUS")

            return {
                "project_id": self.project_id,
                "sentinel_enabled": sentinel_enabled,
                "integrated_at": integrated_at,
                "total_events": total_events,
                "blocked_count": blocked_count,
                "suspicious_count": suspicious_count,
                "event_breakdown": event_breakdown,
                "recent_events": recent_events,
                "timestamp": datetime.utcnow().isoformat()
            }

    def record_event(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a runtime security event."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO runtime_events
                (project_id, event_type, endpoint, action, confidence, evidence, request_id)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                self.project_id,
                event_data.get("event_type", "UNKNOWN"),
                event_data.get("endpoint"),
                event_data.get("action", "LOGGED"),
                event_data.get("confidence", "MEDIUM"),
                event_data.get("evidence"),
                event_data.get("request_id")
            ))
            event_id = cursor.lastrowid

        return {
            "id": event_id,
            "recorded": True,
            "timestamp": datetime.utcnow().isoformat()
        }

    def get_security_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get security events with details."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, event_type, endpoint, action, confidence, evidence, timestamp, request_id
                FROM runtime_events
                WHERE project_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
            """, (self.project_id, limit))

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
                    "request_id": row[7]
                })

        return events

    def get_event_statistics(self, hours: int = 24) -> Dict[str, Any]:
        """Get event statistics for a time period."""
        since = (datetime.utcnow() - timedelta(hours=hours)).isoformat()

        with get_db() as conn:
            cursor = conn.cursor()

            # Events by type
            cursor.execute("""
                SELECT event_type, COUNT(*) as count
                FROM runtime_events
                WHERE project_id = ? AND timestamp > ?
                GROUP BY event_type
                ORDER BY count DESC
            """, (self.project_id, since))
            by_type = [{"event_type": row[0], "count": row[1]} for row in cursor.fetchall()]

            # Events by action
            cursor.execute("""
                SELECT action, COUNT(*) as count
                FROM runtime_events
                WHERE project_id = ? AND timestamp > ?
                GROUP BY action
                ORDER BY count DESC
            """, (self.project_id, since))
            by_action = [{"action": row[0], "count": row[1]} for row in cursor.fetchall()]

            # Events by endpoint
            cursor.execute("""
                SELECT endpoint, COUNT(*) as count
                FROM runtime_events
                WHERE project_id = ? AND timestamp > ? AND endpoint IS NOT NULL
                GROUP BY endpoint
                ORDER BY count DESC
                LIMIT 10
            """, (self.project_id, since))
            by_endpoint = [{"endpoint": row[0], "count": row[1]} for row in cursor.fetchall()]

            # Total count
            cursor.execute("""
                SELECT COUNT(*) FROM runtime_events
                WHERE project_id = ? AND timestamp > ?
            """, (self.project_id, since))
            total = cursor.fetchone()[0]

        return {
            "period_hours": hours,
            "total_events": total,
            "by_type": by_type,
            "by_action": by_action,
            "by_endpoint": by_endpoint,
            "since": since
        }

    def clear_events(self) -> Dict[str, Any]:
        """Clear all runtime events for the project."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM runtime_events WHERE project_id = ?", (self.project_id,))
            deleted = cursor.rowcount

        return {
            "cleared": True,
            "events_deleted": deleted,
            "timestamp": datetime.utcnow().isoformat()
        }


def get_runtime_monitoring(project_id: str) -> RuntimeMonitoringService:
    """Get runtime monitoring service for a project."""
    return RuntimeMonitoringService(project_id)