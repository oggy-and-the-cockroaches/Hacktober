"""Hindsight memory service for tracking scan history, developer decisions, and persistent AI memory."""

import os
import json
import uuid
import logging
import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime
from dotenv import load_dotenv

from backend.database.schema import get_connection
from backend.scanners.base import Finding

load_dotenv()
logger = logging.getLogger(__name__)


class HindsightService:
    """Manages persistent memory across scans for a project using Hindsight Memory API and local SQLite."""

    def __init__(self):
        self.conn = get_connection()
        self.api_key = os.environ.get("HINDSIGHT_API_KEY", "").strip()
        self.base_url = os.environ.get("HINDSIGHT_BASE_URL", "https://api.hindsight.vectorize.io").strip()
        self.bank_id = os.environ.get("HINDSIGHT_BANK_ID", "demo").strip()
        self.client = None

        if self.api_key:
            try:
                from hindsight_client import Hindsight
                self.client = Hindsight(
                    base_url=self.base_url,
                    api_key=self.api_key
                )
            except Exception as e:
                logger.warning(f"Failed to initialize Hindsight client: {e}")
                self.client = None

    def close(self):
        """Close connections and cleanup."""
        if self.conn:
            try:
                self.conn.close()
            except Exception:
                pass
        if self.client:
            try:
                self.client.close()
            except Exception:
                pass

    async def aclose(self):
        """Async close connections and cleanup."""
        if self.conn:
            try:
                self.conn.close()
            except Exception:
                pass
        if self.client:
            try:
                await self.client.aclose()
            except Exception:
                pass

    async def aget_status(self) -> Dict[str, Any]:
        """Async get Hindsight integration status."""
        is_active = self.client is not None
        cloud_reachable = False
        sample_recall_count = 0

        if is_active:
            try:
                res = await self.client.arecall(bank_id=self.bank_id, query="system status check", max_tokens=100)
                cloud_reachable = True
                sample_recall_count = len(res.results) if hasattr(res, 'results') and res.results else 0
            except Exception as e:
                logger.warning(f"Hindsight cloud reachability check failed: {e}")
                cloud_reachable = False

        return {
            "provider": "Hindsight Memory Engine",
            "connected": is_active and cloud_reachable,
            "api_configured": bool(self.api_key),
            "base_url": self.base_url,
            "bank_id": self.bank_id,
            "memory_network_types": ["world", "experience", "observation", "opinion"],
            "sample_memory_units": sample_recall_count
        }

    def get_status(self) -> Dict[str, Any]:
        """Sync get Hindsight integration status."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # If loop is running, we return configured status directly
                return {
                    "provider": "Hindsight Memory Engine",
                    "connected": bool(self.client),
                    "api_configured": bool(self.api_key),
                    "base_url": self.base_url,
                    "bank_id": self.bank_id,
                    "memory_network_types": ["world", "experience", "observation", "opinion"],
                    "sample_memory_units": 0
                }
        except RuntimeError:
            pass

        is_active = self.client is not None
        cloud_reachable = False
        sample_recall_count = 0

        if is_active:
            try:
                res = self.client.recall(bank_id=self.bank_id, query="system status check", max_tokens=100)
                cloud_reachable = True
                sample_recall_count = len(res.results) if hasattr(res, 'results') and res.results else 0
            except Exception as e:
                logger.warning(f"Hindsight cloud reachability check failed: {e}")
                cloud_reachable = False

        return {
            "provider": "Hindsight Memory Engine",
            "connected": is_active and cloud_reachable,
            "api_configured": bool(self.api_key),
            "base_url": self.base_url,
            "bank_id": self.bank_id,
            "memory_network_types": ["world", "experience", "observation", "opinion"],
            "sample_memory_units": sample_recall_count
        }

    # ==================== HINDSIGHT API INTEGRATION (Retain, Recall, Reflect) ====================

    async def aretain_memory(self, content: str, context: Optional[str] = None, tags: Optional[List[str]] = None, metadata: Optional[Dict[str, str]] = None) -> bool:
        """Async retain information into Hindsight memory bank."""
        if not self.client:
            return False
        try:
            await self.client.aretain(
                bank_id=self.bank_id,
                content=content,
                context=context,
                tags=tags or [],
                metadata=metadata or {}
            )
            return True
        except Exception as e:
            logger.error(f"Hindsight async retain failed: {e}")
            return False

    def retain_memory(self, content: str, context: Optional[str] = None, tags: Optional[List[str]] = None, metadata: Optional[Dict[str, str]] = None) -> bool:
        """Sync retain information into Hindsight memory bank."""
        if not self.client:
            return False
        try:
            self.client.retain(
                bank_id=self.bank_id,
                content=content,
                context=context,
                tags=tags or [],
                metadata=metadata or {}
            )
            return True
        except Exception as e:
            logger.error(f"Hindsight sync retain failed: {e}")
            return False

    async def arecall_memories(self, query: str, tags: Optional[List[str]] = None, max_tokens: int = 2048) -> List[Dict[str, Any]]:
        """Async recall relevant memories from Hindsight memory bank."""
        if not self.client:
            return []
        try:
            response = await self.client.arecall(
                bank_id=self.bank_id,
                query=query,
                tags=tags,
                max_tokens=max_tokens
            )
            results = []
            if hasattr(response, 'results') and response.results:
                for item in response.results:
                    results.append({
                        "id": getattr(item, 'id', None),
                        "type": getattr(item, 'type', 'observation'),
                        "text": getattr(item, 'text', str(item)),
                        "score": getattr(item, 'score', None)
                    })
            return results
        except Exception as e:
            logger.error(f"Hindsight async recall failed: {e}")
            return []

    def recall_memories(self, query: str, tags: Optional[List[str]] = None, max_tokens: int = 2048) -> List[Dict[str, Any]]:
        """Sync recall relevant memories from Hindsight memory bank."""
        if not self.client:
            return []
        try:
            response = self.client.recall(
                bank_id=self.bank_id,
                query=query,
                tags=tags,
                max_tokens=max_tokens
            )
            results = []
            if hasattr(response, 'results') and response.results:
                for item in response.results:
                    results.append({
                        "id": getattr(item, 'id', None),
                        "type": getattr(item, 'type', 'observation'),
                        "text": getattr(item, 'text', str(item)),
                        "score": getattr(item, 'score', None)
                    })
            return results
        except Exception as e:
            logger.error(f"Hindsight sync recall failed: {e}")
            return []

    async def areflect_on_project(self, project_id: str, query: Optional[str] = None) -> Optional[str]:
        """Async reflect on accumulated project memories."""
        if not self.client:
            return None
        try:
            prompt = query or f"Synthesize security posture, recurring code debt, and developer decisions for project {project_id}."
            response = await self.client.areflect(
                bank_id=self.bank_id,
                query=prompt,
                tags=[f"project_{project_id}"]
            )
            if hasattr(response, 'text') and response.text:
                return response.text
            return str(response)
        except Exception as e:
            logger.error(f"Hindsight async reflect failed: {e}")
            return None

    def reflect_on_project(self, project_id: str, query: Optional[str] = None) -> Optional[str]:
        """Sync reflect on accumulated project memories."""
        if not self.client:
            return None
        try:
            prompt = query or f"Synthesize security posture, recurring code debt, and developer decisions for project {project_id}."
            response = self.client.reflect(
                bank_id=self.bank_id,
                query=prompt,
                tags=[f"project_{project_id}"]
            )
            if hasattr(response, 'text') and response.text:
                return response.text
            return str(response)
        except Exception as e:
            logger.error(f"Hindsight sync reflect failed: {e}")
            return None

    # ==================== SCAN AND CONTEXT PERSISTENCE ====================

    def save_scan_results(self, project_id: str, scan_id: str, project_context: Dict[str, Any], findings: List[Finding]):
        """Save scan results to Hindsight memory and local database."""
        cursor = self.conn.cursor()

        project_name = project_context.get("name", "Unknown Project")
        cursor.execute("""
            UPDATE projects
            SET name = ?, project_context = ?, last_scan_at = ?
            WHERE id = ?
        """, (project_name, json.dumps(project_context), datetime.utcnow().isoformat(), project_id))

        summary = {
            "total_findings": len(findings),
            "by_category": self._count_by_category(findings),
            "by_severity": self._count_by_severity(findings)
        }
        cursor.execute("""
            INSERT OR REPLACE INTO scans (id, project_id, status, completed_at, summary)
            VALUES (?, ?, ?, ?, ?)
        """, (scan_id, project_id, "completed", datetime.utcnow().isoformat(), json.dumps(summary)))

        for finding in findings:
            finding_id = self._get_or_create_finding_id(project_id, finding)
            cursor.execute("""
                INSERT OR REPLACE INTO findings (
                    id, scan_id, category, severity, title, description, evidence,
                    file_path, line_number, confidence, recommendation, status,
                    first_detected_scan, last_detected_scan,
                    ai_explanation, suggested_fix, existing_solution, project_specific_solution,
                    detection_source, validation_status, validation_result,
                    fix_applied, fix_validated
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                finding_id, scan_id, finding.category, finding.severity, finding.title,
                finding.description, finding.evidence, finding.file_path, finding.line_number,
                finding.confidence, finding.recommendation, finding.status,
                finding.metadata.get("first_detected_scan", scan_id),
                scan_id,
                finding.ai_explanation, finding.suggested_fix,
                finding.existing_solution, finding.project_specific_solution,
                finding.detection_source, finding.validation_status,
                finding.validation_result,
                1 if finding.fix_applied else 0,
                1 if finding.fix_validated else 0
            ))

        self.conn.commit()

        # Retain scan summary and critical findings into Hindsight Memory Cloud
        if self.client:
            try:
                scan_content = (
                    f"Scan {scan_id} completed for project '{project_name}' (ID: {project_id}). "
                    f"Total findings: {len(findings)}. "
                    f"Breakdown by severity: {summary['by_severity']}. "
                    f"Breakdown by category: {summary['by_category']}. "
                    f"Technologies detected: {project_context.get('technologies', [])}."
                )
                self.retain_memory(
                    content=scan_content,
                    context=f"Project {project_name} Scan Audit",
                    tags=[f"project_{project_id}", f"scan_{scan_id}", "scan_summary"],
                    metadata={"project_id": project_id, "scan_id": scan_id}
                )

                significant_findings = [f for f in findings if f.severity in ("critical", "high")]
                for sf in significant_findings[:10]:
                    finding_content = (
                        f"Vulnerability in {project_name} ({sf.file_path or 'unknown'}:{sf.line_number or 0}): "
                        f"[{sf.severity.upper()}] {sf.title} - {sf.description}. "
                        f"Recommendation: {sf.recommendation}"
                    )
                    self.retain_memory(
                        content=finding_content,
                        context=f"Scan Finding for {project_name}",
                        tags=[f"project_{project_id}", f"scan_{scan_id}", sf.category, sf.severity],
                        metadata={"project_id": project_id, "scan_id": scan_id, "category": sf.category}
                    )
            except Exception as e:
                logger.warning(f"Failed to retain scan findings in Hindsight Memory: {e}")

    def _get_or_create_finding_id(self, project_id: str, finding: Finding) -> str:
        """Get existing finding ID or create new one based on similarity."""
        cursor = self.conn.cursor()

        cursor.execute("""
            SELECT id, first_detected_scan FROM findings
            WHERE category = ? AND title = ? AND file_path = ? AND line_number = ?
            ORDER BY last_detected_scan DESC LIMIT 1
        """, (finding.category, finding.title, finding.file_path, finding.line_number))

        row = cursor.fetchone()
        if row:
            finding_id, first_scan = row
            finding.metadata["first_detected_scan"] = first_scan
            return finding_id

        return str(uuid.uuid4())

    def _count_by_category(self, findings: List[Finding]) -> Dict[str, int]:
        counts = {}
        for f in findings:
            counts[f.category] = counts.get(f.category, 0) + 1
        return counts

    def _count_by_severity(self, findings: List[Finding]) -> Dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def compare_scans(self, project_id: str, current_scan_id: str, current_findings: List[Finding]) -> Dict[str, Any]:
        """Compare current scan with previous scan."""
        cursor = self.conn.cursor()

        cursor.execute("""
            SELECT id FROM scans
            WHERE project_id = ? AND id != ? AND status = 'completed'
            ORDER BY completed_at DESC LIMIT 1
        """, (project_id, current_scan_id))

        prev_scan = cursor.fetchone()
        if not prev_scan:
            return {
                "has_previous_scan": False,
                "previous_scan_id": None,
                "fixed_count": 0,
                "unresolved_count": 0,
                "new_count": len(current_findings),
                "reintroduced_count": 0,
                "fixed_findings": [],
                "unresolved_findings": [],
                "new_findings": [f.to_dict() for f in current_findings],
                "reintroduced_findings": []
            }

        prev_scan_id = prev_scan[0]

        cursor.execute("""
            SELECT id, category, severity, title, description, evidence, file_path, line_number, confidence, recommendation, status, first_detected_scan, last_detected_scan
            FROM findings WHERE scan_id = ?
        """, (prev_scan_id,))

        prev_findings = {}
        for row in cursor.fetchall():
            key = self._finding_key(row[1], row[3], row[5], row[6])
            prev_findings[key] = {
                "id": row[0], "category": row[1], "severity": row[2], "title": row[3],
                "description": row[4], "evidence": row[5], "file_path": row[6],
                "line_number": row[7], "confidence": row[8], "recommendation": row[9],
                "status": row[10], "first_detected_scan": row[11], "last_detected_scan": row[12]
            }

        current_keys = set()
        fixed = []
        unresolved = []
        new_findings = []
        reintroduced = []

        for finding in current_findings:
            key = self._finding_key(finding.category, finding.title, finding.evidence, finding.file_path)
            current_keys.add(key)

            if key in prev_findings:
                prev = prev_findings[key]
                if prev["status"] == "fixed":
                    reintroduced.append(prev)
                else:
                    unresolved.append(prev)
            else:
                new_findings.append(finding.to_dict())

        for key, prev in prev_findings.items():
            if key not in current_keys and prev["status"] != "fixed":
                fixed.append(prev)

        return {
            "has_previous_scan": True,
            "previous_scan_id": prev_scan_id,
            "fixed_count": len(fixed),
            "unresolved_count": len(unresolved),
            "new_count": len(new_findings),
            "reintroduced_count": len(reintroduced),
            "fixed_findings": fixed,
            "unresolved_findings": unresolved,
            "new_findings": new_findings,
            "reintroduced_findings": reintroduced
        }

    def _finding_key(self, category: str, title: str, evidence: str, file_path: Optional[str]) -> str:
        """Create a unique key for a finding."""
        return f"{category}:{title}:{file_path}:{evidence[:50] if evidence else ''}"

    def get_project_context(self, project_id: str) -> Dict[str, Any]:
        """Get project context including previous scan summary and Hindsight memories."""
        cursor = self.conn.cursor()

        cursor.execute("""
            SELECT id, name, project_context, created_at, last_scan_at
            FROM projects WHERE id = ?
        """, (project_id,))

        project = cursor.fetchone()
        if not project:
            return {}

        cursor.execute("""
            SELECT id, status, created_at, completed_at, summary
            FROM scans WHERE project_id = ? AND status = 'completed'
            ORDER BY completed_at DESC LIMIT 5
        """, (project_id,))

        scans = []
        for row in cursor.fetchall():
            scans.append({
                "id": row[0], "status": row[1], "created_at": row[2],
                "completed_at": row[3], "summary": json.loads(row[4]) if row[4] else {}
            })

        return {
            "project": {
                "id": project[0], "name": project[1],
                "project_context": json.loads(project[2]) if project[2] else {},
                "created_at": project[3], "last_scan_at": project[4]
            },
            "recent_scans": scans
        }

    def add_developer_note(self, project_id: str, finding_id: Optional[str], note_type: str, content: str):
        """Add a developer note/decision to Hindsight and local SQLite."""
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO hindsight_memory (project_id, finding_id, type, content)
            VALUES (?, ?, ?, ?)
        """, (project_id, finding_id, note_type, content))
        self.conn.commit()

        if self.client:
            try:
                target_str = f"on finding {finding_id}" if finding_id else "on project level"
                note_text = f"Developer decision/note ({note_type}) {target_str} for project {project_id}: {content}"
                self.retain_memory(
                    content=note_text,
                    context=f"Developer Note: {note_type}",
                    tags=[f"project_{project_id}", "developer_note", note_type],
                    metadata={"project_id": project_id, "finding_id": finding_id or "", "note_type": note_type}
                )
            except Exception as e:
                logger.warning(f"Failed to retain developer note in Hindsight: {e}")

    def get_developer_notes(self, project_id: str, finding_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get developer notes for a project or specific finding."""
        cursor = self.conn.cursor()
        if finding_id:
            cursor.execute("""
                SELECT id, finding_id, type, content, created_at
                FROM hindsight_memory WHERE project_id = ? AND finding_id = ?
                ORDER BY created_at DESC
            """, (project_id, finding_id))
        else:
            cursor.execute("""
                SELECT id, finding_id, type, content, created_at
                FROM hindsight_memory WHERE project_id = ?
                ORDER BY created_at DESC
            """, (project_id,))

        notes = []
        for row in cursor.fetchall():
            notes.append({
                "id": row[0], "finding_id": row[1], "type": row[2],
                "content": row[3], "created_at": row[4]
            })
        return notes

    def update_finding_status(self, finding_id: str, status: str):
        """Update finding status (open, fixed, acknowledged)."""
        cursor = self.conn.cursor()
        cursor.execute("UPDATE findings SET status = ? WHERE id = ?", (status, finding_id))
        self.conn.commit()