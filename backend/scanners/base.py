"""Base scanner class and finding model."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from pathlib import Path
import re


@dataclass
class Finding:
    """Represents a single finding from a scanner."""
    category: str
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    evidence: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    confidence: str = "medium"  # confirmed, high, medium, low
    recommendation: str = ""
    status: str = "open"  # open, fixed, acknowledged, ignored, false_positive
    metadata: Dict[str, Any] = field(default_factory=dict)
    # Extended fields for comprehensive findings
    ai_explanation: Optional[str] = None
    suggested_fix: Optional[str] = None
    existing_solution: Optional[str] = None
    project_specific_solution: Optional[str] = None
    detection_source: str = "STATIC"  # STATIC, DYNAMIC, DEPENDENCY, CONFIGURATION, RUNTIME, AI, MULTIPLE
    validation_status: Optional[str] = None
    validation_result: Optional[str] = None
    fix_applied: bool = False
    fix_validated: bool = False

    def __post_init__(self):
        """Keep the actionable rule guidance available as a suggested fix.

        Rule-based scans do not require an LLM; their recommendation is the
        reliable offline fix guidance.  Preserve it in both fields so all API
        consumers can present it consistently.
        """
        if not self.suggested_fix and self.recommendation:
            self.suggested_fix = self.recommendation

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "confidence": self.confidence,
            "recommendation": self.recommendation,
            "status": self.status,
            "metadata": self.metadata,
            "ai_explanation": self.ai_explanation,
            "suggested_fix": self.suggested_fix,
            "existing_solution": self.existing_solution,
            "project_specific_solution": self.project_specific_solution,
            "detection_source": self.detection_source,
            "validation_status": self.validation_status,
            "validation_result": self.validation_result,
            "fix_applied": self.fix_applied,
            "fix_validated": self.fix_validated
        }


class BaseScanner(ABC):
    """Base class for all scanners."""

    def __init__(self, project_root: str, project_context: Dict[str, Any]):
        self.project_root = Path(project_root)
        self.project_context = project_context
        self.findings: List[Finding] = []

    @abstractmethod
    def scan(self) -> List[Finding]:
        """Run the scan and return findings."""
        pass

    def _get_source_files(self, extensions: Optional[List[str]] = None) -> List[Path]:
        """Get all source files in the project, excluding common ignore patterns."""
        if extensions is None:
            extensions = [".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rs", ".php", ".rb", ".cs", ".cpp", ".c", ".kt", ".swift"]

        ignore_dirs = {".git", "venv", ".venv", "node_modules", "__pycache__", "dist", "build", ".next", "target", "vendor", ".idea", ".vscode", "env", ".env", ".pytest_cache", ".shipcheck_cache"}

        files = []
        for ext in extensions:
            for file in self.project_root.rglob(f"*{ext}"):
                if any(ignore in file.parts for ignore in ignore_dirs):
                    continue
                if file.is_file():
                    files.append(file)
        return files

    def _read_file(self, file_path: Path) -> Optional[str]:
        """Safely read a file."""
        try:
            return file_path.read_text(errors="ignore")
        except Exception:
            return None

    def _find_in_file(self, file_path: Path, pattern: str) -> List[tuple]:
        """Find all matches of a pattern in a file, returning (line_number, line_content)."""
        content = self._read_file(file_path)
        if not content:
            return []

        matches = []
        for i, line in enumerate(content.splitlines(), 1):
            if re.search(pattern, line, re.IGNORECASE):
                matches.append((i, line.strip()))
        return matches

    def _add_finding(self, finding: Finding):
        """Add a finding to the scanner's findings."""
        self.findings.append(finding)

    def _generate_ai_explanation(self, finding: Finding) -> str:
        """Generate AI explanation for a finding."""
        return f"AI Analysis: {finding.title}. {finding.description}"

    def _generate_suggested_fix(self, finding: Finding) -> str:
        """Generate suggested fix for a finding."""
        return finding.recommendation

    def _generate_existing_solution(self, finding: Finding) -> str:
        """Generate existing/common solution for a finding."""
        return f"Industry standard solution: {finding.recommendation}"

    def _generate_project_specific_solution(self, finding: Finding) -> str:
        """Generate project-specific solution for a finding."""
        return f"Project-specific fix for {finding.file_path}: {finding.recommendation}"
