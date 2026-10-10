"""Pydantic models for the Shipcheck API."""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    OPEN = "open"
    FIXED = "fixed"
    ACKNOWLEDGED = "acknowledged"
    IGNORED = "ignored"
    FALSE_POSITIVE = "false_positive"


class Confidence(str, Enum):
    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class DetectionSource(str, Enum):
    STATIC = "STATIC"
    DYNAMIC = "DYNAMIC"
    DEPENDENCY = "DEPENDENCY"
    CONFIGURATION = "CONFIGURATION"
    RUNTIME = "RUNTIME"
    AI = "AI"
    MULTIPLE = "MULTIPLE"


class ProjectCreate(BaseModel):
    name: str
    project_context: Optional[Dict[str, Any]] = None


class ProjectResponse(BaseModel):
    id: str
    name: str
    created_at: datetime
    last_scan_at: Optional[datetime] = None
    project_context: Optional[Dict[str, Any]] = None


class ScanCreate(BaseModel):
    project_id: str


class ScanResponse(BaseModel):
    id: str
    project_id: str
    status: ScanStatus
    created_at: datetime
    completed_at: Optional[datetime] = None
    summary: Optional[Dict[str, Any]] = None


class FindingResponse(BaseModel):
    id: str
    scan_id: str
    category: str
    severity: Severity
    title: str
    description: Optional[str] = None
    evidence: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    confidence: Optional[str] = None
    recommendation: Optional[str] = None
    status: FindingStatus
    first_detected_scan: Optional[str] = None
    last_detected_scan: Optional[str] = None
    ai_explanation: Optional[str] = None
    suggested_fix: Optional[str] = None
    existing_solution: Optional[str] = None
    project_specific_solution: Optional[str] = None
    detection_source: Optional[str] = None
    validation_status: Optional[str] = None


class HindsightEntry(BaseModel):
    project_id: str
    finding_id: Optional[str] = None
    type: str
    content: str


class ScanComparison(BaseModel):
    current_scan_id: str
    previous_scan_id: Optional[str] = None
    previous_findings_count: int = 0
    current_findings_count: int = 0
    fixed_count: int = 0
    unresolved_count: int = 0
    new_count: int = 0
    reintroduced_count: int = 0
    fixed_findings: List[Dict[str, Any]] = Field(default_factory=list)
    unresolved_findings: List[Dict[str, Any]] = Field(default_factory=list)
    new_findings: List[Dict[str, Any]] = Field(default_factory=list)
    reintroduced_findings: List[Dict[str, Any]] = Field(default_factory=list)


class SandboxExecutionResponse(BaseModel):
    execution_id: str
    project_id: str
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class SentinelIntegrationResponse(BaseModel):
    project_id: str
    framework: str
    changes: List[Dict[str, Any]]
    dependencies: List[str]
    protection_features: List[str]
    files_modified: List[str]
    estimated_latency: str


class FixValidationResponse(BaseModel):
    validation_id: str
    finding_id: str
    fix_applied: bool
    rescan_result: Dict[str, Any]
    comparison: Dict[str, Any]
    validated: bool
    timestamp: datetime


class RuntimeEventResponse(BaseModel):
    id: int
    project_id: str
    event_type: str
    endpoint: Optional[str] = None
    action: str
    confidence: str
    evidence: Optional[str] = None
    timestamp: datetime
    request_id: Optional[str] = None