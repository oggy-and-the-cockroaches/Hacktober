# Shipcheck Architecture Documentation

## Overview

Shipcheck is an enterprise-grade AI-powered pre-shipment code auditor and verified remediation system. It integrates multi-layer static analysis, dependency scanning, AI patch generation powered by Gemma, controlled verification testing, and Sentinel RASP runtime property checks into a single unified application.

```
+-------------------------------------------------------------------------+
|                        Unified Dashboard (SPA)                          |
|  [Overview]  [Scan Details]  [Remediation]  [Verification]  [Reports]   |
+-------------------------------------------------------------------------+
                                    |
                                HTTP REST
                                    v
+-------------------------------------------------------------------------+
|                        FastAPI Application Gateway                      |
|  /api/projects  /api/scans  /api/remediation  /api/reports  /api/health |
+-------------------------------------------------------------------------+
       |                  |                      |
       v                  v                      v
+--------------+  +--------------------+  +-------------------------------+
| Multi-Scanner|  | Gemma Intelligence |  | Verified Remediation Harness  |
| Orchestrator |  |    Provider        |  |  - Baseline Tests             |
| - Security   |  | - Explain Finding  |  |  - Patched Regression Tests   |
| - Privacy    |  | - Propose Patch    |  |  - Rescan Verification        |
| - Production |  | - Impact Analysis  |  |  - Static & Syntax Checks     |
| - Reliability|  | - Sanitize Prompts |  +-------------------------------+
| - Dependency |  +--------------------+                 |
+--------------+            |                            |
       |                    +------------+---------------+
       |                                 |
       v                                 v
+-------------------------------------------------------------------------+
|                        SQLite Persistence Store                         |
|   projects  |  scans  |  findings  |  remediation_proposals & runs   |
+-------------------------------------------------------------------------+
```

## Core Components

### 1. Unified Scan Engine (`backend/scanners/`, `backend/services/scanner.py`)
- Executes Security, Privacy, Production Readiness, Reliability, Configuration, and Dependency analysis.
- Generates normalized `Finding` objects with standardized risk severities (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).

### 2. Gemma AI Remediation Provider (`backend/services/llm.py`)
- Interfaces with Gemma LLM inference endpoints (remote or local).
- Generates structured remediation proposals containing diffs, root cause explanations, and suggested regression tests.
- Implements strict prompt sanitization to guard against prompt injection attacks.

### 3. Verified Remediation Harness (`backend/services/remediation.py`)
- Executes patch review, safe application to isolated temporary workspaces, and dual-baseline verification runs.
- Computes clear evidence status: `PROPOSED`, `APPROVED`, `APPLIED`, `VERIFYING`, `VERIFIED`, `FAILED`, `INCONCLUSIVE`, `REJECTED`.

### 4. Workspace Security & Isolation (`backend/services/workspace.py`)
- Enforces strict path traversal prevention, archive size/file count extraction limits, and execution timeouts.
