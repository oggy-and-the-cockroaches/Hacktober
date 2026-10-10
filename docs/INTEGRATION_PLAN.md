# Shipcheck + ProofPatch Integration Plan

## 1. Existing Architecture Overview

### Shipcheck
- **Core Purpose**: AI-powered pre-shipment code auditor scanning for security vulnerabilities, privacy leaks, production-readiness flags, and reliability issues.
- **Scanners**: Multi-category AST/regex scanners (`security.py`, `privacy.py`, `production.py`, `reliability.py`, `configuration.py`, `dependency.py`).
- **Persistence**: SQLite database (`shipcheck.db`) tracking projects, scans, findings, dependencies, and sandbox executions.
- **Native Acceleration**: Integrated C++ Sentinel RASP core module for runtime property validation.
- **Dashboard**: Modern glassmorphism SPA frontend (`index.html`, `app.js`, `styles.css`).

### ProofPatch / Verified Remediation Engine
- **Core Purpose**: AI-assisted remediation workflow using Gemma models to produce structured diff patches and execute controlled regression verification before marking fixes as verified.
- **Verification Harness**: Executes dual-baseline testing (original vs. patched project) to ensure vulnerabilities are fixed without introducing regressions.

---

## 2. Integrated Architecture & Key Decisions

1. **Unified Application & Entry Point**:
   - Single FastAPI backend (`backend/main.py`) serving both API routes and the unified SPA dashboard.
   - Single startup command `python -m backend.main` or `uvicorn backend.main:app`.

2. **Gemma LLM Provider**:
   - Implement `GemmaProvider` in `backend/services/llm.py` as the primary remediation intelligence engine.
   - Structured JSON schema for remediation proposals with prompt injection protection.
   - Configurable remote or local endpoints (`GEMMA_ENDPOINT`, `GEMMA_API_KEY`, `GEMMA_MODEL`).
   - Graceful fallback when Gemma is offline; scanning continues deterministically.

3. **Verified Remediation Workflow**:
   - Status pipeline: `PROPOSED` -> `APPROVED` -> `APPLIED` -> `VERIFYING` -> `VERIFIED` / `FAILED` / `INCONCLUSIVE` / `REJECTED`.
   - Workspace isolation using disposable temporary directories and path sanitization.
   - Dual-run verification harness comparing original code baseline vs. patched code results.

4. **Hindsight Memory Deprecation**:
   - Per explicit instruction, Hindsight memory engine is removed and replaced by structured remediation tracking and verification evidence logs in SQLite.

5. **Database Strategy**:
   - Extend SQLite schema with migration support for `remediation_proposals` and `remediation_verifications`.
   - Maintain referential integrity with existing projects, scans, and findings.

---

## 3. Phased Implementation Plan

- **Phase 1: Foundation & Hindsight Removal**:
  - Remove Hindsight references from API routers, backend services, schema, and tests.
  - Establish `GemmaProvider` in `backend/services/llm.py` with structured output parsing and prompt injection sanitization.

- **Phase 2: Database Schema & Remediation Engine Core**:
  - Update `backend/database/schema.py` to add `remediation_proposals` and `remediation_verifications` tables.
  - Build `backend/services/remediation.py` to handle patch generation, patch validation, diff rendering, and verification harness execution.

- **Phase 3: API & Secure Execution Harness**:
  - Expose `/api/remediation/*` endpoints in `backend/api/remediation.py` for proposal generation, approval, patch application, and verification execution.
  - Implement workspace isolation and path traversal guards in `backend/services/workspace.py` and `backend/services/sandbox.py`.

- **Phase 4: Frontend Integration**:
  - Update SPA in `frontend/index.html` and `frontend/app.js` with unified navigation (Overview, Scan Details, Remediation Workspace, Verification Results, Reports).
  - Add interactive diff viewer, AI proposal explanation, approve/reject controls, and verification result evidence cards.

- **Phase 5: Verification, Documentation & Packaging**:
  - Write unit and integration tests for Gemma provider, patch validation, path traversal guards, and dual-baseline verification.
  - Create documentation (`ARCHITECTURE.md`, `VERIFICATION_MODEL.md`, `TEST_REPORT.md`, updated `README.md`).
