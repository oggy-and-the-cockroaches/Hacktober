# 🚢 Shipcheck + Verified Remediation Engine

**Shipcheck** is an enterprise-grade AI-powered pre-shipment code auditor and verified remediation system. It scans software projects for security vulnerabilities, privacy leaks, production-readiness flags, and reliability flaws, proposes AI patches using **Gemma**, and verifies proposed fixes through controlled regression testing in isolated workspaces.

---

## 🌟 Key Features

* **🛡️ Security Audit**: Detects hardcoded secrets, API keys, unescaped `eval()` execution, SQL injection risks, insecure cryptographic primitives, and permissive CORS setups.
* **🔒 Privacy & Compliance Audit**: Identifies unencrypted PII storage, logging of sensitive user data, unauthorized telemetry tracking, and missing privacy consent mechanisms.
* **🚀 Production Readiness**: Flags remaining `DEBUG=True` flags, leftover `console.log()` / print statements, hardcoded `localhost` URLs, and unhandled exception blocks.
* **⚡ Reliability & Robustness**: Detects missing network timeouts, unhandled promise rejections, unclosed resource handles, and missing circuit breakers.
* **🤖 Gemma AI Remediation Engine**: Generates structured patch proposals, root-cause analysis, risk prioritizations, and recommended test cases powered by Gemma.
* **🧪 Verified Remediation Harness**: Executes dual-baseline testing (original code vs. patched code) in isolated disposable workspaces before marking fixes as `VERIFIED`.
* **🔒 Safe Workspace Isolation**: Path-traversal guards, archive extraction limits, and strict sub-process execution timeouts.
* **📊 Modern Glassmorphism Dashboard**: SPA frontend providing real-time scan visualization, category filters, Gemma patch review workbench, verification evidence logs, and downloadable JSON reports.

---

## 🏗️ System Architecture

```
Project Input / Zip Upload
        |
        v
Safe Extraction & Workspace Manager
        |
        v
Unified Multi-Scanner Engine (Security, Privacy, Production, Reliability, Dependencies)
        |
        v
Normalized Finding Model
        |
        v
Gemma AI Remediation Engine (Patch proposal, Impact Analysis, Prompt Injection Guards)
        |
        v
Patch Review Workbench (Approve / Reject)
        |
        v
Dual-Baseline Verification Harness (Disposable Workspace, Syntax & Regression Tests)
        |
        v
SQLite Persistence Store & Dashboard Evidence
```

---

## 🚀 Quick Start (Local Setup)

### 1. Prerequisites
- Python 3.10+
- Virtual environment (`venv`)

### 2. Installation

```bash
# Clone or navigate to workspace
cd Shipcheck

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Configuration

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

Configure your Gemma provider settings in `.env`:

```env
SHIPCHECK_LLM_PROVIDER=gemma
GEMMA_ENDPOINT=http://localhost:11434/api/generate
GEMMA_API_KEY=your_gemma_api_key_here
GEMMA_MODEL=gemma-2-27b-it
```

### 4. Running the Application

```bash
python -m backend.main
```

Access the dashboard at `http://localhost:8000`.

---

## 🧪 Running Automated Tests

```bash
pytest
```

---

## 🌐 DigitalOcean Deployment Guide

### Deployment Options: DigitalOcean App Platform / Droplet

1. **Environment Variables**:
   Set the following variables in the DigitalOcean App Platform console:
   - `PORT=8000`
   - `HOST=0.0.0.0`
   - `SHIPCHECK_DB_PATH=/app/data/shipcheck.db`
   - `SHIPCHECK_PROJECTS_DIR=/app/data/projects`
   - `SHIPCHECK_LLM_PROVIDER=gemma`
   - `GEMMA_API_KEY=<your-key>`

2. **Mount Volume**:
   Attach a persistent volume at `/app/data` to ensure SQLite database (`shipcheck.db`) and workspace files persist across redeployments.

3. **Run Command**:
   ```bash
   python -m backend.main
   ```

4. **Health Check Endpoint**:
   Configured at `/api/health`.

---

## 📜 Documentation

- [`docs/INTEGRATION_PLAN.md`](docs/INTEGRATION_PLAN.md)
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- [`docs/VERIFICATION_MODEL.md`](docs/VERIFICATION_MODEL.md)
- [`docs/TEST_REPORT.md`](docs/TEST_REPORT.md)
"# Hacktober" 
