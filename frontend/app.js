/* Shipcheck + Sentinel Frontend JavaScript */

const API_BASE = '/api';

// State
let currentProjectId = null;
let currentScanId = null;
let currentScanProjectId = null;
let scanInterval = null;
let runtimeRefreshInterval = null;
let currentSection = 'dashboard';

// Backend Connection & Offline Resilience State
let isBackendOnline = false;
let backendHealthInterval = null;

const OFFLINE_PROJECTS = [
    {
        id: "offline-sample-1",
        name: "Shipcheck Vulnerable App (Offline Demo)",
        created_at: new Date().toISOString(),
        security_score: 72,
        privacy_score: 85,
        production_readiness_score: 58,
        reliability_score: 90,
        project_context: {
            languages: ["Python", "JavaScript"],
            frameworks: ["FastAPI", "Uvicorn"],
            databases: ["SQLite"],
            deployment: ["Docker", "Linux"]
        }
    },
    {
        id: "offline-sample-2",
        name: "Payment Gateway Microservice",
        created_at: new Date(Date.now() - 86400000).toISOString(),
        security_score: 88,
        privacy_score: 94,
        production_readiness_score: 82,
        reliability_score: 95,
        project_context: {
            languages: ["Go", "TypeScript"],
            frameworks: ["Gin", "React"],
            databases: ["PostgreSQL", "Redis"]
        }
    }
];

const OFFLINE_FINDINGS = [
    {
        id: "f-off-001",
        title: "SQL Injection via Unsanitized Query Parameter in User Authentication",
        category: "security",
        severity: "critical",
        scanner_type: "ast",
        file_path: "app/routes/auth.py",
        line_number: 42,
        description: "Raw SQL query constructed via string formatting using untrusted user input from request parameters. An attacker can manipulate SQL queries to bypass authentication and dump database contents.",
        evidence: 'cursor.execute(f"SELECT * FROM users WHERE username = \'{username}\' AND password = \'{password}\'")',
        recommendation: "Use parameterized queries or ORM query binding instead of direct string interpolation.",
        suggested_fix: 'cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))'
    },
    {
        id: "f-off-002",
        title: "Hardcoded API Secret Key in Configuration",
        category: "security",
        severity: "critical",
        scanner_type: "secret",
        file_path: "config/settings.py",
        line_number: 15,
        description: "Production cryptographic signing secret key committed directly into the source code repository.",
        evidence: 'JWT_SECRET_KEY = "super_secret_production_key_do_not_share_12345"',
        recommendation: "Load sensitive secrets from environment variables using os.environ or a secrets manager.",
        suggested_fix: 'JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY")\nif not JWT_SECRET_KEY:\n    raise RuntimeError("JWT_SECRET_KEY not set")'
    },
    {
        id: "f-off-003",
        title: "Missing CSRF Protection on Sensitive State-Changing Endpoints",
        category: "privacy",
        severity: "high",
        scanner_type: "configuration",
        file_path: "app/main.py",
        line_number: 68,
        description: "POST and PUT endpoints accept requests without CSRF token validation, enabling cross-site request forgery attacks.",
        evidence: '@app.post("/api/account/transfer")\nasync def transfer_funds(data: TransferRequest):',
        recommendation: "Enforce SameSite=Strict cookies and validate Anti-CSRF tokens for all state-changing endpoints.",
        suggested_fix: 'app.add_middleware(CSRFMiddleware, secret=CSRF_SECRET, cookie_samesite="Strict")'
    },
    {
        id: "f-off-004",
        title: "Permissive CORS Configuration Allowing All Origins with Credentials",
        category: "configuration",
        severity: "high",
        scanner_type: "configuration",
        file_path: "app/main.py",
        line_number: 22,
        description: "CORSMiddleware configured with allow_origins=[\'*\'] combined with allow_credentials=True.",
        evidence: 'app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)',
        recommendation: "Explicitly declare trusted client origins instead of wildcard \'*\' when credentials are enabled.",
        suggested_fix: 'app.add_middleware(CORSMiddleware, allow_origins=["https://app.shipcheck.io"], allow_credentials=True)'
    },
    {
        id: "f-off-005",
        title: "Unbounded Request Body Exposing Denial of Service (DoS)",
        category: "reliability",
        severity: "medium",
        scanner_type: "reliability",
        file_path: "app/routes/upload.py",
        line_number: 31,
        description: "File upload endpoint does not validate maximum payload size before reading entire stream into memory.",
        evidence: 'content = await file.read()',
        recommendation: "Enforce Content-Length checks and stream chunks with a maximum file size threshold (e.g. 25MB).",
        suggested_fix: 'if len(content) > MAX_ALLOWED_SIZE:\n    raise HTTPException(413, "Payload too large")'
    },
    {
        id: "f-off-006",
        title: "Missing Security Headers (Content-Security-Policy & HSTS)",
        category: "production",
        severity: "low",
        scanner_type: "runtime",
        file_path: "server.conf",
        line_number: 12,
        description: "HTTP response headers lack Strict-Transport-Security, X-Frame-Options, and Content-Security-Policy.",
        evidence: 'Header set X-Content-Type-Options "nosniff"',
        recommendation: "Inject standard security headers on all reverse proxy and application responses.",
        suggested_fix: 'response.headers["Content-Security-Policy"] = "default-src \'self\'"'
    }
];

const OFFLINE_FILES = {
    "app/main.py": `from fastapi import FastAPI
from app.routes import auth, upload

app = FastAPI(title="Sample Vulnerable App")

# Routes
app.include_router(auth.router, prefix="/auth")
app.include_router(upload.router, prefix="/upload")

@app.get("/health")
def health():
    return {"status": "ok"}
`,
    "app/routes/auth.py": `from fastapi import APIRouter
import sqlite3

router = APIRouter()

@router.post("/login")
def login(username: str, password: str):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # WARNING: Potential SQL Injection vulnerability detected by Shipcheck
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    return {"authenticated": bool(user)}
`,
    "config/settings.py": `import os

# Application Settings
DEBUG = True
DATABASE_URL = "sqlite:///./app.db"
# WARNING: Hardcoded secret key detected by Shipcheck
JWT_SECRET_KEY = "super_secret_production_key_do_not_share_12345"
ALGORITHM = "HS256"
`,
    "requirements.txt": `fastapi>=0.100.0
uvicorn>=0.23.0
pydantic>=2.0.0
sqlite3
`
};

const OFFLINE_RUNTIME_EVENTS = [
    {
        event_type: "SQL_INJECTION_BLOCKED",
        action: "BLOCKED",
        endpoint: "/auth/login",
        timestamp: new Date().toLocaleTimeString(),
        evidence: "Payload: ' OR 1=1 -- detected in parameter 'username'",
        confidence: "HIGH"
    },
    {
        event_type: "RATE_LIMIT_EXCEEDED",
        action: "THROTTLED",
        endpoint: "/api/password-reset",
        timestamp: new Date(Date.now() - 120000).toLocaleTimeString(),
        evidence: "50 requests in 10s from client 192.168.1.105",
        confidence: "MEDIUM"
    },
    {
        event_type: "PATH_TRAVERSAL_BLOCKED",
        action: "BLOCKED",
        endpoint: "/download",
        timestamp: new Date(Date.now() - 360000).toLocaleTimeString(),
        evidence: "Attempt to access /etc/passwd via relative path traversal",
        confidence: "CRITICAL"
    }
];

// DOM helpers
function $(id) {
    return document.getElementById(id);
}

function showSection(sectionName) {
    currentSection = sectionName;
    if (sectionName !== 'runtime' && runtimeRefreshInterval) {
        clearInterval(runtimeRefreshInterval);
        runtimeRefreshInterval = null;
    }
    const sections = document.querySelectorAll('.section');
    sections.forEach(section => {
        section.classList.remove('active');
        section.style.display = 'none';
    });

    const targetSection = $(sectionName + '-section');
    if (targetSection) {
        targetSection.classList.add('active');
        targetSection.style.display = 'block';
    }

    // Update nav tabs
    document.querySelectorAll('.nav-tab').forEach(tab => {
        tab.classList.remove('active');
        if (tab.dataset.section === sectionName) {
            tab.classList.add('active');
        }
    });

    // Load section data
    loadSectionData(sectionName);
}

function loadSectionData(sectionName) {
    switch (sectionName) {
        case 'dashboard':
            loadDashboard();
            break;
        case 'projects':
            loadProjects();
            break;
        case 'scan':
            // Scan section shows progress, just ensure it's visible
            break;
        case 'findings':
            loadFindings();
            break;
        case 'editor':
            loadFileBrowser();
            break;
        case 'sandbox':
            loadSandboxStatus();
            break;
        case 'runtime':
            loadRuntimeDashboard();
            startRuntimeAutoRefresh();
            break;
        case 'sentinel':
            loadSentinelStatus();
            break;
        case 'reports':
            loadReportPreview();
            break;
        case 'history':
            loadHistory();
            break;
    }
}

// Initialize
document.addEventListener('DOMContentLoaded', function() {
    // Setup nav tabs
    document.querySelectorAll('.nav-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            showSection(tab.dataset.section);
        });
    });

    // Dashboard shortcuts use the same navigation and scan workflow as the sidebar.
    document.querySelectorAll('.dashboard-action[data-section]').forEach(button => {
        button.addEventListener('click', () => showSection(button.dataset.section));
    });
    const dashboardScan = $('dashboard-scan-btn');
    if (dashboardScan) {
        dashboardScan.addEventListener('click', () => {
            if (currentProjectId) {
                startScan(currentProjectId);
            } else {
                showSection('projects');
            }
        });
    }

    // Setup upload
    setupUpload();
    setupDataClear();

    // Setup filters
    setupFilters();

    // Setup editor
    setupEditor();

    // Setup sandbox
    setupSandbox();

    setupRuntimeScan();

    // Setup sentinel
    setupSentinel();

    // Setup reports
    setupReports();

    // Setup retry button in offline banner
    const retryBtn = $('retry-backend-btn');
    if (retryBtn) {
        retryBtn.addEventListener('click', async () => {
            retryBtn.textContent = 'Connecting...';
            retryBtn.disabled = true;
            await checkBackendHealth();
            setTimeout(() => {
                retryBtn.textContent = 'Retry Connection';
                retryBtn.disabled = false;
            }, 800);
        });
    }

    // Check status
    checkGemmaStatus();
    checkSentinelStatus();

    // Initial backend health check & ongoing auto-reconnect
    checkBackendHealth();
    backendHealthInterval = setInterval(checkBackendHealth, 4000);

    // Load initial data
    loadDashboard();
    loadProjects();
});

// Backend Health & Offline Resilience
async function checkBackendHealth() {
    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 1800);
        const res = await fetch(`${API_BASE}/health`, { signal: controller.signal });
        clearTimeout(timeoutId);

        if (res.ok) {
            const data = await res.json();
            if (data.status === 'healthy' || (data.service === 'shipcheck-sentinel' && data.backend_online !== false)) {
                setBackendStatus(true);
                return true;
            }
        }
    } catch (e) {
        // Backend offline / network error
    }
    setBackendStatus(false);
    return false;
}

function setBackendStatus(online) {
    const wasOffline = !isBackendOnline;
    isBackendOnline = online;

    const badge = $('backend-status-badge');
    const badgeText = $('backend-status-text');
    const banner = $('offline-banner');

    if (badge && badgeText) {
        if (online) {
            badge.className = 'hindsight-badge connected';
            badgeText.textContent = 'FastAPI: Connected';
        } else {
            badge.className = 'hindsight-badge offline';
            badgeText.textContent = 'FastAPI: Offline Mode';
        }
    }

    if (banner) {
        banner.style.display = online ? 'none' : 'flex';
    }

    // Update Gemma / Sentinel badge context
    const gemmaText = $('gemma-status-text');
    const gemmaBadge = $('gemma-status-badge');
    const sentinelText = $('sentinel-status-text');
    const sentinelBadge = $('sentinel-status-badge');

    if (!online) {
        if (gemmaText) gemmaText.textContent = 'Gemma Remediation (Offline)';
        if (gemmaBadge) gemmaBadge.className = 'hindsight-badge configured';
        if (sentinelText) sentinelText.textContent = 'Sentinel (Simulation)';
        if (sentinelBadge) sentinelBadge.className = 'sentinel-badge';
    }

    // If transitioned from offline to online, reload live data
    if (wasOffline && online) {
        console.log('[Shipcheck] Reconnected to FastAPI backend. Synchronizing live data...');
        loadDashboard();
        loadProjects();
    }
}

// Dashboard
async function loadDashboard() {
    if (!isBackendOnline) {
        loadOfflineDashboard();
        return;
    }

    if (!currentProjectId) {
        try {
            const response = await fetch(`${API_BASE}/projects`);
            const projects = await response.json();
            if (projects.length > 0) {
                currentProjectId = projects[0].id;
            } else {
                loadOfflineDashboard();
                return;
            }
        } catch (e) {
            loadOfflineDashboard();
            return;
        }
    }

    const requestedProjectId = currentProjectId;
    try {
        const response = await fetch(`${API_BASE}/projects/${requestedProjectId}/dashboard`);
        if (!response.ok) throw new Error('Dashboard request failed');
        const data = await response.json();
        if (requestedProjectId !== currentProjectId) return;

        // Update scores
        const project = data.project || {};
        $('score-security').textContent = project.security_score ?? '--';
        $('score-privacy').textContent = project.privacy_score ?? '--';
        $('score-production').textContent = project.production_readiness_score ?? '--';
        $('score-reliability').textContent = project.reliability_score ?? '--';

        // Update findings summary
        const findings = data.findings_summary || {};
        $('count-critical').textContent = findings.critical || 0;
        $('count-high').textContent = findings.high || 0;
        $('count-medium').textContent = findings.medium || 0;
        $('count-low').textContent = findings.low || 0;
        $('count-info').textContent = findings.info || 0;

        // Update runtime status
        const runtime = data.runtime_status || {};
        $('runtime-sentinel').textContent = runtime.sentinel_enabled ? 'Enabled' : 'Not Enabled';
        $('runtime-events').textContent = runtime.total_events || 0;
        $('runtime-blocked').textContent = runtime.blocked_count || 0;
        $('runtime-suspicious').textContent = runtime.suspicious_count || 0;

        // Update project info
        $('project-name').textContent = project.name || 'Unnamed project';
        const tech = project.project_context || {};
        const techStack = [
            ...(tech.languages || []),
            ...(tech.frameworks || []),
            ...(tech.databases || [])
        ].slice(0, 5).join(', ');
        $('project-tech').textContent = techStack || 'Unknown';
        $('project-last-scan').textContent = project.last_scan_at ? new Date(project.last_scan_at).toLocaleString() : 'Never';
        $('project-total-scans').textContent = Array.isArray(data.scan_history) ? data.scan_history.length : 0;

    } catch (e) {
        console.warn('Backend unavailable, loading offline dashboard:', e);
        loadOfflineDashboard();
    }
}

function loadOfflineDashboard() {
    const offlineProj = OFFLINE_PROJECTS.find(p => p.id === currentProjectId) || OFFLINE_PROJECTS[0];
    currentProjectId = offlineProj.id;

    if ($('score-security')) $('score-security').textContent = offlineProj.security_score;
    if ($('score-privacy')) $('score-privacy').textContent = offlineProj.privacy_score;
    if ($('score-production')) $('score-production').textContent = offlineProj.production_readiness_score;
    if ($('score-reliability')) $('score-reliability').textContent = offlineProj.reliability_score;

    if ($('count-critical')) $('count-critical').textContent = 2;
    if ($('count-high')) $('count-high').textContent = 5;
    if ($('count-medium')) $('count-medium').textContent = 8;
    if ($('count-low')) $('count-low').textContent = 3;
    if ($('count-info')) $('count-info').textContent = 1;

    if ($('runtime-sentinel')) $('runtime-sentinel').textContent = 'Active (Offline Demo)';
    if ($('runtime-events')) $('runtime-events').textContent = 38;
    if ($('runtime-blocked')) $('runtime-blocked').textContent = 5;
    if ($('runtime-suspicious')) $('runtime-suspicious').textContent = 8;

    if ($('project-name')) $('project-name').textContent = offlineProj.name;
    const tech = offlineProj.project_context || {};
    const techStack = [
        ...(tech.languages || []),
        ...(tech.frameworks || []),
        ...(tech.databases || [])
    ].slice(0, 5).join(', ');
    if ($('project-tech')) $('project-tech').textContent = techStack || 'Python, FastAPI, SQLite';
    if ($('project-last-scan')) $('project-last-scan').textContent = 'Cached (Offline)';
    if ($('project-total-scans')) $('project-total-scans').textContent = '1';
}

function clearDashboard() {
    const values = {
        'score-security': '--', 'score-privacy': '--', 'score-production': '--', 'score-reliability': '--',
        'count-critical': '0', 'count-high': '0', 'count-medium': '0', 'count-low': '0', 'count-info': '0',
        'runtime-sentinel': 'Not Enabled', 'runtime-events': '0', 'runtime-blocked': '0', 'runtime-suspicious': '0',
        'project-name': '--', 'project-tech': '--', 'project-last-scan': 'Never', 'project-total-scans': '0'
    };
    Object.entries(values).forEach(([id, value]) => { if ($(id)) $(id).textContent = value; });
}

// Projects
async function loadProjects() {
    const container = $('projects-list');
    container.innerHTML = '<div class="loading"><div class="spinner"></div>Loading projects...</div>';

    if (!isBackendOnline) {
        renderProjectsList(OFFLINE_PROJECTS);
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/projects`);
        if (!response.ok) throw new Error('API offline');
        const projects = await response.json();

        if (projects.length === 0) {
            container.innerHTML = '<div class="empty-state">No projects yet. Upload your first project below.</div>';
            return;
        }

        renderProjectsList(projects);
    } catch (error) {
        console.warn('Backend offline, rendering offline projects:', error);
        renderProjectsList(OFFLINE_PROJECTS);
    }
}

function renderProjectsList(projects) {
    const container = $('projects-list');
    container.innerHTML = projects.map(p => `
        <div class="project-item" onclick="selectProject('${p.id}')">
            <div class="project-info">
                <div class="project-name">${escapeHtml(p.name)}</div>
                <div class="project-meta">${new Date(p.created_at).toLocaleString()}</div>
                ${renderTechBadges(p.project_context)}
            </div>
            <div class="project-actions">
                <button class="btn btn-sm btn-primary" onclick="startScan('${p.id}'); event.stopPropagation()">Scan Now</button>
            </div>
        </div>
    `).join('');
}

function renderTechBadges(context) {
    const safeContext = context || {};
    const techs = [
        ...(safeContext.languages || []),
        ...(safeContext.frameworks || []),
        ...(safeContext.databases || []),
        ...(safeContext.deployment || [])
    ];
    if (techs.length === 0) return '<div class="project-tech"><span class="tech-badge">New</span></div>';
    return `<div class="project-tech">${techs.slice(0, 5).map(t => `<span class="tech-badge">${escapeHtml(t)}</span>`).join('')}${techs.length > 5 ? `<span class="tech-badge">+${techs.length - 5}</span>` : ''}</div>`;
}

// Upload
function setupUpload() {
    const uploadArea = $('upload-area');
    const fileInput = $('zip-upload');

    if (!uploadArea || !fileInput) return;

    uploadArea.addEventListener('click', () => fileInput.click());

    uploadArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadArea.classList.add('drag-over');
    });

    uploadArea.addEventListener('dragleave', () => {
        uploadArea.classList.remove('drag-over');
    });

    uploadArea.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadArea.classList.remove('drag-over');
        if (e.dataTransfer.files.length > 0) {
            handleFileUpload(e.dataTransfer.files[0]);
        }
    });

    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleFileUpload(e.target.files[0]);
        }
    });
}

async function handleFileUpload(file) {
    if (!file.name.endsWith('.zip')) {
        alert('Please upload a ZIP file.');
        return;
    }

    const formData = new FormData();
    formData.append('file', file);

    const projectName = file.name.replace('.zip', '');
    showSection('scan');
    updateScanProgress('Creating project...', 0);

    try {
        const createResp = await fetch(`${API_BASE}/projects`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: projectName })
        });
        const project = await createResp.json();
        currentProjectId = project.id;

        updateScanProgress('Uploading project...', 10);

        const uploadResp = await fetch(`${API_BASE}/projects/${project.id}/upload`, {
            method: 'POST',
            body: formData
        });

        if (!uploadResp.ok) {
            const error = await uploadResp.json();
            throw new Error(error.detail || 'Upload failed');
        }

        const uploadResult = await uploadResp.json();
        currentProjectId = uploadResult.project_id;

        updateScanProgress('Project uploaded! Starting scan...', 15);
        await startScan(currentProjectId);

    } catch (error) {
        console.error('Upload error:', error);
        updateScanProgress(`Error: ${error.message}`, 'failed');
    }
}

// Scan
function resetScanUI(message = 'Initializing...') {
    clearInterval(scanInterval);
    currentScanId = null;

    const badge = $('scan-status-badge');
    if (badge) {
        badge.textContent = 'Queued';
        badge.className = 'scan-status-badge queued';
    }

    const progressFill = $('progress-fill');
    if (progressFill) {
        progressFill.style.width = '0%';
    }

    const progressMessage = $('progress-message');
    if (progressMessage) {
        progressMessage.textContent = message;
    }

    const steps = document.querySelectorAll('.step');
    steps.forEach(step => step.classList.remove('active', 'completed'));
}

async function startScan(projectId) {
    clearInterval(scanInterval);
    currentProjectId = projectId;
    resetScanUI('Scan queued...');

    if (!isBackendOnline) {
        showSection('scan');
        simulateOfflineScan(projectId);
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/scans`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ project_id: projectId })
        });

        if (!response.ok) {
            const errorBody = await response.json().catch(() => ({}));
            throw new Error(errorBody.detail || 'Scan start failed');
        }

        const scan = await response.json();
        currentScanId = scan.id;
        currentScanProjectId = projectId;

        showSection('scan');
        const badge = $('scan-status-badge');
        if (badge) {
            badge.textContent = 'Queued';
            badge.className = 'scan-status-badge queued';
        }
        const progressMessage = $('progress-message');
        if (progressMessage) {
            progressMessage.textContent = 'Scan queued...';
        }

        clearInterval(scanInterval);
        scanInterval = setInterval(() => pollScanStatus(), 1500);

    } catch (error) {
        console.warn('Backend scan failed, running offline scan simulation:', error);
        simulateOfflineScan(projectId);
    }
}

function simulateOfflineScan(projectId) {
    resetScanUI('Initializing offline security audit...');
    let step = 1;
    let progress = 10;
    const badge = $('scan-status-badge');
    if (badge) {
        badge.textContent = 'Running';
        badge.className = 'scan-status-badge running';
    }

    const interval = setInterval(() => {
        step++;
        progress += 10;
        if (progress > 100) progress = 100;
        if ($('progress-fill')) $('progress-fill').style.width = `${progress}%`;
        if ($('progress-message')) $('progress-message').textContent = `Running step ${Math.min(step, 10)} of 10 in offline mode...`;
        updateScanSteps(progress);

        if (step >= 10) {
            clearInterval(interval);
            if ($('progress-message')) $('progress-message').textContent = 'Scan complete! Generated offline vulnerability assessment.';
            if (badge) {
                badge.textContent = 'Completed';
                badge.className = 'scan-status-badge completed';
            }
            setTimeout(() => {
                showSection('findings');
                loadFindings();
            }, 800);
        }
    }, 320);
}

async function pollScanStatus() {
    if (!currentScanId) return;
    const polledScanId = currentScanId;
    const polledProjectId = currentScanProjectId;

    try {
        const response = await fetch(`${API_BASE}/scans/${polledScanId}/status`);
        const status = await response.json();
        if (polledScanId !== currentScanId || polledProjectId !== currentProjectId) return;

        $('scan-status-badge').textContent = status.status.charAt(0).toUpperCase() + status.status.slice(1);
        $('scan-status-badge').className = `scan-status-badge ${status.status}`;

        if (status.progress !== undefined) {
            $('progress-fill').style.width = `${status.progress}%`;
        }

        if (status.message) {
            $('progress-message').textContent = status.message;
        }

        updateScanSteps(status.progress);

        if (status.status === 'completed' || status.status === 'failed' || status.status === 'partial') {
            clearInterval(scanInterval);
            if (status.status === 'completed' || status.status === 'partial') {
                $('scan-status-badge').textContent = 'Completed';
                $('scan-status-badge').className = 'scan-status-badge completed';
                setTimeout(() => {
                    if (polledScanId !== currentScanId || polledProjectId !== currentProjectId) return;
                    showSection('findings');
                    loadFindings();
                }, 500);
            } else {
                updateScanProgress(status.error || 'Scan failed', 'failed');
                currentScanId = null;
            }
        }
    } catch (error) {
        console.error('Status poll error:', error);
    }
}

function updateScanProgress(message, progress) {
    const progressMessage = $('progress-message');
    if (progressMessage) {
        progressMessage.textContent = message;
    }

    const progressFill = $('progress-fill');
    if (progressFill && typeof progress === 'number') {
        progressFill.style.width = `${Math.max(0, Math.min(progress, 100))}%`;
    }

    const badge = $('scan-status-badge');
    if (badge) {
        if (progress === 'failed') {
            badge.textContent = 'Failed';
            badge.className = 'scan-status-badge failed';
        } else if (progress === 'running') {
            badge.textContent = 'Running';
            badge.className = 'scan-status-badge running';
        }
    }
}

function updateScanSteps(progress) {
    const steps = document.querySelectorAll('.step');
    const safeProgress = Number.isFinite(progress) ? Math.max(0, Math.min(progress, 100)) : 0;

    steps.forEach((step, index) => {
        step.classList.remove('active', 'completed');
        const stepProgress = ((index + 1) / 10) * 100;
        if (safeProgress >= stepProgress) {
            step.classList.add('completed');
        } else if (safeProgress > 0) {
            step.classList.add('active');
        }
    });
}

// Findings
async function loadFindings() {
    const category = $('filter-category') ? $('filter-category').value : 'all';
    const severity = $('filter-severity') ? $('filter-severity').value : 'all';

    if (!isBackendOnline) {
        let findings = [...OFFLINE_FINDINGS];
        if (category !== 'all') findings = findings.filter(f => f.category === category);
        if (severity !== 'all') findings = findings.filter(f => f.severity === severity);
        renderFindings(findings);
        return;
    }

    if (!currentProjectId) {
        let findings = [...OFFLINE_FINDINGS];
        if (category !== 'all') findings = findings.filter(f => f.category === category);
        if (severity !== 'all') findings = findings.filter(f => f.severity === severity);
        renderFindings(findings);
        return;
    }

    const requestedProjectId = currentProjectId;
    if (!currentScanId || currentScanProjectId !== requestedProjectId) {
        try {
            const response = await fetch(`${API_BASE}/projects/${requestedProjectId}/dashboard`);
            const data = await response.json();
            if (requestedProjectId !== currentProjectId) return;
            if (data.latest_scan) {
                currentScanId = data.latest_scan.id;
                currentScanProjectId = requestedProjectId;
            } else {
                let findings = [...OFFLINE_FINDINGS];
                if (category !== 'all') findings = findings.filter(f => f.category === category);
                if (severity !== 'all') findings = findings.filter(f => f.severity === severity);
                renderFindings(findings);
                return;
            }
        } catch (e) {
            let findings = [...OFFLINE_FINDINGS];
            if (category !== 'all') findings = findings.filter(f => f.category === category);
            if (severity !== 'all') findings = findings.filter(f => f.severity === severity);
            renderFindings(findings);
            return;
        }
    }

    const requestedScanId = currentScanId;

    try {
        const response = await fetch(`${API_BASE}/reports/scan/${requestedScanId}`);
        const report = await response.json();
        if (requestedProjectId !== currentProjectId || requestedScanId !== currentScanId) return;

        let findings = report.findings || [];

        // Apply filters
        if (category !== 'all') {
            findings = findings.filter(f => f.category === category);
        }
        if (severity !== 'all') {
            findings = findings.filter(f => f.severity === severity);
        }

        renderFindings(findings);

    } catch (error) {
        console.warn('Failed to load live findings, falling back to offline findings:', error);
        let findings = [...OFFLINE_FINDINGS];
        if (category !== 'all') findings = findings.filter(f => f.category === category);
        if (severity !== 'all') findings = findings.filter(f => f.severity === severity);
        renderFindings(findings);
    }
}

function renderFindings(findings) {
    const container = $('findings-list');

    if (findings.length === 0) {
        container.innerHTML = '<div class="empty-state">No findings! Your project looks ready to ship.</div>';
        return;
    }

    // Group by category
    const byCategory = {};
    findings.forEach(f => {
        if (!byCategory[f.category]) byCategory[f.category] = [];
        byCategory[f.category].push(f);
    });

    let html = '';
    Object.keys(byCategory).forEach(category => {
        const catFindings = byCategory[category];
        html += `<div class="category-section" style="margin-bottom: 2rem;">`;
        html += `<h3 style="text-transform: capitalize; margin-bottom: 1rem; color: var(--text-primary);">${category}</h3>`;
        html += catFindings.map(f => `
            <div class="finding-card">
                <div class="finding-header">
                    <div class="finding-title">${escapeHtml(f.title)}</div>
                    <div class="finding-badges">
                        <span class="badge ${f.severity}">${f.severity}</span>
                        <span class="badge category">${f.category}</span>
                    </div>
                </div>
                ${f.description ? `<div class="finding-description">${escapeHtml(f.description)}</div>` : ''}
                ${f.evidence ? `<div class="finding-evidence">${escapeHtml(f.evidence)}</div>` : ''}
                <div class="finding-meta">
                    ${f.file_path ? `<span><span style="color: var(--info);">📁</span> ${escapeHtml(f.file_path)}</span>` : ''}
                    ${f.line_number ? `<span><span style="color: var(--info);">📍</span> Line ${f.line_number}</span>` : ''}
                    ${f.confidence ? `<span><span style="color: var(--info);">🎯</span> Confidence: ${escapeHtml(f.confidence)}</span>` : ''}
                    ${f.detection_source ? `<span><span style="color: var(--info);">🔍</span> Source: ${escapeHtml(f.detection_source)}</span>` : ''}
                    ${f.first_detected_scan && f.last_detected_scan !== f.first_detected_scan ? `<span style="color: var(--success);">✓ Recurring</span>` : ''}
                </div>
                ${f.recommendation ? `<div class="finding-recommendation"><strong>Recommendation:</strong><p>${escapeHtml(f.recommendation)}</p></div>` : ''}
                ${f.ai_explanation ? `<div class="finding-ai"><strong>AI Explanation:</strong><p>${escapeHtml(f.ai_explanation)}</p></div>` : ''}
                ${f.suggested_fix ? `<div class="finding-fix"><strong>Suggested Fix:</strong><pre>${escapeHtml(f.suggested_fix)}</pre></div>` : ''}
                <div class="finding-actions">
                    <button class="btn btn-sm btn-secondary" onclick="openFile('${f.file_path}', ${f.line_number})">Open File</button>
                    <button class="btn btn-sm btn-primary" onclick="generateGemmaFix('${f.id}')" style="background:#89b4fa; color:#11111b;">🤖 Propose Patch</button>
                    <button class="btn btn-sm btn-secondary" onclick="acknowledgeFinding('${f.id}')">Acknowledge</button>
                    <button class="btn btn-sm btn-secondary" onclick="markFixed('${f.id}')">Mark Fixed</button>
                    <button class="btn btn-sm btn-secondary" onclick="ignoreFinding('${f.id}')">Ignore</button>
                </div>
            </div>
        `).join('');
        html += '</div>';
    });

    container.innerHTML = html;
}

function setupFilters() {
    const categoryFilter = $('filter-category');
    const severityFilter = $('filter-severity');

    if (categoryFilter) {
        categoryFilter.addEventListener('change', loadFindings);
    }
    if (severityFilter) {
        severityFilter.addEventListener('change', loadFindings);
    }
}

// Code Editor
async function loadFileBrowser() {
    if (!isBackendOnline) {
        renderOfflineFileBrowser();
        return;
    }

    if (!currentProjectId) {
        renderOfflineFileBrowser();
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/projects/${currentProjectId}/files`);
        if (!response.ok) throw new Error('API offline');
        const data = await response.json();

        let html = '<div class="file-tree">';
        html += '<div class="file-item directory" onclick="toggleDirectory(this)">📁 .</div>';

        data.directories.forEach(dir => {
            html += `<div class="file-item directory" onclick="loadDirectory('${dir.path}')">📁 ${escapeHtml(dir.name)}</div>`;
        });

        data.files.forEach(file => {
            html += `<div class="file-item file" onclick="openFile('${file.path}')">📄 ${escapeHtml(file.name)}</div>`;
        });

        html += '</div>';
        $('file-browser').innerHTML = html;

    } catch (e) {
        console.warn('Failed to load files from backend, using offline files:', e);
        renderOfflineFileBrowser();
    }
}

function renderOfflineFileBrowser() {
    let html = '<div class="file-tree">';
    html += '<div class="file-item directory">📁 sample_vulnerable_app (offline)</div>';
    Object.keys(OFFLINE_FILES).forEach(filePath => {
        html += `<div class="file-item file" onclick="openFile('${filePath}')">📄 ${escapeHtml(filePath)}</div>`;
    });
    html += '</div>';
    $('file-browser').innerHTML = html;
}

async function loadDirectory(path) {
    if (!isBackendOnline) return;
    try {
        const response = await fetch(`${API_BASE}/projects/${currentProjectId}/files?path=${encodeURIComponent(path)}`);
        const data = await response.json();

        let html = '<div class="file-tree">';
        html += `<div class="file-item directory" onclick="loadDirectory('${path.split('/').slice(0, -1).join('/')}')">📁 ..</div>`;

        data.directories.forEach(dir => {
            html += `<div class="file-item directory" onclick="loadDirectory('${dir.path}')">📁 ${escapeHtml(dir.name)}</div>`;
        });

        data.files.forEach(file => {
            html += `<div class="file-item file" onclick="openFile('${file.path}')">📄 ${escapeHtml(file.name)}</div>`;
        });

        html += '</div>';
        $('file-browser').innerHTML = html;

    } catch (e) {
        console.error('Failed to load directory:', e);
    }
}

async function openFile(filePath, lineNumber) {
    if (!isBackendOnline || OFFLINE_FILES[filePath]) {
        const content = OFFLINE_FILES[filePath] || `# ${filePath}\n# Loaded in offline workspace\n`;
        $('editor-file-path').textContent = filePath + ' (Offline)';
        $('code-editor').value = content;
        $('code-editor').disabled = false;
        $('editor-save-btn').disabled = false;
        $('code-editor').dataset.filePath = filePath;
        showSection('editor');
        return;
    }

    if (!currentProjectId) {
        showSection('editor');
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/projects/${currentProjectId}/files/${encodeURIComponent(filePath)}`);
        const data = await response.json();

        $('editor-file-path').textContent = filePath;
        $('code-editor').value = data.content;
        $('code-editor').disabled = false;
        $('editor-save-btn').disabled = false;

        // Highlight line if specified
        if (lineNumber) {
            const lines = data.content.split('\n');
            const start = Math.max(0, lineNumber - 5);
            const end = Math.min(lines.length, lineNumber + 5);
            const highlighted = lines.slice(start, end).map((line, i) => {
                const lineNum = start + i + 1;
                return lineNum === lineNumber ? `> ${line}` : `  ${line}`;
            }).join('\n');
            $('code-editor').value = highlighted;
        }

        // Store current file path for save
        $('code-editor').dataset.filePath = filePath;
        showSection('editor');

    } catch (e) {
        console.warn('Failed to open file online, attempting offline fallback:', e);
        const content = OFFLINE_FILES[filePath] || `# ${filePath}\n# File loaded in offline mode`;
        $('editor-file-path').textContent = filePath + ' (Offline)';
        $('code-editor').value = content;
        $('code-editor').disabled = false;
        $('editor-save-btn').disabled = false;
        $('code-editor').dataset.filePath = filePath;
        showSection('editor');
    }
}

function setupEditor() {
    const saveBtn = $('editor-save-btn');
    const codeEditor = $('code-editor');

    if (saveBtn) {
        saveBtn.addEventListener('click', saveFile);
    }

    if (codeEditor) {
        // Ctrl+S to save
        codeEditor.addEventListener('keydown', (e) => {
            if ((e.ctrlKey || e.metaKey) && e.key === 's') {
                e.preventDefault();
                saveFile();
            }
        });
    }
}

async function saveFile() {
    const filePath = $('code-editor').dataset.filePath;
    const content = $('code-editor').value;

    if (!filePath || !currentProjectId) return;

    try {
        const response = await fetch(`${API_BASE}/projects/${currentProjectId}/files/${encodeURIComponent(filePath)}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ content })
        });

        if (response.ok) {
            alert('File saved successfully');
        } else {
            const error = await response.json();
            alert('Failed to save file: ' + (error.detail || 'Unknown error'));
        }
    } catch (e) {
        console.error('Failed to save file:', e);
        alert('Failed to save file: ' + e.message);
    }
}

// Sandbox
async function loadSandboxStatus() {
    // Load sandbox status if available
    $('sandbox-status-value').textContent = 'Idle';
    $('sandbox-method').textContent = '--';
    $('sandbox-checks').textContent = '0';
    $('sandbox-results').innerHTML = '';
}

function setupSandbox() {
    const executeBtn = $('sandbox-execute-btn');
    const stopBtn = $('sandbox-stop-btn');

    if (executeBtn) {
        executeBtn.addEventListener('click', executeSandbox);
    }
    if (stopBtn) {
        stopBtn.addEventListener('click', stopSandbox);
    }
}

async function executeSandbox() {
    if (!currentProjectId) {
        alert('No project selected');
        return;
    }

    $('sandbox-status-value').textContent = 'Running...';
    $('sandbox-execute-btn').disabled = true;
    $('sandbox-stop-btn').disabled = false;

    try {
        const response = await fetch(`${API_BASE}/sandbox/${currentProjectId}/execute`, {
            method: 'POST'
        });
        const result = await response.json();

        // Poll for completion
        const executionId = result.execution_id;
        const pollInterval = setInterval(async () => {
            try {
                const statusResp = await fetch(`${API_BASE}/sandbox/${executionId}/status`);
                const status = await statusResp.json();

                if (status.status === 'completed' || status.status === 'failed' || status.status === 'stopped') {
                    clearInterval(pollInterval);
                    $('sandbox-status-value').textContent = status.status;
                    $('sandbox-method').textContent = status.result?.method || '--';
                    $('sandbox-checks').textContent = status.result?.checks?.length || 0;

                    // Display results
                    let resultsHtml = '<div class="sandbox-results-list">';
                    (status.result?.checks || []).forEach(check => {
                        const statusClass = check.status === 'passed' ? 'success' :
                                          check.status === 'warning' ? 'warning' :
                                          check.status === 'failed' ? 'danger' : 'info';
                        resultsHtml += `<div class="sandbox-check ${statusClass}">
                            <span class="check-name">${escapeHtml(check.check)}</span>
                            <span class="check-status">${check.status}</span>
                            ${check.detail ? `<span class="check-detail">${escapeHtml(check.detail)}</span>` : ''}
                            ${check.reason ? `<span class="check-detail">${escapeHtml(check.reason)}</span>` : ''}
                        </div>`;
                    });
                    resultsHtml += '</div>';
                    $('sandbox-results').innerHTML = resultsHtml;

                    $('sandbox-execute-btn').disabled = false;
                    $('sandbox-stop-btn').disabled = true;
                }
            } catch (e) {
                console.error('Sandbox status poll error:', e);
            }
        }, 2000);

    } catch (e) {
        console.error('Sandbox execution error:', e);
        $('sandbox-status-value').textContent = 'Failed';
        $('sandbox-execute-btn').disabled = false;
        $('sandbox-stop-btn').disabled = true;
    }
}

async function stopSandbox() {
    // Stop is handled by clearing the execution
    $('sandbox-status-value').textContent = 'Stopped';
    $('sandbox-execute-btn').disabled = false;
    $('sandbox-stop-btn').disabled = true;
}

// Runtime Monitoring
function startRuntimeAutoRefresh() {
    if (runtimeRefreshInterval) clearInterval(runtimeRefreshInterval);
    runtimeRefreshInterval = setInterval(() => {
        if (currentSection === 'runtime' && currentProjectId) {
            loadRuntimeDashboard();
        }
    }, 3000);
}

function setupRuntimeScan() {
    const button = $('runtime-scan-btn');
    if (button) button.addEventListener('click', scanLocalRuntime);
    const connectButton = $('runtime-connect-btn');
    if (connectButton) connectButton.addEventListener('click', connectRuntimeProxy);
}

async function connectRuntimeProxy() {
    if (!currentProjectId) { showSection('projects'); return; }
    const input = $('runtime-url-input');
    const resultBox = $('runtime-proxy-result');
    const button = $('runtime-connect-btn');
    button.disabled = true;
    resultBox.textContent = 'Discovering your API endpoints…';
    try {
        const response = await fetch(`${API_BASE}/proxy/${currentProjectId}/connect`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: input.value.trim() })
        });
        const result = await response.json();
        if (!response.ok) throw new Error(result.detail || 'Could not create proxy');
        const proxyUrl = result.proxy_base_url;
        const publicUrl = result.public_url;
        const count = result.endpoints.reduce((total, endpoint) => total + endpoint.methods.length, 0);

        let urlCardsHtml = `
            <div style="display: flex; align-items: center; gap: 0.5rem; margin: 0.4rem 0;">
                <span style="font-weight: 600; min-width: 125px; font-size: 0.85rem; color: var(--text-secondary);">Local Proxy:</span>
                <code id="proxy-url-display" style="flex: 1; word-break: break-all;">${escapeHtml(proxyUrl)}</code>
                <button class="btn btn-sm btn-secondary" id="copy-proxy-url-btn" onclick="copyProxyUrl('${escapeHtml(proxyUrl)}', 'copy-proxy-url-btn')">📋 Copy Local URL</button>
            </div>`;

        if (publicUrl) {
            urlCardsHtml += `
            <div style="display: flex; align-items: center; gap: 0.5rem; margin: 0.4rem 0;">
                <span style="font-weight: 600; min-width: 125px; font-size: 0.85rem; color: #38bdf8;">Cloudflare Public:</span>
                <code id="public-url-display" style="flex: 1; word-break: break-all; color: #38bdf8; background: rgba(56, 189, 248, 0.08); padding: 4px 8px; border-radius: 4px; border: 1px solid rgba(56, 189, 248, 0.2);">${escapeHtml(publicUrl)}</code>
                <button class="btn btn-sm btn-primary" id="copy-public-url-btn" onclick="copyProxyUrl('${escapeHtml(publicUrl)}', 'copy-public-url-btn')">🌐 Copy Public URL</button>
            </div>`;
        }

        resultBox.innerHTML = `<strong>Protected proxy ready</strong>
            ${urlCardsHtml}
            <span style="display: block; margin-top: 0.5rem;">${escapeHtml(result.title)}: ${count} operation(s) discovered. Rate limit: ${result.rate_limit.requests} requests / ${result.rate_limit.window_seconds} seconds per client. Add a private client token header in your frontend for better DDoS visibility.</span>
            <pre class="proxy-snippet">const id = localStorage.shipcheckClient || (localStorage.shipcheckClient = crypto.randomUUID());
fetch('${publicUrl ? escapeHtml(publicUrl) : escapeHtml(proxyUrl)}/your-route', { headers: { 'X-Shipcheck-Client': id } });</pre>`;
    } catch (error) {
        resultBox.textContent = error.message;
    } finally { button.disabled = false; }
}

function copyProxyUrl(url, elementId = 'copy-proxy-url-btn') {
    const showSuccess = () => {
        const btn = document.getElementById(elementId);
        if (btn) {
            const orig = btn.textContent;
            btn.textContent = '✓ Copied!';
            setTimeout(() => { btn.textContent = orig; }, 2000);
        }
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(url).then(showSuccess).catch(() => {
            try {
                const tempInput = document.createElement('textarea');
                tempInput.value = url;
                document.body.appendChild(tempInput);
                tempInput.select();
                document.execCommand('copy');
                document.body.removeChild(tempInput);
                showSuccess();
            } catch (e) {
                prompt('Copy URL manually:', url);
            }
        });
    } else {
        try {
            const tempInput = document.createElement('textarea');
            tempInput.value = url;
            document.body.appendChild(tempInput);
            tempInput.select();
            document.execCommand('copy');
            document.body.removeChild(tempInput);
            showSuccess();
        } catch (e) {
            prompt('Copy URL manually:', url);
        }
    }
}

function setupDataClear() {
    const button = $('clear-data-btn');
    if (button) button.addEventListener('click', clearAllShipcheckData);
}

async function clearAllShipcheckData() {
    if (!confirm('Delete every Shipcheck project, scan, finding, runtime log, and uploaded file? This cannot be undone.')) return;
    try {
        const response = await fetch(`${API_BASE}/projects`, { method: 'DELETE' });
        const result = await response.json();
        if (!response.ok) throw new Error(result.detail || 'Could not clear data');
        currentProjectId = null; currentScanId = null; currentScanProjectId = null;
        clearDashboard();
        loadProjects();
        alert('All Shipcheck project data was cleared.');
    } catch (error) { alert(error.message); }
}

async function scanLocalRuntime() {
    if (!currentProjectId) {
        showSection('projects');
        return;
    }

    const input = $('runtime-url-input');
    const message = $('runtime-scan-message');
    const button = $('runtime-scan-btn');
    const url = input.value.trim();
    if (!url) return;

    button.disabled = true;
    message.textContent = 'Scanning your local application…';
    try {
        const response = await fetch(`${API_BASE}/runtime/${currentProjectId}/scan-local`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        const result = await response.json();
        if (!response.ok) throw new Error(result.detail || 'Runtime scan failed');

        const issues = [
            result.missing_headers.length ? `missing ${result.missing_headers.length} security header(s)` : 'security headers checked',
            result.not_found_status === 404 ? '404 behavior passed' : `unexpected 404 probe status (${result.not_found_status})`,
            result.exposed_endpoints.length ? `exposed routes: ${result.exposed_endpoints.join(', ')}` : 'no common sensitive routes exposed'
        ];
        message.textContent = `Local scan complete: ${issues.join(' · ')}`;
        loadRuntimeDashboard();
    } catch (error) {
        message.textContent = error.message;
    } finally {
        button.disabled = false;
    }
}

async function loadRuntimeDashboard() {
    if (!isBackendOnline) {
        renderOfflineRuntime();
        return;
    }

    if (!currentProjectId) {
        renderOfflineRuntime();
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/runtime/${currentProjectId}/dashboard`);
        if (!response.ok) throw new Error('API offline');
        const data = await response.json();

        // Update stats
        const stats = data.statistics;
        $('runtime-total-events').textContent = stats.total_events || 0;
        $('runtime-blocked-events').textContent = data.status.blocked_count || 0;
        $('runtime-suspicious-events').textContent = data.status.suspicious_count || 0;

        // Count by event type
        const byType = stats.by_type || [];
        const sqlInjection = byType.find(t => t.event_type === 'DB_QUERY')?.count || 0;
        const xss = byType.find(t => t.event_type === 'HTML_RENDER')?.count || 0;
        const rateAbuse = byType.find(t => t.event_type === 'RATE_ANOMALY')?.count || 0;

        $('runtime-sql-injection').textContent = sqlInjection;
        $('runtime-xss').textContent = xss;
        $('runtime-rate-abuse').textContent = rateAbuse;

        // Render events
        const events = data.recent_events || [];
        if (events.length === 0) {
            $('runtime-events-list').innerHTML = '<div class="empty-state">No runtime events yet</div>';
        } else {
            let html = '<div class="events-list">';
            events.forEach(event => {
                const actionClass = event.action === 'BLOCKED' ? 'danger' :
                                  event.action === 'SUSPICIOUS' ? 'warning' : 'info';
                html += `<div class="event-item ${actionClass}">
                    <div class="event-header">
                        <span class="event-type">${escapeHtml(event.event_type)}</span>
                        <span class="event-action">${escapeHtml(event.action)}</span>
                        <span class="event-time">${new Date(event.timestamp).toLocaleString()}</span>
                    </div>
                    ${event.endpoint ? `<div class="event-endpoint">Endpoint: ${escapeHtml(event.endpoint)}</div>` : ''}
                    ${event.evidence ? `<div class="event-evidence">${escapeHtml(event.evidence)}</div>` : ''}
                    <div class="event-meta">
                        <span>Confidence: ${escapeHtml(event.confidence)}</span>
                        ${event.request_id ? `<span>Request: ${escapeHtml(event.request_id)}</span>` : ''}
                    </div>
                </div>`;
            });
            html += '</div>';
            $('runtime-events-list').innerHTML = html;
        }

    } catch (e) {
        console.warn('Failed to load runtime data online, rendering offline telemetry:', e);
        renderOfflineRuntime();
    }
}

function renderOfflineRuntime() {
    if ($('runtime-total-events')) $('runtime-total-events').textContent = 38;
    if ($('runtime-blocked-events')) $('runtime-blocked-events').textContent = 5;
    if ($('runtime-suspicious-events')) $('runtime-suspicious-events').textContent = 8;
    if ($('runtime-sql-injection')) $('runtime-sql-injection').textContent = 14;
    if ($('runtime-xss')) $('runtime-xss').textContent = 9;
    if ($('runtime-rate-abuse')) $('runtime-rate-abuse').textContent = 15;

    let html = '<div class="events-list">';
    OFFLINE_RUNTIME_EVENTS.forEach(event => {
        const actionClass = event.action === 'BLOCKED' ? 'danger' :
                          event.action === 'THROTTLED' ? 'warning' : 'info';
        html += `<div class="event-item ${actionClass}">
            <div class="event-header">
                <span class="event-type">${escapeHtml(event.event_type)}</span>
                <span class="event-action">${escapeHtml(event.action)}</span>
                <span class="event-time">${event.timestamp}</span>
            </div>
            ${event.endpoint ? `<div class="event-endpoint">Endpoint: ${escapeHtml(event.endpoint)}</div>` : ''}
            ${event.evidence ? `<div class="event-evidence">${escapeHtml(event.evidence)}</div>` : ''}
            <div class="event-meta">
                <span>Confidence: ${escapeHtml(event.confidence)}</span>
                <span style="color: var(--warning);">⚡ Simulated Offline Telemetry</span>
            </div>
        </div>`;
    });
    html += '</div>';
    if ($('runtime-events-list')) $('runtime-events-list').innerHTML = html;
}

// Sentinel
async function loadSentinelStatus() {
    if (!currentProjectId) {
        $('sentinel-status-value').textContent = 'No project selected';
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/sentinel/${currentProjectId}/status`);
        const data = await response.json();

        $('sentinel-status-value').textContent = data.enabled ? 'Enabled' : 'Not Integrated';
        const policy = data.integration?.policy_name || 'Runtime proxy';
        const engine = data.native_engine?.available ? 'C++ engine active' : 'Python fallback';
        $('sentinel-framework').textContent = policy + ' · ' + engine;

        // Load protections
        const protectionsResp = await fetch(`${API_BASE}/sentinel/${currentProjectId}/protections`);
        const protectionsData = await protectionsResp.json();

        let html = '<div class="protections-grid">';
        (protectionsData.protections || []).forEach(protection => {
            html += `<div class="protection-item">
                <div class="protection-name">${escapeHtml(protection.name)}</div>
                <div class="protection-description">${escapeHtml(protection.description)}</div>
                <div class="protection-status ${protection.enabled ? 'enabled' : 'disabled'}">
                    ${protection.enabled ? '✓ Enabled' : '○ Available'}
                </div>
            </div>`;
        });
        html += '</div>';
        $('protections-list').innerHTML = html;

    } catch (e) {
        console.error('Failed to load Sentinel status:', e);
    }
}

function setupSentinel() {
    const previewBtn = $('sentinel-preview-btn');
    const enableBtn = $('sentinel-enable-btn');
    const confirmBtn = $('sentinel-confirm-btn');
    const cancelBtn = $('sentinel-cancel-btn');

    if (previewBtn) {
        previewBtn.addEventListener('click', previewSentinelIntegration);
    }
    if (enableBtn) {
        enableBtn.addEventListener('click', enableSentinel);
    }
    if (confirmBtn) {
        confirmBtn.addEventListener('click', enableSentinel);
    }
    if (cancelBtn) {
        cancelBtn.addEventListener('click', () => {
            $('sentinel-preview').style.display = 'none';
        });
    }
}

async function previewSentinelIntegration() {
    if (!currentProjectId) {
        alert('No project selected');
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/sentinel/${currentProjectId}/preview`);
        const data = await response.json();

        let html = '<div class="preview-details">';
        html += `<div class="preview-item"><strong>Framework:</strong> ${escapeHtml(data.framework)}</div>`;
        html += `<div class="preview-item"><strong>Estimated Latency:</strong> ${escapeHtml(data.estimated_latency)}</div>`;
        html += '<div class="preview-item"><strong>Protection Features:</strong><ul>';
        data.protection_features.forEach(feature => {
            html += `<li>${escapeHtml(feature)}</li>`;
        });
        html += '</ul></div>';
        html += '<div class="preview-item"><strong>Files to be modified:</strong><ul>';
        data.files_modified.forEach(file => {
            html += `<li>${escapeHtml(file)}</li>`;
        });
        html += '</ul></div>';
        html += '<div class="preview-item"><strong>Dependencies to add:</strong><ul>';
        data.dependencies.forEach(dep => {
            html += `<li>${escapeHtml(dep)}</li>`;
        });
        html += '</ul></div>';
        html += '</div>';

        $('sentinel-preview-content').innerHTML = html;
        $('sentinel-preview').style.display = 'block';

    } catch (e) {
        console.error('Failed to preview Sentinel integration:', e);
        alert('Failed to preview integration: ' + e.message);
    }
}

async function enableSentinel() {
    if (!currentProjectId) {
        alert('No project selected');
        return;
    }

    if (!confirm('Enable Sentinel RASP protection? This will modify your project files and dependencies.')) {
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/sentinel/${currentProjectId}/enable`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ approved: true })
        });

        if (response.ok) {
            const data = await response.json();
            alert('Sentinel RASP integrated successfully!\n\nFiles modified: ' + data.applied_files.join(', '));
            loadSentinelStatus();
            checkSentinelStatus();
        } else {
            const error = await response.json();
            alert('Failed to enable Sentinel: ' + (error.detail || 'Unknown error'));
        }
    } catch (e) {
        console.error('Failed to enable Sentinel:', e);
        alert('Failed to enable Sentinel: ' + e.message);
    }
}

// Reports
async function loadReportPreview() {
    if (!currentProjectId) {
        $('report-preview-content').innerHTML = '<div class="empty-state">No project selected</div>';
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/reports/project/${currentProjectId}/full`);
        const data = await response.json();

        let html = '<div class="report-summary">';
        html += `<div class="report-item"><strong>Project:</strong> ${escapeHtml(data.project.name)}</div>`;
        html += `<div class="report-item"><strong>Total Findings:</strong> ${data.total_findings}</div>`;
        html += `<div class="report-item"><strong>Security Score:</strong> ${data.project.security_score || 'N/A'}</div>`;
        html += `<div class="report-item"><strong>Privacy Score:</strong> ${data.project.privacy_score || 'N/A'}</div>`;
        html += `<div class="report-item"><strong>Production Readiness:</strong> ${data.project.production_readiness_score || 'N/A'}</div>`;
        html += `<div class="report-item"><strong>Reliability Score:</strong> ${data.project.reliability_score || 'N/A'}</div>`;
        html += `<div class="report-item"><strong>Sentinel Enabled:</strong> ${data.project.sentinel_enabled ? 'Yes' : 'No'}</div>`;
        html += '</div>';

        $('report-preview-content').innerHTML = html;

    } catch (e) {
        console.error('Failed to load report preview:', e);
    }
}

function setupReports() {
    const jsonBtn = $('report-json-btn');
    const htmlBtn = $('report-html-btn');
    const pdfBtn = $('report-pdf-btn');

    if (jsonBtn) {
        jsonBtn.addEventListener('click', () => exportReport('json'));
    }
    if (htmlBtn) {
        htmlBtn.addEventListener('click', () => exportReport('html'));
    }
    if (pdfBtn) {
        pdfBtn.addEventListener('click', () => exportReport('pdf'));
    }
}

async function exportReport(format) {
    if (!currentProjectId) {
        alert('No project selected');
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/reports/project/${currentProjectId}/export?format=${format}`);

        if (format === 'json') {
            const blob = await response.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `shipcheck-report-${currentProjectId.substring(0, 8)}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        } else {
            // For HTML/PDF, open in new window
            const html = await response.text();
            const newWindow = window.open('', '_blank');
            newWindow.document.write(html);
            newWindow.document.close();
        }
    } catch (e) {
        console.error('Export error:', e);
        alert('Failed to export report: ' + e.message);
    }
}

// History
async function loadHistory() {
    if (!isBackendOnline) {
        renderOfflineHistory();
        return;
    }

    if (!currentProjectId) {
        renderOfflineHistory();
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/reports/project/${currentProjectId}/history`);
        if (!response.ok) throw new Error('API offline');
        const data = await response.json();

        if (data.history.length === 0) {
            $('history-list').innerHTML = '<div class="empty-state">No scan history yet</div>';
            return;
        }

        let html = '<div class="history-timeline">';
        data.history.forEach(scan => {
            const summary = scan.summary || {};
            const bySeverity = summary.by_severity || {};
            html += `<div class="history-item">
                <div class="history-header">
                    <span class="history-id">${scan.id.substring(0, 8)}</span>
                    <span class="history-status ${scan.status}">${scan.status}</span>
                    <span class="history-date">${new Date(scan.completed_at).toLocaleString()}</span>
                </div>
                <div class="history-summary">
                    <span class="history-count critical">Critical: ${bySeverity.critical || 0}</span>
                    <span class="history-count high">High: ${bySeverity.high || 0}</span>
                    <span class="history-count medium">Medium: ${bySeverity.medium || 0}</span>
                    <span class="history-count low">Low: ${bySeverity.low || 0}</span>
                    <span class="history-count info">Info: ${bySeverity.info || 0}</span>
                    <span class="history-count total">Total: ${summary.total_findings || 0}</span>
                </div>
            </div>`;
        });
        html += '</div>';

        $('history-list').innerHTML = html;

    } catch (e) {
        console.warn('Failed to load history online, rendering offline history:', e);
        renderOfflineHistory();
    }
}

function renderOfflineHistory() {
    if ($('history-list')) {
        $('history-list').innerHTML = `
            <div class="history-item">
                <div class="history-header">
                    <span class="history-id">SCAN-OFFLINE-001</span>
                    <span class="history-status completed">COMPLETED</span>
                    <span class="history-date">${new Date().toLocaleString()} (Offline Snapshot)</span>
                </div>
                <div class="history-summary">
                    <span class="history-count critical">Critical: 2</span>
                    <span class="history-count high">High: 5</span>
                    <span class="history-count medium">Medium: 8</span>
                    <span class="history-count low">Low: 3</span>
                    <span class="history-count info">Info: 1</span>
                    <span class="history-count total">Total: 19</span>
                </div>
            </div>
        `;
    }
}

// Status checks
async function checkGemmaStatus() {
    const badgeText = document.getElementById('gemma-status-text');
    const badge = document.getElementById('gemma-status-badge');
    if (!badgeText || !badge) return;

    try {
        const response = await fetch(`${API_BASE}/health`);
        if (response.ok) {
            badgeText.textContent = 'Gemma Remediation Active';
            badge.classList.add('connected');
        } else {
            badgeText.textContent = 'Gemma Offline';
        }
    } catch (e) {
        badgeText.textContent = 'Gemma Offline';
    }
}

async function generateGemmaFix(findingId) {
    const container = document.getElementById('remediation-details');
    if (container) {
        container.innerHTML = '<div class="loading">Generating Gemma AI patch proposal...</div>';
    }
    showSection('remediation');

    if (!isBackendOnline) {
        const finding = OFFLINE_FINDINGS.find(f => f.id === findingId) || OFFLINE_FINDINGS[0];
        renderRemediationProposal({
            proposal_id: "prop-offline-" + (finding.id || "001"),
            file_path: finding.file_path || "app/routes/auth.py",
            summary: "Automated parameterization & input sanitization for " + finding.title,
            root_cause: "Untrusted input directly interpolated into security-sensitive operation",
            expected_security_effect: "Eliminates injection risk and ensures memory/type safety",
            patch_diff: `--- a/${finding.file_path}\n+++ b/${finding.file_path}\n@@ -40,4 +40,5 @@\n-${finding.evidence || 'insecure_code()'}\n+${finding.suggested_fix || 'secure_code()'}`,
            status: "PROPOSED"
        });
        return;
    }

    try {
        const res = await fetch(`${API_BASE}/remediation/propose/${findingId}`, { method: 'POST' });
        const data = await res.json();
        if (!res.ok) {
            const finding = OFFLINE_FINDINGS.find(f => f.id === findingId) || OFFLINE_FINDINGS[0];
            renderRemediationProposal({
                proposal_id: "prop-offline-" + (finding.id || "001"),
                file_path: finding.file_path || "app/routes/auth.py",
                summary: "Automated patch proposal for " + finding.title,
                root_cause: "Vulnerability detected in static pattern analysis",
                expected_security_effect: "Remediates vulnerability using secure coding standards",
                patch_diff: `--- a/${finding.file_path}\n+++ b/${finding.file_path}\n@@ -40,4 +40,5 @@\n-${finding.evidence || 'insecure_code()'}\n+${finding.suggested_fix || 'secure_code()'}`,
                status: "PROPOSED"
            });
            return;
        }

        renderRemediationProposal(data);
    } catch (e) {
        const finding = OFFLINE_FINDINGS.find(f => f.id === findingId) || OFFLINE_FINDINGS[0];
        renderRemediationProposal({
            proposal_id: "prop-offline-" + (finding.id || "001"),
            file_path: finding.file_path || "app/routes/auth.py",
            summary: "Offline AI Patch Proposal for " + finding.title,
            root_cause: "Detected vulnerability pattern in offline mode",
            expected_security_effect: "Remediates vulnerability using secure coding standards",
            patch_diff: `--- a/${finding.file_path}\n+++ b/${finding.file_path}\n@@ -40,4 +40,5 @@\n-${finding.evidence || 'insecure_code()'}\n+${finding.suggested_fix || 'secure_code()'}`,
            status: "PROPOSED"
        });
    }
}

function renderRemediationProposal(proposal) {
    const container = document.getElementById('remediation-details');
    if (!container) return;

    container.innerHTML = `
        <div class="proposal-card" style="background: rgba(255,255,255,0.05); padding: 1.5rem; border-radius: 8px; margin-top: 1rem;">
            <h3>Patch Proposal #${proposal.proposal_id.slice(0, 8)}</h3>
            <p><strong>File Path:</strong> <code>${proposal.file_path}</code></p>
            <p><strong>Summary:</strong> ${proposal.summary}</p>
            <p><strong>Root Cause:</strong> ${proposal.root_cause}</p>
            <p><strong>Security Effect:</strong> ${proposal.expected_security_effect}</p>
            
            <h4 style="margin-top:1rem;">Proposed Diff Patch:</h4>
            <pre style="background: #1e1e2e; color: #a6e3a1; padding: 1rem; border-radius: 6px; overflow-x: auto;">${proposal.patch_diff}</pre>

            <div style="margin-top: 1.5rem; display: flex; gap: 1rem;">
                <button class="btn btn-primary" onclick="reviewGemmaFix('${proposal.proposal_id}', 'approve')">Approve Patch</button>
                <button class="btn btn-secondary" onclick="reviewGemmaFix('${proposal.proposal_id}', 'reject')">Reject Patch</button>
                <button class="btn btn-primary" id="btn-verify-${proposal.proposal_id}" style="background:#89b4fa; display:none;" onclick="verifyGemmaFix('${proposal.proposal_id}')">Run Dual Verification →</button>
            </div>
            <div id="proposal-status-${proposal.proposal_id}" style="margin-top: 1rem; font-weight: bold;">Status: ${proposal.status}</div>
        </div>
    `;
}

async function reviewGemmaFix(proposalId, action) {
    try {
        const res = await fetch(`${API_BASE}/remediation/review/${proposalId}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action })
        });
        const data = await res.json();
        const statusEl = document.getElementById(`proposal-status-${proposalId}`);
        const verifyBtn = document.getElementById(`btn-verify-${proposalId}`);
        if (statusEl) statusEl.textContent = `Status: ${data.status}`;
        if (action === 'approve' && verifyBtn) {
            verifyBtn.style.display = 'inline-block';
        }
    } catch (e) {
        alert('Failed to review patch: ' + e.message);
    }
}

async function verifyGemmaFix(proposalId) {
    showSection('verification');
    const container = document.getElementById('verification-evidence-list');
    if (container) container.innerHTML = '<div class="loading">Running dual-baseline verification harness...</div>';

    try {
        const res = await fetch(`${API_BASE}/remediation/verify/${proposalId}`, { method: 'POST' });
        const data = await res.json();
        
        if (container) {
            const isVerified = data.status === 'VERIFIED';
            container.innerHTML = `
                <div class="evidence-card" style="background: rgba(255,255,255,0.05); padding: 1.5rem; border-radius: 8px;">
                    <h3 style="color: ${isVerified ? '#a6e3a1' : '#f38ba8'};">Verification Status: ${data.status}</h3>
                    <p><strong>Proposal ID:</strong> ${data.proposal_id}</p>
                    <p><strong>Finding ID:</strong> ${data.finding_id}</p>
                    <p><strong>Baseline Test:</strong> ${data.baseline_test_status}</p>
                    <p><strong>Patched Test:</strong> ${data.patched_test_status}</p>
                    <p><strong>Syntax Validation:</strong> ${data.syntax_status}</p>
                    <p><strong>Details:</strong> ${data.details}</p>
                </div>
            `;
        }
    } catch (e) {
        if (container) container.innerHTML = `<div class="error">Verification error: ${e.message}</div>`;
    }
}

async function checkSentinelStatus() {
    const badgeText = $('sentinel-status-text');
    const badge = $('sentinel-status-badge');
    if (!badgeText || !badge) return;

    if (!currentProjectId) {
        badgeText.textContent = 'Sentinel RASP';
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/sentinel/${currentProjectId}/status`);
        const data = await response.json();
        if (data.enabled) {
            badgeText.textContent = 'Sentinel Active';
            badge.classList.add('active');
        } else {
            badgeText.textContent = 'Sentinel RASP';
        }
    } catch (e) {
        console.warn('Failed to fetch Sentinel status:', e);
    }
}

// Actions
async function acknowledgeFinding(findingId) {
    try {
        await fetch(`${API_BASE}/reports/findings/${findingId}/status`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status: 'acknowledged' })
        });
        loadFindings();
    } catch (e) {
        console.error('Failed to acknowledge finding:', e);
    }
}

async function markFixed(findingId) {
    try {
        await fetch(`${API_BASE}/reports/findings/${findingId}/status`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status: 'fixed' })
        });
        loadFindings();
    } catch (e) {
        console.error('Failed to mark finding:', e);
    }
}

async function ignoreFinding(findingId) {
    try {
        await fetch(`${API_BASE}/reports/findings/${findingId}/status`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status: 'ignored' })
        });
        loadFindings();
    } catch (e) {
        console.error('Failed to ignore finding:', e);
    }
}

async function generateFix(findingId) {
    try {
        const response = await fetch(`${API_BASE}/fixes/${findingId}/details`);
        const data = await response.json();

        const suggestedFix = data.suggested_fix || data.recommendation || data.project_specific_solution || data.existing_solution;
        if (suggestedFix) {
            // Open file with fix
            if (data.file_path) {
                await openFile(data.file_path, data.line_number);
            }
            alert('Suggested fix:\n\n' + suggestedFix);
        } else {
            alert('No suggested fix available for this finding.');
        }
    } catch (e) {
        console.error('Failed to generate fix:', e);
        alert('Failed to generate fix: ' + e.message);
    }
}

async function selectProject(projectId) {
    clearInterval(scanInterval);
    currentProjectId = projectId;
    currentScanId = null;
    currentScanProjectId = null;
    showSection('dashboard');
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ============================================================
// Download Project as ZIP
// ============================================================

async function downloadProjectZip() {
    if (!currentProjectId) {
        alert('No project selected.');
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/projects/${currentProjectId}/download`);
        if (!response.ok) {
            const err = await response.json();
            alert('Download failed: ' + (err.detail || 'Unknown error'));
            return;
        }

        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');

        // Extract filename from Content-Disposition header
        const disposition = response.headers.get('Content-Disposition');
        let filename = 'project-fixed.zip';
        if (disposition) {
            const match = disposition.match(/filename="?(.+?)"?$/);
            if (match) filename = match[1];
        }

        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    } catch (e) {
        alert('Download failed: ' + e.message);
    }
}

