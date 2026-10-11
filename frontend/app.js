/* Shipcheck + Sentinel Web Application Frontend */

const API_BASE = '/api';

// State
let currentProjectId = null;
let currentScanId = null;
let currentScanProjectId = null;
let scanInterval = null;
let runtimeRefreshInterval = null;
let currentSection = 'dashboard';

// Backend Connection State
let isBackendOnline = false;
let backendHealthInterval = null;

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
            break;
        case 'findings':
            loadFindings();
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

    // Dashboard shortcuts
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

    // Setup features
    setupUpload();
    setupDataClear();
    setupFilters();
    setupSandbox();
    setupRuntimeScan();
    setupSentinel();
    setupReports();

    // Check status
    checkGemmaStatus();
    checkSentinelStatus();

    // Initial backend health check & ongoing heartbeat
    checkBackendHealth();
    backendHealthInterval = setInterval(checkBackendHealth, 4000);

    // Load initial data
    loadProjects();
    loadDashboard();
});

// Backend Health
async function checkBackendHealth() {
    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 2000);
        const res = await fetch(`${API_BASE}/health`, { signal: controller.signal });
        clearTimeout(timeoutId);

        if (res.ok) {
            setBackendStatus(true);
            return true;
        }
    } catch (e) {
        // Backend offline / connecting
    }
    setBackendStatus(false);
    return false;
}

function setBackendStatus(online) {
    const wasOffline = !isBackendOnline;
    isBackendOnline = online;

    const badge = $('backend-status-badge');
    const badgeText = $('backend-status-text');

    if (badge && badgeText) {
        if (online) {
            badge.className = 'hindsight-badge connected';
            badgeText.textContent = 'Backend: Online';
        } else {
            badge.className = 'hindsight-badge';
            badgeText.textContent = 'Backend: Connecting...';
        }
    }

    if (wasOffline && online) {
        loadDashboard();
        loadProjects();
    }
}

// Dashboard
async function loadDashboard() {
    if (!currentProjectId) {
        try {
            const response = await fetch(`${API_BASE}/projects`);
            if (response.ok) {
                const projects = await response.json();
                if (projects.length > 0) {
                    currentProjectId = projects[0].id;
                } else {
                    clearDashboard();
                    return;
                }
            } else {
                clearDashboard();
                return;
            }
        } catch (e) {
            clearDashboard();
            return;
        }
    }

    const requestedProjectId = currentProjectId;
    try {
        const response = await fetch(`${API_BASE}/projects/${requestedProjectId}/dashboard`);
        if (!response.ok) {
            clearDashboard();
            return;
        }
        const data = await response.json();
        if (requestedProjectId !== currentProjectId) return;

        // Update scores
        const project = data.project || {};
        $('score-security').textContent = project.security_score ?? '--';
        $('score-privacy').textContent = project.privacy_score ?? '--';
        $('score-production').textContent = project.production_readiness_score ?? '--';
        $('score-reliability').textContent = project.reliability_score ?? '--';

        // Update finding counts
        const bySeverity = data.latest_scan?.summary?.by_severity || {};
        $('count-critical').textContent = bySeverity.critical ?? 0;
        $('count-high').textContent = bySeverity.high ?? 0;
        $('count-medium').textContent = bySeverity.medium ?? 0;
        $('count-low').textContent = bySeverity.low ?? 0;
        $('count-info').textContent = bySeverity.info ?? 0;

        // Update runtime status
        const runtime = data.runtime_summary || {};
        $('runtime-sentinel').textContent = data.sentinel?.enabled ? 'Active' : 'Not Enabled';
        $('runtime-events').textContent = runtime.total_events ?? 0;
        $('runtime-blocked').textContent = runtime.blocked ?? 0;
        $('runtime-suspicious').textContent = runtime.suspicious ?? 0;

        // Update project info
        $('project-name').textContent = project.name || '--';
        const tech = project.project_context || {};
        const techStack = [
            ...(tech.languages || []),
            ...(tech.frameworks || []),
            ...(tech.databases || [])
        ].slice(0, 5).join(', ');
        $('project-tech').textContent = techStack || 'Detected upon scan';
        $('project-last-scan').textContent = project.last_scan_at ? new Date(project.last_scan_at).toLocaleString() : 'Never';
        $('project-total-scans').textContent = Array.isArray(data.scan_history) ? data.scan_history.length : 0;

    } catch (e) {
        clearDashboard();
    }
}

function clearDashboard() {
    const values = {
        'score-security': '--', 'score-privacy': '--', 'score-production': '--', 'score-reliability': '--',
        'count-critical': '0', 'count-high': '0', 'count-medium': '0', 'count-low': '0', 'count-info': '0',
        'runtime-sentinel': 'Not Enabled', 'runtime-events': '0', 'runtime-blocked': '0', 'runtime-suspicious': '0',
        'project-name': 'No project selected', 'project-tech': '--', 'project-last-scan': 'Never', 'project-total-scans': '0'
    };
    Object.entries(values).forEach(([id, value]) => { if ($(id)) $(id).textContent = value; });
}

// Projects
async function loadProjects() {
    const container = $('projects-list');
    if (!container) return;
    container.innerHTML = '<div class="loading"><div class="spinner"></div>Loading projects...</div>';

    try {
        const response = await fetch(`${API_BASE}/projects`);
        if (!response.ok) throw new Error('API request failed');
        const projects = await response.json();

        if (projects.length === 0) {
            container.innerHTML = '<div class="empty-state">No projects yet. Upload a project ZIP below to get started.</div>';
            return;
        }

        renderProjectsList(projects);
    } catch (error) {
        container.innerHTML = '<div class="empty-state error">Unable to load projects from backend. Ensure the server is active.</div>';
    }
}

function renderProjectsList(projects) {
    const container = $('projects-list');
    if (!container) return;
    container.innerHTML = projects.map(p => `
        <div class="project-item ${p.id === currentProjectId ? 'selected-project' : ''}" onclick="selectProject('${p.id}')">
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
        scanInterval = setInterval(() => pollScanStatus(), 1200);

    } catch (error) {
        updateScanProgress(`Failed to start scan: ${error.message}`, 'failed');
    }
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
    const container = $('findings-list');

    if (!currentProjectId) {
        if (container) container.innerHTML = '<div class="empty-state">Select a project to view findings.</div>';
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
                if (container) container.innerHTML = '<div class="empty-state">No scans recorded for this project yet. Click "Run a scan" to begin.</div>';
                return;
            }
        } catch (e) {
            if (container) container.innerHTML = '<div class="empty-state error">Failed to retrieve scan data.</div>';
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
        if (container) container.innerHTML = '<div class="empty-state error">Error loading findings report.</div>';
    }
}

function renderFindings(findings) {
    const container = $('findings-list');
    if (!container) return;

    if (findings.length === 0) {
        container.innerHTML = '<div class="empty-state success">✓ No findings matching current filters!</div>';
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
            <div class="finding-card" id="card-finding-${f.id}">
                <div class="finding-header">
                    <div class="finding-title">${escapeHtml(f.title)}</div>
                    <div class="finding-badges">
                        <span class="badge ${f.severity}">${f.severity}</span>
                        <span class="badge category">${f.category}</span>
                    </div>
                </div>
                ${f.description ? `<p class="finding-description">${escapeHtml(f.description)}</p>` : ''}
                ${f.file_path ? `<div class="finding-location">📁 ${escapeHtml(f.file_path)}${f.line_number ? `:${f.line_number}` : ''}</div>` : ''}
                ${f.evidence ? `<pre class="finding-evidence"><code>${escapeHtml(f.evidence)}</code></pre>` : ''}
                ${f.recommendation ? `<div class="finding-recommendation">💡 <strong>Remediation Guidance:</strong> ${escapeHtml(f.recommendation)}</div>` : ''}
                
                <div class="finding-actions">
                    <button class="btn btn-sm btn-primary" id="btn-fix-${f.id}" onclick="toggleAiFix('${f.id}')">✨ Suggest AI Fix</button>
                    <button class="btn btn-sm btn-secondary" onclick="acknowledgeFinding('${f.id}')">Acknowledge</button>
                </div>

                <!-- AI Fix Drawer -->
                <div id="ai-fix-container-${f.id}" class="ai-fix-container" style="display: none;"></div>
            </div>
        `).join('');
        html += `</div>`;
    });

    container.innerHTML = html;
}

// AI Fix Suggestion
async function toggleAiFix(findingId) {
    const container = $(`ai-fix-container-${findingId}`);
    const btn = $(`btn-fix-${findingId}`);
    if (!container) return;

    // Toggle close if already open
    if (container.style.display === 'block') {
        container.style.display = 'none';
        if (btn) btn.textContent = '✨ Suggest AI Fix';
        return;
    }

    container.style.display = 'block';
    container.innerHTML = '<div class="loading" style="padding: 1.5rem;"><div class="spinner"></div>Generating intelligent AI fix suggestion...</div>';
    if (btn) btn.textContent = '✕ Hide Fix';

    try {
        const response = await fetch(`${API_BASE}/fixes/${findingId}/ai-suggest`);
        if (!response.ok) {
            const err = await response.json().catch(() => ({}));
            throw new Error(err.detail || 'Could not generate AI fix.');
        }

        const data = await response.json();
        renderAiFixContent(findingId, data);

    } catch (e) {
        container.innerHTML = `<div class="empty-state error" style="padding: 1rem; margin-top: 0.75rem;">Failed to fetch AI fix: ${escapeHtml(e.message)}</div>`;
    }
}

function renderAiFixContent(findingId, data) {
    const container = $(`ai-fix-container-${findingId}`);
    if (!container) return;

    const fixCode = data.suggested_fix || data.recommendation || '';

    container.innerHTML = `
        <div class="ai-fix-card" style="margin-top: 1rem; padding: 1.25rem; background: rgba(99, 102, 241, 0.08); border: 1px solid rgba(99, 102, 241, 0.25); border-radius: var(--radius);">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem;">
                <h4 style="color: #ffffff; margin: 0; font-size: 0.92rem; display: flex; align-items: center; gap: 0.5rem;">
                    <span>🤖 AI Fix Recommendation</span>
                    <span class="tech-badge" style="background: rgba(45, 212, 191, 0.15); color: #2dd4bf; border-color: rgba(45, 212, 191, 0.3);">${escapeHtml(data.model || 'Gemma 4')}</span>
                </h4>
                <button class="text-button" onclick="toggleAiFix('${findingId}')" style="font-size: 0.75rem;">✕ Close</button>
            </div>

            <div style="margin-bottom: 0.75rem; font-size: 0.85rem; color: var(--text-secondary); line-height: 1.5;">
                <p style="margin: 0 0 0.5rem 0;"><strong>Explanation:</strong> ${escapeHtml(data.summary || data.root_cause || '')}</p>
                ${data.expected_security_effect ? `<p style="margin: 0; color: #a6e3a1;"><strong>Security Benefit:</strong> ${escapeHtml(data.expected_security_effect)}</p>` : ''}
            </div>

            <div style="position: relative; margin-top: 0.75rem;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.35rem;">
                    <span style="font-size: 0.75rem; font-weight: 600; color: var(--text-muted); text-transform: uppercase;">Suggested Code Patch:</span>
                    <button class="btn btn-sm btn-secondary" id="btn-copy-${findingId}" onclick="copyFixCode('${findingId}')" style="padding: 0.25rem 0.55rem; font-size: 0.72rem;">📋 Copy Fix</button>
                </div>
                <pre id="code-fix-${findingId}" class="finding-evidence" style="margin-bottom: 0; max-height: 250px; background: #0f172a; border-color: rgba(99, 102, 241, 0.2); color: #a6e3a1;"><code>${escapeHtml(fixCode)}</code></pre>
            </div>
        </div>
    `;
}

function copyFixCode(findingId) {
    const codeEl = $(`code-fix-${findingId}`);
    const copyBtn = $(`btn-copy-${findingId}`);
    if (!codeEl) return;

    const textToCopy = codeEl.textContent;
    navigator.clipboard.writeText(textToCopy).then(() => {
        if (copyBtn) {
            const prev = copyBtn.textContent;
            copyBtn.textContent = '✓ Copied!';
            setTimeout(() => { copyBtn.textContent = prev; }, 1500);
        }
    }).catch(() => {
        alert('Copied to clipboard.');
    });
}

function setupFilters() {
    const cat = $('filter-category');
    const sev = $('filter-severity');
    if (cat) cat.addEventListener('change', loadFindings);
    if (sev) sev.addEventListener('change', loadFindings);
}

// Sandbox
function setupSandbox() {
    const executeBtn = $('sandbox-execute-btn');
    const stopBtn = $('sandbox-stop-btn');

    if (executeBtn) {
        executeBtn.addEventListener('click', executeInSandbox);
    }
    if (stopBtn) {
        stopBtn.addEventListener('click', stopSandbox);
    }
}

async function executeInSandbox() {
    if (!currentProjectId) {
        alert('Please select a project first.');
        return;
    }

    const statusValue = $('sandbox-status-value');
    const executeBtn = $('sandbox-execute-btn');
    const stopBtn = $('sandbox-stop-btn');

    if (statusValue) statusValue.textContent = 'Starting...';
    if (executeBtn) executeBtn.disabled = true;
    if (stopBtn) stopBtn.disabled = false;

    try {
        const response = await fetch(`${API_BASE}/sandbox/execute`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ project_id: currentProjectId })
        });
        const data = await response.json();
        renderSandboxResults(data);
    } catch (e) {
        if (statusValue) statusValue.textContent = 'Error';
        $('sandbox-results').innerHTML = `<div class="error">Sandbox execution error: ${e.message}</div>`;
    } finally {
        if (executeBtn) executeBtn.disabled = false;
        if (stopBtn) stopBtn.disabled = true;
    }
}

async function stopSandbox() {
    if (!currentProjectId) return;
    try {
        await fetch(`${API_BASE}/sandbox/stop`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ project_id: currentProjectId })
        });
        $('sandbox-status-value').textContent = 'Stopped';
        $('sandbox-execute-btn').disabled = false;
        $('sandbox-stop-btn').disabled = true;
    } catch (e) {
        console.error('Stop sandbox error:', e);
    }
}

async function loadSandboxStatus() {
    if (!currentProjectId) {
        $('sandbox-status-value').textContent = 'No project selected';
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/sandbox/status/${currentProjectId}`);
        const data = await response.json();
        renderSandboxResults(data);
    } catch (e) {
        $('sandbox-status-value').textContent = 'Idle';
    }
}

function renderSandboxResults(data) {
    if ($('sandbox-status-value')) $('sandbox-status-value').textContent = data.status || 'Idle';
    if ($('sandbox-method')) $('sandbox-method').textContent = data.method || 'Native/Docker';
    if ($('sandbox-checks')) $('sandbox-checks').textContent = data.checks_count || 0;

    const resultsContainer = $('sandbox-results');
    if (!resultsContainer) return;

    if (data.results) {
        let html = '<div class="sandbox-results-view">';
        if (data.results.findings) {
            html += `<h4>Runtime Findings (${data.results.findings.length})</h4>`;
            html += data.results.findings.map(f => `
                <div class="finding-item ${f.severity}">
                    <strong>${escapeHtml(f.title)}</strong> - ${escapeHtml(f.description || '')}
                </div>
            `).join('');
        }
        html += '</div>';
        resultsContainer.innerHTML = html;
    } else {
        resultsContainer.innerHTML = '';
    }
}

// Runtime
function setupRuntimeScan() {
    const scanBtn = $('runtime-scan-btn');
    const connectBtn = $('runtime-connect-btn');

    if (scanBtn) scanBtn.addEventListener('click', runLocalRuntimeScan);
    if (connectBtn) connectBtn.addEventListener('click', createProtectedProxy);
}

async function runLocalRuntimeScan() {
    const urlInput = $('runtime-url-input');
    const msg = $('runtime-scan-message');
    const targetUrl = urlInput ? urlInput.value.trim() : 'http://127.0.0.1:8001';

    if (!targetUrl) {
        if (msg) msg.textContent = 'Please provide a valid application URL.';
        return;
    }

    if (msg) msg.textContent = `Scanning ${targetUrl} for runtime vulnerabilities...`;

    try {
        const res = await fetch(`${API_BASE}/runtime/scan-direct`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: targetUrl, project_id: currentProjectId })
        });
        const data = await res.json();
        if (msg) msg.textContent = `Scan completed. Found ${data.findings_count || 0} issues.`;
        loadRuntimeDashboard();
    } catch (e) {
        if (msg) msg.textContent = `Runtime scan error: ${e.message}`;
    }
}

async function createProtectedProxy() {
    const urlInput = $('runtime-url-input');
    const proxyResult = $('runtime-proxy-result');
    const targetUrl = urlInput ? urlInput.value.trim() : 'http://127.0.0.1:8001';

    if (!targetUrl) {
        if (proxyResult) proxyResult.innerHTML = '<div class="error-msg" style="padding: 0.75rem; background: rgba(243,139,168,0.1); border: 1px solid #f38ba8; border-radius: 6px; color: #f38ba8;">Please specify a target application URL (e.g. http://127.0.0.1:8001).</div>';
        return;
    }

    if (proxyResult) proxyResult.innerHTML = '<div class="loading"><div class="spinner"></div>Initializing Sentinel runtime protection proxy...</div>';

    try {
        const res = await fetch(`${API_BASE}/proxy/create`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target_url: targetUrl, project_id: currentProjectId })
        });
        const data = await res.json();

        if (!res.ok) {
            const errorDetail = data.detail || data.message || `Server returned error status ${res.status}`;
            if (proxyResult) {
                proxyResult.innerHTML = `<div class="error-msg" style="padding: 0.75rem; background: rgba(243,139,168,0.1); border: 1px solid #f38ba8; border-radius: 6px; color: #f38ba8; margin-top: 1rem;">
                    <strong>Proxy Startup Failed:</strong> ${escapeHtml(errorDetail)}
                </div>`;
            }
            return;
        }

        if (data.proxy_url && typeof data.proxy_url === 'string' && data.proxy_url.startsWith('http')) {
            if (proxyResult) {
                proxyResult.innerHTML = `
                    <div class="proxy-success" style="padding: 1rem; background: rgba(166,227,161,0.08); border: 1px solid #a6e3a1; border-radius: 6px; margin-top: 1rem;">
                        <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 0.5rem;">
                            <div>
                                <div style="display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap;">
                                    <strong style="color: #a6e3a1;">Protected Proxy Active:</strong>
                                    <a href="${escapeHtml(data.proxy_url)}" target="_blank" style="color: #89b4fa; font-weight: 600; text-decoration: underline;">${escapeHtml(data.proxy_url)}</a>
                                    <span style="font-size: 0.75rem; background: rgba(137,180,250,0.2); color: #89b4fa; padding: 2px 6px; border-radius: 4px;">${escapeHtml(data.waf_engine || 'Hyperion C++ Engine')}</span>
                                </div>
                                <div style="font-size: 0.8rem; color: var(--text-muted, #a6adc8); margin-top: 0.35rem;">
                                    Forwarding to upstream target: <code style="color: #cdd6f4;">${escapeHtml(data.target_url)}</code>
                                </div>
                            </div>
                            <button class="btn btn-sm btn-secondary" onclick="disconnectProtectedProxy('${escapeHtml(data.project_id || currentProjectId || '')}')" style="font-size: 0.8rem; padding: 0.3rem 0.65rem;">Disconnect</button>
                        </div>
                        <p style="font-size: 0.82rem; margin-top: 0.65rem; color: #bac2de; line-height: 1.4;">
                            Route your client/browser traffic through <strong>${escapeHtml(data.proxy_url)}</strong> to enable real-time C++ Hyperion WAF inspection and RASP blocking. <em>Direct requests to ${escapeHtml(data.target_url)} will bypass this proxy.</em>
                        </p>
                    </div>
                `;
            }
        } else {
            if (proxyResult) {
                proxyResult.innerHTML = `<div class="error-msg" style="padding: 0.75rem; background: rgba(243,139,168,0.1); border: 1px solid #f38ba8; border-radius: 6px; color: #f38ba8; margin-top: 1rem;">
                    Proxy listener started, but received an unexpected response format.
                </div>`;
            }
        }
        loadRuntimeDashboard();
    } catch (e) {
        if (proxyResult) {
            proxyResult.innerHTML = `<div class="error-msg" style="padding: 0.75rem; background: rgba(243,139,168,0.1); border: 1px solid #f38ba8; border-radius: 6px; color: #f38ba8; margin-top: 1rem;">
                Proxy creation error: ${escapeHtml(e.message)}
            </div>`;
        }
    }
}

async function disconnectProtectedProxy(projectId) {
    const proxyResult = $('runtime-proxy-result');
    try {
        const url = projectId ? `${API_BASE}/proxy/${projectId}/disconnect` : `${API_BASE}/proxy/disconnect`;
        const res = await fetch(url, { method: 'POST' });
        if (proxyResult) {
            proxyResult.innerHTML = '<div style="padding: 0.75rem; background: rgba(147,154,183,0.1); border: 1px solid #6c7086; border-radius: 6px; color: #bac2de; margin-top: 1rem;">Protected proxy disconnected.</div>';
        }
        loadRuntimeDashboard();
    } catch (e) {
        if (proxyResult) proxyResult.innerHTML = `<div class="error">Disconnect error: ${escapeHtml(e.message)}</div>`;
    }
}

async function loadRuntimeDashboard() {
    try {
        const statsRes = await fetch(`${API_BASE}/runtime/stats`);
        const stats = await statsRes.json();

        if ($('runtime-total-events')) $('runtime-total-events').textContent = stats.total_events || 0;
        if ($('runtime-blocked-events')) $('runtime-blocked-events').textContent = stats.blocked || 0;
        if ($('runtime-suspicious-events')) $('runtime-suspicious-events').textContent = stats.suspicious || 0;
        if ($('runtime-sql-injection')) $('runtime-sql-injection').textContent = stats.sql_injection || 0;
        if ($('runtime-xss')) $('runtime-xss').textContent = stats.xss || 0;
        if ($('runtime-rate-abuse')) $('runtime-rate-abuse').textContent = stats.rate_abuse || 0;

        const eventsRes = await fetch(`${API_BASE}/runtime/events?limit=25`);
        const eventsData = await eventsRes.json();
        const events = eventsData.events || [];

        const listContainer = $('runtime-events-list');
        if (!listContainer) return;

        if (events.length === 0) {
            listContainer.innerHTML = '<div class="empty-state">No runtime security events recorded yet. Send requests through the protected proxy to monitor live traffic.</div>';
            return;
        }

        let html = '<div class="events-list">';
        events.forEach(event => {
            const actionClass = event.action === 'BLOCKED' ? 'danger' :
                              event.action === 'THROTTLED' ? 'warning' : 'info';
            html += `<div class="event-item ${actionClass}">
                <div class="event-header">
                    <span class="event-type">${escapeHtml(event.event_type)}</span>
                    <span class="event-action">${escapeHtml(event.action)}</span>
                    <span class="event-time">${event.timestamp ? new Date(event.timestamp).toLocaleTimeString() : ''}</span>
                </div>
                ${event.endpoint ? `<div class="event-endpoint">Endpoint: ${escapeHtml(event.endpoint)}</div>` : ''}
                ${event.evidence ? `<div class="event-evidence">${escapeHtml(event.evidence)}</div>` : ''}
                <div class="event-meta">
                    <span>Confidence: ${escapeHtml(event.confidence || 'HIGH')}</span>
                    ${event.request_id ? `<span>Request: ${escapeHtml(event.request_id)}</span>` : ''}
                </div>
            </div>`;
        });
        html += '</div>';
        listContainer.innerHTML = html;

    } catch (e) {
        if ($('runtime-events-list')) {
            $('runtime-events-list').innerHTML = '<div class="empty-state">No runtime events recorded.</div>';
        }
    }
}

function startRuntimeAutoRefresh() {
    if (runtimeRefreshInterval) clearInterval(runtimeRefreshInterval);
    runtimeRefreshInterval = setInterval(loadRuntimeDashboard, 3000);
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
        const engine = data.native_engine?.available ? 'C++ Hyperion Engine active' : 'Python fallback';
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

    if (previewBtn) previewBtn.addEventListener('click', previewSentinelIntegration);
    if (enableBtn) enableBtn.addEventListener('click', enableSentinel);
    if (confirmBtn) confirmBtn.addEventListener('click', enableSentinel);
    if (cancelBtn) cancelBtn.addEventListener('click', () => {
        const preview = $('sentinel-preview');
        if (preview) preview.style.display = 'none';
    });
}

async function previewSentinelIntegration() {
    if (!currentProjectId) return;
    try {
        const res = await fetch(`${API_BASE}/sentinel/${currentProjectId}/preview`);
        const data = await res.json();
        const previewEl = $('sentinel-preview');
        const contentEl = $('sentinel-preview-content');
        if (contentEl && previewEl) {
            contentEl.textContent = data.patch_diff || data.preview || 'Ready to inject Sentinel RASP middleware.';
            previewEl.style.display = 'block';
        }
        if ($('sentinel-enable-btn')) $('sentinel-enable-btn').disabled = false;
    } catch (e) {
        alert('Preview failed: ' + e.message);
    }
}

async function enableSentinel() {
    if (!currentProjectId) return;
    try {
        const res = await fetch(`${API_BASE}/sentinel/${currentProjectId}/enable`, { method: 'POST' });
        if (res.ok) {
            alert('Sentinel RASP enabled successfully for project!');
            loadSentinelStatus();
            checkSentinelStatus();
        }
    } catch (e) {
        alert('Enable failed: ' + e.message);
    }
}

// Reports
function setupReports() {
    const jsonBtn = $('report-json-btn');
    const htmlBtn = $('report-html-btn');
    const pdfBtn = $('report-pdf-btn');

    if (jsonBtn) jsonBtn.addEventListener('click', () => exportReport('json'));
    if (htmlBtn) htmlBtn.addEventListener('click', () => exportReport('html'));
    if (pdfBtn) pdfBtn.addEventListener('click', () => exportReport('pdf'));
}

async function exportReport(format) {
    if (!currentScanId) {
        alert('No scan selected to export.');
        return;
    }
    window.open(`${API_BASE}/reports/scan/${currentScanId}/export?format=${format}`, '_blank');
}

async function loadReportPreview() {
    const previewEl = $('report-preview-content');
    if (!previewEl) return;

    if (!currentScanId) {
        previewEl.innerHTML = '<div class="empty-state">No scan report selected. Run or select a scan first.</div>';
        return;
    }

    try {
        const res = await fetch(`${API_BASE}/reports/scan/${currentScanId}`);
        const data = await res.json();
        previewEl.innerHTML = `<pre style="max-height: 400px; overflow: auto; background: #1e1e2e; color: #cdd6f4; padding: 1rem; border-radius: 6px;">${escapeHtml(JSON.stringify(data, null, 2))}</pre>`;
    } catch (e) {
        previewEl.innerHTML = '<div class="error">Failed to load report preview.</div>';
    }
}

// Gemma AI & Sentinel Badges
async function checkGemmaStatus() {
    const badgeText = $('gemma-status-text');
    const badge = $('gemma-status-badge');
    if (!badgeText || !badge) return;

    try {
        const response = await fetch(`${API_BASE}/health`);
        if (response.ok) {
            badgeText.textContent = 'Gemma AI Security';
            badge.classList.add('connected');
        } else {
            badgeText.textContent = 'Gemma Offline';
        }
    } catch (e) {
        badgeText.textContent = 'Gemma Offline';
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
        badgeText.textContent = 'Sentinel RASP';
    }
}

// History
async function loadHistory() {
    const container = $('history-list');
    if (!container) return;

    if (!currentProjectId) {
        container.innerHTML = '<div class="empty-state">Select a project to view its scan history.</div>';
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/projects/${currentProjectId}/dashboard`);
        const data = await response.json();
        const history = data.scan_history || [];

        if (history.length === 0) {
            container.innerHTML = '<div class="empty-state">No scan history recorded for this project yet.</div>';
            return;
        }

        container.innerHTML = history.map(h => `
            <div class="history-item" style="padding: 1rem; background: rgba(255,255,255,0.03); border-radius: 6px; margin-bottom: 0.75rem; display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <strong>Scan #${h.id.slice(0, 8)}</strong>
                    <div style="font-size: 0.85rem; color: var(--text-muted);">${new Date(h.created_at).toLocaleString()}</div>
                </div>
                <div style="display: flex; gap: 1rem; align-items: center;">
                    <span class="badge ${h.status === 'completed' ? 'success' : 'warning'}">${h.status}</span>
                    <button class="btn btn-sm btn-secondary" onclick="viewHistoricScan('${h.id}')">View Report</button>
                </div>
            </div>
        `).join('');
    } catch (e) {
        container.innerHTML = '<div class="empty-state error">Failed to load scan history.</div>';
    }
}

function viewHistoricScan(scanId) {
    currentScanId = scanId;
    showSection('findings');
    loadFindings();
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

async function selectProject(projectId) {
    clearInterval(scanInterval);
    currentProjectId = projectId;
    currentScanId = null;
    currentScanProjectId = null;
    showSection('dashboard');
}

function setupDataClear() {
    const clearBtn = $('clear-data-btn');
    if (!clearBtn) return;
    clearBtn.addEventListener('click', async () => {
        if (!confirm('Are you sure you want to clear all projects, scans, and finding data?')) return;
        try {
            const res = await fetch(`${API_BASE}/projects/clear-all`, { method: 'DELETE' });
            if (res.ok) {
                currentProjectId = null;
                currentScanId = null;
                clearDashboard();
                loadProjects();
                alert('All data cleared.');
            } else {
                alert('Failed to clear data from server: ' + res.statusText);
            }
        } catch (e) {
            alert('Error clearing data: ' + e.message);
        }
    });
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
}
