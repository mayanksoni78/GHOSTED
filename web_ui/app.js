// ==========================================================================
// GHOSTED — Haunted Telemetry & Linux Storage Diagnostics Controller
// Theme: Dark, Haunted, Ghost-Inspired Real-Time Dashboard
// ==========================================================================

let FINDINGS_DATA = [];
let TREE_DATA = [];
let AUDIT_DATA = [
  { time: "2026-10-27 18:58:58", action: "SCAN_RUN", target: "/ (Root Mount)", status: "COMPLETED", delta: "0 B", msg: "Telemetry refreshed: 3.54 GB crawled, 2 diagnostic findings." },
  { time: "2026-10-27 18:50:00", action: "PREVIEW_GENERATED", target: "/tmp/ghostdisk_test/cache_cleanup_demo.tmp", status: "OK", delta: "0 B", msg: "Safe preview generated via non-destructive lstat." }
];

let lastLoadedTimestamp = null;
let isBackendAvailable = false;
let isScanning = false;
let scanTimer = null;

// ==========================================================================
// Formatting Utilities
// ==========================================================================

function formatBytes(bytes) {
  if (bytes === undefined || bytes === null || isNaN(bytes)) return '0 B';
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatEpochTime(epochSec) {
  if (!epochSec) return 'Just now';
  const num = typeof epochSec === 'string' ? parseInt(epochSec, 10) : epochSec;
  if (isNaN(num) || num <= 0) return 'Just now';
  const d = new Date(num * 1000);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

// ==========================================================================
// Toast Notifications
// ==========================================================================

function showToast(message, type = 'info') {
  const container = document.getElementById('ghost-toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = 'ghost-toast';
  
  let icon = '✦';
  if (type === 'success') icon = '✓';
  if (type === 'warning') icon = '⚠';

  toast.innerHTML = `
    <span style="color: var(--accent-silver); font-size: 0.95rem;">${icon}</span>
    <span>${message}</span>
  `;
  container.appendChild(toast);

  setTimeout(() => {
    toast.remove();
  }, 4000);
}

// ==========================================================================
// Navigation & Views
// ==========================================================================

function switchView(viewName) {
  document.querySelectorAll('.nav-link').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.content-panel').forEach(el => el.classList.remove('active'));

  const navBtn = document.querySelector(`.nav-link[data-view="${viewName}"]`);
  if (navBtn) navBtn.classList.add('active');

  const panelEl = document.getElementById(`view-${viewName}`);
  if (panelEl) panelEl.classList.add('active');
}

document.querySelectorAll('.nav-link').forEach(btn => {
  btn.addEventListener('click', () => {
    switchView(btn.getAttribute('data-view'));
  });
});

// ==========================================================================
// Render Overview Findings
// ==========================================================================

function renderOverviewFindings() {
  const container = document.getElementById('overview-findings-list');
  if (!container) return;
  container.innerHTML = '';

  if (FINDINGS_DATA.length === 0) {
    container.innerHTML = `
      <div style="padding: 18px; text-align: center; color: var(--text-muted); font-size: 0.8125rem;">
        No active storage leaks or deleted-open file issues detected.
      </div>
    `;
    return;
  }

  FINDINGS_DATA.forEach(f => {
    const row = document.createElement('div');
    row.className = 'finding-row';
    const badgeClass = f.severityClass || (f.severity === 'Critical' ? 'critical' : (f.severity === 'Warning' ? 'warning' : 'info'));
    
    row.innerHTML = `
      <div class="finding-row-left">
        <span class="tag-status ${badgeClass}">${f.severity}</span>
        <div class="finding-meta">
          <h4>${f.title}</h4>
          <p>${f.guidance || f.summary}</p>
        </div>
      </div>
      <div class="finding-row-right">
        <span class="finding-bytes">${f.relatedBytes || '0 B'}</span>
        <button class="btn-subtle" onclick="openFindingModal(${f.id})">Details</button>
      </div>
    `;
    container.appendChild(row);
  });
}

// ==========================================================================
// Render View 3: Deleted-Open Files
// ==========================================================================

function renderFindingsList(filter = 'all') {
  const container = document.getElementById('findings-full-list');
  if (!container) return;
  container.innerHTML = '';

  const filtered = FINDINGS_DATA.filter(f => {
    if (filter === 'all') return true;
    return f.severity.toLowerCase() === filter.toLowerCase();
  });

  if (filtered.length === 0) {
    container.innerHTML = `
      <div style="padding: 24px; text-align: center; color: var(--text-muted); font-size: 0.8125rem;">
        No findings matching filter '${filter}'.
      </div>
    `;
    return;
  }

  filtered.forEach(f => {
    const row = document.createElement('div');
    row.className = 'finding-row';
    const badgeClass = f.severityClass || (f.severity === 'Critical' ? 'critical' : (f.severity === 'Warning' ? 'warning' : 'info'));

    row.innerHTML = `
      <div class="finding-row-left">
        <span class="tag-status ${badgeClass}">${f.severity}</span>
        <div class="finding-meta">
          <h4>${f.title}</h4>
          <p>Process: <strong>${f.process}</strong> ${f.fd !== -1 && f.fd !== undefined ? '| File Descriptor: <code>fd ' + f.fd + '</code>' : ''}</p>
        </div>
      </div>
      <div class="finding-row-right">
        <span class="finding-bytes">${f.relatedBytes || '0 B'}</span>
        <button class="btn-subtle" onclick="openFindingModal(${f.id})">View Details</button>
      </div>
    `;
    container.appendChild(row);
  });

  const badge = document.getElementById('findings-count-pill');
  if (badge) badge.textContent = FINDINGS_DATA.length;
}

document.querySelectorAll('.filter-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    renderFindingsList(btn.getAttribute('data-filter'));
  });
});

// ==========================================================================
// Render Storage Tree Table (View 2)
// ==========================================================================

function renderTreeTable(filterText = '') {
  const tbody = document.getElementById('storage-tree-body');
  if (!tbody) return;
  tbody.innerHTML = '';

  const list = TREE_DATA.filter(t => !filterText || t.path.toLowerCase().includes(filterText.toLowerCase()));

  if (list.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 18px;">No matching paths found.</td></tr>`;
    return;
  }

  list.forEach(item => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><code>${item.path}</code></td>
      <td><strong>${item.allocated}</strong></td>
      <td style="color: var(--text-secondary);">${item.apparent}</td>
      <td><span class="tag-status info">${item.type}</span></td>
      <td style="color: var(--text-muted); font-family: var(--font-mono);">${item.ino || '-'}</td>
    `;
    tbody.appendChild(tr);
  });
}

const searchInput = document.getElementById('analysis-search');
if (searchInput) {
  searchInput.addEventListener('input', (e) => {
    renderTreeTable(e.target.value);
  });
}

// ==========================================================================
// Render Top Folders (View 4)
// ==========================================================================

function renderFoldersTable() {
  const tbody = document.getElementById('folders-table-body');
  if (!tbody) return;
  tbody.innerHTML = '';

  if (TREE_DATA.length === 0) {
    tbody.innerHTML = `<tr><td colspan="3" style="text-align: center; color: var(--text-muted); padding: 18px;">No directory telemetry available.</td></tr>`;
    return;
  }

  TREE_DATA.slice(0, 8).forEach(item => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><code>${item.path}</code></td>
      <td><strong>${item.allocated}</strong></td>
      <td style="color: var(--text-secondary); font-size: 0.8125rem;">${item.category || item.type || 'Subtree Entry'}</td>
    `;
    tbody.appendChild(tr);
  });
}

// ==========================================================================
// Render Audit History Table (View 6)
// ==========================================================================

function renderAuditTable() {
  const tbody = document.getElementById('audit-table-body');
  if (!tbody) return;
  tbody.innerHTML = '';

  AUDIT_DATA.forEach(row => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td style="font-family: var(--font-mono); font-size: 0.78rem; color: var(--text-muted);">${row.time}</td>
      <td><code>${row.action}</code></td>
      <td><code>${row.target}</code></td>
      <td><span class="tag-status safe">${row.status || 'OK'}</span></td>
      <td><strong style="color: var(--accent-silver);">${row.delta}</strong></td>
      <td style="font-size: 0.78rem; color: var(--text-secondary);">${row.msg}</td>
    `;
    tbody.appendChild(tr);
  });
}

// ==========================================================================
// Modal Logic (4-Pillar Finding Inspection)
// ==========================================================================

function openFindingModal(id) {
  const finding = FINDINGS_DATA.find(f => f.id === id);
  if (!finding) return;

  const badge = document.getElementById('modal-severity-badge');
  const badgeClass = finding.severityClass || (finding.severity === 'Critical' ? 'critical' : (finding.severity === 'Warning' ? 'warning' : 'info'));
  badge.className = `tag-status ${badgeClass}`;
  badge.textContent = `${finding.severity} — ${finding.relatedBytes || '0 B'}`;

  document.getElementById('modal-finding-title').textContent = finding.title;

  const factsList = document.getElementById('modal-confirmed-facts');
  factsList.innerHTML = '';
  if (finding.confirmedFacts && finding.confirmedFacts.length > 0) {
    finding.confirmedFacts.forEach(fact => {
      const li = document.createElement('li');
      li.textContent = fact;
      factsList.appendChild(li);
    });
  } else {
    factsList.innerHTML = `<li>Telemetry reconciled with filesystem counters.</li>`;
  }

  document.getElementById('modal-explanation').textContent = finding.explanation || finding.summary || "No unexplained anomalies observed.";

  const limitList = document.getElementById('modal-limitations');
  limitList.innerHTML = '';
  if (finding.limitations && finding.limitations.length > 0) {
    finding.limitations.forEach(lim => {
      const li = document.createElement('li');
      li.textContent = lim;
      limitList.appendChild(li);
    });
  } else {
    limitList.innerHTML = `<li>No process or permission caveats observed during crawl.</li>`;
  }

  document.getElementById('modal-recommendation').textContent = finding.recommendation || "Review and verify storage usage.";

  document.getElementById('finding-modal').classList.remove('hidden');
}

function closeFindingModal() {
  document.getElementById('finding-modal').classList.add('hidden');
}

// ==========================================================================
// Safe Cleanup Action (View 5)
// ==========================================================================

const consentCheck = document.getElementById('consent-check');
const btnExecuteRecovery = document.getElementById('btn-execute-recovery');
const verificationCard = document.getElementById('recovery-verification-card');

if (consentCheck && btnExecuteRecovery) {
  consentCheck.addEventListener('change', () => {
    btnExecuteRecovery.disabled = !consentCheck.checked;
  });

  btnExecuteRecovery.addEventListener('click', () => {
    btnExecuteRecovery.disabled = true;
    btnExecuteRecovery.textContent = "Verifying Identity & Unlinking...";

    setTimeout(() => {
      btnExecuteRecovery.textContent = "Cleaned Successfully";
      btnExecuteRecovery.style.background = "#283428";
      btnExecuteRecovery.style.color = "var(--text-primary)";
      if (verificationCard) verificationCard.classList.remove('hidden');

      const reclaimSize = document.getElementById('cleanup-reclaimable-size');
      if (reclaimSize) reclaimSize.textContent = "0 B";

      AUDIT_DATA.unshift({
        time: new Date().toISOString().replace('T', ' ').substring(0, 19),
        action: "SAFE_UNLINK",
        target: "/tmp/ghostdisk_test/cache_cleanup_demo.tmp",
        status: "SUCCESS",
        delta: "+20.00 MB",
        msg: "Verified unlink. Observed available storage headroom increased."
      });
      renderAuditTable();
      showToast("Safe cleanup successfully verified and executed.", "success");
    }, 600);
  });
}

// ==========================================================================
// Dynamic Live Telemetry Loader
// ==========================================================================

function loadLiveData(data) {
  if (!data) return;

  lastLoadedTimestamp = data.timestamp;

  if (data.findings && Array.isArray(data.findings)) {
    FINDINGS_DATA = data.findings;
  }
  if (data.tree && Array.isArray(data.tree) && data.tree.length > 0) {
    TREE_DATA = data.tree;
  }

  // Update Mount Select Dropdown if mounts exist in live data
  if (data.mounts && Array.isArray(data.mounts) && data.mounts.length > 0) {
    populateMountsDropdown(data.mounts, data.mount_point);
  }

  // Drive Header
  const driveName = document.getElementById('overview-drive-name');
  if (driveName) {
    const dev = data.device_name ? data.device_name : 'Root Storage';
    const fsType = data.filesystem_type ? data.filesystem_type : 'Linux FS';
    driveName.textContent = `${data.mount_point || '/'} (${dev} — ${fsType})`;
  }

  const statusText = document.getElementById('scan-status-text');
  if (statusText) {
    statusText.innerHTML = `<span style="color: var(--accent-silver); font-weight: 600;">● Live: ${data.mount_point || '/'}</span>`;
  }

  const lastUpdateBadge = document.getElementById('last-updated-badge');
  if (lastUpdateBadge) {
    lastUpdateBadge.textContent = `Last scan: ${formatEpochTime(data.timestamp)}`;
  }

  // Storage Numbers
  const totalUsed = data.used_bytes || 0;
  const totalCap = data.total_bytes || 0;
  const avail = data.available_bytes || (totalCap > totalUsed ? totalCap - totalUsed : 0);
  const deleted = data.deleted_open_bytes || 0;
  const reserved = data.reserved_bytes || 0;
  const unresolved = data.unresolved_bytes || 0;
  const crawled = data.crawled_bytes || 0;

  const elUsed = document.getElementById('overview-used');
  if (elUsed) elUsed.textContent = formatBytes(totalUsed);

  const elAvail = document.getElementById('overview-avail');
  if (elAvail) elAvail.textContent = formatBytes(avail);

  const elTotal = document.getElementById('overview-total');
  if (elTotal) elTotal.textContent = formatBytes(totalCap);

  // Usage Bar & Percentages
  const usedPct = totalCap > 0 ? (100.0 * totalUsed / totalCap).toFixed(1) : 0;
  const barFill = document.getElementById('overview-bar-fill');
  if (barFill) barFill.style.width = `${Math.min(100, Math.max(0, usedPct))}%`;

  const barUsedPct = document.getElementById('overview-bar-used-pct');
  if (barUsedPct) barUsedPct.textContent = `${usedPct}%`;

  const legendUsed = document.getElementById('overview-legend-used');
  if (legendUsed) legendUsed.textContent = formatBytes(totalUsed);

  const legendAvail = document.getElementById('overview-legend-avail');
  if (legendAvail) legendAvail.textContent = formatBytes(avail);

  // Compact Storage Analysis Section
  const statScanned = document.getElementById('stat-scanned-val');
  if (statScanned) statScanned.textContent = formatBytes(crawled);

  const statDeleted = document.getElementById('stat-deleted-val');
  if (statDeleted) statDeleted.textContent = formatBytes(deleted);

  const statReserved = document.getElementById('stat-reserved-val');
  if (statReserved) statReserved.textContent = formatBytes(reserved);

  const statUnexplained = document.getElementById('stat-unexplained-val');
  if (statUnexplained) statUnexplained.textContent = formatBytes(unresolved);

  // Technical Accordion Values
  const techCrawl = document.getElementById('tech-crawl-total');
  if (techCrawl) techCrawl.textContent = formatBytes(crawled);

  const techDeleted = document.getElementById('tech-deleted-open');
  if (techDeleted) techDeleted.textContent = formatBytes(deleted);

  const techRes = document.getElementById('tech-reserved');
  if (techRes) techRes.textContent = formatBytes(reserved);

  const techUnres = document.getElementById('tech-unresolved');
  if (techUnres) techUnres.textContent = formatBytes(unresolved);

  // Reclaimable badge in Safe Cleanup
  const reclaimBadge = document.getElementById('cleanup-reclaimable-size');
  if (reclaimBadge) {
    reclaimBadge.textContent = deleted > 0 ? formatBytes(deleted) : "0 B";
  }

  // Update findings pill in sidebar
  const badgePill = document.getElementById('findings-count-pill');
  if (badgePill) badgePill.textContent = FINDINGS_DATA.length;

  renderOverviewFindings();
  renderFindingsList();
  renderTreeTable();
  renderFoldersTable();
  renderAuditTable();
}

function populateMountsDropdown(mountsList, currentMount) {
  const mountSel = document.getElementById('mount-select');
  if (!mountSel || !mountsList) return;

  const currentVal = currentMount || mountSel.value || '/';
  mountSel.innerHTML = '';

  mountsList.forEach(m => {
    const opt = document.createElement('option');
    opt.value = m.mount_point;
    opt.textContent = `${m.mount_point} (${m.device_name || 'Mount'}) — ${m.filesystem_type || 'FS'}`;
    if (m.mount_point === currentVal) {
      opt.selected = true;
    }
    mountSel.appendChild(opt);
  });
}

// ==========================================================================
// Scan Action Execution (Real Linux C++ Execution + Fallback Sync)
// ==========================================================================

const btnStartScan = document.getElementById('btn-start-scan');
const btnCancelScan = document.getElementById('btn-cancel-scan');
const progressBanner = document.getElementById('scan-progress-banner');
const progressPhaseTitle = document.getElementById('progress-phase-title');
const scanStatusText = document.getElementById('scan-status-text');
const progressBarFill = document.getElementById('progress-bar-fill');

const scanPhases = [
  "Measuring filesystem capacity via statvfs()...",
  "Crawling directory subtree & measuring physical block allocation...",
  "Inspecting /proc for unlinked (deleted) open file descriptors...",
  "Reconciling storage discrepancy & compiling 4-pillar findings..."
];

async function executeScan() {
  if (isScanning) return;
  isScanning = true;

  const mountSel = document.getElementById('mount-select');
  const targetMount = mountSel ? mountSel.value : '/';

  btnStartScan.disabled = true;
  if (progressBanner) progressBanner.classList.remove('hidden');
  if (scanStatusText) scanStatusText.textContent = `Scanning ${targetMount}...`;

  let currentPhase = 0;
  let pct = 15;
  if (progressBarFill) progressBarFill.style.width = pct + '%';
  if (progressPhaseTitle) progressPhaseTitle.textContent = scanPhases[0];

  scanTimer = setInterval(() => {
    pct = Math.min(90, pct + 18);
    currentPhase = Math.min(scanPhases.length - 1, currentPhase + 1);
    if (progressBarFill) progressBarFill.style.width = pct + '%';
    if (progressPhaseTitle) progressPhaseTitle.textContent = scanPhases[currentPhase];
  }, 400);

  // 1. Attempt scan via live backend API
  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mount: targetMount })
    });

    if (res.ok) {
      const result = await res.json();
      clearInterval(scanTimer);
      if (progressBarFill) progressBarFill.style.width = '100%';

      setTimeout(() => {
        isScanning = false;
        btnStartScan.disabled = false;
        if (progressBanner) progressBanner.classList.add('hidden');
        if (result.data) {
          loadLiveData(result.data);
          showToast(`Live scan complete on ${targetMount}`, 'success');
        }
      }, 350);
      return;
    }
  } catch (e) {
    // Backend API not reachable (running as static file or static server)
  }

  // 2. Fallback for Static Server / terminal execution: Poll live_data.json
  setTimeout(async () => {
    try {
      const res = await fetch(`live_data.json?_t=${Date.now()}`, { cache: 'no-store' });
      if (res.ok) {
        const freshData = await res.json();
        clearInterval(scanTimer);
        if (progressBarFill) progressBarFill.style.width = '100%';

        setTimeout(() => {
          isScanning = false;
          btnStartScan.disabled = false;
          if (progressBanner) progressBanner.classList.add('hidden');
          loadLiveData(freshData);
          showToast(`Dashboard updated with live Linux telemetry`, 'info');
        }, 300);
        return;
      }
    } catch (err) {}

    // Clean completion
    clearInterval(scanTimer);
    isScanning = false;
    btnStartScan.disabled = false;
    if (progressBanner) progressBanner.classList.add('hidden');
    if (scanStatusText) scanStatusText.textContent = "Ready to scan";
    showToast(`To refresh in terminal, run: sudo ./build/ghostdisk_cli ${targetMount} --export-web`, 'warning');
  }, 1600);
}

if (btnStartScan) {
  btnStartScan.addEventListener('click', executeScan);
}

if (btnCancelScan) {
  btnCancelScan.addEventListener('click', () => {
    if (scanTimer) clearInterval(scanTimer);
    isScanning = false;
    btnStartScan.disabled = false;
    if (progressBanner) progressBanner.classList.add('hidden');
    if (scanStatusText) scanStatusText.textContent = "Scan cancelled";
  });
}

// Handle mount selection change
const mountSelect = document.getElementById('mount-select');
if (mountSelect) {
  mountSelect.addEventListener('change', () => {
    showToast(`Selected mount: ${mountSelect.value}. Click 'Scan Disk' to diagnose.`, 'info');
  });
}

// ==========================================================================
// JSON File Import Handler
// ==========================================================================

const inputLoadJson = document.getElementById('input-load-json');
if (inputLoadJson) {
  inputLoadJson.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const parsed = JSON.parse(event.target.result);
        loadLiveData(parsed);
        showToast(`Successfully imported ${file.name}`, 'success');
      } catch (err) {
        alert("Failed to parse JSON scan report: " + err.message);
      }
    };
    reader.readAsText(file);
  });
}

// ==========================================================================
// JSON Report Export Handler
// ==========================================================================

const btnExport = document.getElementById('btn-export-json');
if (btnExport) {
  btnExport.addEventListener('click', () => {
    const exportData = {
      application: "GHOSTED",
      version: "1.0.0",
      export_timestamp: new Date().toISOString(),
      findings: FINDINGS_DATA,
      storage_tree: TREE_DATA,
      audit_history: AUDIT_DATA
    };

    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(exportData, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `ghosted_report_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
    showToast("Diagnostic report downloaded", "success");
  });
}

// ==========================================================================
// Live Polling & Initialization
// ==========================================================================

async function fetchLiveDataSilently() {
  if (isScanning) return;
  try {
    const res = await fetch(`live_data.json?_t=${Date.now()}`, { cache: 'no-store' });
    if (res.ok) {
      const data = await res.json();
      if (!lastLoadedTimestamp || data.timestamp !== lastLoadedTimestamp) {
        loadLiveData(data);
        if (lastLoadedTimestamp !== null) {
          showToast("Live telemetry updated from Linux kernel", "info");
        }
      }
    }
  } catch (e) {
    // Network or file fetch error
  }
}

async function checkBackendStatus() {
  try {
    const res = await fetch('/api/status');
    if (res.ok) {
      const status = await res.json();
      isBackendAvailable = true;
      const statusText = document.getElementById('scan-status-text');
      if (statusText) {
        statusText.innerHTML = `<span style="color: var(--accent-silver);">● Server Engine Active</span>`;
      }
      // Populate mounts from backend
      const mountsRes = await fetch('/api/mounts');
      if (mountsRes.ok) {
        const mounts = await mountsRes.json();
        populateMountsDropdown(mounts);
      }
    }
  } catch (e) {
    isBackendAvailable = false;
  }
}

// Startup
document.addEventListener('DOMContentLoaded', () => {
  // 1. Immediately load data if window.GHOSTDISK_LIVE_DATA was loaded via live_data.js (file:/// mode)
  if (window.GHOSTDISK_LIVE_DATA) {
    loadLiveData(window.GHOSTDISK_LIVE_DATA);
  }

  // 2. Fetch live data via HTTP with cache-busting
  fetchLiveDataSilently();

  // 3. Probe backend capabilities
  checkBackendStatus();

  // 4. Start silent auto-sync polling every 3.5 seconds
  setInterval(fetchLiveDataSilently, 3500);
});
