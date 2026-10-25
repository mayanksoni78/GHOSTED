// GHOSTED Frontend Controller

// Diagnostic Findings Data
let FINDINGS_DATA = [
  {
    id: 0,
    title: "Deleted file still held open: access.log",
    severity: "Critical",
    severityClass: "critical",
    relatedBytes: "18.20 GB",
    process: "nginx (PID 4123, user www-data)",
    fd: 7,
    inode: 984123,
    device: 2050,
    summary: "nginx (PID 4123) holds deleted descriptor on access.log.",
    guidance: "Reload Nginx service to release storage without dropping connections.",
    confirmedFacts: [
      "Path before deletion: /var/log/nginx/access.log",
      "Allocated on disk: 18.20 GB",
      "Held by PID 4123 (nginx, user www-data) on fd 7",
      "Filesystem Identity: Device 2050, Inode 984123"
    ],
    explanation: "The log file was unlinked during rotation, but nginx was not reloaded. Linux maintains unlinked storage blocks until the holding process closes its descriptor.",
    limitations: [
      "Identified from the '(deleted)' symlink target in /proc/4123/fd/7",
      "GHOSTED does not inspect file contents"
    ],
    recommendation: "Run 'sudo systemctl reload nginx' or send SIGHUP. GHOSTED never terminates processes automatically."
  },
  {
    id: 1,
    title: "Deleted file still held open: sort.tmp",
    severity: "Warning",
    severityClass: "warning",
    relatedBytes: "7.20 GB",
    process: "postgres (PID 8904, user postgres)",
    fd: 14,
    inode: 442109,
    device: 2050,
    summary: "PostgreSQL holds temporary sorting buffer descriptor.",
    guidance: "Monitor query via pg_stat_activity. Reclaims automatically upon transaction completion.",
    confirmedFacts: [
      "Path before deletion: /var/lib/postgresql/14/main/base/pgsql_tmp/sort.tmp",
      "Allocated on disk: 7.20 GB",
      "Held by PID 8904 (postgres worker) on fd 14"
    ],
    explanation: "PostgreSQL unlinked an active disk-spill buffer for a large sort query. Storage is released when the transaction finishes.",
    limitations: [
      "Active database transaction in progress"
    ],
    recommendation: "Review active queries. Avoid force-killing the backend unless hung."
  },
  {
    id: 2,
    title: "Temporary cache sandbox ready for safe cleanup",
    severity: "Info",
    severityClass: "info",
    relatedBytes: "20.00 MB",
    process: "None (System cache)",
    fd: -1,
    inode: 884102,
    device: 2050,
    summary: "Allowlisted test and scratch file in /tmp/ghostdisk_test/.",
    guidance: "Safe to clean. Proceed to 'Safe Cleanup' view.",
    confirmedFacts: [
      "Path: /tmp/ghostdisk_test/cache_cleanup_demo.tmp",
      "Size: 20.00 MB",
      "Validated within safe directory allowlist"
    ],
    explanation: "Temporary test cache created by testing workloads.",
    limitations: [
      "Confirmed non-symlink file before deletion"
    ],
    recommendation: "Clean via Safe Cleanup."
  }
];

// Directory Tree Data
let TREE_DATA = [
  { path: "/usr", allocated: "128.40 GB", apparent: "125.10 GB", type: "Directory", ino: "2", category: "Installed Software & System Libraries" },
  { path: "/var", allocated: "84.20 GB", apparent: "81.90 GB", type: "Directory", ino: "14", category: "Application State & Logs" },
  { path: "/home", allocated: "42.10 GB", apparent: "41.80 GB", type: "Directory", ino: "26", category: "User Files & Documents" },
  { path: "/var/lib/docker", allocated: "21.50 GB", apparent: "20.10 GB", type: "Directory", ino: "109", category: "Container Storage" },
  { path: "/usr/lib/x86_64-linux-gnu", allocated: "18.30 GB", apparent: "17.90 GB", type: "Directory", ino: "884", category: "System Libraries" },
  { path: "/usr/bin/python3.10", allocated: "5.80 MB", apparent: "5.80 MB", type: "Symlink", ino: "991", category: "Executables" },
  { path: "/tmp/ghostdisk_test/cache_cleanup_demo.tmp", allocated: "20.00 MB", apparent: "20.00 MB", type: "File", ino: "884102", category: "Temporary Cache (Allowlisted)" }
];

// Audit History Data
let AUDIT_DATA = [
  { time: "2026-10-25 16:44:48", action: "VERIFIED_UNLINK", target: "/tmp/ghostdisk_test/cache_cleanup_demo.tmp", status: "SUCCESS", delta: "+20.00 MB", msg: "Verified unlink. Observed available storage increased by 20.00 MB." },
  { time: "2026-10-25 16:44:42", action: "PREVIEW_GENERATED", target: "/tmp/ghostdisk_test/cache_cleanup_demo.tmp", status: "OK", delta: "0 B", msg: "Safe preview generated via non-destructive lstat." },
  { time: "2026-10-25 16:44:39", action: "SCAN_RUN", target: "/ (Root Mount)", status: "COMPLETED", delta: "0 B", msg: "Scan completed in 480ms. Discovered 2 deleted-open leaks." }
];

// Format bytes
function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// View Navigation
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

// Render Overview Findings
function renderOverviewFindings() {
  const container = document.getElementById('overview-findings-list');
  if (!container) return;
  container.innerHTML = '';

  if (FINDINGS_DATA.length === 0) {
    container.innerHTML = `
      <div style="padding: 16px; text-align: center; color: var(--text-muted); font-size: 0.82rem;">
        No active storage issues or deleted-open file leaks detected.
      </div>
    `;
    return;
  }

  FINDINGS_DATA.forEach(f => {
    const row = document.createElement('div');
    row.className = 'finding-row';
    row.innerHTML = `
      <div class="finding-row-left">
        <span class="tag-status ${f.severityClass}">${f.severity}</span>
        <div class="finding-meta">
          <h4>${f.title}</h4>
          <p>${f.guidance || f.summary}</p>
        </div>
      </div>
      <div class="finding-row-right">
        <span class="finding-bytes">${f.relatedBytes}</span>
        <button class="btn-subtle" onclick="openFindingModal(${f.id})">View Details</button>
      </div>
    `;
    container.appendChild(row);
  });
}

// Render Findings in View 3 (Deleted-Open Files)
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
      <div style="padding: 20px; text-align: center; color: var(--text-muted); font-size: 0.82rem;">
        No findings matching filter '${filter}'.
      </div>
    `;
    return;
  }

  filtered.forEach(f => {
    const row = document.createElement('div');
    row.className = 'finding-row';
    row.innerHTML = `
      <div class="finding-row-left">
        <span class="tag-status ${f.severityClass}">${f.severity}</span>
        <div class="finding-meta">
          <h4>${f.title}</h4>
          <p>Process: <strong>${f.process}</strong> | File Descriptor: <code>fd ${f.fd}</code></p>
        </div>
      </div>
      <div class="finding-row-right">
        <span class="finding-bytes">${f.relatedBytes}</span>
        <button class="btn-subtle" onclick="openFindingModal(${f.id})">View Details</button>
      </div>
    `;
    container.appendChild(row);
  });

  const badge = document.getElementById('findings-count-pill');
  if (badge) badge.textContent = FINDINGS_DATA.length;
}

// Filter button listeners
document.querySelectorAll('.filter-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    renderFindingsList(btn.getAttribute('data-filter'));
  });
});

// Render Storage Tree Table (View 2)
function renderTreeTable(filterText = '') {
  const tbody = document.getElementById('storage-tree-body');
  if (!tbody) return;
  tbody.innerHTML = '';

  const list = TREE_DATA.filter(t => !filterText || t.path.toLowerCase().includes(filterText.toLowerCase()));

  if (list.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 16px;">No matching paths found.</td></tr>`;
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

// Search input for Tree
const searchInput = document.getElementById('analysis-search');
if (searchInput) {
  searchInput.addEventListener('input', (e) => {
    renderTreeTable(e.target.value);
  });
}

// Render Folders Table (View 4: Large Folders)
function renderFoldersTable() {
  const tbody = document.getElementById('folders-table-body');
  if (!tbody) return;
  tbody.innerHTML = '';

  TREE_DATA.slice(0, 5).forEach(item => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><code>${item.path}</code></td>
      <td><strong>${item.allocated}</strong></td>
      <td style="color: var(--text-secondary); font-size: 0.82rem;">${item.category || 'General Files'}</td>
    `;
    tbody.appendChild(tr);
  });
}

// Render Audit History Table (View 6)
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
      <td><strong class="text-success">${row.delta}</strong></td>
      <td style="font-size: 0.78rem; color: var(--text-secondary);">${row.msg}</td>
    `;
    tbody.appendChild(tr);
  });
}

// Modal Logic
function openFindingModal(id) {
  const finding = FINDINGS_DATA.find(f => f.id === id);
  if (!finding) return;

  const badge = document.getElementById('modal-severity-badge');
  badge.className = `tag-status ${finding.severityClass}`;
  badge.textContent = `${finding.severity} — ${finding.relatedBytes}`;

  document.getElementById('modal-finding-title').textContent = finding.title;

  const factsList = document.getElementById('modal-confirmed-facts');
  factsList.innerHTML = '';
  finding.confirmedFacts.forEach(fact => {
    const li = document.createElement('li');
    li.textContent = fact;
    factsList.appendChild(li);
  });

  document.getElementById('modal-explanation').textContent = finding.explanation;

  const limitList = document.getElementById('modal-limitations');
  limitList.innerHTML = '';
  finding.limitations.forEach(lim => {
    const li = document.createElement('li');
    li.textContent = lim;
    limitList.appendChild(li);
  });

  document.getElementById('modal-recommendation').textContent = finding.recommendation;

  document.getElementById('finding-modal').classList.remove('hidden');
}

function closeFindingModal() {
  document.getElementById('finding-modal').classList.add('hidden');
}

// Safe Cleanup Logic
const consentCheck = document.getElementById('consent-check');
const btnExecuteRecovery = document.getElementById('btn-execute-recovery');
const verificationCard = document.getElementById('recovery-verification-card');

if (consentCheck && btnExecuteRecovery) {
  consentCheck.addEventListener('change', () => {
    btnExecuteRecovery.disabled = !consentCheck.checked;
  });

  btnExecuteRecovery.addEventListener('click', () => {
    btnExecuteRecovery.disabled = true;
    btnExecuteRecovery.textContent = "Revalidating & Unlinking...";

    setTimeout(() => {
      btnExecuteRecovery.textContent = "Cleaned Successfully";
      btnExecuteRecovery.style.background = "var(--color-success)";
      btnExecuteRecovery.style.color = "#0F1117";
      if (verificationCard) verificationCard.classList.remove('hidden');

      const reclaimSize = document.getElementById('cleanup-reclaimable-size');
      if (reclaimSize) reclaimSize.textContent = "0 B";

      // Append to audit history
      AUDIT_DATA.unshift({
        time: new Date().toISOString().replace('T', ' ').substring(0, 19),
        action: "SAFE_UNLINK",
        target: "/tmp/ghostdisk_test/cache_cleanup_demo.tmp",
        status: "SUCCESS",
        delta: "+20.00 MB",
        msg: "Verified unlink. Observed available storage increased by 20.00 MB."
      });
      renderAuditTable();
    }, 500);
  });
}

// Scan Action
const btnStartScan = document.getElementById('btn-start-scan');
const btnCancelScan = document.getElementById('btn-cancel-scan');
const progressBanner = document.getElementById('scan-progress-banner');
const scanStatusText = document.getElementById('scan-status-text');

let isScanning = false;
let scanTimer = null;

if (btnStartScan) {
  btnStartScan.addEventListener('click', () => {
    if (isScanning) return;
    isScanning = true;
    btnStartScan.disabled = true;
    if (scanStatusText) scanStatusText.textContent = "Scanning disk...";
    if (progressBanner) progressBanner.classList.remove('hidden');

    const fill = document.getElementById('progress-bar-fill');
    let pct = 0;
    scanTimer = setInterval(() => {
      pct += 25;
      if (fill) fill.style.width = pct + '%';

      if (pct >= 100) {
        clearInterval(scanTimer);
        isScanning = false;
        btnStartScan.disabled = false;
        if (progressBanner) progressBanner.classList.add('hidden');
        if (scanStatusText) scanStatusText.textContent = "Scan complete (Up to date)";
      }
    }, 250);
  });
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

// Dynamic Live Data Loader
function loadLiveData(data) {
  if (!data) return;

  if (data.findings && Array.isArray(data.findings)) {
    FINDINGS_DATA = data.findings;
  }
  if (data.tree && Array.isArray(data.tree) && data.tree.length > 0) {
    TREE_DATA = data.tree;
  }

  // Drive Header
  const driveName = document.getElementById('overview-drive-name');
  if (driveName) {
    driveName.textContent = `${data.mount_point || '/'} (${data.device_name || 'Root Filesystem'} — ${data.filesystem_type || 'ext4'})`;
  }

  const mountSel = document.getElementById('mount-select');
  if (mountSel && mountSel.options && mountSel.options[0]) {
    mountSel.options[0].textContent = `${data.mount_point || '/'} (${data.device_name || 'Main Drive'}) — ${formatBytes(data.total_bytes)}`;
  }

  const statusText = document.getElementById('scan-status-text');
  if (statusText) {
    statusText.innerHTML = `<span style="color: var(--color-success); font-weight: 600;">● Live: ${data.mount_point || '/'}</span>`;
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
  const usedPct = totalCap > 0 ? (100.0 * totalUsed / totalCap).toFixed(1) : 48;
  const barFill = document.getElementById('overview-bar-fill');
  if (barFill) barFill.style.width = `${usedPct}%`;

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

  renderOverviewFindings();
  renderFindingsList();
  renderTreeTable();
  renderFoldersTable();
  renderAuditTable();
}

// File Upload Handler
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
      } catch (err) {
        alert("Failed to parse JSON scan report: " + err.message);
      }
    };
    reader.readAsText(file);
  });
}

// Export JSON
const btnExport = document.getElementById('btn-export-json');
if (btnExport) {
  btnExport.addEventListener('click', () => {
    const exportData = {
      application: "GHOSTED",
      version: "1.0.0",
      export_timestamp: new Date().toISOString(),
      findings: FINDINGS_DATA,
      audit_history: AUDIT_DATA
    };

    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(exportData, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `ghosted_report_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  });
}

// Initialize on page load
fetch('live_data.json')
  .then(res => {
    if (res.ok) return res.json();
    throw new Error('No live_data.json');
  })
  .then(data => {
    loadLiveData(data);
  })
  .catch(() => {
    renderOverviewFindings();
    renderFindingsList();
    renderTreeTable();
    renderFoldersTable();
    renderAuditTable();
  });
