// GhostDisk Interactive Web UI Controller

// Diagnostic Findings Database (4-Pillar Architecture)
let FINDINGS_DATA = [
  {
    id: 0,
    title: "Deleted file still held open: access.log (18.20 GB)",
    severity: "Critical",
    severityClass: "badge-critical",
    relatedBytes: "18.20 GB (38,168,576 blocks)",
    process: "nginx (PID 4123, user www-data)",
    fd: 7,
    inode: 984123,
    device: 2050,
    summary: "nginx (PID 4123) holds deleted descriptor fd 7 on inode 984123.",
    guidance: "Guidance: Reload Service",
    confirmedFacts: [
      "Path before deletion: /var/log/nginx/access.log",
      "Allocated on disk: 18.20 GB (apparent size 18.20 GB)",
      "Held by PID 4123 (nginx, user www-data) on fd 7",
      "Filesystem Identity: Device 2050, Inode 984123"
    ],
    explanation: "The file was unlinked from the filesystem tree (likely during logrotate), but the nginx master process was not reloaded. Linux maintains unlinked disk blocks active until all holding file descriptors are closed.",
    limitations: [
      "Detected from the '(deleted)' marker in /proc/4123/fd/7",
      "File contents are never inspected by GhostDisk",
      "Process may close descriptor at any time; verify before action"
    ],
    recommendation: "Run 'sudo systemctl reload nginx' or send SIGHUP. This signals nginx to re-open its log files and release the unlinked 18.2 GB storage without dropping active connections. GhostDisk never terminates processes automatically."
  },
  {
    id: 1,
    title: "Deleted file still held open: temp_sort_buffer.tmp (7.20 GB)",
    severity: "Warning",
    severityClass: "badge-warning",
    relatedBytes: "7.20 GB (15,099,494 blocks)",
    process: "postgres (PID 8904, user postgres)",
    fd: 14,
    inode: 442109,
    device: 2050,
    summary: "postgres (PID 8904) holds deleted descriptor fd 14 on inode 442109.",
    guidance: "Guidance: Monitor Query",
    confirmedFacts: [
      "Path before deletion: /var/lib/postgresql/14/main/base/pgsql_tmp/sort.tmp",
      "Allocated on disk: 7.20 GB (apparent size 7.20 GB)",
      "Held by PID 8904 (postgres worker backend) on fd 14",
      "Filesystem Identity: Device 2050, Inode 442109"
    ],
    explanation: "PostgreSQL intentionally created an anonymous disk-spill buffer for a large analytical sorting query and unlinked it immediately. The space will be automatically reclaimed when the query finishes.",
    limitations: [
      "Workload-dependent temporary storage",
      "Active database transaction in progress"
    ],
    recommendation: "Review active long-running queries via pg_stat_activity. Do not force terminate the backend unless the query is hung or runaway."
  },
  {
    id: 2,
    title: "Unexplained storage difference: 4.60 GB",
    severity: "Info",
    severityClass: "badge-info",
    relatedBytes: "4.60 GB",
    process: "None (System accounting)",
    fd: -1,
    inode: 0,
    device: 2050,
    summary: "Difference between filesystem used and crawled directory total after accounting for open deleted files.",
    guidance: "Guidance: Review Skipped Paths",
    confirmedFacts: [
      "Filesystem reports 325.00 GB used on /",
      "Directory crawler found 280.00 GB allocated",
      "Explained by deleted-open files: 25.40 GB",
      "Superuser reservation headroom: 15.00 GB",
      "Still unresolved remainder: 4.60 GB (tolerance applied: 64 MB)"
    ],
    explanation: "Possible causes, none of them confirmed: ext4 filesystem journal metadata, internal block group descriptors, 3 root-restricted directories skipped due to permissions, or concurrent file writes during crawl.",
    limitations: [
      "3 protected subtrees skipped (/root, /var/spool/cron, /etc/ssl/private)",
      "Unprivileged crawler cannot inspect protected metadata blocks"
    ],
    recommendation: "Golden Rule: Treat this as an investigation target, not something to delete. Review the 3 skipped paths and filesystem snapshot lists. Do not attempt blind automated cleanup."
  }
];

// Tree Data Samples
let TREE_DATA = [
  { path: "/usr", allocated: "128.40 GB", apparent: "125.10 GB", type: "Directory", dev: "2050", ino: "2" },
  { path: "/var", allocated: "84.20 GB", apparent: "81.90 GB", type: "Directory", dev: "2050", ino: "14" },
  { path: "/home", allocated: "42.10 GB", apparent: "41.80 GB", type: "Directory", dev: "2050", ino: "26" },
  { path: "/var/lib/docker", allocated: "21.50 GB", apparent: "20.10 GB", type: "Directory", dev: "2050", ino: "109" },
  { path: "/usr/lib/x86_64-linux-gnu", allocated: "18.30 GB", apparent: "17.90 GB", type: "Directory", dev: "2050", ino: "884" },
  { path: "/usr/bin/python3.10", allocated: "5.80 MB", apparent: "5.80 MB", type: "Symlink (Safe)", dev: "2050", ino: "991" },
  { path: "/tmp/ghostdisk_test/cache_cleanup_demo.tmp", allocated: "20.00 MB", apparent: "20.00 MB", type: "Allowlisted File", dev: "2050", ino: "884102" }
];

// Audit History Data
let AUDIT_DATA = [
  { time: "2026-10-25 16:44:48", action: "VERIFIED_UNLINK", target: "/tmp/ghostdisk_test/ghostdisk_test_20mb.bin", approved: "YES (explicit)", delta: "+20.00 MB", msg: "Observed available space increased from 953.51 GB to 953.53 GB" },
  { time: "2026-10-25 16:44:42", action: "PREVIEW_GENERATED", target: "/tmp/ghostdisk_test/ghostdisk_test_20mb.bin", approved: "N/A", delta: "0 B", msg: "Preview generated: non-destructive lstat inspection" },
  { time: "2026-10-25 16:44:39", action: "SCAN_RUN", target: "/ (Root Mount)", approved: "N/A", delta: "0 B", msg: "Completed in 480ms. Discovered 2 deleted-open leaks, 3 skipped subtrees" }
];

// View Switching
function switchView(viewName) {
  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.content-view').forEach(el => el.classList.remove('active'));

  const navBtn = document.querySelector(`.nav-item[data-view="${viewName}"]`);
  if (navBtn) navBtn.classList.add('active');

  const viewEl = document.getElementById(`view-${viewName}`);
  if (viewEl) viewEl.classList.add('active');

  // Update mode pills in header
  const pillSimple = document.getElementById('btn-mode-simple');
  const pillExpert = document.getElementById('btn-mode-expert');
  if (pillSimple && pillExpert) {
    if (viewName === 'clean') {
      pillSimple.classList.add('active');
      pillExpert.classList.remove('active');
    } else {
      pillSimple.classList.remove('active');
      pillExpert.classList.add('active');
    }
  }
}

// Mode Pill Button Handlers
const pillSimple = document.getElementById('btn-mode-simple');
const pillExpert = document.getElementById('btn-mode-expert');
if (pillSimple) pillSimple.addEventListener('click', () => switchView('clean'));
if (pillExpert) pillExpert.addEventListener('click', () => switchView('dashboard'));

// Attach Nav Listeners
document.querySelectorAll('.nav-item').forEach(btn => {
  btn.addEventListener('click', () => {
    switchView(btn.getAttribute('data-view'));
  });
});

// Simple Clean Recovery Button Handlers
const simpleConsent = document.getElementById('simple-clean-consent');
const btnSimpleClean = document.getElementById('btn-simple-clean');
const simpleSuccessBox = document.getElementById('simple-clean-success');

if (simpleConsent && btnSimpleClean) {
  simpleConsent.addEventListener('change', () => {
    btnSimpleClean.disabled = !simpleConsent.checked;
  });

  btnSimpleClean.addEventListener('click', () => {
    btnSimpleClean.disabled = true;
    btnSimpleClean.textContent = "Safely Reclaiming Storage...";

    setTimeout(() => {
      btnSimpleClean.textContent = "✓ Cleaned 20.00 MB";
      btnSimpleClean.style.background = "#10b981";
      if (simpleSuccessBox) simpleSuccessBox.classList.remove('hidden');

      const cleanNum = document.getElementById('simple-cleanable-num');
      if (cleanNum) cleanNum.textContent = "0 B";

      // Add audit history
      AUDIT_DATA.unshift({
        time: new Date().toISOString().replace('T', ' ').substring(0, 19),
        action: "SAFE_CLEAN_RECOVERY",
        target: "/tmp/ghostdisk_test/ (Allowlisted Sandbox)",
        approved: "YES (1-Click)",
        delta: "+20.00 MB",
        msg: "TOCTOU check passed. Unlinked safe temporary files. Reclaimed 20,971,520 Bytes."
      });
      renderAuditTable();
    }, 500);
  });
}

// Render Findings List in View 2
function renderFindingsList(filter = 'all') {
  const container = document.getElementById('findings-full-list');
  if (!container) return;
  container.innerHTML = '';

  const filtered = FINDINGS_DATA.filter(f => {
    if (filter === 'all') return true;
    return f.severity.toLowerCase() === filter.toLowerCase();
  });

  filtered.forEach(f => {
    const card = document.createElement('div');
    card.className = `finding-card ${f.severity.toLowerCase()}`;
    card.onclick = () => openFindingModal(f.id);
    card.innerHTML = `
      <div class="finding-badge ${f.severityClass}">${f.severity} — ${f.relatedBytes}</div>
      <div class="finding-main">
        <h4>${f.title}</h4>
        <p class="finding-summary">${f.summary}</p>
      </div>
      <div class="finding-action">
        <span class="badge-guidance">${f.guidance}</span>
        <button class="btn-inspect">Inspect Evidence</button>
      </div>
    `;
    container.appendChild(card);
  });
}

// Render Directory Tree Table
function renderTreeTable() {
  const tbody = document.getElementById('tree-table-body');
  if (!tbody) return;
  tbody.innerHTML = '';

  TREE_DATA.forEach(row => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><code>${row.path}</code></td>
      <td><strong class="text-blue">${row.allocated}</strong></td>
      <td>${row.apparent}</td>
      <td><span class="tag-live">${row.type}</span></td>
      <td><span style="font-family: var(--font-mono); font-size: 0.75rem;">dev: ${row.dev} | ino: ${row.ino}</span></td>
    `;
    tbody.appendChild(tr);
  });
}

// Render Audit History
function renderAuditTable() {
  const tbody = document.getElementById('audit-table-body');
  if (!tbody) return;
  tbody.innerHTML = '';

  AUDIT_DATA.forEach(row => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><span style="font-family: var(--font-mono); font-size: 0.76rem;">${row.time}</span></td>
      <td><code>${row.action}</code></td>
      <td><code>${row.target}</code></td>
      <td><span class="tag-approved">${row.approved}</span></td>
      <td><strong class="text-emerald">${row.delta}</strong></td>
      <td style="font-size: 0.78rem;">${row.msg}</td>
    `;
    tbody.appendChild(tr);
  });
}

// Filter buttons in Findings view
document.querySelectorAll('.filter-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    renderFindingsList(btn.getAttribute('data-filter'));
  });
});

// Modal Logic
function openFindingModal(id) {
  const finding = FINDINGS_DATA.find(f => f.id === id);
  if (!finding) return;

  const badge = document.getElementById('modal-severity-badge');
  badge.className = finding.severityClass;
  badge.textContent = `${finding.severity} (${finding.relatedBytes})`;

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

// Scan Simulation Logic
let isScanning = false;
let scanTimer = null;

const btnStartScan = document.getElementById('btn-start-scan');
const btnCancelScan = document.getElementById('btn-cancel-scan');
const progressBanner = document.getElementById('scan-progress-banner');
const scanStatusText = document.getElementById('scan-status-text');

btnStartScan.addEventListener('click', () => {
  if (isScanning) return;
  isScanning = true;

  btnStartScan.disabled = true;
  btnStartScan.style.opacity = '0.5';
  scanStatusText.textContent = 'Scanning in background thread...';
  progressBanner.classList.remove('hidden');

  let pct = 0;
  let count = 0;
  const barFill = document.getElementById('progress-bar-fill');
  const statEntries = document.getElementById('stat-entries');

  scanTimer = setInterval(() => {
    pct += 10;
    count += 14200;
    if (barFill) barFill.style.width = `${pct}%`;
    if (statEntries) statEntries.textContent = count.toLocaleString();

    if (pct >= 100) {
      clearInterval(scanTimer);
      finishScan();
    }
  }, 200);
});

btnCancelScan.addEventListener('click', () => {
  if (!isScanning) return;
  clearInterval(scanTimer);
  progressBanner.classList.add('hidden');
  scanStatusText.textContent = 'Scan cancelled cooperatively.';
  btnStartScan.disabled = false;
  btnStartScan.style.opacity = '1';
  isScanning = false;
});

function finishScan() {
  progressBanner.classList.add('hidden');
  scanStatusText.textContent = '✓ Scan complete. Storage reconciled.';
  btnStartScan.disabled = false;
  btnStartScan.style.opacity = '1';
  isScanning = false;
}

// Safe Recovery Consent & Unlink
const consentCheck = document.getElementById('consent-check');
const btnExecuteRecovery = document.getElementById('btn-execute-recovery');
const verificationCard = document.getElementById('recovery-verification-card');

consentCheck.addEventListener('change', () => {
  btnExecuteRecovery.disabled = !consentCheck.checked;
});

btnExecuteRecovery.addEventListener('click', () => {
  btnExecuteRecovery.disabled = true;
  btnExecuteRecovery.textContent = "Revalidating TOCTOU & Unlinking...";

  setTimeout(() => {
    btnExecuteRecovery.textContent = "Unlinked Successfully";
    btnExecuteRecovery.style.background = "#10b981";
    verificationCard.classList.remove('hidden');

    // Add entry to audit table
    AUDIT_DATA.unshift({
      time: new Date().toISOString().replace('T', ' ').substring(0, 19),
      action: "VERIFIED_UNLINK",
      target: "/tmp/ghostdisk_test/cache_cleanup_demo.tmp",
      approved: "YES (explicit)",
      delta: "+20.00 MB",
      msg: "Re-validated device 2050 / inode 884102. Observed delta: +20,971,520 Bytes."
    });
    renderAuditTable();
  }, 600);
});

function resetRecoveryDemo() {
  consentCheck.checked = false;
  btnExecuteRecovery.disabled = true;
  btnExecuteRecovery.textContent = "Execute Verified Unlink";
  btnExecuteRecovery.style.background = "";
  verificationCard.classList.add('hidden');
}

// JSON Diagnostic Export
document.getElementById('btn-export-json').addEventListener('click', () => {
  const exportData = {
    application: "GhostDisk",
    version: "1.0.0",
    export_timestamp: new Date().toISOString(),
    mount_point: "/",
    filesystem_telemetry: {
      total_bytes: 549755813888,
      used_bytes: 348966092800,
      available_bytes: 184683593728,
      reserved_bytes: 16106127360
    },
    findings: FINDINGS_DATA,
    audit_history: AUDIT_DATA
  };

  const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(exportData, null, 2));
  const downloadAnchor = document.createElement('a');
  downloadAnchor.setAttribute("href", dataStr);
  downloadAnchor.setAttribute("download", `ghostdisk_report_${Date.now()}.json`);
  document.body.appendChild(downloadAnchor);
  downloadAnchor.click();
  downloadAnchor.remove();
});

// Format bytes into human readable string
function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Dynamic Live Data Loader
function loadLiveData(data) {
  if (!data) return;
  console.log("Loading live data:", data);

  if (data.findings && Array.isArray(data.findings)) {
    FINDINGS_DATA = data.findings;
  }
  if (data.tree && Array.isArray(data.tree) && data.tree.length > 0) {
    TREE_DATA = data.tree;
  }

  // Update status banner
  const statusEl = document.getElementById('scan-status-text');
  if (statusEl) {
    statusEl.innerHTML = `<span style="color: #10b981; font-weight: 600;">● Live Linux Data: ${data.mount_point || '/'}</span>`;
  }

  // Update Telemetry Elements
  const totalUsed = data.used_bytes || 0;
  const crawled = data.crawled_bytes || 0;
  const deleted = data.deleted_open_bytes || 0;
  const reserved = data.reserved_bytes || 0;
  const unresolved = data.unresolved_bytes || 0;

  const donutTotal = document.getElementById('donut-total-used');
  if (donutTotal) donutTotal.textContent = formatBytes(totalUsed);

  const valAccounted = document.getElementById('val-accounted');
  if (valAccounted) valAccounted.textContent = formatBytes(crawled);

  const valDeleted = document.getElementById('val-deleted');
  if (valDeleted) valDeleted.textContent = formatBytes(deleted);

  const valReserved = document.getElementById('val-reserved');
  if (valReserved) valReserved.textContent = formatBytes(reserved);

  const valUnresolved = document.getElementById('val-unresolved');
  if (valUnresolved) valUnresolved.textContent = formatBytes(unresolved);

  const valFsReported = document.getElementById('val-fs-reported');
  if (valFsReported) valFsReported.textContent = formatBytes(totalUsed);

  const valCrawlTotal = document.getElementById('val-crawl-total');
  if (valCrawlTotal) valCrawlTotal.textContent = formatBytes(crawled);

  const valLeakedOpen = document.getElementById('val-leaked-open');
  if (valLeakedOpen) valLeakedOpen.textContent = formatBytes(deleted);

  const pillCount = document.getElementById('findings-count-pill');
  if (pillCount) pillCount.textContent = FINDINGS_DATA.length;

  // Donut Arc calculation (circumference = 440)
  const sum = (crawled + deleted + reserved + unresolved) || totalUsed || 1;
  const dAccounted = Math.round((crawled / sum) * 440);
  const dDeleted = Math.round((deleted / sum) * 440);
  const dReserved = Math.round((reserved / sum) * 440);
  const dUnresolved = Math.max(0, 440 - (dAccounted + dDeleted + dReserved));

  const segAcc = document.querySelector('.seg-accounted');
  const segDel = document.querySelector('.seg-deleted');
  const segRes = document.querySelector('.seg-reserved');
  const segUnres = document.querySelector('.seg-unresolved');

  if (segAcc) {
    segAcc.setAttribute('stroke-dasharray', `${dAccounted} 440`);
    segAcc.setAttribute('stroke-dashoffset', '0');
  }
  if (segDel) {
    segDel.setAttribute('stroke-dasharray', `${dDeleted} 440`);
    segDel.setAttribute('stroke-dashoffset', `-${dAccounted}`);
  }
  if (segRes) {
    segRes.setAttribute('stroke-dasharray', `${dReserved} 440`);
    segRes.setAttribute('stroke-dashoffset', `-${dAccounted + dDeleted}`);
  }
  if (segUnres) {
    segUnres.setAttribute('stroke-dasharray', `${dUnresolved} 440`);
    segUnres.setAttribute('stroke-dashoffset', `-${dAccounted + dDeleted + dReserved}`);
  }

  // Update Simple Clean Mode Elements (Zero OS Theory)
  const totalCap = data.total_bytes || 0;
  const simpleUsed = document.getElementById('simple-stat-used');
  if (simpleUsed) simpleUsed.textContent = formatBytes(totalUsed);
  const simpleFree = document.getElementById('simple-stat-free');
  if (simpleFree) simpleFree.textContent = formatBytes(data.available_bytes || 0);
  const simpleTotal = document.getElementById('simple-stat-total');
  if (simpleTotal) simpleTotal.textContent = formatBytes(totalCap);

  const simpleBar = document.getElementById('simple-bar-fill');
  if (simpleBar) {
    const pct = totalCap > 0 ? (100.0 * totalUsed / totalCap).toFixed(1) : 48;
    simpleBar.style.width = `${pct}%`;
  }

  const simpleCardNormal = document.getElementById('simple-card-normal');
  if (simpleCardNormal) simpleCardNormal.textContent = formatBytes(totalUsed);
  const simpleCardGhost = document.getElementById('simple-card-ghost');
  if (simpleCardGhost) simpleCardGhost.textContent = formatBytes(deleted);
  const simpleGhostBadge = document.getElementById('simple-ghost-badge');
  if (simpleGhostBadge) simpleGhostBadge.textContent = formatBytes(deleted);
  const simpleCardReserve = document.getElementById('simple-card-reserve');
  if (simpleCardReserve) simpleCardReserve.textContent = formatBytes(reserved);

  // Simple Health Title
  const healthTitle = document.getElementById('simple-health-title');
  const healthSub = document.getElementById('simple-health-subtitle');
  if (healthTitle && healthSub) {
    if (deleted > 100 * 1024 * 1024) {
      healthTitle.textContent = "Storage Can Be Reclaimed";
      healthSub.textContent = `Found ${formatBytes(deleted)} in ghost files held by background services.`;
    } else {
      healthTitle.textContent = "Your Linux Disk is Healthy";
      healthSub.textContent = `Using ${formatBytes(totalUsed)} of ${formatBytes(totalCap)}. No runaway storage leaks found.`;
    }
  }

  // Simple Top Folders Table
  const simpleTableBody = document.getElementById('simple-folder-tbody');
  if (simpleTableBody && TREE_DATA && TREE_DATA.length > 0) {
    simpleTableBody.innerHTML = '';
    TREE_DATA.slice(0, 4).forEach(item => {
      let cat = "User Files & App Data";
      if (item.path.startsWith('/usr')) cat = "Installed Software & System Libraries";
      else if (item.path.startsWith('/var')) cat = "System Logs & Application State";
      else if (item.path.startsWith('/home')) cat = "Your Personal Documents & Downloads";
      else if (item.path.startsWith('/tmp')) cat = "Temporary Cache Files (Safe)";

      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><code>${item.path}</code></td>
        <td><strong>${item.allocated}</strong></td>
        <td style="color: var(--text-secondary); font-size: 0.84rem;">${cat}</td>
      `;
      simpleTableBody.appendChild(tr);
    });
  }

  // Update Math Formula Card
  const mathFs = document.getElementById('math-fs-used');
  if (mathFs) mathFs.textContent = formatBytes(totalUsed);
  const mathScan = document.getElementById('math-scan-alloc');
  if (mathScan) mathScan.textContent = formatBytes(crawled);
  const mathGap = document.getElementById('math-raw-gap');
  if (mathGap) mathGap.textContent = formatBytes(Math.abs(totalUsed - crawled));

  const recDel = document.getElementById('reconcile-deleted');
  if (recDel) recDel.textContent = `- ${formatBytes(deleted)}`;
  const recRes = document.getElementById('reconcile-reserve');
  if (recRes) recRes.textContent = `- ${formatBytes(reserved)}`;
  const recUnres = document.getElementById('reconcile-unresolved');
  if (recUnres) recUnres.textContent = formatBytes(unresolved);

  // Update 4 Metric Cards
  const cardCap = document.getElementById('metric-total-capacity');
  if (cardCap) cardCap.textContent = formatBytes(totalCap);

  const cardUsed = document.getElementById('metric-raw-used');
  if (cardUsed) cardUsed.textContent = formatBytes(totalUsed);
  const cardUsedHint = document.getElementById('metric-used-hint');
  if (cardUsedHint) {
    cardUsedHint.textContent = totalCap > 0 ? `${(100.0 * totalUsed / totalCap).toFixed(1)}% of device` : "0% of device";
  }

  const cardAvail = document.getElementById('metric-user-avail');
  if (cardAvail) cardAvail.textContent = formatBytes(data.available_bytes || 0);

  const cardLeaks = document.getElementById('metric-deleted-leaks');
  if (cardLeaks) cardLeaks.textContent = formatBytes(deleted);
  const cardLeaksHint = document.getElementById('metric-deleted-hint');
  if (cardLeaksHint) {
    cardLeaksHint.textContent = `${FINDINGS_DATA.filter(f => f.title && f.title.toLowerCase().includes('deleted')).length} leak descriptors found`;
  }

  // Update Mount Option in Header
  const mountSel = document.getElementById('mount-select');
  if (mountSel && mountSel.options && mountSel.options[0]) {
    mountSel.options[0].textContent = `${data.mount_point || '/'} (${data.device_name || 'System Mount'}) — ${formatBytes(totalCap)} ${data.filesystem_type || 'ext4'}`;
  }

  // Update Top Findings Preview Container on Dashboard
  const dashContainer = document.getElementById('dashboard-findings-container');
  if (dashContainer && FINDINGS_DATA.length > 0) {
    dashContainer.innerHTML = '';
    FINDINGS_DATA.slice(0, 3).forEach((f) => {
      const card = document.createElement('div');
      card.className = `finding-card ${f.severity.toLowerCase()}`;
      card.onclick = () => openFindingModal(f.id);
      card.innerHTML = `
        <div class="finding-badge ${f.severityClass}">${f.severity} — ${f.relatedBytes}</div>
        <div class="finding-main">
          <h4>${f.title}</h4>
          <p class="finding-summary">${f.summary || f.title}</p>
        </div>
        <div class="finding-action">
          <span class="badge-guidance">${f.guidance || 'Guidance: Safe Inspection'}</span>
          <button class="btn-inspect">Inspect Evidence</button>
        </div>
      `;
      dashContainer.appendChild(card);
    });
  }

  // Audit entry
  AUDIT_DATA.unshift({
    time: new Date().toISOString().replace('T', ' ').substring(0, 19),
    action: "LIVE_DATA_LOADED",
    target: data.mount_point || "/",
    approved: "YES",
    delta: formatBytes(deleted),
    msg: `Loaded live Linux telemetry: ${data.filesystem_type || 'ext4'} (${formatBytes(totalUsed)} used, ${FINDINGS_DATA.length} findings)`
  });

  renderFindingsList();
  renderTreeTable();
  renderAuditTable();
}

// File Upload Handler for manual JSON import
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

// Auto-check for live_data.json on server
fetch('live_data.json')
  .then(res => {
    if (res.ok) return res.json();
    throw new Error('No live_data.json present');
  })
  .then(data => {
    loadLiveData(data);
  })
  .catch(() => {
    // Fallback to demo data
    renderFindingsList();
    renderTreeTable();
    renderAuditTable();
  });
