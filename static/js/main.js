/* =========================================================
   Scan Oasis — Frontend JS
   ========================================================= */

// Module-level refs kept so runCVEAnalysis() can update the status bar
let _dot           = null;
let _statusLbl     = null;
let _lastReport    = null;
let _cveData       = null;   // set by runCVEAnalysis; used by topology map
let _savedTopology = null;   // set when saved data is loaded from Firestore

// Called by Firebase module once saved scan data is fetched from Firestore
window.__onSavedDataReady = function(data) {
  if (!data) return;
  if (Array.isArray(data.cves)) {
    _cveData = { cves: data.cves, counts: data.counts };
    populateCVEs(data.cves, data.counts);
  }
  if (data.topology) _savedTopology = data.topology;
};

/* --- Toast notifications --- */
window.showToast = function (msg, type = 'info', opts = {}) {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    document.body.appendChild(container);
  }
  const icons = { info: 'ℹ', success: '✓', warning: '⚠', error: '✕', loading: '◴' };
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `<span class="toast-icon"></span><span class="toast-msg"></span>` +
                    `<button class="toast-close" aria-label="Dismiss">✕</button>`;
  toast.querySelector('.toast-icon').textContent = icons[type] ?? icons.info;
  toast.querySelector('.toast-msg').textContent  = msg;

  let timer = null;
  const close = () => {
    if (timer) { clearTimeout(timer); timer = null; }
    toast.classList.remove('toast-show');
    setTimeout(() => toast.remove(), 220);
  };
  toast.querySelector('.toast-close').addEventListener('click', close);
  container.appendChild(toast);
  requestAnimationFrame(() => toast.classList.add('toast-show'));

  const arm = (t) => {
    const dur = opts.duration ?? (t === 'error' ? 6000 : t === 'loading' ? 0 : 3500);
    if (dur > 0) timer = setTimeout(close, dur);
  };
  arm(type);

  return {
    dismiss: close,
    update: (newMsg, newType = type) => {
      if (timer) { clearTimeout(timer); timer = null; }
      toast.className = `toast toast-${newType} toast-show`;
      toast.querySelector('.toast-icon').textContent = icons[newType] ?? icons.info;
      toast.querySelector('.toast-msg').textContent  = newMsg;
      arm(newType);
    },
  };
};

/* --- CVE impact classification (mirrors cve_lookup.py; used as fallback) --- */
const _CVE_TYPE_INFO = {
  RCE:       { label: 'Remote Code Exec',  cls: 'cve-type-rce'      },
  DoS:       { label: 'Denial of Service', cls: 'cve-type-dos'      },
  EscPriv:   { label: 'Privilege Esc',     cls: 'cve-type-escpriv'  },
  InfoDisc:  { label: 'Info Disclosure',   cls: 'cve-type-infodisc' },
  XSS:       { label: 'Cross-Site Script', cls: 'cve-type-xss'      },
  SQLi:      { label: 'SQL Injection',     cls: 'cve-type-sqli'     },
  Overflow:  { label: 'Memory Overflow',   cls: 'cve-type-overflow' },
  Bypass:    { label: 'Auth/ACL Bypass',   cls: 'cve-type-bypass'   },
  Traversal: { label: 'Path Traversal',    cls: 'cve-type-traversal'},
  UAF:       { label: 'Use-After-Free',    cls: 'cve-type-uaf'      },
  Corrupt:   { label: 'Memory Corruption', cls: 'cve-type-corrupt'  },
};
const _CVE_TYPE_KW = [
  ['RCE',       ['arbitrary code execution', 'remote code execution', 'code execution', 'execute arbitrary']],
  ['DoS',       ['denial of service', 'memory exhaustion', 'null pointer', 'infinite loop', 'crash', 'out of memory', 'resource exhaustion']],
  ['EscPriv',   ['privilege escalation', 'gain root', 'local privilege', 'escalation of privilege', 'gain elevated']],
  ['InfoDisc',  ['information disclosure', 'sensitive information', 'memory leak', 'data leak', 'information leak', 'uninitialized memory']],
  ['XSS',       ['cross-site scripting', ' xss', 'html injection', 'script injection']],
  ['SQLi',      ['sql injection']],
  ['Overflow',  ['buffer overflow', 'stack overflow', 'heap overflow', 'integer overflow', 'out-of-bounds write', 'stack-based buffer', 'heap-based buffer']],
  ['Bypass',    ['bypass', 'authentication bypass', 'access control bypass', 'improper authentication']],
  ['Traversal', ['directory traversal', 'path traversal']],
  ['UAF',       ['use after free', 'use-after-free']],
  ['Corrupt',   ['memory corruption', 'heap corruption', 'type confusion']],
];
function cveType(c) {
  if (c.type) return c.type;
  const t = (c.summary || '').toLowerCase();
  for (const [label, kws] of _CVE_TYPE_KW) if (kws.some(k => t.includes(k))) return label;
  return '';
}
function cveVector(c) {
  if (c.vector) return c.vector;
  const t = (c.summary || '').toLowerCase();
  const remote = ['remote', 'network', 'unauthenticated', 'internet', 'http', 'web server', 'listening', 'socket', 'tcp', 'udp', 'attacker-controlled'];
  const local  = ['local user', 'local attacker', 'local access', 'physical access', 'console access', 'authenticated local'];
  if (remote.some(k => t.includes(k))) return 'REMOTE';
  if (local.some(k => t.includes(k)))  return 'LOCAL';
  return '';
}
function cveImpactLabel(c) {
  const info = _CVE_TYPE_INFO[cveType(c)];
  return info ? info.label : 'Other';
}
function _cveBadgesHtml(c) {
  const info = _CVE_TYPE_INFO[cveType(c)];
  const vec  = cveVector(c);
  const parts = [];
  parts.push(info
    ? `<span class="cve-type ${info.cls}">${info.label}</span>`
    : `<span class="cve-type cve-type-bypass">Other</span>`);
  if (vec) parts.push(`<span class="cve-vector cve-vector-${vec.toLowerCase()}">${vec}</span>`);
  return `<div class="cve-badges">${parts.join('')}</div>`;
}

/* --- Nav --- */
document.querySelectorAll('.nav-item[data-section]').forEach(item => {
  item.addEventListener('click', () => {
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    item.classList.add('active');
    const target = item.dataset.section;
    document.querySelectorAll('.page-section').forEach(s => s.classList.add('hidden'));
    const el = document.getElementById(target);
    if (el) { el.classList.remove('hidden'); el.scrollIntoView({ behavior: 'smooth', block: 'start' }); }
    if (target === 'section-topology') {
      if (_lastReport) {
        runTopologyBuild();
      } else {
        const topo = _savedTopology || window.__savedData?.topology;
        const cvs  = _cveData       || (window.__savedData ? { cves: window.__savedData.cves, counts: window.__savedData.counts } : null);
        if (topo) runTopologyFromSaved(topo, cvs);
      }
    }
    if (target === 'section-devices' && window.__deviceCache) {
      buildDeviceNetworkMap(Object.values(window.__deviceCache));
    }
    if (target === 'section-cves') {
      if (!_cveData && window.__savedData?.cves?.length > 0) {
        _cveData = { cves: window.__savedData.cves, counts: window.__savedData.counts };
      }
      renderAllCVEs();
    }
    if (target === 'section-patches') {
      if (!_cveData && window.__savedData?.cves?.length > 0) {
        _cveData = { cves: window.__savedData.cves, counts: window.__savedData.counts };
      }
      renderPatches();
    }
    if (target === 'section-apps') {
      _renderAppsToolbar();
      if (!_lastReport && !Object.keys(_appCache).length) {
        if (typeof window.__loadPackages === 'function') {
          window.__loadPackages().then(data => {
            if (data) _populateApps(data.packages, data.foreign, data.count, data.manager, ' · from last scan');
          });
        }
      }
    }
    if (target === 'section-integrity') {
      // Load all devices that have integrity data and build selector
      if (typeof window.__loadIntegrityDevices === 'function') {
        window.__loadIntegrityDevices().then(async devices => {
          if (devices.length <= 1) return;
          const toolbar = document.getElementById('integrity-toolbar');
          const chipBox = document.getElementById('integrity-dev-chips');
          if (!toolbar || !chipBox) return;
          // Build chips for all devices with integrity data
          const currentHost = _lastReport?.os?.hostname || window.__savedData?.hostname;
          const prefix = `<span style="font-size:11px;color:var(--text-muted);margin-right:4px">Device:</span>`;
          chipBox.innerHTML = prefix + devices.map(d => {
            const tag    = window.__deviceTags?.[d.hostname] || '';
            const active = d.hostname === currentHost ? ' active' : '';
            return `<button class="sec-dev-chip${active}" data-host="${escapeHtml(d.hostname)}">${escapeHtml(tag || d.hostname)}</button>`;
          }).join('');
          toolbar.classList.remove('hidden');
          chipBox.querySelectorAll('.sec-dev-chip[data-host]').forEach(chip => {
            chip.addEventListener('click', async () => {
              chipBox.querySelectorAll('.sec-dev-chip').forEach(c => c.classList.remove('active'));
              chip.classList.add('active');
              chip.textContent = '…';
              const data = await window.__loadIntegrityData(chip.dataset.host);
              chip.textContent = escapeHtml(window.__deviceTags?.[chip.dataset.host] || chip.dataset.host);
              if (data) populateIntegrity(data, chip.dataset.host);
            });
          });
        });
      }
    }
    const label = item.textContent.replace(/[⊞⚠⊡⊟⬡◇✚▷⊙✦↺]/g, '').trim();
    const titleEl = document.getElementById('topbar-section-label');
    if (titleEl) titleEl.textContent = label;
  });
});

/* --- Overview jump-links: clicking a card/button activates the matching tab --- */
document.querySelectorAll('[data-jump]').forEach(el => {
  el.addEventListener('click', () => {
    const navItem = document.querySelector(`.nav-item[data-section="${el.dataset.jump}"]`);
    if (navItem) navItem.click();
  });
});

/* --- Severity filter chips --- */
document.querySelectorAll('.filter-chip').forEach(chip => {
  chip.addEventListener('click', () => {
    chip.classList.toggle('active');
    filterCVETable();
  });
});

function filterCVETable() {
  const activeChips  = [...document.querySelectorAll('.filter-chip.active')];
  const activeSev    = activeChips.filter(c => c.dataset.sev).map(c => c.dataset.sev);
  const activeType   = activeChips.filter(c => c.dataset.type).map(c => c.dataset.type);
  const activeDevice = document.querySelector('#cve-dev-chips .sec-dev-chip.active')?.dataset.device ?? '';
  const search       = (document.getElementById('cve-search')?.value ?? '').trim().toLowerCase();

  document.querySelectorAll('.cve-row').forEach(row => {
    const sevOk    = activeSev.length === 0 || activeSev.includes(row.dataset.severity);
    const typeOk   = activeType.length === 0 || activeType.includes(row.dataset.type);
    const devOk    = !activeDevice || row.dataset.device === activeDevice;
    const searchOk = !search ||
      (row.dataset.cveId  ?? '').toLowerCase().includes(search) ||
      (row.dataset.cvePkg ?? '').toLowerCase().includes(search);

    const visible = sevOk && typeOk && devOk && searchOk;
    row.style.display = visible ? '' : 'none';
    // keep detail row in sync
    const next = row.nextElementSibling;
    if (next?.classList.contains('cve-detail-row')) next.style.display = visible ? '' : 'none';
  });
}

/* --- Scan --- */

async function startScan() {
  if (startScan._running) return;
  startScan._running = true;
  _dot       = document.getElementById('status-dot');
  _statusLbl = document.getElementById('status-label');

  const overlay   = document.getElementById('scan-overlay');
  const stepLabel = document.getElementById('scan-step-label');
  const scanBtn   = document.getElementById('scan-btn');

  if (overlay)   overlay.style.display = 'flex';
  if (_dot)      _dot.className = 'status-dot scanning';
  if (_statusLbl) _statusLbl.textContent = 'Scanning…';
  if (scanBtn)   scanBtn.disabled = true;
  showToast('Running system scan…', 'loading', { duration: 4000 });

  const steps = [
    'Collecting OS info…', 'Reading CPU & memory…', 'Scanning block devices…',
    'Enumerating packages…', 'Checking services…', 'Detecting network config…',
    'Finalizing report…',
  ];
  let si = 0;
  const stepTimer = setInterval(() => {
    if (stepLabel) stepLabel.textContent = steps[si % steps.length];
    si++;
  }, 1300);

  try {
    const res  = await fetch('/api/scan', { method: 'POST' });
    const data = await res.json();
    clearInterval(stepTimer);

    if (!data.ok) throw new Error(data.error || 'Scan failed');

    _lastReport = data.report;
    window.__scanReport = _lastReport;
    populateDashboard(data.report);

    const lastScanEl = document.getElementById('last-scan-time');
    if (lastScanEl) lastScanEl.textContent = new Date().toLocaleTimeString();

  } catch (err) {
    clearInterval(stepTimer);
    startScan._running = false;
    if (_dot)      _dot.className = 'status-dot error';
    if (_statusLbl) _statusLbl.textContent = 'Scan error';
    if (stepLabel) stepLabel.textContent = 'Scan failed: ' + err.message;
    showToast('System scan failed: ' + err.message, 'error');
    setTimeout(() => { if (overlay) overlay.style.display = 'none'; }, 3000);
    if (scanBtn) scanBtn.disabled = false;
    return;
  }

  // Hide overlay immediately — show system specs to user right away
  if (overlay) overlay.style.display = 'none';
  if (scanBtn) scanBtn.disabled = false;
  startScan._running = false;

  // Both checks run in parallel after the overlay closes
  runCVEAnalysis(_lastReport);
  runIntegrityCheck(_lastReport);

  // Continuous monitoring: schedule the next automatic scan
  scheduleNextScan();
}

/* --- Continuous monitoring (auto-rescan + countdown) --- */

let _scanIntervalMs = 5 * 60 * 1000;   // default: every 5 minutes
let _nextScanAt     = 0;
let _countdownTimer = null;

function scheduleNextScan() {
  _nextScanAt = Date.now() + _scanIntervalMs;
  if (_countdownTimer) clearInterval(_countdownTimer);
  _countdownTimer = setInterval(tickCountdown, 1000);
  tickCountdown();
}

function tickCountdown() {
  const el   = document.getElementById('next-scan-countdown');
  const chip = document.getElementById('monitor-chip');
  if (startScan._running) {
    if (chip) chip.classList.add('scanning');
    if (el)   el.textContent = 'now…';
    return;
  }
  if (chip) chip.classList.remove('scanning');

  const remaining = _nextScanAt - Date.now();
  if (remaining <= 0) {
    if (el) el.textContent = 'now…';
    clearInterval(_countdownTimer);
    _countdownTimer = null;
    startScan();              // re-runs the scan; scheduleNextScan() fires again on success
    return;
  }
  if (el) el.textContent = fmtCountdown(remaining);
}

function fmtCountdown(ms) {
  const s = Math.ceil(ms / 1000);
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
}

// Interval selector — change the monitoring frequency on the fly
document.getElementById('scan-interval')?.addEventListener('change', e => {
  _scanIntervalMs = Number(e.target.value) || _scanIntervalMs;
  // Re-anchor the countdown to the new interval without forcing an immediate scan
  if (!startScan._running) scheduleNextScan();
});

/* --- CVE Analysis (runs after scan overlay closes) --- */

async function runCVEAnalysis(report) {
  if (!report) return;

  if (_dot)      _dot.className = 'status-dot scanning';
  if (_statusLbl) _statusLbl.textContent = 'Checking CVEs…';

  // Show spinner inside the CVE table while we wait
  const tbody = document.getElementById('cve-table-body');
  if (tbody) {
    tbody.innerHTML = `<tr><td colspan="7">
      <div class="empty-state">
        <div class="scan-spinner" style="width:28px;height:28px;margin:0 auto 12px"></div>
        <div style="color:var(--text-muted)">Querying CVE database for installed packages…</div>
      </div></td></tr>`;
  }

  try {
    const res  = await fetch('/api/analyze', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(report),
    });
    const data = await res.json();
    if (!data.ok) throw new Error(data.error || 'CVE analysis failed');

    populateCVEs(data.cves, data.counts);

    const _crit = data.counts?.critical ?? 0, _high = data.counts?.high ?? 0;
    const _tot  = data.cves?.length ?? 0;
    showToast(
      _tot === 0 ? 'CVE scan complete — no known vulnerabilities found'
                 : `CVE scan complete — ${_tot} found (${_crit} critical, ${_high} high)`,
      _crit > 0 ? 'warning' : _tot === 0 ? 'success' : 'info');

    _cveData = { cves: data.cves, counts: data.counts };
    window.__cveData = _cveData;
    if (document.getElementById('section-topology') &&
        !document.getElementById('section-topology').classList.contains('hidden')) {
      runTopologyBuild();
    }

    // Save full result (system info + CVE counts) to Firestore
    if (typeof window.__saveScanResult === 'function') {
      const r   = report;
      const os  = r.os            ?? {};
      const cpu = r.cpu?.summary  ?? {};
      const mem = r.memory?.summary ?? {};

      // Extract network topology from the scan report
      const netRoutes = Array.isArray(r.network?.routes) ? r.network.routes : [];
      const netAddrs  = Array.isArray(r.network?.addresses) ? r.network.addresses : [];
      const topoData  = {
        hostname:  os.hostname ?? '',
        gateway:   netRoutes.find(rt => rt.dst === 'default')?.gateway ?? null,
        my_ips:    netAddrs
          .filter(iface => !iface.ifname?.startsWith('lo'))
          .flatMap(iface =>
            (iface.addr_info ?? [])
              .filter(a => a.family === 'inet')
              .map(a => ({ interface: iface.ifname, ip: a.local, prefix: a.prefixlen }))
          ),
        neighbors: r.network_neighbors ?? [],
      };
      await window.__saveScanResult({
        hostname:         os.hostname             ?? '',
        os:               os.pretty_name          ?? '',
        kernel:           os.release              ?? '',
        arch:             os.machine              ?? '',
        cpu:              cpu.model_name          ?? '',
        cpu_cores:        cpu.logical_cpus        ?? 0,
        mem_total:        mem.total_bytes         ?? 0,
        mem_available:    mem.available_bytes     ?? 0,
        pkg_count:        r.packages?.count       ?? 0,
        pkg_manager:      r.packages?.manager     ?? '',
        packages: (r.packages?.packages ?? [])
                    .slice(0, 1000)
                    .map(p => ({ name: p.name, version: p.version ?? '' })),
        foreign:  (r.packages?.foreign  ?? []).slice(0, 500),
        services_running: r.services?.running?.length ?? 0,
        suid_count:       r.suid_files?.length    ?? 0,
        distro_family:    r.distro_family         ?? '',
        critical: data.counts.critical            ?? 0,
        high:     data.counts.high                ?? 0,
        other:    (data.counts.medium ?? 0) + (data.counts.low ?? 0),
        counts:   data.counts,
        cves:     data.cves.map(c => ({
          id: c.id, package: c.package, installed: c.installed ?? '',
          fixed: c.fixed ?? '', severity: c.severity, cvss: c.cvss ?? null,
          summary: (c.summary ?? '').slice(0, 400), url: c.url ?? '',
          type: c.type ?? '', vector: c.vector ?? '',
        })),
        topology: topoData,
      });
      if (typeof window.__loadDevices === 'function') window.__loadDevices();
    }

    if (_dot)      _dot.className = 'status-dot';
    if (_statusLbl) _statusLbl.textContent = 'Done';

  } catch (err) {
    if (_dot)      _dot.className = 'status-dot error';
    if (_statusLbl) _statusLbl.textContent = 'CVE check failed';
    showToast('CVE scan failed: ' + err.message, 'error');
    if (tbody) {
      tbody.innerHTML = `<tr><td colspan="7">
        <div class="empty-state">
          <div class="empty-icon">⚠</div>
          <div>CVE check failed: ${escapeHtml(err.message)}</div>
        </div></td></tr>`;
    }
  }
}

/* --- Integrity Check --- */

async function runIntegrityCheck(report) {
  if (!report) return;

  const loadingIds = ['integrity-mal-tbody', 'integrity-bin-tbody', 'integrity-suid-tbody'];
  loadingIds.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.innerHTML = `<tr><td colspan="5">
      <div class="empty-state">
        <div class="scan-spinner" style="width:24px;height:24px;margin:0 auto 10px"></div>
        <div style="color:var(--text-muted)">Checking…</div>
      </div></td></tr>`;
  });

  try {
    const res  = await fetch('/api/integrity', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(report),
    });
    const data = await res.json();
    if (!data.ok) throw new Error(data.error || 'Integrity check failed');

    // Merge suid_files and services from the scan report into the integrity data
    const extData = {
      ...data,
      suid_files: report.suid_files         ?? [],
      services:   report.services?.running  ?? [],
    };
    populateIntegrity(extData, report?.os?.hostname);
    const _isum   = data.summary ?? {};
    const _issues = (_isum.malicious_pkgs ?? 0) + (_isum.file_issues ?? 0);
    if (_issues > 0)
      showToast(`System audit: ${_issues} integrity issue${_issues !== 1 ? 's' : ''} found — see System Audit`, 'warning');
    const hostname = report?.os?.hostname;
    if (hostname && typeof window.__saveIntegrityData === 'function') {
      window.__saveIntegrityData(hostname, extData);
    }
  } catch (err) {
    ['integrity-mal-tbody', 'integrity-bin-tbody', 'integrity-suid-tbody'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.innerHTML = `<tr><td colspan="5">
        <div class="empty-state" style="color:var(--sev-critical)">
          Failed: ${escapeHtml(err.message)}</div></td></tr>`;
    });
  }
}

function populateIntegrity(data, hostname) {
  const sum  = data.summary       ?? {};
  const mal  = data.malicious     ?? [];
  const bins = data.modified_bins ?? [];
  const suid = data.suid_files    ?? [];
  const svcs = data.services      ?? [];

  // Device chip
  if (hostname) {
    const toolbar = document.getElementById('integrity-toolbar');
    const chipBox = document.getElementById('integrity-dev-chips');
    if (toolbar && chipBox) {
      const tag = window.__deviceTags?.[hostname] || '';
      chipBox.innerHTML = `<span style="font-size:11px;color:var(--text-muted);margin-right:4px">Device:</span>
        <span class="sec-dev-chip active" style="cursor:default">${escapeHtml(tag || hostname)}</span>`;
      toolbar.classList.remove('hidden');
    }
  }

  // Banner — keyed off malicious/modified_bins; file integrity removed
  const banner = document.getElementById('integrity-banner');
  const icon   = document.getElementById('integrity-banner-icon');
  const title  = document.getElementById('integrity-banner-title');
  const sub    = document.getElementById('integrity-banner-sub');
  const clean  = (sum.malicious_pkgs ?? 0) === 0 && (sum.modified_bin_files ?? 0) === 0;

  if (clean) {
    if (banner) banner.className = 'integrity-banner integrity-banner-ok';
    if (icon)   icon.textContent  = '✓';
    if (title)  title.textContent = 'No threats detected';
    if (sub)    sub.textContent   = `No malicious packages or recently modified binaries. ${suid.length} SUID file${suid.length !== 1 ? 's' : ''} · ${svcs.length} service${svcs.length !== 1 ? 's' : ''} running.`;
  } else {
    if (banner) banner.className = 'integrity-banner integrity-banner-warn';
    if (icon)   icon.textContent  = '⚠';
    const parts = [];
    if ((sum.malicious_pkgs ?? 0)     > 0) parts.push(`${sum.malicious_pkgs} malicious package${sum.malicious_pkgs !== 1 ? 's' : ''}`);
    if ((sum.modified_bin_files ?? 0) > 0) parts.push(`${sum.modified_bin_files} modified system binary${sum.modified_bin_files !== 1 ? 's' : ''}`);
    if (title)  title.textContent = 'Issues detected: ' + parts.join(' · ');
    if (sub)    sub.textContent   = 'Review the panels below for details.';
  }

  // Mirror to Overview Security Posture panel
  const ovBox   = document.getElementById('overview-integrity');
  const ovIcon  = document.getElementById('overview-integrity-icon');
  const ovTitle = document.getElementById('overview-integrity-title');
  const ovSub   = document.getElementById('overview-integrity-sub');
  if (ovBox)   ovBox.className        = 'posture-summary ' + (clean ? 'posture-ok' : 'posture-warn');
  if (ovIcon)  ovIcon.textContent     = clean ? '✓' : '⚠';
  if (ovTitle) ovTitle.textContent    = title?.textContent ?? '';
  if (ovSub)   ovSub.textContent      = sub?.textContent   ?? '';

  // Nav badge
  const navBadge   = document.getElementById('nav-integrity-badge');
  const issueCount = (sum.malicious_pkgs ?? 0);
  if (navBadge) {
    navBadge.textContent = issueCount || ((sum.modified_bin_files ?? 0) > 0 ? '!' : '');
    navBadge.classList.toggle('hidden', issueCount === 0 && (sum.modified_bin_files ?? 0) === 0);
    navBadge.style.background = issueCount > 0 ? 'var(--sev-critical)' : 'var(--sev-medium)';
  }

  // ── Malicious packages ───────────────────────────────────────────────────
  const malTbody = document.getElementById('integrity-mal-tbody');
  const malCount = document.getElementById('integrity-mal-count');
  if (malCount) malCount.textContent = mal.length === 0 ? '✓ None detected' : `${mal.length} detected`;
  if (malTbody) {
    malTbody.innerHTML = mal.length === 0
      ? `<tr><td colspan="5"><div class="empty-state">
           <div class="empty-icon" style="color:var(--sev-low)">✓</div>
           <div>No packages matched the OSSF malicious-packages database.</div>
         </div></td></tr>`
      : mal.map(m => `
        <tr>
          <td><a class="cve-id" href="${escapeHtml(m.url)}" target="_blank" rel="noopener">${escapeHtml(m.id)}</a></td>
          <td class="mono" style="font-size:11px">${escapeHtml(m.package)}</td>
          <td class="mono" style="font-size:11px">${escapeHtml(m.version)}</td>
          <td style="font-size:11px;color:var(--sev-critical)">${escapeHtml(m.summary)}</td>
          <td><a href="${escapeHtml(m.url)}" target="_blank" rel="noopener" class="btn btn-ghost btn-sm">Details</a></td>
        </tr>`).join('');
  }

  // ── Modified binaries ────────────────────────────────────────────────────
  const binTbody = document.getElementById('integrity-bin-tbody');
  const binCount = document.getElementById('integrity-bin-count');
  if (binCount) binCount.textContent = bins.length === 0 ? '✓ None' : `${bins.length} in last 7 days`;
  if (binTbody) {
    binTbody.innerHTML = bins.length === 0
      ? `<tr><td colspan="4"><div class="empty-state">
           <div class="empty-icon" style="color:var(--sev-low)">✓</div>
           <div>No system binaries modified in the last 7 days.</div>
         </div></td></tr>`
      : bins.map(b => {
          const ageLabel = b.age_hours < 24 ? `${b.age_hours}h ago` : `${Math.floor(b.age_hours / 24)}d ago`;
          const ageCls   = b.age_hours < 24 ? 'cvss-critical' : b.age_hours < 72 ? 'cvss-high' : 'cvss-medium';
          return `<tr>
            <td class="mono" style="font-size:11px">${escapeHtml(b.path)}</td>
            <td class="mono" style="font-size:11px">${escapeHtml(b.package)}</td>
            <td style="font-size:11px;color:var(--text-secondary)">${escapeHtml(new Date(b.modified).toLocaleString())}</td>
            <td class="${ageCls}" style="font-weight:600">${ageLabel}</td>
          </tr>`;
        }).join('');
  }

  // ── SUID files ───────────────────────────────────────────────────────────
  const suidTbody = document.getElementById('integrity-suid-tbody');
  const suidCount = document.getElementById('integrity-suid-count');
  if (suidCount) suidCount.textContent = suid.length === 0 ? '—' : `${suid.length} files`;
  if (suidTbody) {
    suidTbody.innerHTML = suid.length === 0
      ? `<tr><td colspan="2"><div class="empty-state">
           <div class="empty-icon">—</div>
           <div>No SUID files found in standard binary paths.</div>
         </div></td></tr>`
      : suid.map(path => {
          const file = path.split('/').pop();
          return `<tr>
            <td class="mono" style="font-size:11px;color:var(--text-secondary)">${escapeHtml(path)}</td>
            <td class="mono" style="font-size:11px">${escapeHtml(file)}</td>
          </tr>`;
        }).join('');
  }

  // ── Running services ─────────────────────────────────────────────────────
  const svcBody  = document.getElementById('integrity-svc-body');
  const svcCount = document.getElementById('integrity-svc-count');
  if (svcCount) svcCount.textContent = svcs.length === 0 ? '—' : `${svcs.length} running`;
  if (svcBody) {
    svcBody.innerHTML = svcs.length === 0
      ? `<div class="empty-state"><div class="empty-icon">—</div><div>No service data available. Run a scan on this device.</div></div>`
      : `<div class="service-grid">${svcs.map(s => `<span class="service-chip">${escapeHtml(s)}</span>`).join('')}</div>`;
  }
}

/* --- Populate dashboard (stat cards + apps) --- */

function populateDashboard(r) {
  const pkgs = r.packages ?? {};

  // Stat cards — CVEs shown as "…" until analysis finishes
  setText('stat-apps',     pkgs.count ?? '—');
  setText('stat-critical', '…');
  setText('stat-high',     '…');
  setText('stat-other',    '…');

  // Applications grid
  if (pkgs.packages) {
    _populateApps(pkgs.packages, pkgs.foreign ?? [], pkgs.count, pkgs.manager, '');
  }
}

// Cache for search/filter — keyed by hostname
const _appCache = {};     // hostname → { pkgList, foreignList, totalCount, manager }
let   _appActiveHost = '';

function _populateApps(pkgList, foreignList, totalCount, manager, suffix) {
  const hostname = _lastReport?.os?.hostname || window.__savedData?.hostname || '__current__';
  _appCache[hostname] = { pkgList, foreignList: foreignList ?? [], totalCount, manager };
  _appActiveHost = hostname;

  _renderAppsToolbar();
  _renderPackageRisk(hostname);
}

function _renderAppsToolbar() {
  const toolbar  = document.getElementById('apps-toolbar');
  const chipBox  = document.getElementById('apps-dev-chips');
  const searchEl = document.getElementById('apps-search');
  if (!toolbar || !chipBox) return;

  // Collect all sources: cache + deviceCache
  const sources = new Map(); // hostname → label
  for (const h of Object.keys(_appCache)) sources.set(h, h);
  if (window.__deviceCache) {
    for (const [h, d] of Object.entries(window.__deviceCache)) {
      if (Array.isArray(d.packages) && d.packages.length > 0) sources.set(h, h);
    }
  }

  if (sources.size === 0) return;
  toolbar.classList.remove('hidden');

  chipBox.innerHTML = [...sources.keys()].map(h => {
    const tag    = window.__deviceTags?.[h];
    const lbl    = tag ? `${escapeHtml(tag)} <span class="chip-host">${escapeHtml(h)}</span>` : escapeHtml(h);
    const active = h === _appActiveHost ? ' active' : '';
    return `<button class="sec-dev-chip${active}" data-host="${escapeHtml(h)}">${lbl}</button>`;
  }).join('');

  chipBox.querySelectorAll('.sec-dev-chip').forEach(chip => {
    chip.addEventListener('click', () => {
      chipBox.querySelectorAll('.sec-dev-chip').forEach(c => c.classList.remove('active'));
      chip.classList.add('active');
      _appActiveHost = chip.dataset.host;
      // Load from deviceCache if not already in _appCache
      if (!_appCache[_appActiveHost] && window.__deviceCache?.[_appActiveHost]) {
        const d = window.__deviceCache[_appActiveHost];
        _appCache[_appActiveHost] = {
          pkgList:    d.packages    ?? [],
          foreignList: d.foreign   ?? [],
          totalCount: d.pkg_count  ?? d.packages?.length ?? 0,
          manager:    d.pkg_manager ?? '',
        };
      }
      _renderPackageRisk(_appActiveHost);
    });
  });

  if (searchEl && !searchEl._wired) {
    searchEl._wired = true;
    searchEl.addEventListener('input', () => _renderPackageRisk(_appActiveHost));
  }
}

function _renderPackageRisk(hostname) {
  const entry = _appCache[hostname];
  if (!entry?.pkgList?.length) {
    const cached = window.__deviceCache?.[hostname];
    if (cached?.packages?.length) {
      _appCache[hostname] = {
        pkgList:     cached.packages,
        foreignList: cached.foreign ?? [],
        totalCount:  cached.pkg_count ?? cached.packages.length,
        manager:     cached.pkg_manager ?? '',
      };
      _renderPackageRisk(hostname); return;
    }
    const noData = id => {
      const el = document.getElementById(id);
      if (el) el.innerHTML = `<tr><td colspan="4"><div class="empty-state">
        <div class="empty-icon">⊡</div><div>No package data for this device.</div></div></td></tr>`;
    };
    noData('pkg-vuln-tbody'); noData('pkg-foreign-tbody');
    const grid = document.getElementById('app-grid');
    if (grid) grid.innerHTML = `<div class="empty-state" style="grid-column:1/-1"><div class="empty-icon">⊡</div><div>No package data.</div></div>`;
    return;
  }

  const { pkgList, foreignList, totalCount, manager } = entry;
  const foreign = new Set(foreignList);
  const search  = (document.getElementById('apps-search')?.value ?? '').trim().toLowerCase();
  const match   = name => !search || name.toLowerCase().includes(search);

  // Build vuln map from CVE data for this device
  const vulnMap = _buildVulnPackageMap(hostname);

  // Vulnerable table
  _renderVulnerableTable(vulnMap, pkgList, match);

  // Foreign table
  _renderForeignTable(pkgList, foreign, match);

  // All packages grid (inside collapsible)
  _renderAllPackagesGrid(pkgList, foreign, match, totalCount, manager);

  // Stats bar
  const riskBar = document.getElementById('pkg-risk-bar');
  if (riskBar) riskBar.classList.remove('hidden');
  const vulnStat    = document.getElementById('pkg-stat-vuln');
  const foreignStat = document.getElementById('pkg-stat-foreign');
  const totalStat   = document.getElementById('pkg-stat-total');
  if (vulnStat)    vulnStat.textContent    = `${vulnMap.size} vulnerable`;
  if (foreignStat) foreignStat.textContent = `${foreignList.length} foreign`;
  if (totalStat)   totalStat.textContent   = `${totalCount} total`;

  // Wire All Packages collapse toggle once
  const hdr = document.getElementById('pkg-all-header');
  if (hdr && !hdr._wired) {
    hdr._wired = true;
    hdr.addEventListener('click', () => {
      const body  = document.getElementById('pkg-all-body');
      const arrow = document.getElementById('pkg-all-arrow');
      if (!body) return;
      body.classList.toggle('hidden');
      if (arrow) arrow.textContent = body.classList.contains('hidden') ? '▶' : '▼';
    });
  }
}

function _buildVulnPackageMap(hostname) {
  const currentHost = _lastReport?.os?.hostname || window.__savedData?.hostname;
  let cves = [];
  if (!hostname || hostname === '__current__' || hostname === currentHost) {
    cves = _cveData?.cves ?? window.__savedData?.cves ?? [];
  } else {
    cves = window.__deviceCache?.[hostname]?.cves ?? [];
  }
  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };
  const map = new Map();
  for (const cve of cves) {
    const pkg = cve.package;
    if (!pkg) continue;
    if (!map.has(pkg)) map.set(pkg, { version: cve.installed_version || '', cves: [], worstSev: 'unknown' });
    const e = map.get(pkg);
    e.cves.push(cve);
    if ((sevOrder[cve.severity] ?? 4) < (sevOrder[e.worstSev] ?? 4)) e.worstSev = cve.severity;
  }
  return map;
}

function _renderVulnerableTable(vulnMap, pkgList, match) {
  const tbody   = document.getElementById('pkg-vuln-tbody');
  const countEl = document.getElementById('pkg-vuln-count');
  if (!tbody) return;

  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };
  const rows = [...vulnMap.entries()]
    .filter(([name]) => match(name))
    .sort((a, b) => (sevOrder[a[1].worstSev] ?? 4) - (sevOrder[b[1].worstSev] ?? 4));

  if (countEl) countEl.textContent = rows.length === 0 ? '✓ None' : `${rows.length} packages`;

  if (!rows.length) {
    const hasSearch = document.getElementById('apps-search')?.value?.trim();
    tbody.innerHTML = `<tr><td colspan="4"><div class="empty-state">
      <div class="empty-icon" style="color:var(--sev-low)">✓</div>
      <div>${hasSearch ? 'No matching vulnerable packages.' : 'No packages with known CVEs — run a CVE analysis.'}</div>
    </div></td></tr>`;
    return;
  }

  tbody.innerHTML = rows.map(([name, info]) => {
    const pkg     = pkgList.find(p => p.name === name);
    const version = pkg?.version || info.version || '—';
    return `<tr>
      <td class="mono">${escapeHtml(name)}</td>
      <td class="mono" style="font-size:11px;color:var(--text-secondary)">${escapeHtml(version)}</td>
      <td style="font-size:12px">${info.cves.length}</td>
      <td><span class="cvss-${info.worstSev}" style="font-weight:600">${info.worstSev}</span></td>
    </tr>`;
  }).join('');
}

function _renderForeignTable(pkgList, foreign, match) {
  const tbody   = document.getElementById('pkg-foreign-tbody');
  const countEl = document.getElementById('pkg-foreign-count');
  if (!tbody) return;

  const rows = pkgList.filter(p => foreign.has(p.name) && match(p.name));

  if (countEl) countEl.textContent = rows.length === 0 ? '✓ None' : `${rows.length} packages`;

  tbody.innerHTML = rows.length === 0
    ? `<tr><td colspan="2"><div class="empty-state">
         <div class="empty-icon" style="color:var(--sev-low)">✓</div>
         <div>No foreign or AUR packages detected.</div>
       </div></td></tr>`
    : rows.map(p => `
      <tr>
        <td class="mono">${escapeHtml(p.name)}</td>
        <td class="mono" style="font-size:11px;color:var(--text-secondary)">${escapeHtml(p.version || '—')}</td>
      </tr>`).join('');
}

function _renderAllPackagesGrid(pkgList, foreign, match, totalCount, manager) {
  const grid    = document.getElementById('app-grid');
  const countEl = document.getElementById('apps-count');
  if (!grid) return;

  const filtered = pkgList.filter(p => match(p.name));
  const shown    = filtered.slice(0, 120);
  const search   = document.getElementById('apps-search')?.value?.trim();
  const mgr      = manager ? ` via ${manager}` : '';
  const srch     = search  ? ` · ${filtered.length} matching` : '';
  if (countEl) countEl.textContent = `${totalCount} packages${mgr}${srch}`;

  grid.innerHTML = shown.map(p => `
    <div class="app-card" data-pkg="${escapeHtml(p.name)}">
      <div class="app-icon">${escapeHtml((p.name || '?').charAt(0).toUpperCase())}</div>
      <div class="app-info">
        <div class="app-name">${escapeHtml(p.name)}</div>
        <div class="app-version">${escapeHtml(p.version ?? '')}</div>
      </div>
      ${foreign.has(p.name) ? '<div class="app-vuln-flag" title="AUR / foreign"></div>' : ''}
    </div>`).join('');

  if (filtered.length > 120) {
    grid.innerHTML += `<div class="app-card app-card-more">+${filtered.length - 120} more — refine search</div>`;
  }
}

/* --- Overview: severity breakdown + top vulnerabilities preview --- */

function populateOverviewCVEs(cves, counts) {
  counts = counts ?? {};
  setText('ov-sev-critical', counts.critical ?? 0);
  setText('ov-sev-high',     counts.high     ?? 0);
  setText('ov-sev-medium',   counts.medium   ?? 0);
  setText('ov-sev-low',      counts.low      ?? 0);

  const box = document.getElementById('overview-top-cves');
  if (!box) return;

  const order = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };
  const top = [...(cves ?? [])]
    .sort((a, b) => {
      const s = (order[a.severity] ?? 4) - (order[b.severity] ?? 4);
      return s !== 0 ? s : (Number(b.cvss) || 0) - (Number(a.cvss) || 0);
    })
    .slice(0, 5);

  if (top.length === 0) {
    box.innerHTML = `<div class="empty-state">
      <div class="empty-icon" style="color:var(--sev-low)">✓</div>
      <div>No known vulnerabilities found.</div>
    </div>`;
    return;
  }

  box.innerHTML = top.map(c => {
    const sev   = c.severity || 'unknown';
    const score = c.cvss != null ? Number(c.cvss).toFixed(1) : '—';
    return `<div class="ov-cve-row">
      <span class="cvss-score cvss-${sev}">${score}</span>
      <div class="ov-cve-main">
        <span class="cve-id mono">${escapeHtml(c.id)}</span>
        <span class="ov-cve-pkg">${escapeHtml(c.package)}</span>
      </div>
      <span class="badge badge-${sev}">${sev}</span>
    </div>`;
  }).join('');
}

/* --- Populate CVE data once analysis returns --- */

function populateCVEs(cves, counts) {
  // Update stat cards + nav badge + overview
  setText('stat-critical', counts.critical ?? 0);
  setText('stat-high',     counts.high     ?? 0);
  setText('stat-other',    (counts.medium  ?? 0) + (counts.low ?? 0));
  populateOverviewCVEs(cves, counts);

  const badge = document.getElementById('nav-cve-badge');
  const total = (counts.critical ?? 0) + (counts.high ?? 0);
  if (badge) { badge.textContent = total; badge.classList.toggle('hidden', total === 0); }

  // Full multi-device CVE table render
  renderAllCVEs();
  _updatePatchBadge();

  // Flag vulnerable packages in the app grid
  if (cves.length > 0) {
    const vulnPkgs = new Map();
    for (const c of cves) {
      const cur = vulnPkgs.get(c.package);
      if (!cur || _sevOrder(c.severity) < _sevOrder(cur)) vulnPkgs.set(c.package, c.severity);
    }
    document.querySelectorAll('.app-card[data-pkg]').forEach(card => {
      const sev = vulnPkgs.get(card.dataset.pkg);
      if (!sev) return;
      card.style.borderColor = sevColor(sev);
      if (!card.querySelector('.app-vuln-flag')) {
        const flag = document.createElement('div');
        flag.className = 'app-vuln-flag';
        flag.title = sev + ' severity CVE';
        flag.style.background = sevColor(sev);
        flag.style.boxShadow  = `0 0 5px ${sevColor(sev)}`;
        card.appendChild(flag);
      }
    });
  }
}

/* --- Multi-device CVE rendering --- */

function _buildDeviceCVEMap() {
  const map = new Map(); // hostname → { cves, counts }

  // Current scan (freshest data for this host)
  const curHost = _lastReport?.os?.hostname || window.__savedData?.hostname;
  if (curHost && _cveData?.cves?.length > 0) {
    map.set(curHost, { cves: _cveData.cves, counts: _cveData.counts });
  } else if (curHost && window.__savedData?.cves?.length > 0) {
    map.set(curHost, { cves: window.__savedData.cves, counts: window.__savedData.counts });
  }

  // All devices from Firestore cache
  if (window.__deviceCache) {
    for (const [hostname, d] of Object.entries(window.__deviceCache)) {
      if (map.has(hostname)) continue;
      if (Array.isArray(d.cves) && d.cves.length > 0) {
        map.set(hostname, {
          cves:   d.cves,
          counts: d.counts ?? { critical: d.critical ?? 0, high: d.high ?? 0, medium: 0, low: 0 },
        });
      }
    }
  }
  return map;
}

function renderAllCVEs() {
  const deviceMap = _buildDeviceCVEMap();
  const multiDevice = deviceMap.size > 1;

  // Summary cards row
  const summaryBox = document.getElementById('cve-device-summary');
  if (summaryBox) {
    if (multiDevice) {
      summaryBox.innerHTML = [...deviceMap.entries()].map(([hostname, { counts }]) => {
        const c    = counts || {};
        const crit = c.critical ?? 0;
        const high = c.high ?? 0;
        const risk = crit > 0 ? 'critical' : high > 0 ? 'high' : 'clean';
        const tag  = window.__deviceTags?.[hostname] || '';
        return `
          <div class="cve-dev-card cve-dev-card-${risk}" data-device="${escapeHtml(hostname)}"
               onclick="_setCVEDeviceFilter('${escapeHtml(hostname)}')">
            <div class="cve-dev-card-name">${escapeHtml(tag || hostname)}</div>
            ${tag ? `<div class="cve-dev-card-host">${escapeHtml(hostname)}</div>` : ''}
            <div class="cve-dev-card-counts">
              ${crit > 0 ? `<span class="cvss-critical">${crit}c</span>` : ''}
              ${high > 0 ? `<span class="cvss-high">${high}h</span>`     : ''}
              ${crit + high === 0 ? `<span style="color:var(--sev-low)">✓</span>` : ''}
            </div>
          </div>`;
      }).join('');
    } else {
      summaryBox.innerHTML = '';
    }
  }

  // Device filter chips
  const chipBox = document.getElementById('cve-dev-chips');
  if (chipBox) {
    const totalCVEs = [...deviceMap.values()].reduce((n, { cves }) => n + (cves?.length || 0), 0);
    chipBox.innerHTML =
      `<button class="sec-dev-chip active" data-device="">All (${totalCVEs})</button>` +
      [...deviceMap.entries()].map(([h, { cves, counts }]) => {
        const n    = cves?.length || 0;
        const crit = counts?.critical ?? 0;
        const tag  = window.__deviceTags?.[h];
        const lbl  = tag ? `${escapeHtml(tag)} <span class="chip-host">${escapeHtml(h)}</span>` : escapeHtml(h);
        const suf  = crit > 0 ? ` <span class="cvss-critical" style="font-size:10px">${crit}c</span>` : '';
        return `<button class="sec-dev-chip" data-device="${escapeHtml(h)}">${lbl} <span class="chip-count">${n}</span>${suf}</button>`;
      }).join('');

    chipBox.querySelectorAll('.sec-dev-chip').forEach(chip => {
      chip.addEventListener('click', () => {
        chipBox.querySelectorAll('.sec-dev-chip').forEach(c => c.classList.remove('active'));
        chip.classList.add('active');
        filterCVETable();
        // sync summary card highlight
        document.querySelectorAll('.cve-dev-card').forEach(c => {
          c.classList.toggle('cve-dev-card-selected', c.dataset.device === chip.dataset.device);
        });
      });
    });
  }

  // Show/hide toolbar, impact filter, and device column
  document.getElementById('cve-toolbar')?.classList.remove('hidden');
  document.getElementById('cve-type-filter-bar')?.classList.remove('hidden');
  document.getElementById('cve-main-table')?.classList.toggle('hide-device-col', !multiDevice);

  // Wire search
  const searchEl = document.getElementById('cve-search');
  if (searchEl && !searchEl._wired) {
    searchEl._wired = true;
    searchEl.addEventListener('input', filterCVETable);
  }

  // Flatten + sort all CVEs
  const sevOrd = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };
  const allRows = [];
  for (const [hostname, { cves }] of deviceMap) {
    for (const c of (cves || [])) allRows.push({ ...c, _device: hostname });
  }
  allRows.sort((a, b) => {
    const s = (sevOrd[a.severity] ?? 4) - (sevOrd[b.severity] ?? 4);
    return s !== 0 ? s : (Number(b.cvss) || 0) - (Number(a.cvss) || 0);
  });

  const tbody = document.getElementById('cve-table-body');
  if (!tbody) return;

  if (allRows.length === 0) {
    tbody.innerHTML = `<tr><td colspan="9"><div class="empty-state">
      <div class="empty-icon" style="color:var(--sev-low)">✓</div>
      <div>No known vulnerabilities found for installed packages.</div>
    </div></td></tr>`;
    return;
  }

  tbody.innerHTML = allRows.map(c => {
    const sev   = c.severity || 'unknown';
    const score = c.cvss != null ? Number(c.cvss).toFixed(1) : '—';
    const tag   = window.__deviceTags?.[c._device] || c._device;
    const ty    = cveType(c);
    return `
      <tr class="cve-row" data-severity="${sev}" data-device="${escapeHtml(c._device)}"
          data-type="${escapeHtml(ty)}"
          data-cve-id="${escapeHtml(c.id)}"
          data-cve-pkg="${escapeHtml(c.package)}"
          data-cve-installed="${escapeHtml(c.installed ?? '')}"
          data-cve-fixed="${escapeHtml(c.fixed ?? '')}"
          data-cve-summary="${escapeHtml(c.summary ?? '')}"
          data-cve-url="${escapeHtml(c.url ?? '')}"
          data-cve-cvss="${escapeHtml(score)}">
        <td class="col-device"><span class="cve-device-chip">${escapeHtml(tag)}</span></td>
        <td><span class="cve-id mono">${escapeHtml(c.id)}</span></td>
        <td>${escapeHtml(c.package)}</td>
        <td class="mono" style="font-size:11px">${escapeHtml(c.installed ?? '—')}</td>
        <td class="mono" style="font-size:11px;color:var(--sev-low)">${escapeHtml(c.fixed ?? '—')}</td>
        <td class="cvss-score cvss-${sev}">${score}</td>
        <td><span class="badge badge-${sev}">${sev}</span></td>
        <td>${_cveBadgesHtml(c)}</td>
        <td class="cve-actions"><button class="btn btn-ghost btn-sm cve-expand-btn">Details</button></td>
      </tr>`;
  }).join('');

  // Wire expand buttons
  _wireCVEExpand(tbody);
}

function _wireCVEExpand(tbody) {
  tbody.querySelectorAll('.cve-expand-btn').forEach(btn => {
    btn.addEventListener('click', e => {
      e.stopPropagation();
      const row  = btn.closest('tr');
      const next = row.nextElementSibling;
      if (next?.classList.contains('cve-detail-row')) {
        next.remove(); btn.textContent = 'Details'; return;
      }
      const d      = row.dataset;
      const cveId  = d.cveId || '';
      const summary = d.cveSummary || 'No description available.';
      const impact = cveImpactLabel({ type: d.type, summary });
      const vector = cveVector({ summary });
      const isCVE  = cveId.startsWith('CVE-');
      const isASA  = cveId.startsWith('ASA-');
      const nvdUrl  = isCVE ? `https://nvd.nist.gov/vuln/detail/${cveId}` : '';
      const archUrl = isCVE ? `https://security.archlinux.org/${cveId}`
                   : isASA  ? `https://security.archlinux.org/advisory/${cveId}`
                   : (d.cveUrl || '');
      const osvUrl  = d.cveUrl?.startsWith('https://osv.dev') ? d.cveUrl : '';

      const detail = document.createElement('tr');
      detail.className = 'cve-detail-row';
      detail.innerHTML = `
        <td colspan="9" class="cve-detail-cell">
          <div class="cve-detail-body">
            <p class="cve-detail-summary">${escapeHtml(summary)}</p>
            <div class="cve-detail-meta">
              <span>Device <code>${escapeHtml(d.device ?? '')}</code></span>
              <span>Package <code>${escapeHtml(d.cvePkg)}</code></span>
              <span>Installed <code>${escapeHtml(d.cveInstalled) || '—'}</code></span>
              <span>Fixed in <code class="text-ok">${escapeHtml(d.cveFixed) || 'no fix yet'}</code></span>
              <span>CVSS <code>${escapeHtml(d.cveCvss)}</code></span>
              <span>Impact <code>${escapeHtml(impact)}</code></span>
              ${vector ? `<span>Vector <code>${escapeHtml(vector)}</code></span>` : ''}
            </div>
            <div class="cve-detail-actions">
              ${nvdUrl  ? `<a href="${nvdUrl}"  target="_blank" rel="noopener" class="btn btn-ghost btn-sm">NVD ↗</a>` : ''}
              ${archUrl ? `<a href="${archUrl}" target="_blank" rel="noopener" class="btn btn-ghost btn-sm">Arch ↗</a>` : ''}
              ${osvUrl  ? `<a href="${osvUrl}"  target="_blank" rel="noopener" class="btn btn-ghost btn-sm">OSV ↗</a>` : ''}
              <button class="btn btn-ghost btn-sm"
                onclick="navigator.clipboard.writeText('${escapeHtml(cveId)}').then(()=>{this.textContent='Copied!';setTimeout(()=>this.textContent='Copy ID',1500)})">
                Copy ID
              </button>
              <button class="btn btn-success btn-sm" style="margin-left:auto"
                onclick="window.__gotoPatch('${escapeHtml(d.cvePkg)}','${escapeHtml(cveId)}')">
                Patch this →
              </button>
              <button class="btn btn-primary btn-sm"
                onclick="window.askAICVE?.('${escapeHtml(cveId)}','${escapeHtml(d.cvePkg)}','${escapeHtml(d.cveInstalled)}','${escapeHtml(d.cveFixed)}','${escapeHtml(row.dataset.severity)}','${escapeHtml(summary)}')">
                Ask AI
              </button>
            </div>
          </div>
        </td>`;
      row.insertAdjacentElement('afterend', detail);
      btn.textContent = 'Close';
    });
  });
}

// Called from CVE device summary card click and from chip click
window._setCVEDeviceFilter = function(hostname) {
  const chipBox = document.getElementById('cve-dev-chips');
  if (!chipBox) return;
  chipBox.querySelectorAll('.sec-dev-chip').forEach(c => {
    c.classList.toggle('active', c.dataset.device === hostname);
  });
  document.querySelectorAll('.cve-dev-card').forEach(c => {
    c.classList.toggle('cve-dev-card-selected', c.dataset.device === hostname);
  });
  filterCVETable();
};

/* =========================================================
   PATCHES — remediation to-do list + inline AI
   ========================================================= */

function _patchContext() {
  if (_cveData?.cves?.length)
    return { cves: _cveData.cves,
             host:   _lastReport?.os?.hostname    || window.__savedData?.hostname     || 'this device',
             family: _lastReport?.distro_family   || window.__savedData?.distro_family || 'unknown' };
  if (window.__savedData?.cves?.length)
    return { cves: window.__savedData.cves,
             host:   window.__savedData.hostname     || 'this device',
             family: window.__savedData.distro_family || 'unknown' };
  return { cves: [], host: 'this device', family: 'unknown' };
}

function _patchCmd(family, pkg) {
  return {
    arch:   `sudo pacman -Syu ${pkg}`,
    debian: `sudo apt-get install --only-upgrade ${pkg}`,
    rhel:   `sudo dnf update ${pkg}`,
  }[family] ?? `# upgrade ${pkg} with your package manager`;
}

function _patchDoneSet(host) {
  try { return new Set(JSON.parse(localStorage.getItem('patch_done_' + host) || '[]')); }
  catch { return new Set(); }
}
function _savePatchDone(host, set) {
  localStorage.setItem('patch_done_' + host, JSON.stringify([...set]));
}

// Group a device's CVEs by package → one patch task per vulnerable package
function _groupPatches(cves) {
  const map = new Map();
  for (const c of cves) {
    const key = c.package || '(unknown)';
    if (!map.has(key))
      map.set(key, { pkg: key, installed: c.installed || '?', fixed: c.fixed || '', cves: [] });
    const g = map.get(key);
    g.cves.push(c);
    if ((!g.fixed || g.fixed === '?') && c.fixed && c.fixed !== '?') g.fixed = c.fixed;
  }
  const worst = g => g.cves.reduce((w, c) => Math.min(w, _sevOrder(c.severity)), 4);
  return [...map.values()].sort((a, b) => {
    const s = worst(a) - worst(b);
    return s !== 0 ? s : b.cves.length - a.cves.length;
  });
}

function _worstSev(cves) {
  const order = ['critical', 'high', 'medium', 'low', 'unknown'];
  return order[cves.reduce((w, c) => Math.min(w, _sevOrder(c.severity)), 4)];
}

function renderPatches() {
  const list = document.getElementById('patch-list');
  const bar  = document.getElementById('patch-summary-bar');
  if (!list) return;

  const { cves, host, family } = _patchContext();
  const groups = _groupPatches(cves);
  const done   = _patchDoneSet(host);

  if (groups.length === 0) {
    if (bar) bar.style.display = 'none';
    list.innerHTML = `<div class="empty-state">
      <div class="empty-icon" style="color:var(--sev-low)">✓</div>
      <div>No vulnerable packages — nothing to patch on <strong>${escapeHtml(host)}</strong>.</div>
    </div>`;
    _updatePatchBadge();
    return;
  }

  const totalCVEs = cves.length;
  const doneCount = groups.filter(g => done.has(g.pkg)).length;
  const crit = cves.filter(c => c.severity === 'critical').length;
  const high = cves.filter(c => c.severity === 'high').length;
  const pct  = Math.round((doneCount / groups.length) * 100);

  if (bar) {
    bar.style.display = 'flex';
    bar.innerHTML = `
      <div><div class="patch-summary-num text-accent">${groups.length}</div><div class="patch-summary-label">packages to patch</div></div>
      <div class="patch-summary-div"></div>
      <div><div class="patch-summary-num">${totalCVEs}</div><div class="patch-summary-label">CVEs covered</div></div>
      <div class="patch-summary-div"></div>
      <div><div class="patch-summary-num cvss-critical">${crit}</div><div class="patch-summary-label">critical</div></div>
      <div><div class="patch-summary-num cvss-high">${high}</div><div class="patch-summary-label">high</div></div>
      <div class="patch-summary-div"></div>
      <div style="flex:1">
        <div class="patch-progress-track"><div class="patch-progress-fill" style="width:${pct}%"></div></div>
        <div class="patch-summary-label" style="margin-top:4px">${doneCount} of ${groups.length} resolved · ${pct}%</div>
      </div>
      <div><div class="patch-summary-num" style="color:var(--sev-low)">${pct}%</div><div class="patch-summary-label">done</div></div>`;
  }

  const hideDone = document.getElementById('patch-hide-done')?.checked;

  list.innerHTML = groups.map(g => {
    const isDone = done.has(g.pkg);
    if (isDone && hideDone) return '';
    const sev   = _worstSev(g.cves);
    const cmd   = _patchCmd(family, g.pkg);
    const chips = g.cves.map(c => {
      const ty = cveType(c);
      const info = _CVE_TYPE_INFO[ty];
      return `<span class="patch-cve-chip">
        <span class="badge badge-${c.severity}" style="padding:0 5px">${c.severity[0].toUpperCase()}</span>
        ${escapeHtml(c.id)}${info ? ` · <span style="opacity:.8">${info.label}</span>` : ''}
      </span>`;
    }).join('');
    return `
      <div class="patch-item${isDone ? ' patch-done' : ''}" data-patch-pkg="${escapeHtml(g.pkg)}">
        <div class="patch-header">
          <label class="patch-check"><input type="checkbox" class="patch-done-cb" ${isDone ? 'checked' : ''}></label>
          <span class="patch-pkg-name">${escapeHtml(g.pkg)}</span>
          <span class="badge badge-${sev}">${sev}</span>
          <span class="patch-status patch-status-checking">checking repo…</span>
          <span class="patch-count">${g.cves.length} CVE${g.cves.length !== 1 ? 's' : ''}</span>
          <span class="patch-fix-ver">${g.fixed && g.fixed !== '?'
            ? `fix → <code class="text-ok">${escapeHtml(g.fixed)}</code>` : '<span class="text-muted">no fixed version</span>'}</span>
        </div>
        <div class="patch-warn" style="display:none"></div>
        <div class="patch-cve-list">${chips}</div>
        <div class="patch-cmd-block">
          <code>${escapeHtml(cmd)}</code>
          <button class="btn btn-ghost btn-sm patch-copy-btn" data-cmd="${escapeHtml(cmd)}">Copy</button>
        </div>
        <div class="patch-ai-output" style="display:none"></div>
        <div class="patch-actions">
          <button class="btn btn-primary btn-sm patch-ai-btn">Ask AI to patch</button>
          <button class="btn btn-success btn-sm patch-toggle-btn" style="margin-left:auto">
            ${isDone ? 'Mark as not done' : '✓ Mark as patched'}
          </button>
        </div>
      </div>`;
  }).join('') || `<div class="empty-state"><div class="empty-icon" style="color:var(--sev-low)">✓</div>
      <div>All patch tasks are marked done. Uncheck “Hide done” to review them.</div></div>`;

  _wirePatchItems(list, host, family);
  _updatePatchBadge();
  _loadPatchability();
}

/* --- Patchability: is each package's fix actually available? (backend check) --- */

const _PATCH_STATUS = {
  patchable:     { label: 'Patchable',      cls: 'patch-status-ok',    warn: false },
  already_fixed: { label: 'Already fixed',  cls: 'patch-status-muted', warn: false },
  fix_pending:   { label: 'Fix not in repo', cls: 'patch-status-warn', warn: true },
  no_fix:        { label: 'No fix yet',      cls: 'patch-status-crit', warn: true },
  unknown:       { label: '—',               cls: 'patch-status-muted', warn: false },
};

async function _loadPatchability() {
  const { cves, family } = _patchContext();
  if (!cves.length) return;
  let pkgs;
  try {
    const res = await fetch('/api/patchability', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ report: { distro_family: family }, cves }),
    });
    const data = await res.json();
    if (!data.ok) throw new Error(data.error || 'patchability failed');
    pkgs = data.packages || {};
  } catch (_) {
    // Network/back-end issue — clear the "checking" pills rather than hang
    document.querySelectorAll('.patch-status-checking').forEach(el => {
      el.textContent = ''; el.className = 'patch-status';
    });
    return;
  }
  for (const [pkg, info] of Object.entries(pkgs)) {
    const item = document.querySelector(`.patch-item[data-patch-pkg="${CSS.escape(pkg)}"]`);
    if (item) _applyPatchStatus(item, info);
  }
}

function _applyPatchStatus(item, info) {
  const meta   = _PATCH_STATUS[info.status] || _PATCH_STATUS.unknown;
  const statEl = item.querySelector('.patch-status');
  if (statEl) { statEl.textContent = meta.label; statEl.className = `patch-status ${meta.cls}`; }

  const warnEl = item.querySelector('.patch-warn');
  const aiBtn  = item.querySelector('.patch-ai-btn');
  if (meta.warn && warnEl) {
    warnEl.style.display = 'flex';
    warnEl.innerHTML = `<span class="patch-warn-icon">!</span>
      <span>${escapeHtml(info.note || 'This package may not be directly patchable.')}</span>`;
    // Not directly patchable → steer the user to AI mitigation as the next step
    if (aiBtn) aiBtn.textContent = info.status === 'no_fix'
      ? 'Get mitigation steps (AI)' : 'Get next steps (AI)';
    item.classList.add('patch-item-warn');
  } else if (warnEl) {
    warnEl.style.display = 'none';
    item.classList.remove('patch-item-warn');
  }
}

function _wirePatchItems(list, host, family) {
  // Copy command
  list.querySelectorAll('.patch-copy-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      navigator.clipboard.writeText(btn.dataset.cmd).then(() => {
        showToast('Patch command copied to clipboard', 'success');
        btn.textContent = 'Copied!';
        setTimeout(() => (btn.textContent = 'Copy'), 1500);
      });
    });
  });

  // Mark done / undo (button + checkbox stay in sync)
  const setDone = (pkg, val) => {
    const set = _patchDoneSet(host);
    val ? set.add(pkg) : set.delete(pkg);
    _savePatchDone(host, set);
    showToast(val ? `Marked ${pkg} as patched` : `Reopened ${pkg}`, val ? 'success' : 'info');
    renderPatches();
  };
  list.querySelectorAll('.patch-item').forEach(item => {
    const pkg = item.dataset.patchPkg;
    item.querySelector('.patch-toggle-btn')?.addEventListener('click',
      () => setDone(pkg, !_patchDoneSet(host).has(pkg)));
    item.querySelector('.patch-done-cb')?.addEventListener('change',
      e => setDone(pkg, e.target.checked));
    item.querySelector('.patch-ai-btn')?.addEventListener('click',
      () => _aiPatchPackage(pkg, host, family));
  });
}

function _patchPlanKey(host, pkg, pkgCves) {
  const ids = pkgCves.map(c => c.id).sort().join('+');
  return `${host}_${pkg}_${pkgCves[0]?.installed ?? '?'}_${ids}`.replace(/[^a-zA-Z0-9_+.-]/g, '_');
}

function _renderPatchPlan(out, text) {
  out.innerHTML = `<div class="patch-ai-head">Remediation plan</div>
    <div class="patch-ai-body">${_mdLite(text || 'No response.')}</div>`;
}

async function _aiPatchPackage(pkg, host, family) {
  const item = document.querySelector(`.patch-item[data-patch-pkg="${CSS.escape(pkg)}"]`);
  if (!item) return;
  const out = item.querySelector('.patch-ai-output');
  const btn = item.querySelector('.patch-ai-btn');
  const { cves } = _patchContext();
  const pkgCves = cves.filter(c => (c.package || '(unknown)') === pkg);
  const cacheKey = _patchPlanKey(host, pkg, pkgCves);

  out.style.display = 'block';

  // Cache: localStorage → Firebase. Only spend tokens if neither has this plan.
  try {
    const raw = localStorage.getItem('patch_plan_' + cacheKey);
    if (raw) { _renderPatchPlan(out, JSON.parse(raw).text); return; }
  } catch (_) {}
  if (typeof window.__loadPatchPlan === 'function') {
    const cached = await window.__loadPatchPlan(cacheKey);
    if (cached?.text) {
      try { localStorage.setItem('patch_plan_' + cacheKey, JSON.stringify({ text: cached.text })); } catch (_) {}
      _renderPatchPlan(out, cached.text);
      return;
    }
  }

  out.innerHTML = `<div class="patch-ai-loading"><span class="scan-spinner" style="width:16px;height:16px"></span> J.A.R.V.I.S. is drafting a remediation plan…</div>`;
  if (btn) btn.disabled = true;
  const toast = showToast(`Generating patch plan for ${pkg}…`, 'loading');

  const cveLines = pkgCves.map(c =>
    `  - ${c.id} (${c.severity}, ${cveImpactLabel(c)}): ${(c.summary || '').slice(0, 120)}`).join('\n');
  const cmd = _patchCmd(family, pkg);
  const prompt =
    `You are a Linux security engineer. Give a concise remediation for ONE package on a ${family} system (host ${host}).\n\n` +
    `Package: ${pkg}\nInstalled: ${pkgCves[0]?.installed ?? '?'}  Fixed in: ${pkgCves[0]?.fixed ?? '?'}\n` +
    `CVEs (${pkgCves.length}):\n${cveLines}\n\n` +
    `Suggested upgrade command: ${cmd}\n\n` +
    `Respond in EXACTLY this structure, terse and practical, under 160 words, no preamble:\n` +
    `**Risk:** one sentence on real-world impact.\n` +
    `**Fix:** the exact shell commands (in a \`\`\`bash code block\`\`\`). Prefer upgrading to the fixed version.\n` +
    `**If you can't patch now:** one or two mitigations.`;

  try {
    const res = await fetch('/api/ai/complete', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ messages: [{ role: 'user', content: prompt }], temperature: 0.3, max_tokens: 600 }),
    });
    const data = await res.json();
    if (!data.ok) throw new Error(data.error || 'AI request failed');
    const text = data.text || 'No response.';
    _renderPatchPlan(out, text);
    // Persist so the same package isn't re-billed (localStorage + Firebase)
    try { localStorage.setItem('patch_plan_' + cacheKey, JSON.stringify({ text })); } catch (_) {}
    if (typeof window.__savePatchPlan === 'function') window.__savePatchPlan(cacheKey, text);
    toast.update(`Patch plan ready for ${pkg}`, 'success');
  } catch (err) {
    out.innerHTML = `<div class="patch-ai-body" style="color:var(--sev-critical)">AI request failed: ${escapeHtml(err.message)}</div>`;
    toast.update(`Couldn't generate plan for ${pkg}`, 'error');
  } finally {
    if (btn) btn.disabled = false;
  }
}

// Minimal, safe markdown → HTML (escapes first, then re-applies a few tokens)
function _mdLite(text) {
  let h = escapeHtml(text);
  h = h.replace(/```(?:\w+)?\n?([\s\S]*?)```/g,
    (_, code) => `<pre class="patch-ai-pre"><code>${code.replace(/\n+$/, '')}</code></pre>`);
  h = h.replace(/`([^`]+)`/g, '<code>$1</code>');
  h = h.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  h = h.replace(/^\s*[-*]\s+(.*)$/gm, '• $1');
  return h.replace(/\n/g, '<br>');
}

function _updatePatchBadge() {
  const { cves, host } = _patchContext();
  const groups = _groupPatches(cves);
  const done   = _patchDoneSet(host);
  const open   = groups.filter(g => !done.has(g.pkg)).length;
  const badge  = document.getElementById('nav-patch-badge');
  if (badge) {
    badge.textContent = open;
    badge.classList.toggle('hidden', open === 0);
  }
}
window.__updatePatchBadge = _updatePatchBadge;

// Deep-link to a specific CVE: jump to the CVE tab, clear filters, expand its detail
window.__gotoCVE = function (cveId) {
  const nav = document.querySelector('.nav-item[data-section="section-cves"]');
  if (nav) nav.click();
  setTimeout(() => {
    document.querySelectorAll('#cve-filter-bar .filter-chip.active, #cve-type-filter-bar .filter-chip.active')
      .forEach(c => c.classList.remove('active'));
    const allChip = document.querySelector('#cve-dev-chips .sec-dev-chip[data-device=""]');
    if (allChip) {
      document.querySelectorAll('#cve-dev-chips .sec-dev-chip').forEach(c => c.classList.remove('active'));
      allChip.classList.add('active');
    }
    const search = document.getElementById('cve-search');
    if (search) search.value = '';
    filterCVETable();

    const row = document.querySelector(`.cve-row[data-cve-id="${CSS.escape(cveId)}"]`);
    if (!row) { showToast(`${cveId} is not in the current results`, 'warning'); return; }
    row.scrollIntoView({ behavior: 'smooth', block: 'center' });
    row.classList.add('cve-row-flash');
    setTimeout(() => row.classList.remove('cve-row-flash'), 1600);
    const next = row.nextElementSibling;
    if (!(next && next.classList.contains('cve-detail-row'))) row.querySelector('.cve-expand-btn')?.click();
  }, 140);
};

// Deep-link from a CVE row: jump to Patches, focus the package, run AI
window.__gotoPatch = function (pkg, cveId) {
  const nav = document.querySelector('.nav-item[data-section="section-patches"]');
  if (nav) nav.click();
  setTimeout(() => {
    const item = document.querySelector(`.patch-item[data-patch-pkg="${CSS.escape(pkg)}"]`);
    if (!item) { showToast(`No patch task found for ${pkg}`, 'warning'); return; }
    item.scrollIntoView({ behavior: 'smooth', block: 'center' });
    item.classList.add('patch-flash');
    setTimeout(() => item.classList.remove('patch-flash'), 1600);
    const { host, family } = _patchContext();
    _aiPatchPackage(pkg, host, family);
  }, 120);
};

// Wire the Patches toolbar controls once
(function _wirePatchToolbar() {
  document.getElementById('patch-reset-btn')?.addEventListener('click', () => {
    const { host } = _patchContext();
    localStorage.removeItem('patch_done_' + host);
    showToast('Patch progress reset', 'info');
    renderPatches();
  });
  document.getElementById('patch-hide-done')?.addEventListener('change', renderPatches);
})();

/* --- Helpers --- */

function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function _sevOrder(sev) {
  return { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 }[sev] ?? 4;
}

function sevColor(sev) {
  return { critical: 'var(--sev-critical)', high: 'var(--sev-high)',
           medium: 'var(--sev-medium)', low: 'var(--sev-low)' }[sev]
         ?? 'var(--text-muted)';
}

/* =========================================================
   NMAP NETWORK SCAN
   ========================================================= */

window.runNmapScan = async function() {
  // Infer subnet from the last scan report's IP addresses, or ask user
  let subnet = '';
  if (_lastReport?.network?.addresses) {
    for (const iface of _lastReport.network.addresses) {
      if (iface.ifname?.startsWith('lo')) continue;
      for (const addr of (iface.addr_info ?? [])) {
        if (addr.family === 'inet' && addr.local && addr.prefixlen) {
          // Build CIDR from IP + prefix
          const parts = addr.local.split('.').map(Number);
          const prefix = addr.prefixlen;
          subnet = `${parts[0]}.${parts[1]}.${parts[2]}.0/${prefix}`;
          break;
        }
      }
      if (subnet) break;
    }
  }
  if (!subnet) {
    subnet = prompt('Enter subnet to scan (e.g. 192.168.1.0/24):');
    if (!subnet) return;
  }

  const btn = document.getElementById('nmap-scan-btn');
  if (btn) { btn.disabled = true; btn.textContent = '⬡ Scanning…'; }

  try {
    const res  = await fetch('/api/nmap_scan', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ subnet }),
    });
    const data = await res.json();

    if (!data.ok || !data.available) {
      alert('Nmap scan failed: ' + (data.error || data.reason || 'unknown error'));
      return;
    }

    _mergeNmapResults(data.hosts ?? []);
  } catch (err) {
    alert('Nmap scan error: ' + err.message);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = '⬡ Nmap Scan'; }
  }
};

function _mergeNmapResults(hosts) {
  const grid  = document.getElementById('devices-grid');
  const count = document.getElementById('devices-count');
  if (!grid || hosts.length === 0) return;

  // Remove old nmap placeholder cards
  grid.querySelectorAll('.nmap-card').forEach(el => el.remove());

  let added = 0;
  for (const h of hosts) {
    const label    = h.hostname !== h.ip ? h.hostname : h.ip;
    const sublabel = h.hostname !== h.ip ? h.ip : '';
    const vendor   = h.vendor ? ` · ${escapeHtml(h.vendor)}` : '';

    // Skip if already in device cache
    if (window.__deviceCache?.[h.hostname] || window.__deviceCache?.[h.ip]) continue;

    const card = document.createElement('div');
    card.className = 'device-card nmap-card';
    card.innerHTML = `
      <div class="device-card-header">
        <div class="device-icon">🔍</div>
        <div>
          <div class="device-name">${escapeHtml(label)}</div>
          <div class="device-os">${escapeHtml(sublabel)}${vendor}</div>
        </div>
      </div>
      <div class="device-footer" style="padding-top:8px">
        <span class="device-kernel">Discovered via nmap</span>
        ${h.mac ? `<span class="device-last-scan mono" style="font-size:10px">${escapeHtml(h.mac)}</span>` : ''}
      </div>`;
    grid.appendChild(card);
    added++;
  }

  if (count) {
    const existing = parseInt(count.textContent) || 0;
    const total    = existing + added;
    count.textContent = `${total} device${total !== 1 ? 's' : ''}`;
  }

  if (added === 0) alert(`Nmap found ${hosts.length} host${hosts.length !== 1 ? 's' : ''} — all already registered.`);
}

/* =========================================================
   DEVICES — modal + network map
   ========================================================= */

document.getElementById('devices-map-rebuild')?.addEventListener('click', () => {
  if (window.__deviceCache) buildDeviceNetworkMap(Object.values(window.__deviceCache));
});

// Wire nav click to trigger device map build
const _origNavHandler = document.querySelectorAll('.nav-item[data-section]');

window.__openDeviceModal = function(d) {
  const modal = document.getElementById('device-modal');
  const body  = document.getElementById('device-modal-body');
  if (!modal || !body) return;

  const hostname = d.hostname ?? '—';
  const os       = d.os      ?? '—';
  const kernel   = d.kernel  ?? '—';
  const arch     = d.arch    ?? '—';
  const cpu      = d.cpu     ?? '—';
  const cores    = d.cpu_cores ?? '?';
  const memGB    = d.mem_total      ? (d.mem_total / (1024 ** 3)).toFixed(1) + ' GiB' : '?';
  const freeGB   = d.mem_available  ? (d.mem_available / (1024 ** 3)).toFixed(1) + ' GiB' : '?';
  const pkgCount = d.pkg_count ?? 0;
  const pkgMgr   = d.pkg_manager ?? '';
  const critical = d.critical ?? 0;
  const high     = d.high    ?? 0;
  const other    = d.other   ?? 0;
  const cves     = Array.isArray(d.cves) ? d.cves : [];
  const topo     = d.topology ?? null;
  const scanDate = d.createdAt?.toDate?.()?.toLocaleString()
                ?? (d.scanned_at ? new Date(d.scanned_at).toLocaleString() : '—');

  document.getElementById('modal-hostname').textContent = hostname;
  document.getElementById('modal-os').textContent       = os;

  const riskLvl   = critical > 0 ? 'critical' : high > 0 ? 'high' : (d.critical !== undefined ? 'clean' : 'unknown');
  const riskBadge = document.getElementById('modal-risk-badge');
  if (riskBadge) {
    const cls = { critical: 'badge-critical', high: 'badge-high', clean: 'badge-low', unknown: '' }[riskLvl];
    riskBadge.className = 'badge ' + cls;
    riskBadge.textContent = riskLvl;
    riskBadge.style.display = riskLvl === 'unknown' ? 'none' : '';
  }

  const cveTableHtml = cves.length > 0
    ? `<div class="modal-section">
        <div class="modal-section-title">CVEs — top ${Math.min(cves.length, 10)} of ${cves.length}</div>
        <table class="modal-cve-table">
          <thead><tr><th>ID</th><th>Package</th><th>Sev.</th><th>CVSS</th><th></th></tr></thead>
          <tbody>
            ${cves.slice(0, 10).map(c => {
              const id    = c.id || '';
              const nvd   = id.startsWith('CVE-') ? `https://nvd.nist.gov/vuln/detail/${id}` : '';
              const arch  = id.startsWith('CVE-') ? `https://security.archlinux.org/${id}`
                          : id.startsWith('ASA-') ? `https://security.archlinux.org/advisory/${id}` : '';
              const links = [
                nvd  ? `<a href="${escapeHtml(nvd)}"  target="_blank" rel="noopener" style="margin-right:4px;font-size:10px" class="btn btn-ghost btn-sm">NVD</a>`  : '',
                arch ? `<a href="${escapeHtml(arch)}" target="_blank" rel="noopener" style="font-size:10px" class="btn btn-ghost btn-sm">Arch</a>` : '',
              ].join('');
              return `<tr>
                <td class="mono" style="font-size:11px">${escapeHtml(id)}</td>
                <td>${escapeHtml(c.package)}</td>
                <td><span class="badge badge-${c.severity}">${c.severity}</span></td>
                <td class="cvss-score cvss-${c.severity}">${c.cvss != null ? Number(c.cvss).toFixed(1) : '—'}</td>
                <td style="white-space:nowrap">${links || '—'}</td>
              </tr>`;
            }).join('')}
          </tbody>
        </table>
      </div>`
    : (d.critical !== undefined
        ? `<div class="modal-section"><div class="device-clean" style="padding:8px 0">✓ No known CVEs detected</div></div>`
        : `<div class="modal-section"><div class="text-muted" style="font-size:12px">CVE data not yet available — run a scan with CVE analysis.</div></div>`);

  const netHtml = topo
    ? `<div class="modal-section">
        <div class="modal-section-title">Network</div>
        <div class="modal-meta-grid">
          ${topo.gateway ? `<div class="modal-meta-item"><div class="modal-meta-label">Gateway</div><div class="modal-meta-value mono">${escapeHtml(topo.gateway)}</div></div>` : ''}
          ${(topo.my_ips ?? []).slice(0, 3).map(ip => `
            <div class="modal-meta-item">
              <div class="modal-meta-label">${escapeHtml(ip.interface ?? '')}</div>
              <div class="modal-meta-value mono">${escapeHtml(ip.ip ?? '')}/${ip.prefix ?? ''}</div>
            </div>`).join('')}
          ${(topo.neighbors ?? []).length > 0 ? `
            <div class="modal-meta-item">
              <div class="modal-meta-label">LAN devices</div>
              <div class="modal-meta-value">${topo.neighbors.length} in ARP table</div>
            </div>` : ''}
        </div>
      </div>` : '';

  const currentTag   = typeof window.__getDeviceTag   === 'function' ? window.__getDeviceTag(hostname)   : '';
  const currentNotes = typeof window.__getDeviceNotes === 'function' ? window.__getDeviceNotes(hostname) : '';

  body.innerHTML = `
    <div class="modal-specs-row">
      <div class="modal-spec"><div class="modal-spec-label">Kernel</div><div class="modal-spec-value mono">${escapeHtml(kernel)}</div></div>
      <div class="modal-spec"><div class="modal-spec-label">Arch</div><div class="modal-spec-value">${escapeHtml(arch)}</div></div>
      <div class="modal-spec"><div class="modal-spec-label">CPU</div><div class="modal-spec-value">${escapeHtml(cpu)}</div></div>
      <div class="modal-spec"><div class="modal-spec-label">Cores</div><div class="modal-spec-value">${escapeHtml(String(cores))}</div></div>
      <div class="modal-spec"><div class="modal-spec-label">Memory</div><div class="modal-spec-value">${escapeHtml(memGB)} · ${escapeHtml(freeGB)} free</div></div>
      <div class="modal-spec"><div class="modal-spec-label">Packages</div><div class="modal-spec-value">${pkgCount} via ${escapeHtml(pkgMgr)}</div></div>
    </div>
    <div class="modal-cve-summary">
      <div class="modal-cve-badge"><div class="modal-cve-num" style="color:var(--sev-critical)">${critical}</div><div class="modal-cve-lbl">critical</div></div>
      <div class="modal-cve-badge"><div class="modal-cve-num" style="color:var(--sev-high)">${high}</div><div class="modal-cve-lbl">high</div></div>
      <div class="modal-cve-badge"><div class="modal-cve-num" style="color:var(--sev-medium)">${other}</div><div class="modal-cve-lbl">med/low</div></div>
      <div style="margin-left:auto;font-size:11px;color:var(--text-muted)">Last scan<br>${escapeHtml(scanDate)}</div>
    </div>
    ${cveTableHtml}
    ${netHtml}
    <div class="modal-section modal-label-section">
      <div class="modal-section-title">Label &amp; Notes</div>
      <div class="modal-label-row">
        <label class="modal-field-label">Short label</label>
        <div style="display:flex;gap:8px;align-items:center">
          <input id="modal-tag-input" type="text"
            placeholder="e.g. web-server-prod, dev-laptop, db-primary"
            value="${escapeHtml(currentTag)}"
            class="modal-text-input modal-tag-input" />
        </div>
      </div>
      <div class="modal-label-row">
        <label class="modal-field-label">Notes</label>
        <textarea id="modal-notes-input" rows="3"
          placeholder="Purpose, owner, environment, anything relevant…"
          class="modal-text-input modal-notes-input">${escapeHtml(currentNotes)}</textarea>
      </div>
      <div style="display:flex;align-items:center;gap:10px;margin-top:10px">
        <button class="btn btn-primary btn-sm" id="modal-label-save">Save Label</button>
        <span id="modal-tag-status" style="font-size:11px;color:var(--text-muted)"></span>
      </div>
    </div>`;

  // Wire label save
  const tagInput    = body.querySelector('#modal-tag-input');
  const notesInput  = body.querySelector('#modal-notes-input');
  const tagSave     = body.querySelector('#modal-label-save');
  const tagStatus   = body.querySelector('#modal-tag-status');

  if (tagSave) {
    tagSave.addEventListener('click', async () => {
      const tag   = tagInput?.value.trim()  || '';
      const notes = notesInput?.value.trim() || '';
      tagSave.disabled = true;
      if (typeof window.__saveDeviceLabel === 'function') {
        await window.__saveDeviceLabel(hostname, tag, notes);
        if (tagStatus) {
          tagStatus.textContent = '✓ Saved';
          setTimeout(() => { tagStatus.textContent = ''; }, 2000);
        }
        // Refresh the tag label on the device card
        document.querySelectorAll('.device-card').forEach(card => {
          const nameEl = card.querySelector('.device-name');
          if (nameEl?.textContent !== hostname) return;
          let labelEl = card.querySelector('.device-tag-label');
          if (!labelEl && tag) {
            labelEl = document.createElement('div');
            labelEl.className = 'device-tag-label';
            labelEl.style.cssText = 'font-size:10px;color:var(--accent);font-family:var(--font-mono);margin-top:2px';
            nameEl.after(labelEl);
          }
          if (labelEl) labelEl.textContent = tag;
        });
      }
      tagSave.disabled = false;
    });
    tagInput?.addEventListener('keydown', e => { if (e.key === 'Enter') tagSave.click(); });
  }

  // Wire delete button
  const deleteBtn = document.getElementById('modal-delete-btn');
  if (deleteBtn) {
    deleteBtn.onclick = async () => {
      const confirmed = confirm(
        `Delete "${hostname}" from Scan Oasis?\n\nThis removes all scan history and labels for this device. It cannot be undone.`
      );
      if (!confirmed) return;
      deleteBtn.disabled = true;
      deleteBtn.textContent = 'Deleting…';
      const result = await window.__deleteDevice?.(hostname);
      if (result?.ok) {
        modal.style.display = 'none';
        // Remove the device card from the grid
        document.querySelectorAll('.device-card').forEach(card => {
          if (card.querySelector('.device-name')?.textContent === hostname) card.remove();
        });
        // Rebuild the device network map
        if (window.__deviceCache && typeof window.__buildDeviceNetworkMap === 'function') {
          window.__buildDeviceNetworkMap(Object.values(window.__deviceCache));
        }
        // Update device count badge
        const remaining = document.querySelectorAll('#devices-grid .device-card:not(.nmap-card)').length;
        const countEl   = document.getElementById('devices-count');
        const badgeEl   = document.getElementById('nav-device-badge');
        if (countEl) countEl.textContent = `${remaining} device${remaining !== 1 ? 's' : ''}`;
        if (badgeEl) {
          badgeEl.textContent = remaining;
          badgeEl.classList.toggle('hidden', remaining === 0);
        }
        const statEl = document.getElementById('stat-devices');
        if (statEl) statEl.textContent = remaining;
      } else {
        deleteBtn.textContent = '⊗ Delete';
        deleteBtn.disabled = false;
        alert('Delete failed: ' + (result?.error || 'unknown error'));
      }
    };
  }

  modal.style.display = 'flex';
};

window.__buildDeviceNetworkMap = buildDeviceNetworkMap;
function buildDeviceNetworkMap(devicesArray) {
  const container = document.getElementById('devices-map-cy');
  if (!container) return;

  if (!devicesArray || devicesArray.length === 0) {
    container.innerHTML = '<div class="empty-state"><div class="empty-icon">⬡</div><div>No devices found — run a scan first.</div></div>';
    return;
  }

  if (typeof cytoscape === 'undefined') {
    container.innerHTML = '<div class="empty-state"><div class="empty-icon">⚠</div><div>Cytoscape not loaded yet — try again in a moment.</div></div>';
    return;
  }

  container.innerHTML = '';

  // Group devices by gateway to form LAN clusters
  const byGateway = new Map();
  const noGateway = [];
  for (const d of devicesArray) {
    const gw = d.topology?.gateway;
    if (gw) {
      if (!byGateway.has(gw)) byGateway.set(gw, []);
      byGateway.get(gw).push(d);
    } else {
      noGateway.push(d);
    }
  }

  const elements = [];

  byGateway.forEach((devs, gw) => {
    const gwId = 'gw-' + gw.replace(/[.:]/g, '_');
    elements.push({ data: { id: gwId, label: gw, sublabel: 'Router', type: 'router', risk: 'none' } });

    for (const d of devs) {
      const did  = 'dev-' + d.hostname.replace(/[^a-zA-Z0-9]/g, '_');
      const risk = _deviceRisk(d);
      elements.push({ data: {
        id:       did,
        label:    d.hostname,
        sublabel: (d.topology?.my_ips?.[0]?.ip ?? ''),
        type:     'known',
        risk,
        color:    _RISK_COLOR[risk],
        hostname: d.hostname,
      }});
      elements.push({ data: { id: 'e-' + gwId + '-' + did, source: gwId, target: did, etype: 'lan' } });
    }

    // Lateral movement arrows: high-risk device → peers on same LAN
    const risky = devs.filter(d => (d.critical ?? 0) + (d.high ?? 0) > 0);
    for (const hr of risky) {
      const hrId = 'dev-' + hr.hostname.replace(/[^a-zA-Z0-9]/g, '_');
      for (const peer of devs) {
        if (peer.hostname === hr.hostname) continue;
        const peerId = 'dev-' + peer.hostname.replace(/[^a-zA-Z0-9]/g, '_');
        elements.push({
          data: { id: 'pivot-' + hrId + '-' + peerId, source: hrId, target: peerId, etype: 'pivot' },
          classes: 'attack-pivot',
        });
      }
    }
  });

  // Devices with no gateway saved (old scans) — show as isolated nodes
  for (const d of noGateway) {
    const did  = 'dev-' + d.hostname.replace(/[^a-zA-Z0-9]/g, '_');
    const risk = _deviceRisk(d);
    if (!elements.some(e => e.data?.id === did)) {
      elements.push({ data: { id: did, label: d.hostname, sublabel: 'no network data', type: 'known', risk, color: _RISK_COLOR[risk], hostname: d.hostname } });
    }
  }

  const cy = cytoscape({
    container,
    elements,
    style: _topoStyle(),
    layout: {
      name:            'cose',
      animate:          true,
      animationDuration: 500,
      nodeRepulsion:    5000,
      idealEdgeLength:  120,
      padding:          40,
    },
    userZoomingEnabled:  true,
    userPanningEnabled:  true,
    boxSelectionEnabled: false,
    minZoom: 0.3,
    maxZoom: 4,
  });

  cy.on('tap', 'node', evt => {
    const data = evt.target.data();
    const info = document.getElementById('devices-map-info');
    if (!info) return;

    if (data.type === 'router') {
      info.innerHTML = `<strong>Gateway Router</strong> <code>${escapeHtml(data.label)}</code> — all devices on this row share this LAN.`;
      info.style.display = 'block';
    } else if (data.hostname && window.__deviceCache?.[data.hostname]) {
      info.innerHTML = `<strong>${escapeHtml(data.hostname)}</strong> — <span style="color:${_RISK_COLOR[data.risk]}">${data.risk}</span> risk · <button class="btn btn-ghost btn-sm" style="margin-left:8px" onclick="window.__openDeviceModal(window.__deviceCache['${escapeHtml(data.hostname)}'])">View Details</button>`;
      info.style.display = 'block';
    }
  });

  window._devices_cy = cy;
}

/* =========================================================
   TOPOLOGY / ATTACK MAP
   ========================================================= */

document.getElementById('topo-rebuild-btn')?.addEventListener('click', () => {
  if (_lastReport) runTopologyBuild();
});

// Explicit, user-triggered AI attack analysis. Cache-aware: only spends tokens
// if there is no cached analysis for the current host + CVE posture.
window.__genAttackAnalysis = function () {
  const topo = window.__lastTopo || _savedTopology || window.__savedData?.topology;
  const cvs  = _cveData || (window.__savedData
    ? { cves: window.__savedData.cves, counts: window.__savedData.counts } : null);
  if (!topo) { showToast('Open the Attack Map first to build the topology', 'warning'); return; }
  if (!cvs)  { showToast('No CVE data yet — run a scan first', 'warning'); return; }
  buildAIAttackNarrative(topo, cvs);   // uses cache; calls Groq only if not cached
};
// Back-compat alias for the toolbar button handler in ai.js
window.__regenAttackVectors = window.__genAttackAnalysis;

async function runTopologyFromSaved(topo, cveData) {
  const container = document.getElementById('topology-cy');
  if (!container) return;
  container.innerHTML = `<div class="empty-state">
    <div class="scan-spinner" style="width:32px;height:32px;margin:0 auto 12px"></div>
    <div style="color:var(--text-muted)">Loading saved topology…</div>
  </div>`;
  let fsDevices = [];
  if (typeof window.__getFirestoreDevices === 'function') {
    fsDevices = await window.__getFirestoreDevices();
  }
  renderTopology(topo, cveData, fsDevices, null);
  showCachedNarrativeOrHint(topo, cveData);   // no AI call unless cached
}

async function runTopologyBuild() {
  const container = document.getElementById('topology-cy');
  if (!container) return;

  container.innerHTML = `<div class="empty-state">
    <div class="scan-spinner" style="width:32px;height:32px;margin:0 auto 12px"></div>
    <div style="color:var(--text-muted)">Building topology…</div>
  </div>`;

  try {
    const res  = await fetch('/api/topology', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(_lastReport),
    });
    const topo = await res.json();
    if (!topo.ok) throw new Error(topo.error || 'Topology failed');

    let fsDevices = [];
    if (typeof window.__getFirestoreDevices === 'function') {
      fsDevices = await window.__getFirestoreDevices();
    }

    renderTopology(topo, _cveData, fsDevices, null);
    showCachedNarrativeOrHint(topo, _cveData);   // no AI call unless cached

  } catch (err) {
    container.innerHTML = `<div class="empty-state">
      <div class="empty-icon">⚠</div>
      <div>Topology failed: ${escapeHtml(err.message)}</div>
    </div>`;
  }
}

const _RISK_COLOR = {
  critical: '#ff3860',
  high:     '#ff6b35',
  clean:    '#27c93f',
  unknown:  '#4a5568',
};

function _deviceRisk(d) {
  if ((d.critical ?? 0) > 0) return 'critical';
  if ((d.high ?? 0) > 0)     return 'high';
  if (d.critical !== undefined) return 'clean';
  return 'unknown';
}

function renderTopology(topo, cveData, fsDevices, aiPaths) {
  window.__lastTopo = topo;          // so the AI-analysis button can find the current topo
  const hostname = topo.hostname || 'This Device';
  const gateway  = topo.gateway;
  const myIps    = topo.my_ips || [];
  const neighbors = topo.neighbors || [];
  const myIp     = myIps[0]?.ip || '?';

  const critical = cveData?.counts?.critical ?? 0;
  const high     = cveData?.counts?.high ?? 0;
  const riskLevel = critical > 0 ? 'critical' : high > 0 ? 'high' : (cveData ? 'clean' : 'unknown');
  const hasNetworkCVEs = (critical + high) > 0;

  const elements = [];

  // Internet node
  elements.push({ data: { id: 'internet', label: 'Internet', type: 'internet', risk: 'none' } });

  // Gateway/router
  if (gateway) {
    elements.push({ data: { id: 'router', label: gateway, sublabel: 'Router / Gateway', type: 'router', risk: 'none' } });
    elements.push({ data: { id: 'e-inet-router', source: 'internet', target: 'router', etype: 'wan' } });
  }

  // Current device
  elements.push({ data: {
    id:       'current',
    label:    hostname,
    sublabel: myIp,
    type:     'current',
    risk:     riskLevel,
    color:    _RISK_COLOR[riskLevel],
  }});
  elements.push({ data: { id: 'e-gw-current', source: gateway ? 'router' : 'internet', target: 'current', etype: 'lan' } });

  // ARP neighbors
  const neighborIds = [];
  for (const n of neighbors) {
    if (!n.ip || n.ip === gateway) continue;
    const nid = 'n-' + n.ip.replace(/[:.]/g, '_');
    neighborIds.push(nid);

    const known  = fsDevices.find(d => d.hostname === n.ip);
    const nRisk  = known ? _deviceRisk(known) : 'unknown';

    elements.push({ data: {
      id:       nid,
      label:    known ? known.hostname : n.ip,
      sublabel: known ? n.ip : (n.mac ? n.mac.slice(-8) : ''),
      type:     'neighbor',
      risk:     nRisk,
      color:    _RISK_COLOR[nRisk],
      state:    Array.isArray(n.state) ? n.state[0] : (n.state || ''),
    }});
    elements.push({ data: { id: 'e-gw-' + nid, source: gateway ? 'router' : 'current', target: nid, etype: 'lan' } });
  }

  // Firestore devices not seen in ARP (previously scanned, maybe offline now)
  for (const d of fsDevices) {
    if (d.hostname === hostname) continue;
    const fid = 'fs-' + d.hostname.replace(/[^a-zA-Z0-9]/g, '_');
    if (elements.some(e => e.data?.id === fid || e.data?.label === d.hostname)) continue;
    const dRisk = _deviceRisk(d);
    elements.push({ data: {
      id:       fid,
      label:    d.hostname,
      sublabel: 'prev. scanned',
      type:     'known',
      risk:     dRisk,
      color:    _RISK_COLOR[dRisk],
    }});
    elements.push({ data: { id: 'e-gw-' + fid, source: gateway ? 'router' : 'internet', target: fid, etype: 'lan' } });
  }

  // Attack web — 100% deterministic from real CVE + network data (one edge per
  // CVE → host, lateral movement, secondary entry points). No AI/invented data
  // is ever drawn on the map; the AI only writes the narrative text below it.
  const webDefs = _cveAttackEdges(topo, cveData, neighbors, fsDevices);
  for (const def of webDefs) {
    const okSrc = elements.some(e => e.data?.id === def.data.source);
    const okTgt = elements.some(e => e.data?.id === def.data.target);
    if (okSrc && okTgt) elements.push(def);
  }

  // Compose the in-node label so each shape is FILLED with device info
  const _cntByName = {};
  for (const d of (fsDevices || [])) if (d.hostname) _cntByName[d.hostname] = { c: d.critical ?? 0, h: d.high ?? 0 };
  for (const el of elements) {
    const d = el.data;
    if (!d || d.source !== undefined) continue;            // skip edges
    if (d.type === 'internet') { d.info = 'INTERNET'; continue; }
    if (d.type === 'router')   { d.info = 'GATEWAY\n' + (d.label || ''); continue; }
    const parts = [d.label || '?'];
    if (d.sublabel) parts.push(d.sublabel);
    const cnt = d.type === 'current' ? { c: critical, h: high }
              : (_cntByName[d.label] || _cntByName[d.hostname]);
    if (cnt && (cnt.c || cnt.h)) parts.push(`${cnt.c} crit · ${cnt.h} high`);
    else if (d.risk === 'clean')   parts.push('no known CVEs');
    else if (d.risk === 'unknown') parts.push('not yet scanned');
    d.info = parts.join('\n');
  }

  const container = document.getElementById('topology-cy');
  container.innerHTML = '';

  if (typeof cytoscape === 'undefined') {
    container.innerHTML = '<div class="empty-state"><div class="empty-icon">⚠</div><div>Cytoscape.js not loaded yet — try again in a moment.</div></div>';
    return;
  }

  const cy = cytoscape({
    container: container,
    elements:  elements,
    style:     _topoStyle(),
    layout: {
      name:                       'cose',   // force-directed → organic web, not a line
      animate:                     true,
      animationDuration:           700,
      nodeRepulsion:               24000,    // push nodes well apart
      idealEdgeLength:             170,      // longer edges = more breathing room
      edgeElasticity:              90,
      gravity:                     0.18,     // weaker pull → spreads out
      componentSpacing:            140,
      nodeOverlap:                 24,
      nodeDimensionsIncludeLabels: true,     // reserve space for edge/node labels
      padding:                     60,
      randomize:                   false,
    },
    userZoomingEnabled:   true,
    userPanningEnabled:   true,
    boxSelectionEnabled:  false,
    minZoom: 0.25,
    maxZoom: 3,
  });

  cy.on('tap', 'node', evt => showTopoNodeInfo(evt.target.data()));
  cy.on('tap', 'edge', evt => showTopoEdgeInfo(evt.target.data()));
  window._topo_cy = cy;
  _applyTopoFilters();   // honour the current filter selection on (re)build
}

// Show/hide topology nodes (by risk) and attack/lateral edges from the filter chips
function _applyTopoFilters() {
  const cy = window._topo_cy;
  if (!cy) return;
  const risks = [...document.querySelectorAll('.topo-filter.active[data-filter="risk"]')].map(b => b.dataset.val);
  const showAttack = document.querySelector('.topo-filter[data-filter="edge"][data-val="attack"]')?.classList.contains('active');
  const showPivot  = document.querySelector('.topo-filter[data-filter="edge"][data-val="pivot"]')?.classList.contains('active');
  cy.batch(() => {
    cy.nodes().forEach(n => {
      const t = n.data('type');
      if (t === 'internet' || t === 'router') { n.style('display', 'element'); return; }   // keep infrastructure
      const risk = n.data('risk') || 'unknown';
      n.style('display', risks.includes(risk) ? 'element' : 'none');
    });
    cy.edges('.attack-path').style('display', showAttack ? 'element' : 'none');
    cy.edges('.attack-pivot').style('display', showPivot ? 'element' : 'none');
  });
}

// Wire the topology filter chips once
document.querySelectorAll('#topo-filters .topo-filter').forEach(btn => {
  btn.addEventListener('click', () => { btn.classList.toggle('active'); _applyTopoFilters(); });
});

function _topoStyle() {
  return [
    {
      selector: 'node',
      style: {
        'background-color':  '#0f1117',
        'border-color':      '#2a3050',
        'border-width':       1.5,
        'label':             'data(info)',          // multi-line device info INSIDE the shape
        'color':             '#cbd5e1',
        'font-size':         '8px',
        'font-family':       '"JetBrains Mono", monospace',
        'text-valign':       'center',
        'text-halign':       'center',
        'text-wrap':         'wrap',
        'text-max-width':     106,
        'line-height':        1.35,
        'shape':             'round-rectangle',
        'width':              120,
        'height':             52,
        'padding':           '6px',
      },
    },
    {
      selector: 'node[type="internet"]',
      style: {
        'background-color': '#0a1628',
        'border-color':     '#4a9eff',
        'border-width':      2,
        'shape':            'ellipse',
        'width':             74,
        'height':            74,
        'color':            '#7fc0ff',
        'font-size':        '9px',
        'font-weight':      '700',
      },
    },
    {
      selector: 'node[type="router"]',
      style: {
        'background-color': '#15121f',
        'border-color':     '#7b61ff',
        'border-width':      1.5,
        'width':             100,
        'height':            48,
        'color':            '#b9a6ff',
      },
    },
    {
      selector: 'node[type="current"]',
      style: {
        'background-color': '#11141d',
        'border-color':     'data(color)',
        'border-width':      2.5,
        'width':             148,
        'height':            62,
        'color':            '#ffffff',
        'font-size':        '9px',
        'font-weight':      '700',
      },
    },
    {
      selector: 'node[type="neighbor"], node[type="known"]',
      style: {
        'background-color': '#0f1117',
        'border-color':     'data(color)',
        'border-width':      1.5,
        'color':            '#c0caf5',
      },
    },
    {
      selector: 'node[risk="critical"]',
      style: { 'border-color': '#ff3860', 'border-width': 3 },
    },
    {
      selector: 'node[risk="high"]',
      style: { 'border-color': '#ff6b35', 'border-width': 3 },
    },
    {
      selector: 'node[risk="clean"]',
      style: { 'border-color': '#27c93f' },
    },
    {
      selector: 'edge',
      style: {
        'width':                2,
        'line-color':          '#2a3050',
        'target-arrow-color':  '#2a3050',
        'target-arrow-shape':  'triangle',
        'curve-style':         'bezier',
        'opacity':              0.5,
      },
    },
    {
      selector: 'edge[etype="wan"]',
      style: {
        'line-color':         '#4a9eff',
        'target-arrow-color': '#4a9eff',
        'opacity': 0.6,
      },
    },
    {
      selector: '.attack-path',
      style: {
        'line-color':          '#ff3860',
        'target-arrow-color':  '#ff3860',
        'width':                4,
        'line-style':          'dashed',
        'line-dash-pattern':   [12, 6],
        'opacity':              1,
        'z-index':              10,
        'label':               'data(cveLabel)',
        'font-size':           '8px',
        'font-family':         '"JetBrains Mono", monospace',
        'color':               '#ffd0d8',
        'text-background-color':   '#08090e',
        'text-background-opacity': 0.85,
        'text-background-padding': '2px',
        'text-rotation':       'autorotate',
      },
    },
    {
      selector: '.attack-pivot',
      style: {
        'line-color':          '#ff6b35',
        'target-arrow-color':  '#ff6b35',
        'width':                2,
        'line-style':          'dashed',
        'line-dash-pattern':   [6, 3],
        'opacity':              0.85,
        'z-index':              9,
        'label':               'data(cveLabel)',
        'font-size':           '7px',
        'font-family':         '"JetBrains Mono", monospace',
        'color':               '#cbd5e1',
        'text-background-color':   '#08090e',
        'text-background-opacity': 0.8,
        'text-background-padding': '2px',
        'text-rotation':       'autorotate',
      },
    },
    // Per-vector colors (up to 4 distinct AI-generated attack paths)
    { selector: '.attack-path-0',  style: { 'line-color': '#ff3860', 'target-arrow-color': '#ff3860', 'color': '#ffd0d8' } },
    { selector: '.attack-path-1',  style: { 'line-color': '#ff9500', 'target-arrow-color': '#ff9500', 'color': '#ffe6c2' } },
    { selector: '.attack-path-2',  style: { 'line-color': '#a855f7', 'target-arrow-color': '#a855f7', 'color': '#ecd9ff' } },
    { selector: '.attack-path-3',  style: { 'line-color': '#22d3ee', 'target-arrow-color': '#22d3ee', 'color': '#cdf6fd' } },
    { selector: '.attack-pivot-0', style: { 'line-color': '#ff3860', 'target-arrow-color': '#ff3860' } },
    { selector: '.attack-pivot-1', style: { 'line-color': '#ff9500', 'target-arrow-color': '#ff9500' } },
    { selector: '.attack-pivot-2', style: { 'line-color': '#a855f7', 'target-arrow-color': '#a855f7' } },
    { selector: '.attack-pivot-3', style: { 'line-color': '#22d3ee', 'target-arrow-color': '#22d3ee' } },
  ];
}

function showTopoNodeInfo(d) {
  const panel = document.getElementById('topo-node-info');
  if (!panel) return;
  const riskLabel = {
    critical: '<span style="color:var(--sev-critical)">● Critical</span>',
    high:     '<span style="color:var(--sev-high)">● High</span>',
    clean:    '<span style="color:var(--sev-low)">● Clean</span>',
    unknown:  '<span style="color:var(--text-muted)">● Unknown</span>',
    none:     '',
  }[d.risk] ?? '';

  if (d.type === 'internet') {
    panel.innerHTML = '<strong>Internet</strong> — External attacker entry point. Devices with network-accessible CVEs are reachable from here.';
  } else if (d.type === 'router') {
    panel.innerHTML = `<strong>Gateway Router</strong> <code>${escapeHtml(d.label)}</code> — Controls all traffic on this network. A compromised host can intercept or reroute router-level traffic.`;
  } else {
    const sub = d.sublabel ? ` <span class="text-muted">${escapeHtml(d.sublabel)}</span>` : '';
    panel.innerHTML = `<strong>${escapeHtml(d.label)}</strong>${sub} — Risk: ${riskLabel}`;
    if (d.type === 'known') panel.innerHTML += ' <span class="text-muted">(previously scanned, not seen on ARP table)</span>';
    if (d.state && d.state !== 'REACHABLE') panel.innerHTML += ` <span class="text-muted">· ARP state: ${escapeHtml(d.state)}</span>`;
  }
  panel.style.display = 'block';
}

/* --- Multi-vector attack paths --- */
const _ATTACK_COLORS = ['#ff3860', '#ff9500', '#a855f7', '#22d3ee'];

// Normalize AI output to an array of path objects (handles old single-path shape)
function _attackPaths(aiPaths) {
  if (!aiPaths) return [];
  if (Array.isArray(aiPaths)) return aiPaths;
  if (Array.isArray(aiPaths.attack_paths)) return aiPaths.attack_paths;
  if (aiPaths.attack_source || aiPaths.entry_cves || aiPaths.pivot_targets) return [aiPaths];
  return [];
}

// Resolve an AI node reference ("internet" / "current" / gateway / neighbour IP) to a graph node id
function _resolveNodeId(ref, topo, neighbors) {
  if (!ref) return null;
  const r = String(ref).trim().toLowerCase();
  if (['internet', 'external', 'attacker', 'wan'].includes(r)) return 'internet';
  if (['current', 'host', 'this', 'this device', 'localhost', 'me'].includes(r)) return 'current';
  if (topo.hostname && r === topo.hostname.toLowerCase()) return 'current';
  const myIp = topo.my_ips?.[0]?.ip;
  if (myIp && r === myIp.toLowerCase()) return 'current';
  if (topo.gateway && (r === topo.gateway.toLowerCase() || r === 'gateway' || r === 'router')) return 'router';
  const n = (neighbors || []).find(x => x.ip && x.ip.toLowerCase() === r);
  if (n) return 'n-' + n.ip.replace(/[:.]/g, '_');
  return null;
}

// Build cytoscape edge definitions forming a kill-web of interconnected attack edges.
// Each vector may carry an explicit `edges` graph; older {entry_cves,pivot_targets} is synthesised.
function _attackEdgeDefs(paths, topo, neighbors) {
  const defs = [];
  let seq = 0;
  paths.forEach((p, i) => {
    const idx   = i % _ATTACK_COLORS.length;
    const vname = p.name || `Vector ${i + 1}`;

    let edges = Array.isArray(p.edges) ? p.edges : null;
    if (!edges) {                                   // backward-compat synthesis
      edges = [];
      const entryFrom = p.attack_source === 'internal' ? (topo.gateway || 'router') : 'internet';
      edges.push({ from: entryFrom, to: 'current', cve: (p.entry_cves || [])[0] || '', technique: 'Initial access' });
      for (const ip of (p.pivot_targets || []))
        edges.push({ from: 'current', to: ip, cve: '', technique: 'Lateral movement' });
    }

    for (const e of edges) {
      const src = _resolveNodeId(e.from, topo, neighbors);
      const tgt = _resolveNodeId(e.to, topo, neighbors);
      if (!src || !tgt || src === tgt) continue;
      const isEntry  = src === 'internet';
      const cves     = (Array.isArray(e.cves) ? e.cves : (e.cve ? [e.cve] : [])).filter(Boolean);
      const cveLabel = cves[0] ? (cves.length > 1 ? `${cves[0]} +${cves.length - 1}` : cves[0]) : (e.technique || '');
      defs.push({
        data: {
          id: `atk-${i}-${seq++}`, source: src, target: tgt,
          etype: isEntry ? 'attack' : 'pivot',
          pathIndex: idx, vector: vname,
          cves: cves.join(', '), cveLabel, technique: e.technique || '',
        },
        classes: `${isEntry ? 'attack-path attack-path' : 'attack-pivot attack-pivot'}-${idx}`,
      });
    }
  });
  return defs;
}

// Deterministic kill-web: one attack edge per network-relevant CVE converging on
// the host (multiple CVEs → same target), plus lateral movement and secondary
// entry points. Guarantees a web regardless of what the LLM returns.
function _cveAttackEdges(topo, cveData, neighbors, fsDevices) {
  const defs = [];
  const top = (cveData?.cves || [])
    .filter(c => ['critical', 'high'].includes(c.severity))
    .sort((a, b) => (Number(b.cvss) || 0) - (Number(a.cvss) || 0))
    .slice(0, 8);

  // Each CVE is its own attack edge from the internet onto this host
  top.forEach((c, i) => {
    const idx = i % _ATTACK_COLORS.length;
    defs.push({
      data: { id: `cveatk-${i}`, source: 'internet', target: 'current', etype: 'attack',
              pathIndex: idx, vector: c.id, technique: cveImpactLabel(c),
              cves: c.id, cveLabel: c.id },
      classes: `attack-path attack-path-${idx}`,
    });
  });

  // Lateral movement: a compromised host pivots to every visible neighbour
  (neighbors || []).forEach((n, j) => {
    if (!n.ip) return;
    const idx = j % _ATTACK_COLORS.length;
    defs.push({
      data: { id: `cvepivot-${j}`, source: 'current', target: 'n-' + n.ip.replace(/[:.]/g, '_'),
              etype: 'pivot', pathIndex: idx, vector: 'Lateral movement',
              technique: 'Lateral movement', cves: '', cveLabel: '' },
      classes: `attack-pivot attack-pivot-${idx}`,
    });
  });

  // Secondary entry points: previously-scanned devices that are themselves risky
  (fsDevices || []).forEach((d, k) => {
    if (!d.hostname || d.hostname === topo.hostname) return;
    const n = (d.critical ?? 0) + (d.high ?? 0);
    if (n === 0) return;
    const idx = (k + 1) % _ATTACK_COLORS.length;
    defs.push({
      data: { id: `cveentry2-${k}`, source: 'internet', target: 'fs-' + d.hostname.replace(/[^a-zA-Z0-9]/g, '_'),
              etype: 'attack', pathIndex: idx, vector: d.hostname,
              technique: `${n} CVEs`, cves: '', cveLabel: `${n} CVE${n !== 1 ? 's' : ''}` },
      classes: `attack-path attack-path-${idx}`,
    });
  });

  return defs;
}

function showTopoEdgeInfo(d) {
  const panel = document.getElementById('topo-node-info');
  if (!panel || (d.etype !== 'attack' && d.etype !== 'pivot')) return;
  const kind  = d.etype === 'attack' ? 'Initial access' : 'Lateral movement';
  const color = _ATTACK_COLORS[d.pathIndex ?? 0] || '#ff3860';
  const cveLinks = (d.cves ? d.cves.split(',').map(s => s.trim()).filter(Boolean) : [])
    .map(id => `<a class="cve-link" onclick="window.__gotoCVE('${escapeHtml(id)}')">${escapeHtml(id)}</a>`)
    .join('  ');
  panel.innerHTML =
    `<span class="topo-edge-vector" style="color:${color}">${escapeHtml(d.vector || 'Attack path')}</span>` +
    `<span class="topo-edge-kind">${kind}${d.technique ? ' · ' + escapeHtml(d.technique) : ''}</span>` +
    (cveLinks ? `<span class="topo-edge-cves">Exploits ${cveLinks}</span>`
              : `<span class="topo-edge-cves text-muted">No specific CVE required</span>`);
  panel.style.display = 'block';
}

function _renderAttackNarrativeResult(narrative, aiPaths, topo, subline, steps) {
  // The kill-web edges are drawn deterministically in renderTopology — here we
  // only render the AI narrative text, with clickable CVE links.
  const linkifyCVE = s => s.replace(/\b(CVE-\d{4}-\d{4,7}|ASA-\d{4}-\d+)\b/g,
    m => `<a class="cve-link" onclick="window.__gotoCVE('${m}')">${m}</a>`);
  const lines = narrative.split('\n').filter(l => l.trim());
  steps.innerHTML = lines.length > 0
    ? lines.map(l => `<p class="attack-step">${linkifyCVE(escapeHtml(l.trim()))}</p>`).join('')
    : `<p class="attack-step" style="color:var(--text-secondary)">No narrative returned.</p>`;

  if (subline) {
    const edges = window._topo_cy ? window._topo_cy.edges('.attack-path').length : 0;
    subline.textContent = edges > 0
      ? `AI analysis · ${edges} CVE attack path${edges !== 1 ? 's' : ''} on the map · click any edge for its CVE`
      : 'AI analysis · based on live CVE data + network topology';
  }
}

// Stable cache key for a host's AI attack analysis (host + CVE posture + neighbours)
function _narrativeCacheKey(topo, cveData) {
  const neighbors = (topo.neighbors || []).filter(n => n.ip && n.ip !== topo.gateway);
  return `atk_${topo.hostname || 'this'}_${cveData?.counts?.critical ?? 0}c_` +
         `${cveData?.counts?.high ?? 0}h_${neighbors.length}n`.replace(/[^a-zA-Z0-9_-]/g, '_');
}

// Auto-path: show a cached AI narrative if one exists (free), otherwise show a
// hint with a Generate button. NEVER calls Groq — that only happens on click.
async function showCachedNarrativeOrHint(topo, cveData) {
  const panel   = document.getElementById('attack-narrative-panel');
  const steps   = document.getElementById('attack-steps');
  const subline = document.getElementById('attack-narrative-sub');
  if (!panel || !steps) return;
  if (!cveData) { panel.style.display = 'none'; return; }
  panel.style.display = '';
  const cacheKey = _narrativeCacheKey(topo, cveData);

  // localStorage cache (free)
  try {
    const raw = localStorage.getItem('ai_narrative_' + cacheKey);
    if (raw) {
      const cached = JSON.parse(raw);
      if (cached?.narrative && Date.now() - (cached.savedAt || 0) < 86400000) {
        if (subline) subline.textContent = 'AI analysis · cached';
        steps.innerHTML = '';
        _renderAttackNarrativeResult(cached.narrative, cached.aiPaths, topo, subline, steps);
        return;
      }
    }
  } catch (_) {}

  // Firebase cache (free)
  if (typeof window.__loadAINarrative === 'function') {
    const cached = await window.__loadAINarrative(cacheKey);
    if (cached?.narrative) {
      try { localStorage.setItem('ai_narrative_' + cacheKey, JSON.stringify({ narrative: cached.narrative, aiPaths: cached.aiPaths, savedAt: Date.now() })); } catch (_) {}
      if (subline) subline.textContent = 'AI analysis · cached';
      steps.innerHTML = '';
      _renderAttackNarrativeResult(cached.narrative, cached.aiPaths, topo, subline, steps);
      return;
    }
  }

  // No cache → invite the user; do NOT spend tokens automatically
  if (subline) subline.textContent = 'Not generated yet';
  steps.innerHTML = `<div class="attack-hint">
    <p>The attack map above is built directly from your live CVE and network data.</p>
    <button class="btn btn-primary btn-sm" onclick="window.__genAttackAnalysis()">Generate AI analysis</button>
    <span class="text-muted">optional · uses AI</span>
  </div>`;
}

async function buildAIAttackNarrative(topo, cveData, opts = {}) {
  const panel   = document.getElementById('attack-narrative-panel');
  const steps   = document.getElementById('attack-steps');
  const subline = document.getElementById('attack-narrative-sub');
  if (!panel || !steps) return;
  if (!cveData) { panel.style.display = 'none'; return; }

  // Remember the last topo so the "AI Attack Vectors" button can regenerate
  window.__lastTopo = topo;
  panel.style.display = '';

  const hostname  = topo.hostname || 'this device';
  const gateway   = topo.gateway;
  const myIp      = topo.my_ips?.[0]?.ip ?? 'unknown';
  const prefix    = topo.my_ips?.[0]?.prefix ?? '24';
  const neighbors = (topo.neighbors || []).filter(n => n.ip && n.ip !== gateway);

  const critCount     = cveData?.counts?.critical ?? 0;
  const highCount     = cveData?.counts?.high     ?? 0;
  const neighborCount = neighbors.length;
  const cacheKey      = `atk_${hostname}_${critCount}c_${highCount}h_${neighborCount}n`
    .replace(/[^a-zA-Z0-9_-]/g, '_');

  // 1. Check localStorage first (instant) — unless a fresh regen was requested
  try {
    const raw = opts.force ? null : localStorage.getItem('ai_narrative_' + cacheKey);
    if (raw) {
      const cached = JSON.parse(raw);
      // Expire after 24 hours
      if (cached?.narrative && Date.now() - (cached.savedAt || 0) < 86400000) {
        if (subline) subline.textContent = 'AI-generated · cached';
        steps.innerHTML = '';
        _renderAttackNarrativeResult(cached.narrative, cached.aiPaths, topo, subline, steps);
        return;
      }
    }
  } catch (_) {}

  // 2. Check Firebase cache (cross-device)
  if (typeof window.__loadAINarrative === 'function') {
    const cached = await window.__loadAINarrative(cacheKey);
    if (cached?.narrative) {
      try { localStorage.setItem('ai_narrative_' + cacheKey, JSON.stringify({ narrative: cached.narrative, aiPaths: cached.aiPaths, savedAt: Date.now() })); } catch (_) {}
      if (subline) subline.textContent = 'AI-generated · cached';
      steps.innerHTML = '';
      _renderAttackNarrativeResult(cached.narrative, cached.aiPaths, topo, subline, steps);
      return;
    }
  }

  if (subline) subline.textContent = 'Generating AI analysis…';
  steps.innerHTML = `<div class="attack-stream-loading">
    <span class="scan-spinner" style="display:inline-block;width:14px;height:14px;vertical-align:middle;margin-right:8px"></span>
    Analysing CVE data and network topology…
  </div>`;

  const topCVEs = (cveData?.cves ?? [])
    .filter(c => ['critical', 'high'].includes(c.severity))
    .sort((a, b) => (Number(b.cvss) || 0) - (Number(a.cvss) || 0))
    .slice(0, 6);

  const suid     = _lastReport?.suid_files        ?? [];
  const services = _lastReport?.services?.running ?? [];

  const cveBlock = topCVEs.length > 0
    ? topCVEs.map(c => `- ${c.id} [${c.severity.toUpperCase()} CVSS:${Number(c.cvss || 0).toFixed(1)}] package:${c.package}${c.description ? ' — ' + c.description.slice(0, 120) : ''}`).join('\n')
    : 'No high/critical CVEs found.';

  const neighborBlock = neighbors.slice(0, 6).map(n => {
    const known = window.__deviceCache?.[n.ip];
    const risk  = known ? `(${known.critical ?? 0} critical, ${known.high ?? 0} high CVEs)` : '(CVE posture unknown)';
    return `- ${n.ip} ${risk}`;
  }).join('\n') || '- None visible';

  const prompt =
`You are a penetration tester writing an attack path report. Given the scan data below, output EXACTLY two sections:

SECTION 1 — one line of JSON (no markdown, no explanation):
{"attack_paths":[{"name":"short label","edges":[{"from":"internet","to":"current","cve":"CVE-ID","technique":"Remote code execution"}]}]}
Build a KILL WEB: 2-4 distinct attack vectors that together form an INTERCONNECTED graph, not isolated lines. Use MULTIPLE entry sources where realistic (e.g. "internet" for an exposed service AND a vulnerable neighbour as a second foothold). Chain edges so compromise propagates across hosts: internet→current→neighbour→neighbour, and add cross-links between neighbours on the same subnet when plausible.
Every edge has: "from" and "to" (each MUST be one of: "internet", "current", the gateway IP, or an IP from NEIGHBORS), "cve" (a CVE ID actually present in the data, or "" if none is needed for that hop), and "technique" (3-4 words, e.g. "Remote code execution", "Privilege escalation", "Lateral movement", "ARP spoofing", "Credential reuse"). Only reference CVE IDs and IPs that appear in the data.

SECTION 2 — after the exact separator line "---NARRATIVE---":
Write a short numbered analysis (4-8 steps). Walk through each named vector and how the compromise spreads across the web. Reference actual CVE IDs, package names, service names, and neighbour IPs. Be specific and technical. End with one concrete remediation step.

=== SCAN DATA ===
HOST: ${hostname}
IP: ${myIp}/${prefix}
GATEWAY: ${gateway ?? 'unknown'}

HIGH/CRITICAL CVEs ON THIS HOST:
${cveBlock}

NETWORK NEIGHBORS:
${neighborBlock}

RUNNING SERVICES: ${services.slice(0, 12).join(', ') || 'none recorded'}
SUID FILES: ${suid.length} found`;

  try {
    const resp = await fetch('/api/ai/chat', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({
        messages:    [{ role: 'user', content: prompt }],
        temperature: 0.55,
        max_tokens:  1200,
      }),
    });

    const reader  = resp.body.getReader();
    const decoder = new TextDecoder();
    let buf       = '';
    let fullText  = '';
    let streamEl  = null;

    steps.innerHTML = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      let nl;
      while ((nl = buf.indexOf('\n')) !== -1) {
        const line = buf.slice(0, nl).trim();
        buf = buf.slice(nl + 1);
        if (!line.startsWith('data: ')) continue;
        const payload = line.slice(6);
        if (payload === '[DONE]') break;
        try {
          const delta = JSON.parse(payload)?.choices?.[0]?.delta?.content;
          if (delta) {
            fullText += delta;
            if (!streamEl) {
              streamEl = document.createElement('pre');
              streamEl.className = 'attack-stream-text';
              steps.appendChild(streamEl);
            }
            streamEl.textContent = fullText;
          }
        } catch {}
      }
    }

    // Parse the two sections
    const sepIdx = fullText.indexOf('---NARRATIVE---');
    let narrative = fullText;
    let aiPaths   = null;

    if (sepIdx !== -1) {
      const jsonPart = fullText.slice(0, sepIdx).trim();
      narrative      = fullText.slice(sepIdx + 15).trim();
      try {
        // Greedy match captures the whole (possibly nested) JSON object
        const m = jsonPart.match(/\{[\s\S]*\}/);
        if (m) aiPaths = JSON.parse(m[0]);
      } catch {}
    }

    // Save to localStorage (immediate) and Firebase (cross-device)
    try { localStorage.setItem('ai_narrative_' + cacheKey, JSON.stringify({ narrative, aiPaths, savedAt: Date.now() })); } catch (_) {}
    if (typeof window.__saveAINarrative === 'function') window.__saveAINarrative(cacheKey, narrative, aiPaths);

    steps.innerHTML = '';
    _renderAttackNarrativeResult(narrative, aiPaths, topo, subline, steps);

  } catch (err) {
    steps.innerHTML = `<p class="attack-step" style="color:var(--sev-critical)">AI analysis failed: ${escapeHtml(err.message)}</p>`;
    if (subline) subline.textContent = 'Error';
  }
}
