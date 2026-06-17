/* =========================================================
   Oasis Scan — Frontend JS
   ========================================================= */

// Module-level refs kept so runCVEAnalysis() can update the status bar
let _dot        = null;
let _statusLbl  = null;
let _lastReport = null;
let _cveData    = null;   // set by runCVEAnalysis; used by topology map

/* --- Nav --- */
document.querySelectorAll('.nav-item[data-section]').forEach(item => {
  item.addEventListener('click', () => {
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    item.classList.add('active');
    const target = item.dataset.section;
    document.querySelectorAll('.page-section').forEach(s => s.classList.add('hidden'));
    const el = document.getElementById(target);
    if (el) { el.classList.remove('hidden'); el.scrollIntoView({ behavior: 'smooth', block: 'start' }); }
    if (target === 'section-topology' && _lastReport) runTopologyBuild();
    const label = item.textContent.replace(/[⊞⚠⊡⊟⬡✦↺⚙]/g, '').trim();
    const titleEl = document.getElementById('topbar-section-label');
    if (titleEl) titleEl.textContent = label;
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
  const active = [...document.querySelectorAll('.filter-chip.active')].map(c => c.dataset.sev);
  document.querySelectorAll('.cve-row').forEach(row => {
    const sev = row.dataset.severity;
    row.style.display = (active.length === 0 || active.includes(sev)) ? '' : 'none';
  });
}

/* --- Chat input --- */
const chatInput = document.getElementById('chat-input');
if (chatInput) {
  chatInput.addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendAdvisorMessage(); }
  });
}
document.getElementById('chat-send-btn')?.addEventListener('click', sendAdvisorMessage);

function sendAdvisorMessage() {
  const input = document.getElementById('chat-input');
  const text = input?.value.trim();
  if (!text) return;
  appendChatMessage('user', text);
  input.value = '';
  showTypingIndicator();
}

function appendChatMessage(role, text) {
  const feed = document.getElementById('chat-messages');
  if (!feed) return;
  const avatar = role === 'system' ? '🛡' : '👤';
  const label  = role === 'system' ? 'Oasis AI' : 'You';
  const msg = document.createElement('div');
  msg.className = `msg ${role}`;
  msg.innerHTML = `
    <div class="msg-avatar">${avatar}</div>
    <div class="msg-body">
      <div class="msg-role">${label}</div>
      <div class="msg-text">${escapeHtml(text)}</div>
    </div>`;
  feed.appendChild(msg);
  feed.scrollTop = feed.scrollHeight;
}

function showTypingIndicator() {
  const feed = document.getElementById('chat-messages');
  if (!feed) return;
  const el = document.createElement('div');
  el.className = 'msg system';
  el.id = 'typing-indicator';
  el.innerHTML = `
    <div class="msg-avatar">🛡</div>
    <div class="msg-body">
      <div class="msg-role">Oasis AI</div>
      <div class="typing-indicator">
        <div class="typing-dot"></div><div class="typing-dot"></div><div class="typing-dot"></div>
      </div>
    </div>`;
  feed.appendChild(el);
  feed.scrollTop = feed.scrollHeight;
}

function removeTypingIndicator() {
  document.getElementById('typing-indicator')?.remove();
}

/* --- Scan --- */
document.getElementById('scan-btn')?.addEventListener('click', startScan);

async function startScan() {
  _dot       = document.getElementById('status-dot');
  _statusLbl = document.getElementById('status-label');

  const overlay   = document.getElementById('scan-overlay');
  const stepLabel = document.getElementById('scan-step-label');
  const scanBtn   = document.getElementById('scan-btn');

  if (overlay)   overlay.style.display = 'flex';
  if (_dot)      _dot.className = 'status-dot scanning';
  if (_statusLbl) _statusLbl.textContent = 'Scanning…';
  if (scanBtn)   scanBtn.disabled = true;

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
    populateDashboard(data.report);

    const lastScanEl = document.getElementById('last-scan-time');
    if (lastScanEl) lastScanEl.textContent = new Date().toLocaleTimeString();

  } catch (err) {
    clearInterval(stepTimer);
    if (_dot)      _dot.className = 'status-dot error';
    if (_statusLbl) _statusLbl.textContent = 'Scan error';
    if (stepLabel) stepLabel.textContent = 'Scan failed: ' + err.message;
    setTimeout(() => { if (overlay) overlay.style.display = 'none'; }, 3000);
    if (scanBtn) scanBtn.disabled = false;
    return;
  }

  // Hide overlay immediately — show system specs to user right away
  if (overlay) overlay.style.display = 'none';
  if (scanBtn) scanBtn.disabled = false;

  // Both checks run in parallel after the overlay closes
  runCVEAnalysis(_lastReport);
  runIntegrityCheck(_lastReport);
}

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

    _cveData = { cves: data.cves, counts: data.counts };
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
        services_running: r.services?.running?.length ?? 0,
        suid_count:       r.suid_files?.length    ?? 0,
        distro_family:    r.distro_family         ?? '',
        critical: data.counts.critical            ?? 0,
        high:     data.counts.high                ?? 0,
        other:    (data.counts.medium ?? 0) + (data.counts.low ?? 0),
      });
      if (typeof window.__loadDevices === 'function') window.__loadDevices();
    }

    if (_dot)      _dot.className = 'status-dot';
    if (_statusLbl) _statusLbl.textContent = 'Done';

  } catch (err) {
    if (_dot)      _dot.className = 'status-dot error';
    if (_statusLbl) _statusLbl.textContent = 'CVE check failed';
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

  // Show loading state in all three integrity tables
  ['integrity-file-tbody', 'integrity-mal-tbody', 'integrity-bin-tbody'].forEach(id => {
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
    populateIntegrity(data);
  } catch (err) {
    ['integrity-file-tbody', 'integrity-mal-tbody', 'integrity-bin-tbody'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.innerHTML = `<tr><td colspan="5">
        <div class="empty-state" style="color:var(--sev-critical)">
          Failed: ${escapeHtml(err.message)}</div></td></tr>`;
    });
  }
}

function populateIntegrity(data) {
  const sum   = data.summary ?? {};
  const files = data.file_integrity  ?? [];
  const mal   = data.malicious       ?? [];
  const bins  = data.modified_bins   ?? [];

  // Top banner
  const banner = document.getElementById('integrity-banner');
  const icon   = document.getElementById('integrity-banner-icon');
  const title  = document.getElementById('integrity-banner-title');
  const sub    = document.getElementById('integrity-banner-sub');

  if (sum.clean) {
    if (banner) banner.className = 'integrity-banner integrity-banner-ok';
    if (icon)   icon.textContent  = '✓';
    if (title)  title.textContent = 'All checks passed — no integrity issues found';
    if (sub)    sub.textContent   = 'Package files match their checksums. No known malicious packages detected.';
  } else {
    if (banner) banner.className = 'integrity-banner integrity-banner-warn';
    if (icon)   icon.textContent  = '⚠';
    const parts = [];
    if (sum.file_issues        > 0) parts.push(`${sum.file_issues} file integrity issue${sum.file_issues !== 1 ? 's' : ''}`);
    if (sum.malicious_pkgs     > 0) parts.push(`${sum.malicious_pkgs} known malicious package${sum.malicious_pkgs !== 1 ? 's' : ''}`);
    if (sum.modified_bin_files > 0) parts.push(`${sum.modified_bin_files} recently modified system binary${sum.modified_bin_files !== 1 ? 's' : ''}`);
    if (title)  title.textContent = 'Issues detected: ' + parts.join(' · ');
    if (sub)    sub.textContent   = 'Review the tables below for details.';
  }

  // Nav badge (show if any real issue found)
  const navBadge = document.getElementById('nav-integrity-badge');
  const issueCount = sum.file_issues + sum.malicious_pkgs;
  if (navBadge) {
    navBadge.textContent = issueCount || (sum.modified_bin_files > 0 ? '!' : '');
    navBadge.classList.toggle('hidden', issueCount === 0 && sum.modified_bin_files === 0);
    navBadge.style.background = issueCount > 0 ? 'var(--sev-critical)' : 'var(--sev-medium)';
  }

  // ── File integrity table ─────────────────────────────────────────────────
  const fileTbody = document.getElementById('integrity-file-tbody');
  const fileCount = document.getElementById('integrity-file-count');
  if (fileCount) fileCount.textContent = files.length === 0
    ? '✓ All files intact' : `${files.length} issue${files.length !== 1 ? 's' : ''} found`;

  if (fileTbody) {
    if (files.length === 0) {
      fileTbody.innerHTML = `<tr><td colspan="4">
        <div class="empty-state">
          <div class="empty-icon" style="color:var(--sev-low)">✓</div>
          <div>All installed package files match their checksums.</div>
        </div></td></tr>`;
    } else {
      fileTbody.innerHTML = files.map(f => {
        const cls = f.issue === 'checksum_mismatch' ? 'cvss-critical'
                  : f.issue === 'missing_file'      ? 'cvss-high'
                  : 'cvss-medium';
        const label = {
          checksum_mismatch:  '⚠ Checksum',
          size_mismatch:      '⚠ Size',
          missing_file:       '✗ Missing',
          permission_changed: '~ Permissions',
          mtime_changed:      '~ Modified',
          altered:            '⚠ Altered',
        }[f.issue] ?? f.issue;
        return `<tr>
          <td class="mono" style="font-size:11px">${escapeHtml(f.package)}</td>
          <td class="mono" style="font-size:11px">${escapeHtml(f.file)}</td>
          <td><span class="${cls}" style="font-weight:600">${label}</span></td>
          <td style="font-size:11px;color:var(--text-secondary)">${escapeHtml(f.detail)}</td>
        </tr>`;
      }).join('');
    }
  }

  // ── Malicious packages table ─────────────────────────────────────────────
  const malTbody = document.getElementById('integrity-mal-tbody');
  const malCount = document.getElementById('integrity-mal-count');
  if (malCount) malCount.textContent = mal.length === 0
    ? '✓ No known malicious packages' : `${mal.length} detected`;

  if (malTbody) {
    if (mal.length === 0) {
      malTbody.innerHTML = `<tr><td colspan="5">
        <div class="empty-state">
          <div class="empty-icon" style="color:var(--sev-low)">✓</div>
          <div>No packages matched the OSSF malicious-packages database.</div>
        </div></td></tr>`;
    } else {
      malTbody.innerHTML = mal.map(m => `
        <tr>
          <td><a class="cve-id" href="${escapeHtml(m.url)}" target="_blank" rel="noopener">${escapeHtml(m.id)}</a></td>
          <td class="mono" style="font-size:11px">${escapeHtml(m.package)}</td>
          <td class="mono" style="font-size:11px">${escapeHtml(m.version)}</td>
          <td style="font-size:11px;color:var(--sev-critical)">${escapeHtml(m.summary)}</td>
          <td><a href="${escapeHtml(m.url)}" target="_blank" rel="noopener" class="btn btn-ghost btn-sm">Details</a></td>
        </tr>`).join('');
    }
  }

  // ── Modified binaries table ──────────────────────────────────────────────
  const binTbody = document.getElementById('integrity-bin-tbody');
  const binCount = document.getElementById('integrity-bin-count');
  if (binCount) binCount.textContent = bins.length === 0
    ? '✓ No recent modifications' : `${bins.length} file${bins.length !== 1 ? 's' : ''} modified in last 7 days`;

  if (binTbody) {
    if (bins.length === 0) {
      binTbody.innerHTML = `<tr><td colspan="4">
        <div class="empty-state">
          <div class="empty-icon" style="color:var(--sev-low)">✓</div>
          <div>No system binaries were modified in the last 7 days.</div>
        </div></td></tr>`;
    } else {
      binTbody.innerHTML = bins.map(b => {
        const ageLabel = b.age_hours < 24
          ? `${b.age_hours}h ago`
          : `${Math.floor(b.age_hours / 24)}d ago`;
        const ageCls = b.age_hours < 24 ? 'cvss-critical'
                     : b.age_hours < 72 ? 'cvss-high'
                     : 'cvss-medium';
        return `<tr>
          <td class="mono" style="font-size:11px">${escapeHtml(b.path)}</td>
          <td class="mono" style="font-size:11px">${escapeHtml(b.package)}</td>
          <td style="font-size:11px;color:var(--text-secondary)">${escapeHtml(new Date(b.modified).toLocaleString())}</td>
          <td class="${ageCls}" style="font-weight:600">${ageLabel}</td>
        </tr>`;
      }).join('');
    }
  }
}

/* --- Populate dashboard (system specs, apps) --- */

function populateDashboard(r) {
  const os   = r.os            ?? {};
  const mem  = r.memory?.summary ?? {};
  const cpu  = r.cpu?.summary  ?? {};
  const pkgs = r.packages      ?? {};
  const svcs = r.services      ?? {};

  // System spec cards
  setText('spec-os',        os.pretty_name ?? '—');
  setText('spec-os-ver',    `${os.id ?? ''} ${os.version_id ?? ''}`.trim() || '—');
  setText('spec-kernel',    os.release ?? '—');
  setText('spec-arch',      os.machine  ?? '—');
  setText('spec-cpu',       cpu.model_name ?? '—');
  setText('spec-cpu-cores', `${cpu.logical_cpus ?? '?'} logical @ ${parseFloat(cpu.cpu_mhz ?? 0).toFixed(0)} MHz`);
  setText('spec-host',      os.hostname ?? '—');
  setText('spec-uptime',    `${svcs.running?.length ?? 0} services running`);

  const memTotal = mem.total_bytes     ?? 0;
  const memAvail = mem.available_bytes ?? 0;
  const memUsed  = memTotal - memAvail;
  setText('spec-mem',        humanBytes(memTotal));
  setText('spec-mem-detail', `${humanBytes(memUsed)} used · ${humanBytes(memAvail)} free`);
  setBar('mem-usage-bar', memTotal ? memUsed / memTotal : 0,
    memUsed / memTotal > 0.9 ? 'crit' : memUsed / memTotal > 0.7 ? 'warn' : '');

  // Disk (df -hT: Filesystem Type Size Used Avail Use% MountPoint)
  const dfLine = (r.filesystems?.df ?? '').split('\n').find(l => /^\//.test(l));
  if (dfLine) {
    const cols = dfLine.split(/\s+/);
    setText('spec-disk',        cols[2] ?? '—');
    setText('spec-disk-detail', `${cols[3] ?? '?'} used · ${cols[4] ?? '?'} avail (${cols[5] ?? '?'})`);
    const pct = parseInt(cols[5] ?? '0');
    setBar('disk-usage-bar', pct / 100, pct > 85 ? 'crit' : pct > 70 ? 'warn' : '');
  }

  // Stat cards — CVEs shown as "…" until analysis finishes
  setText('stat-apps',     pkgs.count ?? '—');
  setText('stat-critical', '…');
  setText('stat-high',     '…');
  setText('stat-other',    '…');

  // Applications grid
  const grid     = document.getElementById('app-grid');
  const appCount = document.getElementById('apps-count');
  if (grid && pkgs.packages) {
    const shown   = pkgs.packages.slice(0, 80);
    const foreign = new Set(pkgs.foreign ?? []);
    if (appCount) appCount.textContent = `${pkgs.count} packages via ${pkgs.manager}`;
    grid.innerHTML = shown.map(p => `
      <div class="app-card" data-pkg="${escapeHtml(p.name)}">
        <div class="app-icon">📦</div>
        <div class="app-info">
          <div class="app-name">${escapeHtml(p.name)}</div>
          <div class="app-version">${escapeHtml(p.version ?? '')}</div>
        </div>
        ${foreign.has(p.name) ? '<div class="app-vuln-flag" title="AUR / foreign"></div>' : ''}
      </div>`).join('');
    if (pkgs.packages.length > 80) {
      grid.innerHTML += `<div class="app-card" style="justify-content:center;color:var(--text-muted)">
        +${pkgs.packages.length - 80} more…</div>`;
    }
  }
}

/* --- Populate CVE data once analysis returns --- */

function populateCVEs(cves, counts) {
  // Stat cards
  setText('stat-critical', counts.critical ?? 0);
  setText('stat-high',     counts.high     ?? 0);
  setText('stat-other',    (counts.medium  ?? 0) + (counts.low ?? 0));

  // Nav badge (critical + high only)
  const badge = document.getElementById('nav-cve-badge');
  const total = (counts.critical ?? 0) + (counts.high ?? 0);
  if (badge) {
    badge.textContent = total;
    badge.classList.toggle('hidden', total === 0);
  }

  // CVE table
  const tbody = document.getElementById('cve-table-body');
  if (tbody) {
    if (cves.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7">
        <div class="empty-state">
          <div class="empty-icon" style="color:var(--sev-low)">✓</div>
          <div>No known vulnerabilities found for installed packages.</div>
        </div></td></tr>`;
    } else {
      tbody.innerHTML = cves.map(c => {
        const sev   = c.severity || 'unknown';
        const score = c.cvss != null ? Number(c.cvss).toFixed(1) : '—';
        return `
          <tr class="cve-row" data-severity="${sev}">
            <td>
              <a class="cve-id" href="${escapeHtml(c.url)}" target="_blank" rel="noopener">
                ${escapeHtml(c.id)}
              </a>
            </td>
            <td>${escapeHtml(c.package)}</td>
            <td class="mono" style="font-size:11px">${escapeHtml(c.installed)}</td>
            <td class="mono" style="font-size:11px;color:var(--sev-low)">${escapeHtml(c.fixed)}</td>
            <td class="cvss-score cvss-${sev}">${score}</td>
            <td><span class="badge badge-${sev}">${sev}</span></td>
            <td class="cve-actions">
              <a href="${escapeHtml(c.url)}" target="_blank" rel="noopener"
                 class="btn btn-ghost btn-sm">Details</a>
            </td>
          </tr>`;
      }).join('');
    }
  }

  // Advisor CVE sidebar
  const advisorList = document.getElementById('advisor-cve-list');
  if (advisorList) {
    if (cves.length === 0) {
      advisorList.innerHTML = `<li style="padding:16px;color:var(--text-muted);font-size:12px">
        No CVEs found.</li>`;
    } else {
      advisorList.innerHTML = cves.slice(0, 40).map(c => `
        <li class="advisor-cve-item"
            data-cve="${escapeHtml(c.id)}"
            data-pkg="${escapeHtml(c.package)}"
            data-summary="${escapeHtml(c.summary)}">
          <div>
            <div class="advisor-cve-id">${escapeHtml(c.id)}</div>
            <div class="advisor-cve-pkg">${escapeHtml(c.package)}</div>
          </div>
          <span class="badge badge-${c.severity}">${c.severity}</span>
        </li>`).join('');

      document.querySelectorAll('.advisor-cve-item').forEach(item => {
        item.addEventListener('click', () => {
          document.querySelectorAll('.advisor-cve-item').forEach(i => i.classList.remove('selected'));
          item.classList.add('selected');
        });
      });
    }
  }

  // Flag vulnerable packages in the app grid
  if (cves.length > 0) {
    const vulnPkgs = new Map();   // pkgName → highest severity
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

/* --- Helpers --- */

function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function setBar(id, ratio, cls = '') {
  const el = document.getElementById(id);
  if (!el) return;
  el.style.width = Math.min(100, Math.round(ratio * 100)) + '%';
  el.className = 'usage-fill' + (cls ? ' ' + cls : '');
}

function humanBytes(n) {
  if (!n) return '?';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return n.toFixed(1) + ' ' + units[i];
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
   TOPOLOGY / ATTACK MAP
   ========================================================= */

document.getElementById('topo-rebuild-btn')?.addEventListener('click', () => {
  if (_lastReport) runTopologyBuild();
});

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

    renderTopology(topo, _cveData, fsDevices);
    buildAttackNarrative(topo, _cveData);

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

function renderTopology(topo, cveData, fsDevices) {
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

  // Attack path edges
  if (hasNetworkCVEs) {
    elements.push({
      data: { id: 'atk-entry', source: 'internet', target: 'current', etype: 'attack' },
      classes: 'attack-path',
    });
    for (const nid of neighborIds) {
      elements.push({
        data: { id: 'atk-pivot-' + nid, source: 'current', target: nid, etype: 'pivot' },
        classes: 'attack-pivot',
      });
    }
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
      name:              'breadthfirst',
      directed:          true,
      roots:             ['#internet'],
      padding:           48,
      spacingFactor:     1.75,
      animate:           true,
      animationDuration: 500,
    },
    userZoomingEnabled:   true,
    userPanningEnabled:   true,
    boxSelectionEnabled:  false,
    minZoom: 0.3,
    maxZoom: 3,
  });

  cy.on('tap', 'node', evt => showTopoNodeInfo(evt.target.data()));
  window._topo_cy = cy;
}

function _topoStyle() {
  return [
    {
      selector: 'node',
      style: {
        'background-color':  '#0f1117',
        'border-color':      '#2a3050',
        'border-width':       2,
        'label':             'data(label)',
        'color':             '#e2e8f0',
        'font-size':         '10px',
        'font-family':       '"JetBrains Mono", monospace',
        'text-valign':       'bottom',
        'text-halign':       'center',
        'text-margin-y':      8,
        'width':              50,
        'height':             50,
        'text-wrap':         'wrap',
        'text-max-width':     110,
        'shape':             'ellipse',
      },
    },
    {
      selector: 'node[type="internet"]',
      style: {
        'background-color': '#0a1628',
        'border-color':     '#4a9eff',
        'border-width':      3,
        'width':             68,
        'height':            68,
        'color':            '#4a9eff',
        'font-size':        '11px',
      },
    },
    {
      selector: 'node[type="router"]',
      style: {
        'background-color': '#0f1117',
        'border-color':     '#7b61ff',
        'border-width':      2,
        'shape':            'diamond',
        'width':             60,
        'height':            60,
        'color':            '#a78bfa',
      },
    },
    {
      selector: 'node[type="current"]',
      style: {
        'background-color': 'data(color)',
        'border-color':     'data(color)',
        'border-width':      3,
        'shape':            'rectangle',
        'width':             76,
        'height':            58,
        'color':            '#ffffff',
        'font-size':        '12px',
        'font-weight':      '700',
      },
    },
    {
      selector: 'node[type="neighbor"], node[type="known"]',
      style: {
        'background-color': '#0f1117',
        'border-color':     'data(color)',
        'border-width':      2,
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
      },
    },
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

function buildAttackNarrative(topo, cveData) {
  const panel = document.getElementById('attack-narrative-panel');
  const steps = document.getElementById('attack-steps');
  if (!panel || !steps) return;

  const hostname  = topo.hostname || 'this device';
  const critical  = cveData?.counts?.critical ?? 0;
  const high      = cveData?.counts?.high ?? 0;
  const gateway   = topo.gateway;
  const neighbors = (topo.neighbors || []).filter(n => n.ip && n.ip !== topo.gateway);
  const topCVEs   = (cveData?.cves ?? [])
    .filter(c => ['critical', 'high'].includes(c.severity))
    .slice(0, 3);

  const html = [];

  if (!cveData) {
    panel.style.display = 'none';
    return;
  }

  if (critical + high > 0) {
    const cveNames = topCVEs.map(c => `<code>${escapeHtml(c.id)}</code>`).join(', ') || 'see CVEs tab';
    html.push(
      `<strong>${escapeHtml(hostname)}</strong> has ` +
      `<strong style="color:${critical > 0 ? 'var(--sev-critical)' : 'var(--sev-high)'}">` +
      `${critical + high} high/critical CVE${critical + high !== 1 ? 's' : ''}</strong> ` +
      `(${cveNames}). These vulnerabilities are network-reachable and may not require authentication.`
    );
    html.push(
      `A remote attacker discovers <strong>${escapeHtml(hostname)}</strong> via internet scanning ` +
      `(Shodan, Censys, Masscan). They craft a payload for one of the identified CVEs and gain ` +
      `remote code execution — without ever touching the physical machine.`
    );
    if (gateway) {
      html.push(
        `The attacker is now <em>inside your network</em>. They can directly reach the gateway ` +
        `router (<strong>${escapeHtml(gateway)}</strong>) and may perform ARP spoofing, ` +
        `DNS hijacking, or traffic interception for all devices on this subnet.`
      );
    }
    if (neighbors.length > 0) {
      const ipList = neighbors.slice(0, 5).map(n => `<code>${escapeHtml(n.ip)}</code>`).join(', ');
      const more   = neighbors.length > 5 ? ` and ${neighbors.length - 5} more` : '';
      html.push(
        `Lateral movement: from <strong>${escapeHtml(hostname)}</strong> the attacker probes ` +
        `${ipList}${more}. Each device on <code>${topo.my_ips?.[0]?.ip ?? '192.168.x.x'}/` +
        `${topo.my_ips?.[0]?.prefix ?? '24'}</code> is now a target — ` +
        `NAS drives, cameras, smart TVs, other computers. This is the <strong>kill web</strong>.`
      );
      html.push(
        `If any neighbor device has its own unpatched CVEs, the attacker can pivot to it ` +
        `without ever touching the internet again — staying invisible to perimeter defenses.`
      );
    }
    const sev = critical > 0 ? 'critical' : 'high';
    html.push(
      `<strong style="color:var(--sev-${sev})">Action required:</strong> ` +
      `Patch or mitigate ${sev}-severity CVEs on <strong>${escapeHtml(hostname)}</strong> ` +
      `to break the initial attack chain before an attacker gains a foothold.`
    );
  } else {
    html.push(
      `<strong style="color:var(--sev-low)">✓ No high or critical CVEs found on ${escapeHtml(hostname)}.</strong> ` +
      `This device is not a known high-risk remote entry point at this time.`
    );
    if (neighbors.length > 0) {
      html.push(
        `${neighbors.length} neighbor device${neighbors.length !== 1 ? 's are' : ' is'} visible on the network. ` +
        `Run Oasis Scan on those machines to check their CVE posture — ` +
        `a vulnerable neighbor could pivot <em>into</em> this device laterally.`
      );
    }
  }

  panel.style.display = '';
  steps.innerHTML = html.map(s => `<li class="attack-step">${s}</li>`).join('');
}
