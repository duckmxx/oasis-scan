/* =========================================================
   Oasis Scan — Frontend JS
   ========================================================= */

// Module-level refs kept so runCVEAnalysis() can update the status bar
let _dot       = null;
let _statusLbl = null;
let _lastReport = null;

/* --- Nav --- */
document.querySelectorAll('.nav-item[data-section]').forEach(item => {
  item.addEventListener('click', () => {
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    item.classList.add('active');
    const target = item.dataset.section;
    document.querySelectorAll('.page-section').forEach(s => s.classList.add('hidden'));
    const el = document.getElementById(target);
    if (el) { el.classList.remove('hidden'); el.scrollIntoView({ behavior: 'smooth', block: 'start' }); }
    const label = item.textContent.replace(/[⊞⚠⊡⊟✦↺⚙]/g, '').trim();
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
