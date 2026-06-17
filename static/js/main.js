/* =========================================================
   Oasis Scan — Frontend JS
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
    if (data.cves.length > 0) populateCVEs(data.cves, data.counts);
  }
  if (data.topology) _savedTopology = data.topology;
};

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
    if (target === 'section-cves' && !_cveData && window.__savedData?.cves?.length > 0) {
      _cveData = { cves: window.__savedData.cves, counts: window.__savedData.counts };
      populateCVEs(window.__savedData.cves, window.__savedData.counts);
    }
    if (target === 'section-apps' && !_lastReport) {
      if (typeof window.__loadPackages === 'function') {
        window.__loadPackages().then(data => {
          if (data) _populateApps(data.packages, data.foreign, data.count, data.manager, ' · from last scan');
        });
      }
    }
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

function _populateApps(pkgList, foreignList, totalCount, manager, suffix) {
  const grid     = document.getElementById('app-grid');
  const appCount = document.getElementById('apps-count');
  if (!grid || !pkgList) return;
  const foreign = new Set(foreignList);
  const shown   = pkgList.slice(0, 80);
  if (appCount) appCount.textContent = `${totalCount} packages via ${manager}${suffix}`;
  grid.innerHTML = shown.map(p => `
    <div class="app-card" data-pkg="${escapeHtml(p.name)}">
      <div class="app-icon">📦</div>
      <div class="app-info">
        <div class="app-name">${escapeHtml(p.name)}</div>
        <div class="app-version">${escapeHtml(p.version ?? '')}</div>
      </div>
      ${foreign.has(p.name) ? '<div class="app-vuln-flag" title="AUR / foreign"></div>' : ''}
    </div>`).join('');
  if (pkgList.length > 80) {
    grid.innerHTML += `<div class="app-card" style="justify-content:center;color:var(--text-muted)">
      +${pkgList.length - 80} more…</div>`;
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
          <tr class="cve-row" data-severity="${sev}"
              data-cve-id="${escapeHtml(c.id)}"
              data-cve-pkg="${escapeHtml(c.package)}"
              data-cve-installed="${escapeHtml(c.installed ?? '')}"
              data-cve-fixed="${escapeHtml(c.fixed ?? '')}"
              data-cve-summary="${escapeHtml(c.summary ?? '')}"
              data-cve-url="${escapeHtml(c.url ?? '')}"
              data-cve-cvss="${escapeHtml(score)}">
            <td>
              <span class="cve-id mono">${escapeHtml(c.id)}</span>
            </td>
            <td>${escapeHtml(c.package)}</td>
            <td class="mono" style="font-size:11px">${escapeHtml(c.installed ?? '—')}</td>
            <td class="mono" style="font-size:11px;color:var(--sev-low)">${escapeHtml(c.fixed ?? '—')}</td>
            <td class="cvss-score cvss-${sev}">${score}</td>
            <td><span class="badge badge-${sev}">${sev}</span></td>
            <td class="cve-actions">
              <button class="btn btn-ghost btn-sm cve-expand-btn">Details</button>
            </td>
          </tr>`;
      }).join('');

      // Expandable detail rows
      tbody.querySelectorAll('.cve-expand-btn').forEach(btn => {
        btn.addEventListener('click', e => {
          e.stopPropagation();
          const row  = btn.closest('tr');
          const next = row.nextElementSibling;
          if (next?.classList.contains('cve-detail-row')) {
            next.remove();
            btn.textContent = 'Details';
            return;
          }
          const d       = row.dataset;
          const cveId   = d.cveId || '';
          const summary = d.cveSummary || 'No description available.';

          // Build reliable links — never trust the stored URL alone for Arch CVEs
          // because the advisory URL format changes; derive fresh links from the ID.
          const isCVE    = cveId.startsWith('CVE-');
          const isASA    = cveId.startsWith('ASA-');
          const nvdUrl   = isCVE ? `https://nvd.nist.gov/vuln/detail/${cveId}` : '';
          const archUrl  = isCVE ? `https://security.archlinux.org/${cveId}`
                         : isASA ? `https://security.archlinux.org/advisory/${cveId}`
                         : (d.cveUrl || '');
          const osvUrl   = d.cveUrl?.startsWith('https://osv.dev') ? d.cveUrl : '';

          const detail  = document.createElement('tr');
          detail.className = 'cve-detail-row';
          detail.innerHTML = `
            <td colspan="7" class="cve-detail-cell">
              <div class="cve-detail-body">
                <p class="cve-detail-summary">${escapeHtml(summary)}</p>
                <div class="cve-detail-meta">
                  <span>Package <code>${escapeHtml(d.cvePkg)}</code></span>
                  <span>Installed <code>${escapeHtml(d.cveInstalled) || '—'}</code></span>
                  <span>Fixed in <code class="text-ok">${escapeHtml(d.cveFixed) || 'no fix yet'}</code></span>
                  <span>CVSS <code>${escapeHtml(d.cveCvss)}</code></span>
                </div>
                <div class="cve-detail-actions">
                  ${nvdUrl  ? `<a href="${nvdUrl}"  target="_blank" rel="noopener" class="btn btn-ghost btn-sm">NVD ↗</a>` : ''}
                  ${archUrl ? `<a href="${archUrl}" target="_blank" rel="noopener" class="btn btn-ghost btn-sm">Arch ↗</a>` : ''}
                  ${osvUrl  ? `<a href="${osvUrl}"  target="_blank" rel="noopener" class="btn btn-ghost btn-sm">OSV ↗</a>` : ''}
                  <button class="btn btn-ghost btn-sm"
                    onclick="navigator.clipboard.writeText('${escapeHtml(cveId)}').then(()=>{this.textContent='Copied!';setTimeout(()=>this.textContent='Copy ID',1500)})">
                    Copy ID
                  </button>
                </div>
              </div>
            </td>`;
          row.insertAdjacentElement('afterend', detail);
          btn.textContent = 'Close';
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
    ${netHtml}`;

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
  renderTopology(topo, cveData, fsDevices);
  buildAttackNarrative(topo, cveData);
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
