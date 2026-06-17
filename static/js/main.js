/* =========================================================
   Oasis Scan — Frontend JS
   ========================================================= */

/* --- Nav --- */
document.querySelectorAll('.nav-item[data-section]').forEach(item => {
  item.addEventListener('click', () => {
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    item.classList.add('active');
    const target = item.dataset.section;
    document.querySelectorAll('.page-section').forEach(s => s.classList.add('hidden'));
    const el = document.getElementById(target);
    if (el) { el.classList.remove('hidden'); el.scrollIntoView({ behavior: 'smooth', block: 'start' }); }
    const label = item.textContent.replace(/[⊞⚠⊡✦↺⚙]/g, '').trim();
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

/* --- CVE Advisor --- */
document.querySelectorAll('.advisor-cve-item').forEach(item => {
  item.addEventListener('click', () => {
    document.querySelectorAll('.advisor-cve-item').forEach(i => i.classList.remove('selected'));
    item.classList.add('selected');
  });
});

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
  const overlay   = document.getElementById('scan-overlay');
  const stepLabel = document.getElementById('scan-step-label');
  const dot       = document.getElementById('status-dot');
  const statusLbl = document.getElementById('status-label');
  const scanBtn   = document.getElementById('scan-btn');

  if (overlay)  overlay.style.display = 'flex';
  if (dot)      dot.className = 'status-dot scanning';
  if (statusLbl) statusLbl.textContent = 'Scanning…';
  if (scanBtn)  scanBtn.disabled = true;

  const steps = [
    'Collecting OS info…', 'Reading CPU & memory…', 'Scanning block devices…',
    'Enumerating packages…', 'Checking services…', 'Detecting network config…',
    'Finalizing report…'
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

    populateDashboard(data.report);

    if (typeof window.__saveScanResult === 'function') {
      const r = data.report;
      window.__saveScanResult({
        hostname: r.os?.hostname ?? '',
        os:       r.os?.pretty_name ?? '',
        apps:     r.packages?.count ?? 0,
        critical: 0, high: 0, other: 0,
      });
    }

    if (dot)       { dot.className = 'status-dot'; }
    if (statusLbl) statusLbl.textContent = 'Done';
    const lastScanEl = document.getElementById('last-scan-time');
    if (lastScanEl) lastScanEl.textContent = new Date().toLocaleTimeString();

  } catch (err) {
    clearInterval(stepTimer);
    if (dot)      dot.className = 'status-dot error';
    if (statusLbl) statusLbl.textContent = 'Error';
    if (stepLabel) stepLabel.textContent  = 'Scan failed: ' + err.message;
    setTimeout(() => { if (overlay) overlay.style.display = 'none'; }, 3000);
    return;
  } finally {
    if (overlay) overlay.style.display = 'none';
    if (scanBtn) scanBtn.disabled = false;
  }
}

function populateDashboard(r) {
  const os   = r.os   ?? {};
  const mem  = r.memory?.summary ?? {};
  const cpu  = r.cpu?.summary ?? {};
  const pkgs = r.packages ?? {};
  const svcs = r.services ?? {};

  // ── System spec cards ──────────────────────────────────────────
  setText('spec-os',        os.pretty_name ?? '—');
  setText('spec-os-ver',    `${os.id ?? ''} ${os.version_id ?? ''}`.trim() || '—');
  setText('spec-kernel',    os.release ?? '—');
  setText('spec-arch',      os.machine ?? '—');
  setText('spec-cpu',       cpu.model_name ?? '—');
  setText('spec-cpu-cores', `${cpu.logical_cpus ?? '?'} logical @ ${parseFloat(cpu.cpu_mhz ?? 0).toFixed(0)} MHz`);
  setText('spec-host',      os.hostname ?? '—');
  setText('spec-uptime',    `${svcs.running?.length ?? 0} services running`);

  const memTotal = mem.total_bytes ?? 0;
  const memAvail = mem.available_bytes ?? 0;
  const memUsed  = memTotal - memAvail;
  setText('spec-mem',        humanBytes(memTotal));
  setText('spec-mem-detail', `${humanBytes(memUsed)} used · ${humanBytes(memAvail)} free`);
  setBar('mem-usage-bar', memTotal ? memUsed / memTotal : 0,
    memUsed / memTotal > 0.9 ? 'crit' : memUsed / memTotal > 0.7 ? 'warn' : '');

  // Disk — parse df -hT root line (cols: Filesystem Type Size Used Avail Use% Mount)
  const dfLines = (r.filesystems?.df ?? '').split('\n');
  const dfLine  = dfLines.find(l => /^\//.test(l));
  if (dfLine) {
    const cols = dfLine.split(/\s+/);
    setText('spec-disk',        cols[2] ?? '—');
    setText('spec-disk-detail', `${cols[3] ?? '?'} used · ${cols[4] ?? '?'} avail (${cols[5] ?? '?'})`);
    const pct = parseInt(cols[5] ?? '0');
    setBar('disk-usage-bar', pct / 100, pct > 85 ? 'crit' : pct > 70 ? 'warn' : '');
  }

  // ── Stat cards ─────────────────────────────────────────────────
  setText('stat-apps',     pkgs.count ?? '—');
  setText('stat-critical', '—');
  setText('stat-high',     '—');
  setText('stat-other',    '—');

  // ── Applications grid ──────────────────────────────────────────
  const grid     = document.getElementById('app-grid');
  const appCount = document.getElementById('apps-count');
  if (grid && pkgs.packages) {
    const shown   = pkgs.packages.slice(0, 80);
    const foreign = new Set(pkgs.foreign ?? []);
    if (appCount) appCount.textContent = `${pkgs.count} packages via ${pkgs.manager}`;
    grid.innerHTML = shown.map(p => `
      <div class="app-card">
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

  // ── CVE badge (placeholder until CVE lookup is wired) ──────────
  const cveBadge = document.getElementById('nav-cve-badge');
  if (cveBadge) cveBadge.classList.add('hidden');
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
