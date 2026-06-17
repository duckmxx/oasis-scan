/* =========================================================
   Oasis Scan — Frontend JS Scaffold
   ========================================================= */

/* --- Nav: activate section on click --- */
document.querySelectorAll('.nav-item[data-section]').forEach(item => {
  item.addEventListener('click', () => {
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    item.classList.add('active');

    const target = item.dataset.section;
    document.querySelectorAll('.page-section').forEach(s => s.classList.add('hidden'));
    const el = document.getElementById(target);
    if (el) { el.classList.remove('hidden'); el.scrollIntoView({ behavior: 'smooth', block: 'start' }); }
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

/* --- CVE Advisor: select a CVE to load patch guidance --- */
document.querySelectorAll('.advisor-cve-item').forEach(item => {
  item.addEventListener('click', () => {
    document.querySelectorAll('.advisor-cve-item').forEach(i => i.classList.remove('selected'));
    item.classList.add('selected');
    /* TODO: fetch /api/advisor?cve=<id> and append to chat */
  });
});

/* --- Chat input: send on Enter (Shift+Enter for newline) --- */
const chatInput = document.getElementById('chat-input');
if (chatInput) {
  chatInput.addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendAdvisorMessage();
    }
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
  /* TODO: POST /api/advisor { prompt: text } -> appendChatMessage('system', response) */
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
        <div class="typing-dot"></div>
        <div class="typing-dot"></div>
        <div class="typing-dot"></div>
      </div>
    </div>`;
  feed.appendChild(el);
  feed.scrollTop = feed.scrollHeight;
}

function removeTypingIndicator() {
  document.getElementById('typing-indicator')?.remove();
}

/* --- Scan trigger --- */
document.getElementById('scan-btn')?.addEventListener('click', startScan);

function startScan() {
  const overlay = document.getElementById('scan-overlay');
  if (overlay) overlay.style.display = 'flex';
  /* TODO: POST /api/scan  -> poll /api/scan/status -> hide overlay, populate data */
}

/* --- Helpers --- */
function escapeHtml(str) {
  return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
