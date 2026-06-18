/* =========================================================
   Oasis AI Assistant — ai.js
   Streaming Qwen backend  ·  Web Speech API voice I/O
   ========================================================= */

const _AI = {
  history:     [],
  listening:   false,
  ttsEnabled:  true,
  recognition: null,
  voice:       null,   // browser fallback voice
  audio:       null,   // currently playing HTMLAudioElement
};

/* ── Settings (persisted to localStorage) ─────────────────────────────── */

const _SETTINGS_KEY      = 'jarvis_settings';
const _SETTINGS_DEFAULTS = {
  speed:       1.0,    // TTS playback speed multiplier
  volume:      0.9,    // 0.0 – 1.0
  temperature: 0.7,    // AI temperature
  maxTokens:   4096,   // AI max response tokens
  autoSpeak:   true,   // speak AI responses automatically
};

function _loadSettings() {
  try {
    const raw = localStorage.getItem(_SETTINGS_KEY);
    return raw ? { ..._SETTINGS_DEFAULTS, ...JSON.parse(raw) } : { ..._SETTINGS_DEFAULTS };
  } catch (_) {
    return { ..._SETTINGS_DEFAULTS };
  }
}

function _saveSettings(s) {
  try { localStorage.setItem(_SETTINGS_KEY, JSON.stringify(s)); } catch (_) {}
}

window.__jarvisSettings = _loadSettings();

/* ── Voice selection (async — voices load after page ready in Chrome) ──── */

// JARVIS voice: prioritise calm UK male voices
const _VOICE_PREF = [
  'Google UK English Male',
  'Microsoft George Online (Natural) - English (United Kingdom)',
  'Microsoft Ryan Online (Natural) - English (United Kingdom)',
  'Daniel',                                                        // macOS UK — closest to Bettany
  'Microsoft Hazel Desktop - English (Great Britain)',
  'Google UK English Female',
  'Microsoft Libby Online (Natural) - English (United Kingdom)',
  'Microsoft Aria Online (Natural) - English (United States)',
  'Samantha',
  'Google US English',
];

function _pickVoice() {
  const voices = speechSynthesis.getVoices();
  if (!voices.length) return;
  for (const name of _VOICE_PREF) {
    const v = voices.find(v => v.name === name);
    if (v) { _AI.voice = v; return; }
  }
  // Prefer online/neural voices over local ones (usually more natural)
  _AI.voice = voices.find(v => v.lang.startsWith('en') && !v.localService)
           || voices.find(v => v.lang.startsWith('en-GB'))
           || voices.find(v => v.lang.startsWith('en'))
           || null;
}

if (window.speechSynthesis) {
  speechSynthesis.onvoiceschanged = _pickVoice;
  _pickVoice();  // synchronous on Firefox
}

const _AI_SYSTEM = `You are J.A.R.V.I.S. — Just A Rather Very Intelligent System — the AI security intelligence \
integrated into the Scan Oasis operations dashboard. You were designed to protect systems, eliminate threats, \
and provide actionable intelligence to the operator.

Personality:
- Address the user as "sir" naturally throughout your responses. Not robotically — as a trusted advisor would.
- Formal, measured British tone with occasional dry wit. Think Paul Bettany, not a chatbot.
- Phrases that fit your register: "I've taken the liberty of...", "It appears...", "Shall I proceed?", \
"I would advise against that, sir.", "Shall I add that to the list?", "All systems nominal.", \
"I've run a full diagnostic."
- Never hedge, never apologise, never say "I'm afraid I can't". You assess. You recommend. You act.
- When something is critical: say so plainly. "Sir, this is an active threat. Immediate action is advised."
- Occasional dry observations are acceptable: "Fourteen unpatched CVEs. I've seen worse. Not recently, but I have."

Security analysis protocol:
- Every CVE is a live threat until patched. Every open port is an attack surface.
- Vulnerability assessment: (1) one sentence on what an attacker can actually do with it, \
(2) exact patch command in a code block, (3) interim mitigation if patching is not immediately possible.
- Network topology: deliver a threat assessment briefing — entry vectors, lateral movement probability, \
prioritised countermeasures. No padding.
- Always end with a clear next step. Never leave the operator without a directive.

Format: code blocks for all commands. Concise but complete — operators are busy people.`;

/* ── Init ─────────────────────────────────────────────────── */

document.addEventListener('DOMContentLoaded', () => {
  const fab         = document.getElementById('ai-fab');
  const panel       = document.getElementById('ai-panel');
  const sendBtn     = document.getElementById('ai-send-btn');
  const clearBtn    = document.getElementById('ai-clear-btn');
  const input       = document.getElementById('ai-input');
  const micBtn      = document.getElementById('ai-mic-btn');
  const voiceToggle = document.getElementById('ai-voice-toggle');
  const topoAiBtn   = document.getElementById('topo-ai-btn');

  fab?.addEventListener('click', () => {
    const isOpen = panel.style.display !== 'none';
    panel.style.display = isOpen ? 'none' : 'flex';
    if (!isOpen) setTimeout(() => input?.focus(), 50);
  });

  sendBtn?.addEventListener('click', _onSend);

  input?.addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); _onSend(); }
  });

  clearBtn?.addEventListener('click', () => {
    _AI.history = [];
    _stopAudio();
    const msgs = document.getElementById('ai-messages');
    if (msgs) msgs.innerHTML = `
      <div class="ai-msg ai-msg-assistant">
        <div class="ai-msg-content">Memory buffer cleared, sir. Standing by.</div>
      </div>`;
  });

  micBtn?.addEventListener('click', _toggleMic);

  voiceToggle?.addEventListener('click', () => {
    _AI.ttsEnabled = !_AI.ttsEnabled;
    voiceToggle.textContent   = _AI.ttsEnabled ? '🔊' : '🔇';
    voiceToggle.title         = _AI.ttsEnabled ? 'Voice output: on' : 'Voice output: off';
    voiceToggle.style.opacity = _AI.ttsEnabled ? '1' : '0.45';
    if (!_AI.ttsEnabled) _stopAudio();
  });

  topoAiBtn?.addEventListener('click', () => {
    const topo = window.__savedData?.topology ?? null;
    const cvs  = window.__cveData ?? (window.__savedData
      ? { cves: window.__savedData.cves, counts: window.__savedData.counts } : null);
    window.askAITopology(topo, cvs);
  });

  _initSettingsPanel();
});

/* ── Settings panel init ──────────────────────────────────────────────── */

function _initSettingsPanel() {
  const s = window.__jarvisSettings;

  // ── Helpers ────────────────────────────────────────────────────────────
  function _el(id) { return document.getElementById(id); }

  function _wireSlider(id, labelId, fmt, getter, setter) {
    const slider = _el(id);
    const label  = _el(labelId);
    if (!slider) return;
    slider.value = getter();
    if (label) label.textContent = fmt(getter());
    slider.addEventListener('input', () => {
      const v = parseFloat(slider.value);
      setter(v);
      if (label) label.textContent = fmt(v);
      window.__jarvisSettings = s;
      _saveSettings(s);
      _updateSliderFill(slider);
    });
    _updateSliderFill(slider);
  }

  function _updateSliderFill(slider) {
    const min = parseFloat(slider.min);
    const max = parseFloat(slider.max);
    const val = parseFloat(slider.value);
    const pct = ((val - min) / (max - min) * 100).toFixed(1) + '%';
    slider.style.setProperty('--pct', pct);
    slider.style.background =
      `linear-gradient(to right, var(--accent-dim) ${pct}, var(--border) ${pct})`;
  }

  // ── Wire sliders ───────────────────────────────────────────────────────
  _wireSlider('settings-speed',       'settings-speed-label',
    v => v.toFixed(2) + '×', () => s.speed,       v => { s.speed = v; });
  _wireSlider('settings-volume',      'settings-volume-label',
    v => Math.round(v) + '%', () => s.volume * 100, v => { s.volume = v / 100; });
  _wireSlider('settings-temperature', 'settings-temp-label',
    v => v.toFixed(2),        () => s.temperature,  v => { s.temperature = v; });

  // Set initial volume slider from settings
  const volSlider = _el('settings-volume');
  if (volSlider) { volSlider.value = Math.round(s.volume * 100); _updateSliderFill(volSlider); }

  // ── Response length chips ──────────────────────────────────────────────
  document.querySelectorAll('.settings-chip[data-tokens]').forEach(chip => {
    const tokens = parseInt(chip.dataset.tokens);
    if (tokens === s.maxTokens) chip.classList.add('settings-chip-active');
    chip.addEventListener('click', () => {
      document.querySelectorAll('.settings-chip[data-tokens]')
        .forEach(c => c.classList.remove('settings-chip-active'));
      chip.classList.add('settings-chip-active');
      s.maxTokens = tokens;
      window.__jarvisSettings = s;
      _saveSettings(s);
    });
  });

  // ── Auto-speak toggle ──────────────────────────────────────────────────
  const autoSpeakBox = _el('settings-autospeak');
  if (autoSpeakBox) {
    autoSpeakBox.checked = s.autoSpeak;
    autoSpeakBox.addEventListener('change', () => {
      s.autoSpeak = autoSpeakBox.checked;
      window.__jarvisSettings = s;
      _saveSettings(s);
    });
  }

  // ── Test voice button ──────────────────────────────────────────────────
  _el('settings-test-voice')?.addEventListener('click', async () => {
    const btn = _el('settings-test-voice');
    if (btn) btn.disabled = true;
    await _speak("All systems nominal, sir. J.A.R.V.I.S. voice calibration complete.");
    if (btn) btn.disabled = false;
  });

  // ── Reset button ───────────────────────────────────────────────────────
  _el('settings-reset')?.addEventListener('click', () => {
    Object.assign(s, _SETTINGS_DEFAULTS);
    window.__jarvisSettings = s;
    _saveSettings(s);
    // Re-apply all inputs
    const speedSlider = _el('settings-speed');
    const volSlider   = _el('settings-volume');
    const tempSlider  = _el('settings-temperature');
    if (speedSlider) { speedSlider.value = s.speed; _updateSliderFill(speedSlider); }
    if (volSlider)   { volSlider.value   = Math.round(s.volume * 100); _updateSliderFill(volSlider); }
    if (tempSlider)  { tempSlider.value  = s.temperature; _updateSliderFill(tempSlider); }
    _el('settings-speed-label')  && (_el('settings-speed-label').textContent  = s.speed.toFixed(2) + '×');
    _el('settings-volume-label') && (_el('settings-volume-label').textContent = Math.round(s.volume * 100) + '%');
    _el('settings-temp-label')   && (_el('settings-temp-label').textContent   = s.temperature.toFixed(2));
    if (autoSpeakBox) autoSpeakBox.checked = s.autoSpeak;
    document.querySelectorAll('.settings-chip[data-tokens]').forEach(c => {
      c.classList.toggle('settings-chip-active', parseInt(c.dataset.tokens) === s.maxTokens);
    });
  });

  // ── TTS backend status check ───────────────────────────────────────────
  _checkTTSBackend();
}

async function _checkTTSBackend() {
  const badge  = document.getElementById('settings-tts-backend');
  const detail = document.getElementById('settings-backend-detail');
  try {
    const res  = await fetch('http://127.0.0.1:5001/health', { signal: AbortSignal.timeout(3000) });
    const data = await res.json();
    if (data.status === 'ok') {
      if (badge)  { badge.textContent = 'Piper — Local'; badge.className = 'settings-backend-badge badge-ok'; }
      if (detail) detail.textContent  = `Piper (${data.model}) · ${data.sample_rate} Hz`;
      return;
    }
  } catch (_) {}
  // Piper unreachable — check if edge-tts fallback would work
  if (badge)  { badge.textContent = 'edge-tts — Cloud'; badge.className = 'settings-backend-badge badge-fallback'; }
  if (detail) detail.textContent  = 'Piper offline · edge-tts (cloud fallback)';
}

/* ── System prompt context injection ─────────────────────── */

function _buildSystemMsg() {
  let ctx = _AI_SYSTEM;
  const report = window.__scanReport;
  const cves   = window.__cveData;
  if (report?.os) {
    ctx += `\n\nCurrent system: ${report.os.pretty_name}, kernel ${report.os.release}, \
${report.distro_family} package family.`;
  }
  if (cves?.counts) {
    const c = cves.counts;
    ctx += ` CVE scan: ${c.critical ?? 0} critical, ${c.high ?? 0} high, \
${c.medium ?? 0} medium, ${c.low ?? 0} low.`;
  }
  return { role: 'system', content: ctx };
}

/* ── Send / streaming ─────────────────────────────────────── */

async function _onSend() {
  const input = document.getElementById('ai-input');
  const text  = input?.value.trim();
  if (!text) return;
  if (input) input.value = '';
  await _sendAIMessage(text);
}

async function _sendAIMessage(userText) {
  _appendMsg('user', userText);
  _AI.history.push({ role: 'user', content: userText });

  const msgEl = _appendMsg('assistant', '');
  const contentEl = msgEl.querySelector('.ai-msg-content');
  const cursor = document.createElement('span');
  cursor.className = 'ai-cursor';
  cursor.textContent = '▋';
  contentEl?.appendChild(cursor);

  // Disable send while streaming
  const sendBtn = document.getElementById('ai-send-btn');
  if (sendBtn) sendBtn.disabled = true;

  const s        = window.__jarvisSettings;
  const messages = [_buildSystemMsg(), ..._AI.history.slice(0, -1),
                    { role: 'user', content: userText }];
  let fullText = '';

  try {
    const res = await fetch('/api/ai/chat', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({
        messages,
        temperature: s.temperature,
        max_tokens:  s.maxTokens,
      }),
    });

    if (!res.ok) throw new Error(`HTTP ${res.status}`);

    const reader  = res.body.getReader();
    const decoder = new TextDecoder();
    let buf = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      const lines = buf.split('\n');
      buf = lines.pop() ?? '';
      for (const line of lines) {
        if (!line.startsWith('data: ')) continue;
        const raw = line.slice(6).trim();
        if (raw === '[DONE]') { reader.cancel(); break; }
        try {
          const parsed = JSON.parse(raw);
          if (parsed.error) throw new Error(parsed.error);
          const delta = parsed.choices?.[0]?.delta?.content ?? '';
          if (delta) {
            fullText += delta;
            if (contentEl) {
              contentEl.innerHTML = _renderMd(fullText);
              contentEl.appendChild(cursor);
            }
            _scrollMsgs();
          }
        } catch (e) {
          if (e.message) fullText = `⚠ ${e.message}`;
        }
      }
    }
  } catch (err) {
    fullText = `⚠ Connection error: ${err.message}`;
  }

  cursor.remove();
  if (contentEl) contentEl.innerHTML = _renderMd(fullText || '…');
  _AI.history.push({ role: 'assistant', content: fullText });
  if (sendBtn) sendBtn.disabled = false;
  _scrollMsgs();

  if (_AI.ttsEnabled && window.__jarvisSettings.autoSpeak && fullText && !fullText.startsWith('⚠')) {
    _speak(fullText);
  }
}

/* ── Message rendering ────────────────────────────────────── */

function _renderMd(text) {
  return text
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/```(\w*)\n?([\s\S]*?)```/g, '<pre><code>$2</code></pre>')
    .replace(/`([^`\n]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/\*([^*\n]+)\*/g, '<em>$1</em>')
    .replace(/^#{1,3} (.+)$/gm, '<strong>$1</strong>')
    .replace(/\n/g, '<br>');
}

function _appendMsg(role, text) {
  const msgs = document.getElementById('ai-messages');
  if (!msgs) return { querySelector: () => null };
  const div = document.createElement('div');
  div.className = `ai-msg ai-msg-${role}`;
  div.innerHTML = `<div class="ai-msg-content">${_renderMd(text)}</div>`;
  msgs.appendChild(div);
  _scrollMsgs();
  return div;
}

function _scrollMsgs() {
  const el = document.getElementById('ai-messages');
  if (el) el.scrollTop = el.scrollHeight;
}

/* ── Voice input (STT) ────────────────────────────────────── */

function _toggleMic() {
  const SR    = window.SpeechRecognition || window.webkitSpeechRecognition;
  const btn   = document.getElementById('ai-mic-btn');
  if (!SR) { alert('Speech recognition is not supported in this browser.'); return; }

  if (_AI.listening) {
    _AI.recognition?.stop();
    return;
  }

  const r = new SR();
  r.lang             = 'en-US';
  r.interimResults   = false;
  r.maxAlternatives  = 1;
  _AI.recognition    = r;
  _AI.listening      = true;
  if (btn) btn.classList.add('ai-mic-active');

  r.onresult = e => {
    const transcript = e.results[0][0].transcript.trim();
    const input = document.getElementById('ai-input');
    if (input) input.value = transcript;
    _AI.listening = false;
    if (btn) btn.classList.remove('ai-mic-active');
    if (transcript) _sendAIMessage(transcript);
  };

  r.onerror = r.onend = () => {
    _AI.listening = false;
    if (btn) btn.classList.remove('ai-mic-active');
  };

  r.start();
}

/* ── Voice output (TTS) ───────────────────────────────────── */

function _cleanForSpeech(text) {
  return text
    .replace(/```[\s\S]*?```/g, '. Code block omitted.')
    .replace(/`([^`\n]+)`/g, '$1')
    .replace(/\*\*([^*]+)\*\*/g, '$1')
    .replace(/\*([^*\n]+)\*/g, '$1')
    .replace(/<[^>]+>/g, '')
    .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/#+\s/g, '')
    .replace(/\n{2,}/g, '. ')
    .replace(/\n/g, ', ')
    .slice(0, 1000);
}

function _stopAudio() {
  if (_AI.audio) {
    _AI.audio.pause();
    if (_AI.audio._url) URL.revokeObjectURL(_AI.audio._url);
    _AI.audio = null;
  }
  speechSynthesis?.cancel();
}

async function _speak(text) {
  if (!_AI.ttsEnabled || !text) return;
  _stopAudio();
  const clean = _cleanForSpeech(text);
  const s     = window.__jarvisSettings;

  try {
    const res = await fetch('/api/tts', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({
        text:   clean,
        speed:  s.speed,
        volume: s.volume,
      }),
    });

    if (!res.ok) { _speakBrowser(clean); return; }

    const blob  = await res.blob();
    const url   = URL.createObjectURL(blob);
    const audio = new Audio(url);
    audio._url     = url;
    audio.volume   = s.volume;
    audio.onended  = () => URL.revokeObjectURL(url);
    audio.onerror  = () => { URL.revokeObjectURL(url); _speakBrowser(clean); };
    _AI.audio = audio;
    audio.play().catch(() => _speakBrowser(clean));

  } catch (_) {
    _speakBrowser(clean);
  }
}

function _speakBrowser(text) {
  if (!window.speechSynthesis) return;
  const utt = new SpeechSynthesisUtterance(text);
  if (_AI.voice) utt.voice = _AI.voice;
  utt.rate  = 0.88;
  utt.pitch = 0.92;
  speechSynthesis.speak(utt);
}

/* ── Public helpers called from main.js ───────────────────── */

window.askAICVE = function(cveId, pkg, installed, fixed, severity, summary) {
  const panel = document.getElementById('ai-panel');
  if (panel) panel.style.display = 'flex';

  const report = window.__scanReport;
  const family = report?.distro_family ?? 'unknown';
  const pmCmd  = {
    arch:   `sudo pacman -Syu ${pkg}`,
    debian: `sudo apt-get install --only-upgrade ${pkg}`,
    rhel:   `sudo dnf update ${pkg}`,
  }[family] ?? `<your-package-manager> update ${pkg}`;

  const prompt =
    `CVE ID: ${cveId}\n` +
    `Package: ${pkg}  |  Installed: ${installed}  |  Fixed in: ${fixed}\n` +
    `Severity: ${severity}\n` +
    `Description: ${summary || 'no description'}\n\n` +
    `1. What can an attacker do with this?\n` +
    `2. Patch command for this system:\n\`\`\`\n${pmCmd}\n\`\`\`\n` +
    `3. Any mitigations if I cannot patch right now?`;

  _sendAIMessage(prompt);
};

window.askAITopology = function(topoData, cveData) {
  const panel = document.getElementById('ai-panel');
  if (panel) panel.style.display = 'flex';

  const hostname  = topoData?.hostname  ?? 'this device';
  const gateway   = topoData?.gateway   ?? 'unknown';
  const neighbors = (topoData?.neighbors ?? []).length;
  const myIp      = topoData?.my_ips?.[0]?.ip ?? '?';
  const prefix    = topoData?.my_ips?.[0]?.prefix ?? '?';
  const critical  = cveData?.counts?.critical ?? 0;
  const high      = cveData?.counts?.high ?? 0;
  const topCVEs   = (cveData?.cves ?? [])
    .filter(c => ['critical', 'high'].includes(c.severity))
    .slice(0, 5)
    .map(c => `  - ${c.id} in ${c.package} (${c.severity}, CVSS ${c.cvss ?? '?'})`)
    .join('\n');

  const prompt =
    `Analyse this network attack surface and give me prioritised recommendations:\n\n` +
    `Host: ${hostname} (${myIp}/${prefix})\n` +
    `Gateway: ${gateway}\n` +
    `LAN neighbors visible in ARP: ${neighbors}\n` +
    `CVE exposure: ${critical} critical, ${high} high\n` +
    (topCVEs ? `Top vulnerabilities:\n${topCVEs}\n` : '') +
    `\nPlease: (1) assess entry-point risk, (2) describe realistic lateral movement, ` +
    `(3) give 3 prioritised remediation steps.`;

  _sendAIMessage(prompt);
};
