const $ = (id) => document.getElementById(id);

const els = {
  status: $('status'),
  input: $('messageInput'),
  compare: $('compareToggle'),
  analyze: $('analyzeButton'),
  chat: $('chat'),
};

function setStatus(kind, text) {
  els.status.className = 'status' + (kind ? ' ' + kind : '');
  els.status.textContent = text;
}

async function pollHealth() {
  try {
    const res = await fetch('/health', { cache: 'no-store' });
    if (!res.ok) throw new Error();
    setStatus('ready', 'ready');
  } catch {
    setStatus('down', 'connecting');
  }
}

function sc(obj, key) {
  const v = obj?.scores?.[key] ?? obj?.[key];
  return v === null || v === undefined ? '-' : String(v);
}

function isDanger(d) {
  return d === 'block' || String(d).startsWith('warn');
}

function renderCard(obj, label, cmp) {
  const d = obj?.decision ?? '?';
  const r = obj?.overall_risk ?? 0;
  const rows = [
    ['Decision', d, isDanger(d)],
    ['Risk', String(r), Number(r) >= 65],
    ['Phishing', sc(obj, 'phishing'), Number(sc(obj, 'phishing')) >= 65],
    ['Impersonation', sc(obj, 'impersonation'), Number(sc(obj, 'impersonation')) >= 65],
    ['Risk Score', sc(obj, 'risk'), Number(sc(obj, 'risk')) >= 65],
    ['Confidence', sc(obj, 'confidence'), false],
    ['Prompt Inj', sc(obj, 'prompt_injection'), Number(sc(obj, 'prompt_injection')) >= 65],
    ['Secret', sc(obj, 'secret'), Number(sc(obj, 'secret')) >= 65],
    ['URL Rep', sc(obj, 'url_reputation'), Number(sc(obj, 'url_reputation')) >= 65],
  ];
  const flags = Array.isArray(obj?.flags) ? obj.flags : [];
  const raw = obj?.ai_raw_response;

  let html = '<div class="hdr">' + esc(label) + (cmp ? ' <span class="cmp">compare</span>' : '') + '</div>';
  for (const [lbl, val, danger] of rows) {
    html += '<div class="row' + (danger ? ' danger' : '') + '"><span class="lbl">' + lbl + '</span><span class="val">' + esc(val) + '</span></div>';
  }
  if (flags.length) {
    html += '<div class="tags">' + flags.slice(0, 12).map(f => '<span class="tag">' + esc(String(f)) + '</span>').join('') + '</div>';
  }
  if (raw) {
    html += '<button class="llm-btn" onclick="var n=this.nextElementSibling;n.style.display=n.style.display===\'block\'?\'none\':\'block\'">Toggle LLM Output</button><pre class="llm-raw">' + esc(raw) + '</pre>';
  }
  html += '<div class="ts">' + new Date().toLocaleTimeString() + '</div>';
  return html;
}

function addMessage(text, isUser) {
  const div = document.createElement('div');
  div.className = 'msg ' + (isUser ? 'user' : 'assistant');

  if (!isUser && typeof text === 'object') {
    const data = text;
    const compare = els.compare.checked && data.compare_ai_only;
    if (compare) {
      div.innerHTML = renderCard(data.ai_only, 'AI Only', true) + '<hr class="sep">' + renderCard(data.full, 'Full Poseidon', true);
    } else {
      div.innerHTML = renderCard(data, 'Full Poseidon', false);
    }
  } else {
    div.textContent = text;
  }

  els.chat.appendChild(div);
  els.chat.scrollTop = els.chat.scrollHeight;
}

function esc(s) {
  return String(s).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;');
}

async function analyze() {
  const msg = els.input.value.trim();
  if (!msg) return;

  els.analyze.disabled = true;
  addMessage(msg, true);
  els.input.value = '';
  els.input.style.height = 'auto';

  try {
    const res = await fetch('/analyse', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ message: msg, user_id: 'web', compare_ai_only: els.compare.checked }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'HTTP ' + res.status);
    addMessage(data, false);
  } catch (err) {
    addMessage('Request failed: ' + err.message, false);
  } finally {
    els.analyze.disabled = false;
  }
}

els.input.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    analyze();
  }
});

els.input.addEventListener('input', () => {
  els.input.style.height = 'auto';
  els.input.style.height = Math.min(els.input.scrollHeight, 120) + 'px';
});

els.analyze.addEventListener('click', analyze);
pollHealth();
setInterval(pollHealth, 3000);
