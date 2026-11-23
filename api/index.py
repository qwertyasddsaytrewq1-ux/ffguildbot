# api/index.py
# Vercel serverless function — serves the HTML dashboard only
# All real work happens on the Railway worker (RAILWAY_URL env var)

import os
from http.server import BaseHTTPRequestHandler

RAILWAY_URL = os.environ.get("RAILWAY_URL", "").rstrip("/")

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FF Guild Glory Bot</title>
<style>
  :root {
    --bg: #0d0f14; --card: #161920; --border: #2a2d38;
    --accent: #f7a832; --ok: #3ddc84; --err: #ff5252;
    --warn: #ffca28; --text: #e8ecf0; --muted: #7a8290;
    --radius: 10px; --font: 'Segoe UI', system-ui, sans-serif;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: var(--font);
         min-height: 100vh; display: flex; flex-direction: column; align-items: center;
         padding: 24px 16px; }
  h1 { font-size: 1.6rem; font-weight: 700; color: var(--accent); letter-spacing: .02em; margin-bottom: 24px; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: var(--radius);
          padding: 20px 24px; width: 100%; max-width: 680px; margin-bottom: 20px; }
  label { font-size: .78rem; color: var(--muted); display: block; margin-bottom: 6px; text-transform: uppercase; letter-spacing: .06em; }
  input[type=text], input[type=number] {
    width: 100%; background: #1e222d; border: 1px solid var(--border); border-radius: 7px;
    padding: 10px 14px; color: var(--text); font-size: .95rem; outline: none;
    transition: border .2s;
  }
  input:focus { border-color: var(--accent); }
  .row { display: flex; gap: 14px; }
  .row .field { flex: 1; }
  .btn-row { display: flex; gap: 10px; margin-top: 20px; flex-wrap: wrap; }
  button { flex: 1; min-width: 110px; padding: 11px 18px; border: none; border-radius: 7px;
           font-size: .92rem; font-weight: 600; cursor: pointer; transition: opacity .15s; }
  button:disabled { opacity: .4; cursor: not-allowed; }
  #btn-start  { background: var(--accent); color: #111; }
  #btn-pause  { background: var(--warn); color: #111; }
  #btn-stop   { background: var(--err);  color: #fff; }
  .stats-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; }
  .stat { background: #1a1d26; border-radius: 8px; padding: 14px 10px; text-align: center; }
  .stat-val { font-size: 1.5rem; font-weight: 700; color: var(--accent); }
  .stat-lbl { font-size: .72rem; color: var(--muted); margin-top: 2px; text-transform: uppercase; letter-spacing: .06em; }
  #status-badge { display: inline-block; padding: 4px 12px; border-radius: 20px;
                  font-size: .8rem; font-weight: 600; letter-spacing: .04em; margin-bottom: 14px; }
  .badge-idle    { background: #2a2d38; color: var(--muted); }
  .badge-running { background: #1a3a1a; color: var(--ok); }
  .badge-paused  { background: #3a2d10; color: var(--warn); }
  .badge-stopped { background: #3a1515; color: var(--err); }
  .badge-done    { background: #102a20; color: var(--ok); }
  #log { background: #111318; border-radius: 8px; padding: 12px; height: 300px;
         overflow-y: auto; font-family: 'Cascadia Code', 'Consolas', monospace;
         font-size: .78rem; line-height: 1.6; }
  .log-line { padding: 1px 0; }
  .log-success { color: var(--ok); }
  .log-error   { color: var(--err); }
  .log-warning { color: var(--warn); }
  .log-info    { color: #90beff; }
  .ts { color: var(--muted); font-size: .7rem; margin-right: 6px; }
  #worker-url-row { display: flex; gap: 10px; align-items: flex-end; }
  #worker-url-row input { flex: 1; }
  #worker-url-row button { flex: none; padding: 10px 16px; background: #2a2d38; color: var(--text); border-radius: 7px; font-size: .82rem; border: 1px solid var(--border); }
</style>
</head>
<body>
<h1>🤖 FF Guild Glory Bot</h1>

<!-- Worker URL config -->
<div class="card">
  <label>Railway Worker URL</label>
  <div id="worker-url-row">
    <input type="text" id="worker-url" placeholder="https://your-app.railway.app" />
    <button onclick="saveUrl()">Save</button>
  </div>
</div>

<!-- Config -->
<div class="card">
  <div class="row">
    <div class="field">
      <label>Guild ID</label>
      <input type="text" id="guild-id" placeholder="e.g. 123456789" />
    </div>
    <div class="field">
      <label>Number of Accounts</label>
      <input type="number" id="account-count" value="10" min="1" max="200" />
    </div>
  </div>
  <div class="btn-row">
    <button id="btn-start" onclick="startBot()">▶ Start</button>
    <button id="btn-pause" onclick="pauseBot()" disabled>⏸ Pause</button>
    <button id="btn-stop"  onclick="stopBot()"  disabled>⏹ Stop</button>
  </div>
</div>

<!-- Stats -->
<div class="card">
  <div id="status-badge" class="badge-idle">IDLE</div>
  <div class="stats-grid">
    <div class="stat"><div class="stat-val" id="st-gen">0</div><div class="stat-lbl">Generated</div></div>
    <div class="stat"><div class="stat-val" id="st-join">0</div><div class="stat-lbl">Joined Guild</div></div>
    <div class="stat"><div class="stat-val" id="st-match">0</div><div class="stat-lbl">Matches</div></div>
  </div>
</div>

<!-- Log -->
<div class="card">
  <label style="margin-bottom:10px">Live Log</label>
  <div id="log"></div>
</div>

<script>
const LS_KEY = 'ff_worker_url';
let _evtSrc = null;
let _statusTimer = null;

function getWorkerUrl() {
  return (document.getElementById('worker-url').value || localStorage.getItem(LS_KEY) || '').replace(/\/$/, '');
}
function saveUrl() {
  const u = document.getElementById('worker-url').value.trim();
  if (u) { localStorage.setItem(LS_KEY, u); addLog('Worker URL saved: ' + u, 'info'); }
}

window.onload = () => {
  const saved = localStorage.getItem(LS_KEY) || '';
  if (saved) document.getElementById('worker-url').value = saved;
  refreshStatus();
  startSSE();
};

// ── SSE ─────────────────────────────────────────────────────────────────
function startSSE() {
  if (_evtSrc) { _evtSrc.close(); }
  const base = getWorkerUrl();
  if (!base) return;
  _evtSrc = new EventSource(base + '/stream');
  _evtSrc.onmessage = e => {
    try {
      const d = JSON.parse(e.data);
      addLog(d.msg, d.type || 'info');
    } catch(_) {}
  };
  _evtSrc.onerror = () => {
    // reconnect after 3s
    setTimeout(startSSE, 3000);
  };
}

// ── log ──────────────────────────────────────────────────────────────────
function addLog(msg, type) {
  const el = document.getElementById('log');
  const d = new Date();
  const ts = d.toTimeString().slice(0,8);
  const line = document.createElement('div');
  line.className = 'log-line log-' + (type || 'info');
  line.innerHTML = '<span class="ts">' + ts + '</span>' + escHtml(msg);
  el.appendChild(line);
  if (el.children.length > 600) el.removeChild(el.firstChild);
  el.scrollTop = el.scrollHeight;
}
function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// ── status polling ────────────────────────────────────────────────────────
async function refreshStatus() {
  const base = getWorkerUrl();
  if (!base) { _statusTimer = setTimeout(refreshStatus, 3000); return; }
  try {
    const r = await fetch(base + '/status');
    if (r.ok) {
      const d = await r.json();
      updateUI(d);
    }
  } catch(_) {}
  _statusTimer = setTimeout(refreshStatus, 3000);
}

function updateUI(d) {
  document.getElementById('st-gen').textContent   = d.accounts_gen  || 0;
  document.getElementById('st-join').textContent  = d.joined        || 0;
  document.getElementById('st-match').textContent = d.matches       || 0;

  const badge = document.getElementById('status-badge');
  const s = d.status || 'idle';
  badge.textContent = s.toUpperCase();
  badge.className = 'badge-' + (
    ['generating','joining','playing'].includes(s) ? 'running' :
    s === 'paused'  ? 'paused'  :
    s === 'stopped' ? 'stopped' :
    s === 'done'    ? 'done'    : 'idle'
  );

  const running = ['generating','joining','playing','paused'].includes(s);
  document.getElementById('btn-start').disabled = running;
  document.getElementById('btn-pause').disabled = !running;
  document.getElementById('btn-stop').disabled  = !running;
  document.getElementById('btn-pause').textContent = d.paused ? '▶ Resume' : '⏸ Pause';
}

// ── controls ──────────────────────────────────────────────────────────────
async function startBot() {
  const base = getWorkerUrl();
  if (!base) { addLog('Set Railway Worker URL first', 'error'); return; }
  const guildId = document.getElementById('guild-id').value.trim();
  const count   = parseInt(document.getElementById('account-count').value) || 10;
  if (!guildId) { addLog('Enter a Guild ID', 'error'); return; }
  try {
    const r = await fetch(base + '/start', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({guild_id: guildId, account_count: count}),
    });
    const d = await r.json();
    if (r.ok) addLog('Started job ' + d.job_id, 'success');
    else addLog('Start error: ' + JSON.stringify(d), 'error');
    // reconnect SSE on new job
    startSSE();
  } catch(e) { addLog('Start failed: ' + e, 'error'); }
}

async function pauseBot() {
  const base = getWorkerUrl();
  if (!base) return;
  try {
    const r = await fetch(base + '/pause', {method: 'POST'});
    const d = await r.json();
    addLog(d.paused ? 'Paused' : 'Resumed', 'warning');
  } catch(e) { addLog('Pause failed: ' + e, 'error'); }
}

async function stopBot() {
  const base = getWorkerUrl();
  if (!base) return;
  try {
    await fetch(base + '/stop', {method: 'POST'});
    addLog('Stop signal sent', 'warning');
  } catch(e) { addLog('Stop failed: ' + e, 'error'); }
}
</script>
</body>
</html>"""

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = HTML.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass
  
