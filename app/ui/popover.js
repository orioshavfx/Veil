// Menu bar panel (macOS): power button, mode, pinned servers with live ping.
const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const $ = (id) => document.getElementById(id);
const PING_EVERY_MS = 10000;

let state = null;
let busyLabel = null; // status text while an action runs
let open = false; // the panel is on screen
let pingTimer = null;
let trafficTimer = null;
let pinging = false;
let polling = false;
let last = null; // previous traffic sample, for speed
let seconds = 0;

function bytes(n) {
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return `${n < 10 && i ? n.toFixed(1) : Math.round(n)} ${units[i]}`;
}

function clock(s) {
  const p = (x) => String(x).padStart(2, '0');
  return `${p(Math.floor(s / 3600))}:${p(Math.floor(s / 60) % 60)}:${p(s % 60)}`;
}

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

// The main window's "Speed: on/off" switch (same origin, so the same storage).
function speedOn() {
  try { return localStorage.getItem('veil.speed') !== '0'; } catch { return true; }
}

function showError(e) {
  const el = $('error');
  if (!el) return;
  el.textContent = String((e && e.message) || e);
  el.hidden = false;
}

async function reload() {
  try {
    state = await invoke('popover_state');
  } catch (e) {
    console.warn(e);
    showError(e);
    return;
  }
  render();
}

function render() {
  if (!state) return;
  const s = state;
  document.body.classList.toggle('busy', Boolean(busyLabel));
  const hero = $('hero');
  hero.classList.toggle('on', s.connected);
  hero.classList.toggle('busy', Boolean(busyLabel));
  $('power').setAttribute('aria-label', s.connected ? 'Disconnect' : 'Connect');
  $('status').textContent = busyLabel || (s.connected ? `Connected · ${clock(seconds)}` : 'Disconnected');
  $('server').textContent = s.server_name || 'No server selected';
  $('speed').hidden = !(s.connected && speedOn());
  if (!s.connected) { last = null; seconds = 0; }

  $('error').hidden = !s.error || s.connected;
  $('error').textContent = s.error || '';
  $('error').title = s.error || '';

  for (const b of $('mode').querySelectorAll('button')) {
    b.setAttribute('aria-checked', String(b.dataset.mode === s.mode));
    b.disabled = b.dataset.mode === 'tun' && !s.tun_available && s.mode !== 'tun';
  }

  $('list-title').textContent = s.pinned ? 'Pinned servers' : 'Servers';
  $('hint').hidden = s.pinned || !s.has_servers;
  const rows = s.servers.map(renderServer);
  if (!rows.length) rows.push(el('div', 'empty', 'No servers yet. Open Veil to add a link or a subscription.'));
  $('list').replaceChildren(...rows);
}

function renderServer(p) {
  const row = el('button', 'srv' + (p.selected ? ' sel' : ''));
  row.type = 'button';
  row.setAttribute('role', 'option');
  row.setAttribute('aria-selected', String(p.selected));
  row.title = p.name;
  const ms = p.latency_ms === 0 ? 'timeout' : p.latency_ms ? `${p.latency_ms} ms` : '—';
  row.append(el('span', `dot ${p.level}`), el('span', 'name', p.name), el('span', 'ms', ms), el('span', 'check', p.selected ? '✓' : ''));
  row.onclick = () => {
    if (p.selected) return;
    // Same as the main window: the running session switches to the new server.
    action(state.connected ? 'Switching…' : null, () => invoke('select_profile', { id: p.id }));
  };
  return row;
}

/// One action at a time; clicks during it are ignored.
async function action(label, fn) {
  if (busyLabel !== null || document.body.classList.contains('busy')) return;
  busyLabel = label || '';
  let failed = null;
  render();
  try {
    await fn();
  } catch (e) {
    console.warn(e);
    failed = e;
  } finally {
    busyLabel = null;
    await reload();
    if (failed) showError(failed);
  }
}

$('power').onclick = () => {
  const on = state?.connected;
  action(on ? 'Disconnecting…' : 'Connecting…', () => invoke(on ? 'disconnect' : 'connect'));
};

$('mode').onclick = (e) => {
  const mode = e.target.dataset?.mode;
  if (!mode || !state || mode === state.mode || e.target.disabled) return;
  action(state.connected ? 'Reconnecting…' : null, () => invoke('set_mode', { mode }));
};

$('open').onclick = () => invoke('open_main_window');
$('quit').onclick = () => invoke('quit_app');

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') invoke('hide_popover');
});

// ---- ping: only the servers shown, only while the panel is open --------------

async function ping() {
  if (!open || pinging || !state?.servers.length) return;
  pinging = true;
  try {
    await invoke('ping_servers', { ids: state.servers.map((s) => s.id) });
  } catch (e) {
    console.warn(e);
  } finally {
    pinging = false;
  }
  if (open) await reload();
}

// ---- traffic: time and speed while connected ---------------------------------

async function traffic() {
  if (!open || polling || !state?.connected) return;
  polling = true;
  try {
    const t = await invoke('traffic');
    if (!state?.connected) return;
    if (!t.connected) { reload(); return; }
    const now = performance.now();
    if (last && now > last.at && t.seconds >= last.seconds) {
      const dt = (now - last.at) / 1000;
      $('up').textContent = `${bytes(Math.max(0, t.upload - last.upload) / dt)}/s`;
      $('down').textContent = `${bytes(Math.max(0, t.download - last.download) / dt)}/s`;
    }
    last = { ...t, at: now };
    seconds = t.seconds;
    if (busyLabel === null) $('status').textContent = `Connected · ${clock(seconds)}`;
  } catch {
    last = null;
  } finally {
    polling = false;
  }
}

async function opened() {
  if (open) return;
  open = true;
  last = null;
  $('up').textContent = $('down').textContent = '0 B/s';
  await reload();
  if (!open) return;
  traffic();
  ping();
  clearInterval(pingTimer);
  clearInterval(trafficTimer);
  pingTimer = setInterval(ping, PING_EVERY_MS);
  trafficTimer = setInterval(traffic, 1000);
}

function closed() {
  open = false;
  clearInterval(pingTimer);
  clearInterval(trafficTimer);
  pingTimer = trafficTimer = null;
}

listen('popover-opened', opened);
listen('popover-closed', closed);
listen('state-changed', reload);
// The window can be shown before this page listens (first click right after start).
window.addEventListener('focus', opened);
reload().then(() => { if (document.hasFocus()) opened(); });
