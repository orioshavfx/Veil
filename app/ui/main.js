const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const $ = (id) => document.getElementById(id);

// The badge names the release line of a beta (1.0.0-beta.2 → "Beta 1.0") and is hidden for a
// stable version; the full version is in its tooltip (core:default allows app.getVersion).
// Without a version it keeps the plain "Beta" from index.html.
function betaBadgeText(version) {
  const m = /^v?(\d+)\.(\d+)\.\d+(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/.exec(String(version).trim());
  if (!m) return 'Beta';
  if (!m[3]) return null; // stable
  return m[3].split('.').some((id) => id.toLowerCase() === 'beta') ? `Beta ${m[1]}.${m[2]}` : `Pre-release ${m[1]}.${m[2]}`;
}
Promise.resolve()
  .then(() => window.__TAURI__.app.getVersion())
  .then((v) => {
    const badge = $('beta-badge');
    const text = betaBadgeText(v);
    badge.title = `Veil ${v}`;
    if (text) badge.textContent = text;
    badge.hidden = !text;
  })
  .catch(() => {});

let state = null;
let busy = false;
let busyLabel = null; // status text while a connection action runs
let last = null; // previous traffic sample, for speed
let shownError = null; // last backend error already shown as a toast
let polling = false; // a traffic/state request is in flight
let idleTicks = 0;
let showSpeed = true; // speed readout on/off (remembered per device)
try { showSpeed = localStorage.getItem('veil.speed') !== '0'; } catch {}

const SECURITY = { reality: 'REALITY', tls: 'TLS' };
const MODE_NAMES = { proxy: 'Proxy', tun: 'TUN' };
const MODE_DESC = {
  macos: {
    proxy: 'Uses the macOS system proxy. No password needed.',
    tun: 'Routes all system traffic, including apps that ignore the proxy. Asks for an administrator password the first time.',
  },
  linux: {
    proxy: 'Runs a local proxy (SOCKS/HTTP on 127.0.0.1) for apps that use it. No password needed.',
    tun: 'Routes all traffic through the veil0 network device, including apps that ignore the proxy. Asks for your password (polkit) the first time to install the helper service.',
  },
  windows: {
    proxy: 'Uses the Windows system proxy. No administrator rights needed.',
    tun: 'Routes all traffic, including apps that ignore the proxy. Veil restarts with administrator permission (Windows asks you to confirm).',
  },
};
const ROUTING_DESC = {
  global: 'All traffic goes through the VPN except the local network. Rules below can send specific sites and apps direct or block them.',
  'selected-only': 'Only sites and apps from the rules below with “Via VPN” use the VPN; everything else goes direct. If a site does not open directly (blocked), Veil sends it through the VPN automatically.',
};

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

let toastTimer;
function toast(text, error = false) {
  const t = $('toast');
  t.textContent = text;
  t.classList.toggle('error', error);
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.hidden = true), error ? 7000 : 3500);
}

async function call(cmd, args) {
  try {
    return await invoke(cmd, args);
  } catch (e) {
    shownError = String(e); // the backend also keeps it as `state.error`
    toast(String(e), true);
    throw e;
  }
}

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

// Windows has no flag glyphs: a regional-indicator pair renders as bare letters
// ("EU", "PL"). There, draw each pair as a small country-code badge instead.
// Elsewhere (macOS has Apple Color Emoji flags) the text is left untouched.
const NO_FLAG_FONT = /Windows/i.test(navigator.userAgent);
const FLAG_RE = /([\u{1F1E6}-\u{1F1FF}])([\u{1F1E6}-\u{1F1FF}])/gu;
function setName(node, text) {
  text = String(text);
  if (!NO_FLAG_FONT || !FLAG_RE.test(text)) {
    FLAG_RE.lastIndex = 0;
    node.textContent = text;
    return node;
  }
  FLAG_RE.lastIndex = 0;
  node.textContent = '';
  let last = 0;
  for (const m of text.matchAll(FLAG_RE)) {
    if (m.index > last) node.append(text.slice(last, m.index));
    const code = [...m[0]].map((c) => String.fromCharCode(c.codePointAt(0) - 0x1F1E6 + 65)).join('');
    node.append(el('span', 'flag-code', code));
    last = m.index + m[0].length;
  }
  if (last < text.length) node.append(text.slice(last));
  return node;
}

async function reload() {
  state = await invoke('snapshot');
  render();
  renderUpdates();
  showBackendError();
}

// Errors of actions the UI did not start itself (the elevated copy connecting on
// startup, the tray menu) are only known to the backend: show them once.
function showBackendError() {
  const e = state?.error ?? null;
  if (e && e !== shownError) toast(e, true);
  shownError = e;
}

/// Runs one action at a time; clicks during it are ignored instead of queued.
async function action(label, fn) {
  if (busy) return;
  busy = true;
  busyLabel = label;
  render();
  try {
    return await fn();
  } finally {
    busy = false;
    busyLabel = null;
    await reload();
  }
}

// ---- views ----------------------------------------------------------------

function showSettings(on) {
  $('view-main').hidden = on;
  $('view-settings').hidden = !on;
  $('open-settings').hidden = on;
  $('close-settings').hidden = !on;
  $('top-title').textContent = on ? 'Settings' : 'Veil';
  // The Beta badge and the update pill belong to the main screen only.
  document.body.classList.toggle('in-settings', on);
  window.scrollTo(0, 0);
  if (on) loadRules();
}
$('open-settings').onclick = () => showSettings(true);
$('close-settings').onclick = () => showSettings(false);
$('caption').onclick = () => showSettings(true);

function render() {
  if (!state) return;
  const s = state;
  document.body.classList.toggle('busy', busy);

  // Main screen.
  const hero = $('hero');
  hero.classList.toggle('on', s.connected);
  hero.classList.toggle('standby', !s.connected && s.standby);
  hero.classList.toggle('busy', Boolean(busyLabel));
  $('status').textContent = busyLabel
    || (s.connected ? 'Connected' : s.standby ? 'Standby — VPN traffic blocked' : 'Disconnected');
  $('status').title = !s.connected && s.standby
    ? 'Sites and apps that use the VPN are blocked until you connect again. Quit Veil to restore normal internet.'
    : '';
  $('power').setAttribute('aria-label', s.connected ? 'Disconnect' : 'Connect');
  const current = s.profiles.find((p) => p.id === s.selected);
  setName($('current'), current ? current.name : 'No server selected');
  const presetName = (s.presets.find(([n]) => n === s.preset) || [])[1] || '';
  $('caption').textContent = `${MODE_NAMES[s.mode]} · ${presetName}`;
  if (!s.connected) {
    last = null;
    $('up').textContent = $('down').textContent = showSpeed ? '0 B/s' : '';
    $('timer').textContent = clock(0);
  }
  renderGroups();

  // Settings screen.
  for (const b of $('mode').querySelectorAll('button')) {
    b.setAttribute('aria-checked', String(b.dataset.mode === s.mode));
    b.disabled = b.dataset.mode === 'tun' && !s.tun_available && s.mode !== 'tun';
  }
  $('mode-desc').textContent = (MODE_DESC[s.platform] || MODE_DESC.macos)[s.mode];
  const killShown = s.standby_available && s.tun_available && s.mode === 'tun';
  $('kill-switch-row').hidden = !killShown;
  $('kill-switch-desc').hidden = !killShown;
  $('kill-switch').checked = Boolean(s.kill_switch);
  $('launch-at-login').checked = Boolean(s.launch_at_login);
  $('launch-at-login-row').hidden = !s.autostart_available;
  $('auto-connect').checked = Boolean(s.auto_connect);
  if ($('routing').children.length !== s.presets.length) {
    $('routing').replaceChildren(...s.presets.map(([name, label]) => {
      const b = el('button', null, label);
      b.dataset.preset = name;
      b.setAttribute('role', 'radio');
      return b;
    }));
  }
  for (const b of $('routing').querySelectorAll('button')) {
    b.setAttribute('aria-checked', String(b.dataset.preset === s.preset));
  }
  $('routing-desc').textContent = ROUTING_DESC[s.preset] || '';
}

// ---- servers ----------------------------------------------------------------

function renderGroups() {
  const s = state;
  const groups = [];
  const pinned = s.profiles.filter((p) => p.pinned);
  if (pinned.length) groups.push({ title: 'Pinned', items: pinned });
  for (const sub of s.subscriptions) {
    groups.push({ sub, title: sub.name, items: s.profiles.filter((p) => p.subscription_id === sub.id && !p.pinned) });
  }
  const manual = s.profiles.filter((p) => !p.subscription_id && !p.pinned);
  if (manual.length) groups.push({ title: 'Added manually', items: manual });

  $('groups').replaceChildren(...groups.map(renderGroup));
  $('empty').hidden = s.profiles.length > 0 || s.subscriptions.length > 0;
}

function renderGroup({ sub, title, items }) {
  const g = el('section', 'group');
  const head = el('div', 'group-head');
  head.append(setName(el('div', 'group-title'), title));
  if (sub) {
    const del = el('button', 'icon-btn', '✕');
    del.title = 'Remove subscription';
    del.onclick = () => action(null, () => call('delete_subscription', { id: sub.id }));
    head.append(del);
  }
  g.append(head);

  if (sub && sub.usage && (sub.usage.total || sub.usage.expire)) {
    const u = sub.usage;
    const used = u.upload + u.download;
    const meta = el('div', 'group-meta');
    const parts = [];
    if (u.total) parts.push(`${bytes(used)} of ${bytes(u.total)}`);
    if (u.expire) parts.push(`until ${new Date(u.expire * 1000).toLocaleDateString('en-GB')}`);
    meta.append(parts.join(' · '));
    if (u.total) {
      const bar = el('div', 'usage');
      const fill = el('i');
      fill.style.width = `${Math.min(100, (used / u.total) * 100)}%`;
      bar.append(fill);
      meta.append(bar);
    }
    g.append(meta);
  }

  for (const p of items) g.append(renderRow(p));
  return g;
}

function renderRow(p) {
  const row = el('div', 'row' + (p.id === state.selected ? ' sel' : '') + (p.pinned ? ' pinned' : ''));
  row.tabIndex = 0;
  row.setAttribute('role', 'button');
  const main = el('div', 'row-main');
  main.append(setName(el('div', 'row-name'), p.name));
  const kind = [p.protocol.toUpperCase(), SECURITY[p.security]].filter(Boolean).join(' · ');
  main.append(el('div', 'row-sub', kind));

  const ping = el('span', 'ping');
  if (p.latency_ms === 0) {
    ping.textContent = 'no response';
    ping.classList.add('bad');
  } else if (p.latency_ms) {
    ping.textContent = `${p.latency_ms} ms`;
    ping.classList.add(p.latency_ms < 150 ? 'good' : p.latency_ms < 400 ? 'mid' : 'bad');
  }

  const pin = el('button', 'icon-btn pin', p.pinned ? '★' : '☆');
  pin.title = p.pinned ? 'Unpin' : 'Pin to top';
  pin.onclick = (e) => {
    e.stopPropagation();
    action(null, () => call('toggle_pin', { id: p.id }));
  };
  const del = el('button', 'icon-btn del', '✕');
  del.title = 'Remove server';
  del.onclick = (e) => {
    e.stopPropagation();
    action(null, () => call('delete_profile', { id: p.id }));
  };

  row.append(el('span', 'dot'), main, ping, pin, del);
  const choose = () => {
    if (p.id === state.selected) return;
    action(state.connected ? 'Switching…' : null, () => call('select_profile', { id: p.id }));
  };
  row.onclick = choose;
  row.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); choose(); } };
  return row;
}

$('power').onclick = () => {
  const on = state.connected;
  action(on ? 'Disconnecting…' : 'Connecting…', () => call(on ? 'disconnect' : 'connect'));
};

$('add').onsubmit = (e) => {
  e.preventDefault();
  const input = $('link').value.trim();
  if (!input) return;
  action(null, async () => {
    toast(await call('import', { input }));
    $('link').value = '';
  });
};

$('ping').onclick = () => action(null, () => call('ping_all'));
$('refresh').onclick = () => action(null, async () => toast(await call('refresh_subscriptions')));

// ---- settings: mode and routing ------------------------------------------

$('mode').onclick = (e) => {
  const mode = e.target.dataset?.mode;
  if (!mode || mode === state.mode) return;
  action(state.connected ? 'Reconnecting…' : null, () => call('set_mode', { mode }));
};

$('kill-switch').onchange = (e) => {
  const enabled = e.target.checked;
  // Another action is running: action() would drop this one, so undo the click.
  if (busy) { e.target.checked = !enabled; return; }
  action(null, () => call('set_kill_switch', { enabled }));
};

$('routing').onclick = (e) => {
  const name = e.target.dataset?.preset;
  if (!name || name === state.preset) return;
  action(null, async () => {
    await call('set_preset', { name });
    if (name === 'selected-only') $('rule-action').value = 'proxy';
  }).then(renderRules);
};

// ---- settings: rules -------------------------------------------------------

let rules = [];
let ruleKind = 'site';
let allApps = [];
let pickedApps = [];
const ACTIONS = { proxy: 'Via VPN', direct: 'Direct', block: 'Block' };
const DOMAIN_PREFIXES = /^(full|domain|keyword|regexp|geosite):/i;
const IP_LIKE = /^(geoip:.+|\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?|[0-9a-f:]*:[0-9a-f:]*(\/\d{1,3})?)$/i;

function setRuleKind(kind) {
  ruleKind = kind;
  for (const b of $('rule-kind').querySelectorAll('button')) b.setAttribute('aria-checked', String(b.dataset.kind === kind));
  const input = $('rule-input');
  input.value = '';
  $('app-list').hidden = kind !== 'app';
  if (kind === 'site') {
    input.placeholder = 'youtube.com, 1.2.3.0/24';
    $('rule-hint').textContent = 'A domain covers all its subdomains; you can paste a full link. Rules are checked top to bottom. Optional: geosite:/geoip: lists need your own geoip.dat/geosite.dat in the data folder.';
  } else {
    input.placeholder = 'Search, or a program name (e.g. curl)';
    $('rule-hint').textContent = state.tun_available
      ? 'Tick apps in the list or type a program name. App rules fully work in TUN mode.'
      : 'Tick apps in the list or type a program name. In Proxy mode, app rules only apply to apps that use the system proxy.';
    refreshApps();
  }
}
$('rule-kind').onclick = (e) => { if (e.target.dataset?.kind) setRuleKind(e.target.dataset.kind); };

async function refreshApps() {
  allApps = await invoke('list_apps').catch(() => []);
  pickedApps = [];
  renderAppList();
}

function renderAppList() {
  const q = $('rule-input').value.trim().toLowerCase();
  // Running apps first, then alphabetical (the backend already sorts by name).
  const list = allApps
    .filter((a) => !q || a.name.toLowerCase().includes(q) || pickedApps.includes(a.name))
    .sort((a, b) => Number(b.running) - Number(a.running));
  const items = list.map((a) => {
    const b = el('button', 'app-item');
    b.type = 'button';
    b.setAttribute('role', 'option');
    const picked = pickedApps.includes(a.name);
    b.setAttribute('aria-selected', String(picked));
    b.append(el('span', 'check', picked ? '✓' : ''), el('span', 'name', a.name));
    if (a.running) b.append(el('span', 'badge', 'running'));
    b.onclick = () => {
      pickedApps = picked ? pickedApps.filter((x) => x !== a.name) : [...pickedApps, a.name];
      renderAppList();
    };
    return b;
  });
  if (!items.length) items.push(el('div', 'none', q ? `No app matches “${q}” — it will be added as a program name` : 'No apps found'));
  $('app-list').replaceChildren(...items);
}

$('rule-input').oninput = () => { if (ruleKind === 'app') renderAppList(); };

/** Turns "https://www.YouTube.com/watch?v=1" into "domain:youtube.com". */
function siteEntry(raw) {
  let v = raw.trim();
  if (!v) return null;
  if (DOMAIN_PREFIXES.test(v) || IP_LIKE.test(v)) return v.toLowerCase().startsWith('regexp:') ? v : v.toLowerCase();
  v = v.replace(/^[a-z]+:\/\//i, '').split(/[/?#]/)[0].replace(/:\d+$/, '').replace(/^www\./i, '').toLowerCase();
  return v ? `domain:${v}` : null;
}

async function rulesFromInput(text, act) {
  if (ruleKind === 'app') {
    // Ticked apps, plus a typed name that matches no listed app (e.g. "curl").
    const typed = text.trim();
    const lower = typed.toLowerCase();
    const exact = allApps.find((a) => a.name.toLowerCase() === lower);
    const partial = allApps.some((a) => a.name.toLowerCase().includes(lower));
    const extra = !typed ? [] : exact ? [exact.name] : partial ? [] : [typed];
    const process = [...new Set([...pickedApps, ...extra])];
    if (!process.length && typed) toast('Tick an app in the list');
    return process.length ? [{ action: act, process }] : [];
  }
  const entries = text.split(/[,\s]+/).map(siteEntry).filter(Boolean);
  const ip = entries.filter((e) => IP_LIKE.test(e) && !DOMAIN_PREFIXES.test(e));
  const domain = entries.filter((e) => !ip.includes(e));
  // A site loads from many domains (CDN, video, images): add the service's list,
  // only when the user put their own geosite.dat into the data folder.
  const added = [];
  for (const d of domain.filter((x) => x.startsWith('domain:'))) {
    const code = await invoke('suggest_geosite', { domain: d.slice(7) }).catch(() => null);
    const tag = code && `geosite:${code}`;
    if (tag && !domain.includes(tag)) {
      domain.push(tag);
      added.push(tag);
    }
  }
  if (added.length) toast(`Added all of the service’s domains: ${added.join(', ')}`);
  // Within one rule all conditions must match, so domains and IPs go into separate rules.
  const out = [];
  if (domain.length) out.push({ action: act, domain });
  if (ip.length) out.push({ action: act, ip });
  return out;
}

async function loadRules() {
  rules = await invoke('get_rules');
  renderRules();
}

async function saveRules(next) {
  let ok = false;
  await action(null, async () => {
    await call('set_rules', { rules: next });
    rules = next;
    ok = true;
  }).catch(() => {});
  renderRules();
  return ok;
}

function ruleLabel(r) {
  const parts = [...(r.process || []), ...(r.domain || []).map((d) => d.replace(/^domain:/, '')), ...(r.ip || [])];
  if (r.port?.length) parts.push(`port ${r.port.join(', ')}`);
  return parts.join(', ');
}

function renderRules() {
  const selectedOnly = state?.preset === 'selected-only';
  $('rules-empty').textContent = selectedOnly
    ? 'Add sites and apps with “Via VPN” — everything else goes direct.'
    : 'No rules yet — all traffic goes through the VPN.';
  $('rules-empty').hidden = rules.length > 0;
  $('rules').replaceChildren(...rules.map((r, i) => {
    const row = el('div', 'rule');
    row.append(el('span', 'rule-kind', r.process?.length ? 'APP' : (r.ip?.length && !r.domain?.length ? 'IP' : 'WEB')));
    row.append(el('span', 'rule-text', ruleLabel(r)));

    const sel = el('select');
    sel.setAttribute('aria-label', 'Action');
    for (const [v, t] of Object.entries(ACTIONS)) { const o = el('option', null, t); o.value = v; sel.append(o); }
    sel.value = r.action;
    sel.dataset.action = r.action;
    sel.onchange = () => saveRules(rules.map((x, j) => (j === i ? { ...x, action: sel.value } : x)));

    const up = el('button', 'icon-btn', '↑');
    up.title = 'Move up (checked earlier)';
    up.disabled = i === 0;
    up.onclick = () => { const n = [...rules]; [n[i - 1], n[i]] = [n[i], n[i - 1]]; saveRules(n); };
    const del = el('button', 'icon-btn del', '✕');
    del.title = 'Remove rule';
    del.onclick = () => saveRules(rules.filter((_, j) => j !== i));
    row.append(sel, up, del);
    return row;
  }));
}

$('rule-form').onsubmit = async (e) => {
  e.preventDefault();
  if (busy) return;
  const added = await rulesFromInput($('rule-input').value, $('rule-action').value);
  if (!added.length) return;
  if (await saveRules([...added, ...rules])) {
    $('rule-input').value = '';
    pickedApps = [];
    if (ruleKind === 'app') renderAppList();
  }
};

// ---- traffic ---------------------------------------------------------------

function applySpeedToggle() {
  $('speed-toggle').setAttribute('aria-pressed', String(showSpeed));
  $('speed-toggle').textContent = showSpeed ? 'Speed: on' : 'Speed: off';
  document.querySelector('.meters').classList.toggle('no-speed', !showSpeed);
  if (!showSpeed) $('up').textContent = $('down').textContent = '';
  else $('up').textContent = $('down').textContent = '0 B/s';
  last = null;
}
$('speed-toggle').onclick = () => {
  showSpeed = !showSpeed;
  try { localStorage.setItem('veil.speed', showSpeed ? '1' : '0'); } catch {}
  applySpeedToggle();
};

async function tick() {
  if (polling) return; // never overlap: slow replies would give a bogus speed
  polling = true;
  try {
    if (!state?.connected) {
      last = null;
      // A connection can appear without a click (elevated copy, tray menu) and the
      // event may fire before this page listens: look again every few seconds.
      if (!busy && ++idleTicks >= 3) {
        idleTicks = 0;
        const s = await invoke('snapshot');
        if (!busy && (s.connected !== state?.connected || s.standby !== state?.standby
            || (s.error ?? null) !== (state?.error ?? null))) {
          state = s;
          render();
          showBackendError();
        }
      }
      return;
    }
    const t = await invoke('traffic');
    // Disconnected (or reconnected) while waiting: the sample belongs to the old session.
    if (!state?.connected) return;
    if (!t.connected) { reload(); return; }
    const now = performance.now();
    if (showSpeed && last && now > last.at && t.seconds >= last.seconds) {
      const dt = (now - last.at) / 1000;
      $('up').textContent = `${bytes(Math.max(0, t.upload - last.upload) / dt)}/s`;
      $('down').textContent = `${bytes(Math.max(0, t.download - last.download) / dt)}/s`;
    }
    $('timer').textContent = clock(t.seconds);
    last = { ...t, at: now };
  } catch {
    last = null;
  } finally {
    polling = false;
  }
}

// ---- settings: updates ------------------------------------------------------
// macOS only; the backend decides (`availability`): `ready`, `not_configured` (built without
// an update key) or `unsupported` (Windows: download new versions from the releases page).

let updates = null; // UpdateStatus from the backend
let installing = false;
let checking = false;
let confirming = false; // the inline "Install anyway?" is open

const PHASE_TEXT = {
  downloading: 'Downloading…',
  stopping: 'Stopping the VPN…',
  installing: 'Installing…',
  restarting: 'Restarting…',
};

function renderUpdates() {
  const u = updates;
  if (!u) return;
  const ready = u.availability === 'ready';
  $('app-version').textContent = u.current_version;
  $('check-update').hidden = !ready;
  $('check-update').disabled = checking || installing;
  $('check-update').textContent = checking ? 'Checking…' : 'Check for updates';
  $('check-updates-row').hidden = !ready;
  $('updates-desc').hidden = !ready;
  $('update-pill').hidden = !(ready && u.available);
  let text = '';
  if (u.availability === 'unsupported') text = state?.platform === 'linux'
    ? 'Veil does not update itself on Linux. Update it with your package manager, or download new versions from ' + u.releases_page
    : `Veil does not update itself on this system. Download new versions from ${u.releases_page}`;
  else if (u.availability === 'not_configured') text = 'Updates are not configured in this build.';
  else if (u.error) text = u.error;
  else if (u.available) text = `Version ${u.available.version} is available${u.available.date ? ` (${u.available.date})` : ''}.`;
  else if (u.checked) text = 'You are up to date.';
  $('update-result').textContent = text;
  $('update-result').hidden = !text;
  $('update-result').classList.toggle('selectable', u.availability === 'unsupported');
  const offer = ready && Boolean(u.available);
  $('update-available').hidden = !offer;
  const notes = u.available?.notes || '';
  $('update-notes').textContent = notes;
  $('update-notes').hidden = !notes;
  $('install-update').disabled = installing || u.phase !== 'idle';
  if (!offer || installing) confirming = false;
  $('install-update').hidden = confirming;
  $('update-confirm').hidden = !confirming;
  if (state) $('check-updates').checked = Boolean(state.check_updates);
}

async function loadUpdates() {
  try {
    updates = await invoke('update_status');
  } catch {
    return;
  }
  renderUpdates();
}

function showPhase(p) {
  const shown = p && p.phase !== 'idle';
  $('update-progress').hidden = !shown;
  $('update-phase').hidden = !shown;
  if (!shown) return;
  const known = p.phase === 'downloading' && p.total;
  $('update-progress').classList.toggle('indeterminate', !known);
  $('update-bar').style.width = known ? `${Math.min(100, (p.downloaded / p.total) * 100).toFixed(1)}%` : '';
  let text = PHASE_TEXT[p.phase] || '';
  if (p.phase === 'downloading' && p.downloaded) {
    text = known
      ? `Downloading… ${Math.floor((p.downloaded / p.total) * 100)}% of ${bytes(p.total)}`
      : `Downloading… ${bytes(p.downloaded)}`;
  }
  $('update-phase').textContent = text;
}

$('check-update').onclick = async () => {
  if (checking || installing) return;
  checking = true;
  renderUpdates();
  try {
    updates = await invoke('check_update');
  } catch {
    await loadUpdates(); // the backend keeps the error as `updates.error`
  } finally {
    checking = false;
    renderUpdates();
  }
};

$('install-update').onclick = () => {
  if (installing) return;
  // A connection is being set up: the backend refuses too, say it here first.
  if (busy) { toast('Wait until Veil has finished connecting, then install the update.', true); return; }
  // Installing stops the VPN (a standby too): ask first, inline (window.confirm would block
  // the webview).
  if (state?.connected || state?.standby) {
    confirming = true;
    renderUpdates();
    $('update-confirm-no').focus();
    return;
  }
  installUpdate();
};
$('update-confirm-yes').onclick = () => {
  confirming = false;
  if (busy) { renderUpdates(); toast('Wait until Veil has finished connecting, then install the update.', true); return; }
  installUpdate();
};
$('update-confirm-no').onclick = () => {
  confirming = false;
  renderUpdates();
  $('install-update').focus();
};

async function installUpdate() {
  if (installing) return;
  installing = true;
  renderUpdates();
  showPhase({ phase: 'downloading', downloaded: 0, total: null });
  try {
    await invoke('install_update'); // on success the app restarts
  } catch (e) {
    showPhase(null);
    // If the VPN was already stopped, the backend keeps the same text as `state.error`
    // (and Settings → Updates as `updates.error`): one toast is enough.
    shownError = String(e);
    toast(String(e), true);
    installing = false;
    await reload();
    await loadUpdates();
  }
}

$('auto-connect').onchange = (e) => {
  const enabled = e.target.checked;
  call('set_auto_connect', { enabled }).catch(() => { e.target.checked = !enabled; });
};

$('launch-at-login').onchange = (e) => {
  const enabled = e.target.checked;
  call('set_launch_at_login', { enabled }).catch(() => { e.target.checked = !enabled; });
};

$('check-updates').onchange = (e) => {
  const enabled = e.target.checked;
  call('set_check_updates', { enabled }).catch(() => { e.target.checked = !enabled; });
};

$('update-pill').onclick = () => {
  showSettings(true);
  $('updates-card').scrollIntoView({ block: 'nearest' });
};

listen('update-progress', (e) => {
  if (installing) showPhase(e.payload);
});
listen('update-status', loadUpdates);

setRuleKind('site');
applySpeedToggle();
listen('state-changed', reload);
setInterval(tick, 1000);
reload();
loadUpdates();
