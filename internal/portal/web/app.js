// Shepherd portal entry point: wires the data sources (live SSE, replay,
// in-browser demo), the model, the globe and the HUD chrome together. Pure
// logic lives in js/*.js and is unit tested; this file is the glue.
import { $ } from './js/dom.js';
import { createApi } from './js/api.js';
import { createDemoApi } from './js/demoapi.js';
import { DemoGenerator, DEMO_HOME } from './js/demo.js';
import { normalizeEntry, destKey, placeName } from './js/entry.js';
import { LiveSource } from './js/sources.js';
import { ReplaySource } from './js/replay.js';
import { ReplayClock } from './js/clock.js';
import { Model } from './js/model.js';
import { weightScale, entryWeight } from './js/weight.js';
import { validLatLon } from './js/geo.js';
import { fmtClock } from './js/format.js';
import { createDetails } from './js/details.js';
import { createTiles, createFeed, createFilters, createLegend, createInspector, createTimeline } from './js/hud.js';
import { createToaster } from './js/ui.js';
import { createMgmt } from './js/mgmt.js';
import { createNameBook } from './js/names.js';
import { createPolicyStore } from './js/policystore.js';
import { createDevices } from './js/devices.js';
import { createBlocking, createDevicePolicy } from './js/blocking.js';
import { createUpstreams } from './js/upstreamsview.js';
import { createAlarms } from './js/alarmsview.js';
import { createVulnscan } from './js/vulnscanview.js';
import { createNethealth } from './js/nethealthview.js';
import { createReverseProxy } from './js/reverseproxyview.js';
import { createHistory } from './js/historyview.js';
import { createAccountability } from './js/accountability.js';
import { createDemoMgmt } from './js/demomgmt.js';
import { DEVICE_BY_IP } from './js/demodata.js';
import { createLocking } from './js/lockingview.js';
import { lockedURL, unlockedURL } from './js/locking.js';

const params = new URLSearchParams(location.search);
const demoParam = params.get('demo');
const DEMO = demoParam !== null && demoParam !== '0' && demoParam !== 'false';
// LOCKED means the portal put itself here (first visit, idle relock, or the
// Lock button), rather than someone choosing the demo-data toggle by hand.
const LOCKED = params.get('locked') === '1';
const DEBUG = params.get('debug') === '1';
const reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

const COMET_BUDGET = 24;
const SHIELD_BUDGET = 6;
const FEED_BURST = 12;

// ---------------------------------------------------------------- core state
const model = new Model();
const gen = DEMO ? new DemoGenerator({ rate: Number(params.get('rate')) || 5, bytes: demoParam === 'bytes' || params.get('bytes') === '1', deviceOf: (ip) => (demoMgmt ? demoMgmt.deviceOf(ip) : DEVICE_BY_IP.get(ip)) }) : null;
const names = createNameBook();
let demoMgmt = null;
let home = DEMO ? { ...DEMO_HOME } : null;
let globe = null;
let mode = 'live';
let lastStatus = null;
let historyAvailable = DEMO;
let bounds = { oldest: Date.now() - 24 * 3600 * 1000, newest: Date.now() };
let hudVisible = true;
let homeMode = false;
let liveState = 'connecting';
const scratch = [];
const clock = new ReplayClock(Date.now(), 1);

const toaster = createToaster($('#toasts'));
function notify(msg) { toaster.show(msg); }

// ---------------------------------------------------------------- api
let api;
let sources = null;
// Losing a real session (idle relock, or the server restarting) bounces the
// whole page into the locked demo view by reloading with ?demo=1&locked=1 -
// the same "reload to switch modes" trick the manual demo toggle already
// uses (see the demo-toggle listener below), rather than rewiring every
// place DEMO is read at module load into something reactive.
function showLogin() {
  location.assign(lockedURL(location.href));
}
if (DEMO) {
  api = createDemoApi({
    mgmt: (demoMgmt = createDemoMgmt({ count: Math.min(20000, Math.max(9, Number(params.get('devices')) || 38)), gen, history: params.get('history') || 'encrypted' })),
    getCounters: () => model.counters,
    topClients: () => [...model.clients.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6).map(([key, n]) => ({ key, n })),
    home: DEMO_HOME,
  });
} else {
  api = createApi({ onUnauthorized: showLogin });
}
// Login, PIN login and the explicit Lock always talk to the real backend,
// never the in-browser demo fake, even while DEMO is showing the lock
// screen's synthetic data behind it.
const realApi = createApi({ onUnauthorized: () => {} });

// ---------------------------------------------------------------- UI pieces
const details = createDetails({ api, getRows: () => model.recentNewestFirst(400), notify, onRulesChanged: () => {}, names });
const setTiles = createTiles();
const legend = createLegend();
const filters = createFilters({ model, onChange: onFiltersChanged });
const feed = createFeed({ onSelect: selectEntry });
const inspector = createInspector({
  api, notify, names,
  onRule: () => { details.refreshRules(); },
});
inspector.onClose = () => { if (globe) globe.setSelected(null); $('#lbl-sel').hidden = true; };

const timeline = createTimeline({
  onLive: () => goLive(),
  onSeek: (t) => enterReplay(t),
  onPlayPause: () => { if (mode === 'replay') clock.toggle(); },
  onSpeed: (n) => { clock.setSpeed(n); replay.setChunk(Math.max(30 * 60 * 1000, n * 120 * 1000)); },
});

// The retained span reported by /api/history. An empty store reports the zero
// time, which must not stretch the scrubber back to the year 1.
function setBounds(r) {
  const o = Date.parse(r && r.oldest), n = Date.parse(r && r.newest);
  const sane = (t) => Number.isFinite(t) && t > 946684800000;
  if (sane(o) && sane(n) && n >= o) bounds = { oldest: o, newest: n };
}

// ---------------------------------------------------------------- sources
const historyLoader = DEMO
  ? (from, to, limit) => gen.load(from, to, limit)
  : async (from, to, limit) => {
    const q = new URLSearchParams({ from: new Date(from).toISOString(), to: new Date(to).toISOString(), limit: String(limit) });
    const r = await api('/api/history?' + q);
    setBounds(r);
    const entries = [];
    for (const raw of r.entries || []) { const e = normalizeEntry(raw); if (e) entries.push(e); }
    return { entries };
  };

const replay = new ReplaySource({
  load: async (from, to, limit) => {
    const r = await historyLoader(from, to, limit);
    for (const e of r.entries) normalizeEntry(e);
    return r;
  },
});
replay.onChange = () => {
  if (replay.error && mode === 'replay') {
    if (replay.error.status === 423) { notify('History is locked. Unlock it to replay earlier traffic.'); goLive(); }
    else if (replay.error.status === 404) { historyAvailable = false; notify('History is not available on this server yet.'); goLive(); updateTimelineAvailability(); }
    else if (replay.error.message !== 'unauthorized') notify('Could not load history: ' + replay.error.message);
  }
};

const live = DEMO ? gen : new LiveSource({
  fetchJson: (p) => api(p),
  onState: (s) => { liveState = s; paintPill(); },
});

function activeSource() { return mode === 'replay' ? replay : live; }

function stopData() {
  if (!DEMO) live.stop();
  replay.stop();
}

// ---------------------------------------------------------------- processing
function resetView() {
  model.reset();
  feed.clear();
  inspector.clear();
  if (globe) { globe.setSelected(null); globe.setHover(null); }
  $('#lbl-sel').hidden = true;
  dirty = true;
}

let dirty = false;
let lastSync = 0;
let lastSlow = 0;

function processEntries(list, vnow, animate) {
  let comets = 0, shields = 0;
  const feedFrom = Math.max(0, list.length - FEED_BURST);
  for (let i = 0; i < list.length; i++) {
    const e = list[i];
    names.note(e);
    filters.noteClient(e.client, e.device);
    const res = model.ingest(e);
    if (res === 'filtered') continue;
    if (i >= feedFrom) feed.push(e);
    if (res === 'lane') {
      dirty = true;
      if (animate && globe) {
        const t = model.lanes;
        for (const lane of model.touched) {
          if (comets >= COMET_BUDGET || globe.time - lane.lastComet < 0.09) continue;
          lane.lastComet = globe.time;
          const s = t.mode === 'bytes'
            ? weightScale(entryWeight(e, 'bytes') / model.touched.length, 'bytes')
            : weightScale(t.valueAt(lane, vnow), 'lookups');
          globe.spawnComet(lane, Math.max(0.05, s));
          comets++;
        }
      }
    } else if (res === 'blocked' && animate && globe && shields < SHIELD_BUDGET) {
      globe.spawnShield(0.35);
      shields++;
    }
  }
}

function frame(nowPerf, render) {
  const dtMs = Math.min(250, nowPerf - lastFrame);
  lastFrame = nowPerf;
  let vnow;
  if (mode === 'live') {
    vnow = Date.now();
  } else {
    const edge = Date.now();
    clock.tick(dtMs, Math.min(replay.ceiling, edge));
    vnow = clock.time;
    if (vnow >= edge - 1500 && clock.playing && !replay.loading) { goLive(); vnow = edge; }
  }
  scratch.length = 0;
  activeSource().drain(vnow, scratch);
  if (scratch.length) processEntries(scratch, vnow, true);

  const wall = performance.now();
  if (globe && (dirty ? wall - lastSync > 50 : wall - lastSync > 100)) {
    model.lanes.prune(vnow);
    globe.sync(vnow, (l) => model.laneVisible(l));
    legend.setMode(model.mode);
    legend.setLanes(globe.stats.lanes);
    lastSync = wall;
    dirty = false;
  }
  if (wall - lastSlow > 250) {
    lastSlow = wall;
    slowTick(vnow);
  }
  if (render && globe) {
    globe.render(dtMs / 1000);
    updateLabels();
  }
}

function slowTick(vnow) {
  if (!globe) model.lanes.prune(vnow);
  const real = !DEMO && mode === 'live' && lastStatus;
  const st = real ? lastStatus.stats || {} : null;
  setTiles({
    total: real ? st.total : model.counters.total,
    blockedPct: real ? (st.total ? (100 * st.blocked) / st.total : 0) : model.blockedPct,
    cached: real ? st.cached : model.counters.cached,
    errors: real ? st.errors : model.counters.errors,
    devices: real ? Math.max(model.clients.size, (st.top_clients || []).length) : model.clients.size,
  });
  feed.setCount(model.counters.total);
  inspector.refresh(model, vnow);
  $('#clock').textContent = fmtClock(vnow);
  timeline.setBounds(DEMO ? gen.history(Date.now()).oldest : bounds.oldest, DEMO ? Date.now() : Math.max(bounds.newest, Date.now()));
  timeline.setState({ live: mode === 'live', playing: clock.playing, speed: clock.speed, time: vnow, loading: replay.loading });
  $('#no-map').hidden = DEMO || !model.mapUnavailable || mode !== 'live';
  $('#no-home').hidden = !globe || home !== null || homeMode;
  paintPill();
  if (DEBUG && globe) window.__hud = { model, globe, replay, clock };
}

let lastFrame = performance.now();

// ---------------------------------------------------------------- pill
function paintPill() {
  const p = $('#live');
  let text = 'connecting', cls = 'pill';
  if (DEMO && mode === 'live') { text = 'demo'; cls = 'pill demo'; }
  else if (mode === 'replay') { text = 'replay'; cls = 'pill replay'; }
  else if (liveState === 'live' || liveState === 'poll') { text = 'live'; cls = 'pill live'; }
  else if (liveState === 'offline') { text = 'offline'; cls = 'pill down'; }
  if (p.textContent !== text) p.textContent = text;
  if (p.className !== cls) p.className = cls;
}

// ---------------------------------------------------------------- mode switches
function updateTimelineAvailability() {
  const r = $('#tl-range');
  r.disabled = !historyAvailable;
  r.title = historyAvailable ? '' : 'History is not available on this server yet';
}

function enterReplay(t) {
  if (!historyAvailable) { notify('History is not available on this server yet.'); return; }
  if (!DEMO) live.stop();
  mode = 'replay';
  resetView();
  replay.setChunk(Math.max(30 * 60 * 1000, clock.speed * 120 * 1000));
  clock.seek(t);
  clock.play();
  replay.seek(t);
  if (clock.speed === 1 && Date.now() - t > 3600 * 1000) clock.setSpeed(60);
  paintPill();
}

function goLive() {
  mode = 'live';
  replay.stop();
  resetView();
  clock.pause();
  if (DEMO) startDemo();
  else startLive();
  paintPill();
}

// Pre-fill the globe with the last couple of minutes so demo mode opens busy.
function startDemo() {
  const now = Date.now();
  const list = gen.range(now - 150000, now);
  for (const e of list) normalizeEntry(e);
  processEntries(list, now, false);
  gen.start(now);
}

async function startLive() {
  live.stop();
  try {
    const r = await api('/api/queries?limit=200');
    const list = [];
    for (const raw of r.entries || []) { const e = normalizeEntry(raw); if (e) list.push(e); }
    live.seed(r.last);
    processEntries(list, Date.now(), false);
  } catch (e) {
    if (e.message === 'unauthorized') return;
  }
  live.start();
}

// ---------------------------------------------------------------- selection
// On phones the feed and filter panels are sheets; close them when a pick is made.
function closeSheets() {
  $('#panel-feed').classList.remove('show');
  $('#panel-filters').classList.remove('show');
  $('#btn-feed').setAttribute('aria-pressed', 'false');
  $('#btn-filters').setAttribute('aria-pressed', 'false');
}

function selectLane(lane, domain, entry) {
  closeSheets();
  if (globe) { globe.setSelected(lane.key); dirty = true; }
  inspector.select({ lane, entry: entry || null, domain: domain || lane.lastName }, model, Date.now());
}

function selectEntry(e) {
  closeSheets();
  const d = e.dests && e.dests[0];
  const lane = d ? model.lanes.byKey.get(e.client + '|' + destKey(d)) : null;
  if (lane) {
    selectLane(lane, e.name, e);
    if (globe) globe.focusLane(lane);
  } else {
    if (globe) { globe.setSelected(null); dirty = true; }
    inspector.select({ lane: null, entry: e, domain: e.name }, model, Date.now());
    if (globe && home) globe.resetView();
  }
}

function onPick(hit) {
  if (!hit) { inspector.clear(); if (globe) globe.setSelected(null); $('#lbl-sel').hidden = true; dirty = true; return; }
  selectLane(hit.lane, hit.lane.lastName, null);
}

const tip = $('#tip');
function onHover(hit, x, y) {
  const key = hit ? hit.lane.key : null;
  if (globe && key !== globe.hoverKey) { globe.setHover(key); dirty = true; }
  if (!hit) { tip.hidden = true; return; }
  const r = $('#stage').getBoundingClientRect();
  tip.textContent = hit.lane.lastName + '  ' + placeName(hit.lane.dest) + '  ' + hit.lane.count;
  tip.hidden = false;
  tip.style.transform = `translate(${Math.round(x - r.left + 14)}px, ${Math.round(y - r.top + 14)}px)`;
}

function updateLabels() {
  const lh = $('#lbl-home');
  if (home) {
    const p = globe.projectLatLon(home.lat, home.lon, 1.01);
    lh.hidden = !p.visible;
    if (p.visible) lh.style.transform = `translate(${Math.round(p.x + 12)}px, ${Math.round(p.y - 24)}px)`;
  } else lh.hidden = true;
  const ls = $('#lbl-sel');
  const sel = inspector.selection;
  const dest = sel && sel.lane ? sel.lane.dest : null;
  if (dest) {
    const p = globe.projectLatLon(dest.lat, dest.lon, 1.01);
    ls.hidden = !p.visible;
    if (p.visible) {
      ls.textContent = placeName(dest);
      ls.style.transform = `translate(${Math.round(p.x + 12)}px, ${Math.round(p.y - 24)}px)`;
    }
  } else ls.hidden = true;
}

function onFiltersChanged() {
  feed.clear();
  const rows = [];
  for (const e of model.recentNewestFirst(400)) {
    if (model.matches(e)) rows.push(e);
    if (rows.length >= 60) break;
  }
  for (let i = rows.length - 1; i >= 0; i--) feed.push(rows[i]);
  dirty = true;
}

// ---------------------------------------------------------------- home
function applyHome(h, focus) {
  home = h && validLatLon(h.lat, h.lon) ? h : null;
  const label = home && typeof home.label === 'string' && home.label && home.label !== 'Home' ? home.label.slice(0, 40) : '';
  $('#lbl-home').textContent = label ? 'HOME  ' + label : 'HOME';
  model.lanes.setHome(home);
  if (globe) { globe.setHome(home); if (home && focus) globe.resetView(); }
  dirty = true;
}

function setHomeMode(on) {
  homeMode = on;
  if (globe) globe.setHomeMode(on);
  $('#btn-home').setAttribute('aria-pressed', on ? 'true' : 'false');
  $('#home-banner').hidden = !on;
  if (on) $('#no-home').hidden = true;
}

async function saveHome(ll) {
  const h = { lat: Math.round(ll.lat * 100) / 100, lon: Math.round(ll.lon * 100) / 100, label: 'Home' };
  setHomeMode(false);
  applyHome(h, false);
  try {
    await api('/api/settings/home', { method: 'POST', body: JSON.stringify(h) });
  } catch (err) {
    if (err.status === 404 || err.status === 405) {
      try { localStorage.setItem('shepherd.home', JSON.stringify(h)); } catch { /* storage may be blocked */ }
      notify('Home saved in this browser only (the server has no settings endpoint yet).');
    } else if (err.message !== 'unauthorized') notify('Could not save home: ' + err.message);
  }
}

async function loadHome() {
  if (DEMO) { applyHome(home, true); return; }
  try {
    const s = await api('/api/settings');
    if (s && s.home) { applyHome(s.home, true); return; }
  } catch (err) {
    if (err.message === 'unauthorized') return;
  }
  try {
    const h = JSON.parse(localStorage.getItem('shepherd.home') || 'null');
    if (h && validLatLon(h.lat, h.lon)) applyHome(h, true);
  } catch { /* ignore */ }
}

// ---------------------------------------------------------------- status polling
let statusTimer = 0;
async function pollStatus() {
  try {
    lastStatus = await api('/api/status');
    details.renderStatus(lastStatus);
  } catch { /* the pill reflects connectivity */ }
}

// ---------------------------------------------------------------- management screens
const mgmt = createMgmt(api);
const policyStore = createPolicyStore({ mgmt });
const VIEWS = ['hud', 'devices', 'blocking', 'alarms', 'vulnscan', 'network', 'upstreams', 'proxy', 'history', 'accountability', 'locking', 'details'];

const blocking = createBlocking({
  root: $('#view-blocking'), mgmt, store: policyStore, notify,
  getGroups: () => devicesView.groups,
});
const devicesView = createDevices({
  root: $('#view-devices'), mgmt, notify, toaster,
  renderBlocking: createDevicePolicy({ store: policyStore, notify, openBlocking: (scope, d) => openBlocking(scope, d) }),
  onOpenHistory: (d) => { showView('history'); historyView.showFor(d); },
  onGroupsChanged: () => { blocking.onGroupsChanged(); accountabilityView.onGroupsChanged(); },
});
const alarmsView = createAlarms({ root: $('#view-alarms'), mgmt, notify, toaster });
const vulnscanView = createVulnscan({
  root: $('#view-vulnscan'), mgmt, notify, toaster,
  onOpenDevice: (id) => { showView('devices'); devicesView.openDevice(id); },
});
const networkView = createNethealth({ root: $('#view-network'), mgmt, notify });
const upstreamsView = createUpstreams({ root: $('#view-upstreams'), mgmt, notify });
const proxyView = createReverseProxy({ root: $('#view-proxy'), mgmt, notify });
const lockingView = createLocking({ root: $('#view-locking'), mgmt, notify });
const historyView = createHistory({
  root: $('#view-history'), mgmt, notify, api,
  onReplay: (t) => { showView('hud'); enterReplay(Math.max(0, t - 20000)); },
  demo: DEMO ? { setLocked: (locked) => api('/api/demo/history-lock', { method: 'POST', body: JSON.stringify({ locked }) }) } : null,
});
const accountabilityView = createAccountability({
  root: $('#view-accountability'), mgmt, notify,
  getGroups: () => devicesView.groups,
});

function openBlocking(scope, device) {
  blocking.setScope(scope, device && device.name, device && device.groups);
  showView('blocking');
}

// ---------------------------------------------------------------- views
function showView(name) {
  if (!VIEWS.includes(name)) name = 'hud';
  const hud = name === 'hud';
  hudVisible = hud;
  for (const v of VIEWS) {
    $('#view-' + v).hidden = v !== name;
    $('#tab-' + v).setAttribute('aria-selected', v === name ? 'true' : 'false');
    $('#tab-' + v).tabIndex = v === name ? 0 : -1;
  }
  document.body.classList.toggle('on-details', name === 'details');
  document.body.classList.toggle('on-page', !hud);
  try { history.replaceState(null, '', location.pathname + location.search + (hud ? '' : '#' + name)); } catch { /* ignore */ }
  if (name === 'details') details.renderRows();
  if (name !== 'upstreams') upstreamsView.hide();
  if (name !== 'proxy') proxyView.hide();
  if (name !== 'alarms') alarmsView.hide();
  if (name !== 'vulnscan') vulnscanView.hide();
  if (name !== 'network') networkView.hide();
  if (name !== 'locking') lockingView.hide();
  if (name === 'devices') devicesView.show();
  else if (name === 'blocking') devicesView.reloadGroups().catch(() => {}).finally(() => blocking.show());
  else if (name === 'alarms') alarmsView.show();
  else if (name === 'vulnscan') vulnscanView.show();
  else if (name === 'network') networkView.show();
  else if (name === 'upstreams') upstreamsView.show();
  else if (name === 'proxy') proxyView.show();
  else if (name === 'history') historyView.show();
  else if (name === 'accountability') devicesView.reloadGroups().catch(() => {}).finally(() => accountabilityView.show());
  else if (name === 'locking') lockingView.show();
}
// Below the width the horizontal .tabs row would otherwise scroll
// sideways (10 tabs do not fit at phone widths), it becomes a
// hamburger-triggered vertical dropdown instead (CSS only: the nav
// itself, showView, hash routing and arrow-key navigation below are all
// unchanged - closeNavMenu just also runs wherever the tab list should
// dismiss itself on mobile).
function closeNavMenu() {
  $('.tabs').classList.remove('open');
  $('#btn-navmenu').setAttribute('aria-expanded', 'false');
}
$('#btn-navmenu').addEventListener('click', () => {
  const on = !$('.tabs').classList.contains('open');
  $('.tabs').classList.toggle('open', on);
  $('#btn-navmenu').setAttribute('aria-expanded', on ? 'true' : 'false');
});
document.addEventListener('click', (e) => {
  if (!$('.tabs').classList.contains('open')) return;
  if (e.target.closest('.tabs') || e.target.closest('#btn-navmenu')) return;
  closeNavMenu();
});
for (const v of VIEWS) $('#tab-' + v).addEventListener('click', () => { showView(v); closeNavMenu(); });
window.addEventListener('hashchange', () => { const h = location.hash.slice(1) || 'hud'; if (VIEWS.includes(h) && $('#view-' + h).hidden) showView(h); });
$('.tabs').addEventListener('keydown', (e) => {
  if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
  const cur = VIEWS.findIndex((v) => $('#tab-' + v).getAttribute('aria-selected') === 'true');
  const next = VIEWS[(cur + (e.key === 'ArrowRight' ? 1 : VIEWS.length - 1)) % VIEWS.length];
  showView(next);
  $('#tab-' + next).focus();
});
setInterval(() => { if (!$('#view-details').hidden) details.renderRows(); }, 1000);

// ---------------------------------------------------------------- toolbar
$('#btn-home').addEventListener('click', () => setHomeMode(!homeMode));
$('#prompt-home').addEventListener('click', () => setHomeMode(true));
$('#btn-rotate').addEventListener('click', (e) => {
  const on = e.currentTarget.getAttribute('aria-pressed') !== 'true';
  e.currentTarget.setAttribute('aria-pressed', on ? 'true' : 'false');
  if (globe) globe.setAutoRotate(on);
});
$('#btn-recenter').addEventListener('click', () => { if (globe) globe.resetView(); });
for (const [btn, panel] of [['#btn-feed', '#panel-feed'], ['#btn-filters', '#panel-filters']]) {
  $(btn).addEventListener('click', (e) => {
    const on = e.currentTarget.getAttribute('aria-pressed') !== 'true';
    $('#panel-feed').classList.remove('show'); $('#panel-filters').classList.remove('show');
    $('#btn-feed').setAttribute('aria-pressed', 'false'); $('#btn-filters').setAttribute('aria-pressed', 'false');
    if (on) { $(panel).classList.add('show'); e.currentTarget.setAttribute('aria-pressed', 'true'); }
  });
}
// The Legend panel is its own toggle, independent of the Feed/Filters pair
// above (it lives in the opposite rail and does not need to exclude them):
// on mobile it otherwise takes up a disproportionate share of the screen, so
// it starts hidden there and opens only behind this small "i" button.
$('#btn-legend').addEventListener('click', (e) => {
  const on = e.currentTarget.getAttribute('aria-pressed') !== 'true';
  e.currentTarget.setAttribute('aria-pressed', on ? 'true' : 'false');
  $('#legend').classList.toggle('show', on);
});
document.addEventListener('keydown', (e) => {
  if (e.key !== 'Escape') return;
  if ($('.tabs').classList.contains('open')) closeNavMenu();
  else if (homeMode) setHomeMode(false);
  else if (inspector.selection) { inspector.clear(); if (globe) globe.setSelected(null); dirty = true; }
});

// Demo toggle reloads with or without ?demo=1 so the two modes never mix.
const demoToggle = $('#demo-toggle');
demoToggle.checked = DEMO;
demoToggle.addEventListener('change', () => {
  const u = new URL(location.href);
  if (demoToggle.checked) u.searchParams.set('demo', '1'); else { u.searchParams.delete('demo'); u.searchParams.delete('rate'); u.searchParams.delete('bytes'); }
  location.assign(u.toString());
});

// ---------------------------------------------------------------- login
// Both forms reload into the real, unlocked view on success (the same
// mode-switch-by-reload pattern as the demo toggle), so there is no partial
// in-place teardown of the demo pipeline to get wrong.
$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    const r = await realApi('/api/login', { method: 'POST', body: JSON.stringify({ token: $('#token').value }) });
    const u = new URL(unlockedURL(location.href));
    if (r && r.pin_set === false) u.searchParams.set('setup_pin', '1'); // offer a PIN right after the first token unlock
    location.assign(u.toString());
  } catch { $('#login-err').textContent = 'That token did not work.'; }
});
$('#pin-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    await realApi('/api/login/pin', { method: 'POST', body: JSON.stringify({ pin: $('#pin').value }), keep401: true });
    location.assign(unlockedURL(location.href));
  } catch (err) { $('#pin-err').textContent = err.message === 'unauthorized' ? 'Wrong PIN.' : err.message; }
});
$('#btn-lock').addEventListener('click', async () => {
  try { await realApi('/api/lock', { method: 'POST' }); } catch { /* lock locally regardless of what the server says */ }
  location.assign(lockedURL(location.href));
});

// ---------------------------------------------------------------- boot
async function bootData() {
  clearInterval(statusTimer);
  pollStatus();
  statusTimer = setInterval(pollStatus, 3000);
  details.refreshRules();
  loadHome();
  if (DEMO) { startDemo(); return; }
  // Probe history so the scrubber knows the retained span (404 = not built yet).
  try {
    const now = Date.now();
    const r = await api('/api/history?' + new URLSearchParams({ from: new Date(now - 60000).toISOString(), to: new Date(now).toISOString(), limit: '1' }));
    historyAvailable = true;
    setBounds(r);
  } catch (err) {
    historyAvailable = err.status === 423; // locked history is still replayable once unlocked
  }
  updateTimelineAvailability();
  startLive();
}

async function initGlobe() {
  const { Globe, webglAvailable } = await import('./js/globe.js');
  if (!webglAvailable() || params.get('nogl') === '1') throw new Error('webgl');
  globe = new Globe($('#stage'), { reducedMotion: reduced, onPick, onHover, onGlobeClick: saveHome });
  globe.setLanes(model.lanes);
  globe.setHome(home);
  if (params.get('rotate') === '0') { globe.setAutoRotate(false); $('#btn-rotate').setAttribute('aria-pressed', 'false'); }
  if (reduced) { $('#btn-rotate').setAttribute('aria-pressed', 'false'); $('#btn-rotate').disabled = true; }
  const topo = await (await fetch('vendor/land-110m.json')).json();
  globe.loadLand(topo);
  if (home) globe.resetView();
}

async function main() {
  updateTimelineAvailability();
  legend.setMode('lookups');
  document.body.classList.toggle('demo', DEMO);
  // The Locking screen and the Lock button manage a real session; they make
  // no sense while showing synthetic data, locked or not. The demo-data
  // toggle itself is hidden while locked so "unlock" only ever happens
  // through the forms below, never by silently flipping that switch back.
  $('#tab-locking').hidden = DEMO;
  $('#btn-lock').hidden = DEMO;
  $('.demo-switch').hidden = LOCKED;
  if (LOCKED) $('#login').hidden = false;
  if (params.get('setup_pin') === '1') { try { history.replaceState(null, '', location.pathname + location.search.replace(/[?&]setup_pin=1/, '').replace(/^&/, '?') + location.hash); } catch { /* ignore */ } showView('locking'); }
  { const h = location.hash.slice(1); if (VIEWS.includes(h) && h !== 'hud') showView(h); }
  try {
    await initGlobe();
  } catch (err) {
    globe = null;
    $('#no-gl').hidden = false;
    for (const id of ['#tilebar', '#toolbar', '#timeline', '#rail-right']) $(id).hidden = true;
    const b = $('#details-banner');
    b.textContent = 'The globe needs WebGL, which is not available in this browser. Everything else works here.';
    b.hidden = false;
    if (location.hash !== '#hud' && !VIEWS.includes(location.hash.slice(1))) showView('details');
    if (DEBUG) console.warn('globe disabled:', err && err.message);
  }
  bootData();

  const loop = (t) => {
    requestAnimationFrame(loop);
    if (hudVisible && !document.hidden) frame(t, true);
  };
  requestAnimationFrame(loop);
  setInterval(() => { if (!hudVisible || document.hidden) frame(performance.now(), false); }, 400);
}

main();
