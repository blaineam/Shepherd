// HUD chrome: stat tiles, live feed, filters, inspector, legend and timeline.
// DOM only; all state it needs comes in through the model and callbacks.
// Everything from the network is placed with textContent.
import { $, el } from './dom.js';
import { fmtNum, fmtPct, fmtClock, fmtDateTime, fmtAgo } from './format.js';
import { placeName, deviceLabel } from './entry.js';
import { shadowNote } from './wander.js';
import { weightScale, weightFromScale, widthPx, legendText, fmtWeight, fmtBytes } from './weight.js';

const FEED_MAX = 60;

export function createTiles() {
  const t = { total: $('#t-total'), pct: $('#t-blockedpct'), cached: $('#t-cached'), errors: $('#t-errors'), devices: $('#t-devices') };
  return function setTiles(v) {
    t.total.textContent = fmtNum(v.total);
    t.pct.textContent = fmtPct(v.blockedPct);
    t.cached.textContent = fmtNum(v.cached);
    t.errors.textContent = fmtNum(v.errors);
    t.devices.textContent = fmtNum(v.devices);
  };
}

export function createFeed({ onSelect }) {
  const ul = $('#feed');
  const count = $('#feed-count');
  const pool = [];
  let shown = 0;

  function make() {
    const li = el('li', 'feed-row');
    li.tabIndex = 0;
    li.setAttribute('role', 'button');
    const f = { time: el('span', 'f-time mono'), dot: el('i', 'f-dot'), dev: el('span', 'f-dev mono'), name: el('span', 'f-name mono'), via: el('span', 'f-via'), shadow: el('span', 'f-shadow') };
    li.append(f.time, f.dot, f.name, f.dev, f.via, f.shadow);
    li._f = f;
    li.addEventListener('click', () => li._entry && onSelect(li._entry));
    li.addEventListener('keydown', (ev) => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); li._entry && onSelect(li._entry); } });
    return li;
  }

  function push(e) {
    const li = shown >= FEED_MAX ? ul.lastElementChild : (pool.pop() || make());
    const f = li._f;
    li._entry = e;
    li.className = 'feed-row a-' + e.action + (e.wandering ? ' wand' : '');
    const note = shadowNote(e);
    f.shadow.textContent = note;
    f.shadow.hidden = !note;
    f.time.textContent = fmtClock(e.t);
    f.name.textContent = e.name;
    f.dev.textContent = deviceLabel(e) + (e.wandering ? ' \u00b7 W' : '');
    const place = e.dests && e.dests[0];
    f.via.textContent = place ? place.country || '' : e.action === 'blocked' ? 'shield' : '';
    li.title = e.name + '  ' + deviceLabel(e) + (e.device ? ' (' + e.client + ')' : '') + (e.wandering ? '  [wandering: not filtered]' : '') + (shadowNote(e) ? '  ' + shadowNote(e) : '') + (e.reason ? '  ' + e.reason : '');
    ul.insertBefore(li, ul.firstChild);
    if (shown < FEED_MAX) shown++;
  }

  function clear() {
    while (ul.lastElementChild) { const li = ul.lastElementChild; li._entry = null; ul.removeChild(li); pool.push(li); }
    shown = 0;
  }

  return { push, clear, setCount: (n) => { count.textContent = n ? fmtNum(n) + ' seen' : ''; } };
}

export function createFilters({ model, onChange }) {
  const dev = $('#f-device');
  const search = $('#f-search');
  const chips = [...document.querySelectorAll('#f-actions .chip')];
  const wb = $('#f-wander'), sb = $('#f-shadow');
  for (const [b, k] of [[wb, 'wandering'], [sb, 'shadow']]) {
    b.addEventListener('click', () => { const on = b.getAttribute('aria-pressed') !== 'true'; b.setAttribute('aria-pressed', on ? 'true' : 'false'); model.setFilters({ [k]: on }); onChange(); });
  }
  const known = new Map();
  let timer = 0;

  dev.addEventListener('change', () => { model.setFilters({ device: dev.value }); onChange(); });
  search.addEventListener('input', () => {
    clearTimeout(timer);
    timer = setTimeout(() => { model.setFilters({ q: search.value.trim() }); onChange(); }, 120);
  });
  for (const c of chips) {
    c.addEventListener('click', () => {
      const a = c.dataset.action;
      const set = model.filters.actions;
      if (set.has(a)) set.delete(a); else set.add(a);
      c.setAttribute('aria-pressed', set.has(a) ? 'true' : 'false');
      onChange();
    });
  }

  return {
    noteClient(ip, name) {
      const label = name && name !== ip ? name + '  ' + ip : ip;
      const have = known.get(ip);
      if (have) { if (have.textContent !== label && label !== ip) have.textContent = label; return; }
      if (known.size > 200) return;
      const opts = [...dev.options].slice(1);
      const o = el('option', '', label);
      o.value = ip;
      known.set(ip, o);
      const after = opts.find((x) => x.value > ip);
      dev.insertBefore(o, after || null);
    },
    reset() {
      known.clear();
      dev.replaceChildren(Object.assign(el('option', '', 'All devices'), { value: '' }));
      dev.value = '';
      search.value = '';
      model.setFilters({ device: '', q: '', wandering: false, shadow: false });
      wb.setAttribute('aria-pressed', 'false'); sb.setAttribute('aria-pressed', 'false');
      model.filters.actions = new Set(['allowed', 'cached', 'blocked', 'error']);
      chips.forEach((c) => c.setAttribute('aria-pressed', 'true'));
    },
  };
}

export function createLegend() {
  const thick = $('#thick');
  const text = $('#legend-text');
  const lanes = $('#lane-count');
  let lastMode = '';
  return {
    setMode(mode) {
      if (mode === lastMode) return;
      lastMode = mode;
      text.textContent = legendText(mode);
      thick.replaceChildren();
      for (const s of [0.12, 0.45, 0.78, 1]) {
        const row = el('div', 'thick-row');
        const line = el('i', 'thick-line');
        line.style.height = widthPx(s).toFixed(1) + 'px';
        row.append(line, el('span', 'mono small muted', (s === 1 ? '' : '') + fmtWeight(weightFromScale(s, mode), mode) + (s === 1 ? '+' : '')));
        thick.append(row);
      }
    },
    setLanes(n) { lanes.textContent = n ? n + ' lanes' : ''; },
  };
}

// The inspector panel: shows a lane or a single event, and exposes the
// block/allow controls with an undo.
export function createInspector({ api, notify, onRule, names = null }) {
  const R = {
    empty: $('#insp-empty'), root: $('#insp'), close: $('#insp-close'), action: $('#i-action'), place: $('#i-place'),
    device: $('#i-device'), domain: $('#i-domain'), loc: $('#i-loc'), countK: $('#i-count-k'), count: $('#i-count'), last: $('#i-last'),
    domains: $('#i-domains'), block: $('#i-block'), allow: $('#i-allow'), fb: $('#i-fb'), fbText: $('#i-fb-text'), undo: $('#i-undo'),
    panel: $('#inspector'),
    modeK: $('#i-mode-k'), mode: $('#i-mode'), shadowK: $('#i-shadow-k'), shadow: $('#i-shadow'),
    reasonK: $('#i-reason-k'), reason: $('#i-reason'),
  };
  let sel = null; // {lane, entry, domain}
  let lastRule = null;
  let onClose = () => {};

  function paint(model, now) {
    if (!sel) return;
    const lane = sel.lane, e = sel.entry;
    const action = lane ? lane.action : e.action;
    R.action.className = 'act ' + action;
    R.action.textContent = action;
    const dest = lane ? lane.dest : e && e.dests && e.dests[0];
    R.place.textContent = dest ? placeName(dest) : action === 'blocked' ? 'Blocked at home' : 'No destination';
    const cl = lane ? lane.client : e.client;
    const nm = (e && e.device) || (names ? names.label(cl) : cl);
    R.device.textContent = nm && nm !== cl ? nm + '  ' + cl : cl;
    R.domain.textContent = sel.domain;
    const wandering = e ? !!e.wandering : !!(names && names.isWandering(cl));
    R.modeK.hidden = R.mode.hidden = !wandering;
    const note = e && e.shadow && sel.domain === e.name ? shadowNote(e) : '';
    R.shadowK.hidden = R.shadow.hidden = !note;
    R.shadow.textContent = note;
    // Names what blocked it: a catalog/custom list id, "custom rule",
    // "allowlist", a geo block or a policy name (dnsengine.Entry.Reason).
    // Only meaningful for one specific blocked query, not an aggregated lane.
    const reason = action === 'blocked' && e && e.reason ? e.reason : '';
    R.reasonK.hidden = R.reason.hidden = !reason;
    R.reason.textContent = reason;
    R.loc.textContent = dest ? `${dest.lat.toFixed(2)}, ${dest.lon.toFixed(2)}` + (dest.ip ? '  ' + dest.ip : '') : 'Not geolocated';
    if (lane) {
      const bytes = model.mode === 'bytes';
      R.countK.textContent = bytes ? 'Bytes' : 'Lookups';
      R.count.textContent = bytes ? fmtBytes(lane.bytes) + ' in ' + fmtNum(lane.count) : fmtNum(lane.count);
      R.last.textContent = fmtAgo(Math.max(0, now - lane.last));
    } else {
      R.countK.textContent = 'Lookups';
      R.count.textContent = '1';
      R.last.textContent = fmtClock(e.t);
    }
    R.domains.replaceChildren();
    if (lane && lane.domains.size > 1) {
      R.domains.hidden = false;
      for (const d of model.lanes.topDomains(lane, 5)) {
        const b = el('button', 'dchip mono' + (d.name === sel.domain ? ' on' : ''), d.name + '  ' + d.n);
        b.type = 'button';
        b.addEventListener('click', () => { sel.domain = d.name; paint(model, now); });
        R.domains.append(b);
      }
    } else R.domains.hidden = true;
  }

  async function doRule(kind) {
    if (!sel || !sel.domain) return;
    const domain = sel.domain;
    try {
      await api('/api/rules', { method: 'POST', body: JSON.stringify({ kind, domain }) });
      lastRule = { kind, domain };
      R.fbText.textContent = (kind === 'block' ? 'Blocked ' : 'Allowed ') + domain + '.';
      R.undo.hidden = false;
      R.fb.hidden = false;
      R.fb.classList.remove('bad');
      onRule(kind, domain);
    } catch (err) {
      lastRule = null;
      R.fbText.textContent = err.status === 404 ? 'Rules are not available on this server.' : 'Could not save: ' + err.message;
      R.undo.hidden = true;
      R.fb.hidden = false;
      R.fb.classList.add('bad');
    }
  }

  R.block.addEventListener('click', () => doRule('block'));
  R.allow.addEventListener('click', () => doRule('allow'));
  R.undo.addEventListener('click', async () => {
    if (!lastRule) return;
    const { kind, domain } = lastRule;
    try {
      await api('/api/rules?' + new URLSearchParams({ kind, domain }), { method: 'DELETE' });
      R.fbText.textContent = 'Undone: ' + (kind === 'block' ? 'block' : 'allow') + ' rule for ' + domain + ' removed.';
      R.undo.hidden = true;
      lastRule = null;
      onRule(null, domain);
    } catch (err) { notify('Undo failed: ' + err.message); }
  });
  R.close.addEventListener('click', () => { clear(); onClose(); });

  function clear() {
    sel = null;
    R.root.hidden = true;
    R.close.hidden = true;
    R.empty.hidden = false;
    R.panel.classList.remove('open');
  }

  return {
    set onClose(fn) { onClose = fn; },
    select(next, model, now) {
      sel = next;
      R.empty.hidden = true;
      R.root.hidden = false;
      R.close.hidden = false;
      R.fb.hidden = true;
      lastRule = null;
      R.panel.classList.add('open');
      paint(model, now);
    },
    refresh(model, now) {
      if (!sel) return;
      if (sel.lane && model.lanes.byKey.get(sel.lane.key) !== sel.lane) {
        // The lane decayed away; keep showing its last state.
        sel.lane = null;
        sel.entry = sel.entry || { client: '', action: 'allowed', name: sel.domain, t: now, dests: null };
      }
      paint(model, now);
    },
    clear,
    get selection() { return sel; },
  };
}

// Timeline: LIVE button, play/pause, speed, scrubber and time label. It only
// reports intent through callbacks; app.js owns the clock and sources.
export function createTimeline({ onLive, onSeek, onPlayPause, onSpeed }) {
  const R = {
    live: $('#tl-live'), play: $('#tl-play'), speeds: [...document.querySelectorAll('#tl-speeds button')], range: $('#tl-range'),
    start: $('#tl-start'), end: $('#tl-end'), time: $('#tl-time'),
  };
  let oldest = Date.now() - 24 * 3600 * 1000;
  let newest = Date.now();
  let dragging = false;

  const valueToTime = (v) => oldest + ((newest - oldest) * v) / 1000;
  R.live.addEventListener('click', onLive);
  R.play.addEventListener('click', onPlayPause);
  for (const b of R.speeds) b.addEventListener('click', () => onSpeed(Number(b.dataset.speed)));
  R.range.addEventListener('pointerdown', () => { dragging = true; });
  R.range.addEventListener('input', () => { dragging = true; R.time.textContent = 'REPLAY ' + fmtDateTime(valueToTime(Number(R.range.value))); });
  R.range.addEventListener('change', () => { dragging = false; onSeek(valueToTime(Number(R.range.value))); });
  R.range.addEventListener('pointerup', () => { dragging = false; });

  return {
    setBounds(o, n) {
      oldest = o; newest = n;
      R.start.textContent = n - o >= 3600 * 1000 * 36 ? fmtDateTime(o) : '-' + Math.max(1, Math.round((n - o) / 3600000)) + 'h';
    },
    setState({ live, playing, speed, time, loading }) {
      R.live.classList.toggle('on', live);
      R.live.setAttribute('aria-pressed', live ? 'true' : 'false');
      R.play.textContent = playing ? 'Pause' : 'Play';
      R.play.setAttribute('aria-label', playing ? 'Pause' : 'Play');
      R.play.disabled = live;
      for (const b of R.speeds) b.setAttribute('aria-pressed', Number(b.dataset.speed) === speed ? 'true' : 'false');
      for (const b of R.speeds) b.disabled = live;
      if (dragging) return;
      if (live) {
        R.range.value = '1000';
        R.time.textContent = 'LIVE ' + fmtClock(time);
      } else {
        const span = Math.max(1, newest - oldest);
        R.range.value = String(Math.round(Math.min(1, Math.max(0, (time - oldest) / span)) * 1000));
        R.time.textContent = 'REPLAY ' + fmtDateTime(time) + ' ' + speed + 'x' + (loading ? ' (loading)' : '');
      }
    },
  };
}
