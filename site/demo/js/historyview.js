// The History screen: trace what a device did, after the fact. Time range,
// device, action and domain filters, paging backwards in time, a jump to the
// HUD replay, and the locked state for encrypted history.
import { el } from './dom.js';
import { icon, button, segmented, emptyState, unavailableCard, debounce, relTime } from './ui.js';
import { RANGES, rangeFor, buildQuery, normalizeResponse, mergeOlder, retainedSpan, fmtSpan, placeOf, toLocalInput } from './history.js';
import { unavailable } from './mgmt.js';
import { fmtClock } from './format.js';
import { shadowNote } from './wander.js';
import { isIP } from './upstreams.js';

const PAGE = 100;
const ACTIONS = ['all', 'allowed', 'cached', 'blocked', 'error'];

export function createHistory({ root, mgmt, notify, onReplay, demo = null, api = null }) {
  let onlyShadow = false;
  const st = { range: '24h', custom: { from: '', to: '' }, device: '', deviceLabel: '', action: 'all', q: '' };
  let entries = [];
  let meta = { source: '', span: null, skipped: 0 };
  let phase = 'idle'; // idle | loading | locked | error | unavailable | ready
  let error = null;
  let hasMore = false;
  let cursorTo = 0;
  let loadingMore = false;
  let settings = null;
  let devices = [];
  let gen = 0;
  let started = false;

  root.replaceChildren();
  const head = el('div', 'pg-head');
  const title = el('h2', 'pg-title');
  title.append(el('span', '', 'History'));
  const metaEl = el('div', 'hist-meta');
  head.append(title, metaEl);

  const controls = el('section', 'hist-controls panel-lite');
  const notice = el('div', 'hist-notice');
  const lockCard = el('div', 'lock-card');
  lockCard.hidden = true;
  const results = el('section', 'hist-results panel-lite');
  root.append(head, controls, notice, lockCard, results);

  // ------------------------------------------------------------- controls
  const rangeSeg = segmented(RANGES.map((r) => ({ id: r.id, label: r.label })), st.range, (id) => { st.range = id; customRow.hidden = id !== 'custom'; run(); }, 'Time range');
  const customRow = el('div', 'custom-range');
  customRow.hidden = true;
  const from = el('input');
  from.type = 'datetime-local';
  from.setAttribute('aria-label', 'From');
  const to = el('input');
  to.type = 'datetime-local';
  to.setAttribute('aria-label', 'To');
  const now0 = Date.now();
  from.value = toLocalInput(now0 - 86400000);
  to.value = toLocalInput(now0);
  customRow.append(el('span', 'k', 'From'), from, el('span', 'k', 'To'), to);
  const onCustom = () => { st.custom = { from: from.value, to: to.value }; run(); };
  from.addEventListener('change', onCustom);
  to.addEventListener('change', onCustom);

  const dev = el('input');
  dev.placeholder = 'Any device';
  dev.setAttribute('aria-label', 'Device');
  dev.setAttribute('list', 'hist-devices');
  dev.autocomplete = 'off';
  const dl = el('datalist');
  dl.id = 'hist-devices';
  const clearDev = el('button', 'ibtn clear-dev');
  clearDev.type = 'button';
  clearDev.setAttribute('aria-label', 'Any device');
  clearDev.append(icon('x', 13));
  clearDev.hidden = true;
  clearDev.addEventListener('click', () => { setDevice('', ''); run(); });
  const devWrap = el('div', 'dev-pick');
  devWrap.append(dev, dl, clearDev);
  const applyDevice = () => {
    const v = dev.value.trim();
    if (!v) { setDevice('', ''); return; }
    const d = devices.find((x) => x.name.toLowerCase() === v.toLowerCase());
    if (d) setDevice((d.ips || [])[0] || '', d.name);
    else if (isIP(v)) setDevice(v, v);
    else notify('Choose a device from the list, or type an IP address.');
  };
  dev.addEventListener('change', () => { applyDevice(); run(); });
  function setDevice(ip, label) { st.device = ip; st.deviceLabel = label; dev.value = label; clearDev.hidden = !ip; }

  const actSeg = segmented(ACTIONS.map((a) => ({ id: a, label: a })), st.action, (id) => { st.action = id; run(); }, 'Action');
  actSeg.root.classList.add('act-seg');
  const q = el('input');
  q.type = 'search';
  q.placeholder = 'Domain contains…';
  q.setAttribute('aria-label', 'Domain search');
  q.autocomplete = 'off';
  q.spellcheck = false;
  const runSoon = debounce(() => { st.q = q.value.trim(); run(); }, 250);
  q.addEventListener('input', runSoon);

  const rowA = el('div', 'hc-row');
  rowA.append(rangeSeg.root, customRow);
  const rowB = el('div', 'hc-row');
  const f1 = el('label', 'hc-f'); f1.append(el('span', 'k', 'Device'), devWrap);
  const f2 = el('div', 'hc-f'); f2.append(el('span', 'k', 'Result'), actSeg.root);
  const f3 = el('label', 'hc-f grow'); f3.append(el('span', 'k', 'Domain'), q);
  const shadowBox = el('label', 'hc-f chk');
  const sc = el('input');
  sc.type = 'checkbox';
  sc.addEventListener('change', () => { onlyShadow = sc.checked; paintResults(); });
  shadowBox.append(el('span', 'k', 'Shadow'), el('span', 'chk-row'));
  shadowBox.lastChild.append(sc, document.createTextNode(' Only would-have-blocked'));
  rowB.append(f1, f2, f3, shadowBox);
  controls.append(rowA, rowB);

  // ------------------------------------------------------------- paint
  function paintMeta() {
    metaEl.replaceChildren();
    if (!meta.source) return;
    const b = el('span', 'badge ' + (meta.source === 'encrypted' ? 'enc' : 'warn'), meta.source === 'encrypted' ? 'Encrypted on disk' : 'Memory only');
    metaEl.append(b);
    if (meta.span) metaEl.append(el('span', 'muted small', 'Kept ' + fmtSpan(meta.span.ms) + ', since ' + new Date(meta.span.oldest).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })));
    if (meta.skipped) metaEl.append(el('span', 'badge warn', meta.skipped + ' damaged record' + (meta.skipped === 1 ? '' : 's') + ' skipped'));
    if (demo) metaEl.append(button(phase === 'locked' ? 'Demo: unlocked state' : 'Demo: lock history', 'ghost mini-b', async () => { await demo.setLocked(phase !== 'locked'); run(); }, 'lock'));
  }

  function paintNotice() {
    notice.replaceChildren();
    const mem = meta.source === 'memory' || (settings && settings.history && settings.history.mode === 'memory');
    if (mem && phase !== 'locked' && phase !== 'unavailable') {
      const n = el('div', 'note-card');
      n.append(icon('shield', 16), el('p', '', ''));
      const p = n.lastChild;
      p.append(document.createTextNode('History is kept in memory only, so it is lost when Shepherd restarts and covers a short window. To keep it for days or weeks, turn on encrypted history: set '), el('code', '', 'mode = "encrypted"'), document.createTextNode(' under '), el('code', '', '[history]'), document.createTextNode(' in shepherd.toml and restart. See docs/HISTORY.md.'));
      notice.append(n);
    }
  }

  function paintLock() {
    lockCard.hidden = phase !== 'locked';
    if (phase !== 'locked') return;
    lockCard.replaceChildren();
    const first = !!(settings && settings.history && settings.history.initialized === false);
    const c = el('form', 'lock-in');
    const ic = el('span', 'lock-ico');
    ic.append(icon('lock', 28));
    c.append(ic, el('h3', '', first ? 'Create a history passphrase' : 'History is locked'));
    c.append(el('p', 'muted', first
      ? 'This is the first unlock, so the passphrase you choose now becomes the key that encrypts your history. Shepherd cannot recover it, so keep it somewhere safe.'
      : 'Your history is encrypted. Enter the passphrase to read it. DNS keeps working while it is locked.'));
    const pw = el('input');
    pw.type = 'password';
    pw.placeholder = first ? 'Choose a passphrase (8+ characters)' : 'Passphrase';
    pw.autocomplete = first ? 'new-password' : 'current-password';
    pw.setAttribute('aria-label', 'Passphrase');
    pw.required = true;
    c.append(pw);
    let pw2 = null;
    if (first) {
      pw2 = el('input');
      pw2.type = 'password';
      pw2.placeholder = 'Repeat the passphrase';
      pw2.autocomplete = 'new-password';
      pw2.setAttribute('aria-label', 'Repeat passphrase');
      pw2.required = true;
      c.append(pw2);
    }
    const err = el('p', 'err small');
    err.setAttribute('role', 'alert');
    const go = button(first ? 'Create and unlock' : 'Unlock', 'primary');
    go.type = 'submit';
    c.append(go, err);
    c.addEventListener('submit', async (e) => {
      e.preventDefault();
      err.textContent = '';
      if (first && pw.value.length < 8) { err.textContent = 'Use at least 8 characters.'; return; }
      if (first && pw.value !== pw2.value) { err.textContent = 'The two passphrases do not match.'; return; }
      go.disabled = true;
      try {
        await mgmt.unlock(pw.value);
        pw.value = '';
        settings = null;
        notify(first ? 'Passphrase created. History unlocked.' : 'History unlocked.');
        await loadSettings();
        run();
      } catch (ex) {
        err.textContent = ex.status === 401 ? 'That passphrase is not right.' : ex.message;
        go.disabled = false;
        pw.select();
      }
    });
    lockCard.append(c);
    pw.focus();
  }

  // allowDomain gives a blocked History row the same one-click override the
  // HUD inspector's "Allow domain" button already offers live (createInspector's
  // doRule() in hud.js) — POST /api/rules, the same flat network-scope rule
  // endpoint, kept here rather than a new mechanism. Narrower and safer than
  // disabling whatever list blocked it: it only overrides this one domain.
  async function allowDomain(e, btn) {
    if (!api) return;
    btn.disabled = true;
    btn.textContent = 'Allowing…';
    try {
      await api('/api/rules', { method: 'POST', body: JSON.stringify({ kind: 'allow', domain: e.name }) });
      btn.textContent = 'Allowed';
      notify('Allowed ' + e.name + '. New queries for it will not be blocked.');
    } catch (err) {
      btn.disabled = false;
      btn.textContent = 'Allow';
      notify(err.status === 404 ? 'Rules are not available on this server.' : 'Could not allow ' + e.name + ': ' + err.message);
    }
  }

  function rowEl(e) {
    const tr = el('tr', 'a-' + e.action);
    const t = new Date(e.t);
    const tc = el('td', 'h-time mono');
    tc.append(el('span', '', t.toLocaleDateString([], { month: 'short', day: 'numeric' })), document.createTextNode(' '), el('b', '', fmtClock(e.t)));
    tc.title = t.toLocaleString() + ' (' + relTime(e.t) + ')';
    const dc = el('td', 'h-dev');
    const name = e.device || e.client;
    if (name) {
      const b = el('button', 'linkcell', name);
      b.type = 'button';
      b.title = 'Only show ' + name;
      b.addEventListener('click', () => { setDevice(e.client, name); run(); });
      dc.append(b);
      if (e.device && e.client) dc.append(el('span', 'muted small mono', ' ' + e.client));
    }
    const dom = el('td', 'h-dom mono', e.name);
    dom.title = e.name;
    const ty = el('td', 'muted h-type', e.type || '');
    const rc = el('td', 'h-res');
    const pill = el('span', 'act ' + e.action, e.action);
    if (e.reason) pill.title = e.reason;
    rc.append(pill);
    if (e.wandering) rc.append(' ', el('span', 'wbadge', 'wandering'));
    if (e.shadow) rc.append(el('div', 'muted small shadow-note', shadowNote(e)));
    else if (e.reason && e.action !== 'error' && e.reason !== 'wandering') rc.append(' ', el('span', 'muted small h-reason', e.reason));
    const pc = el('td', 'muted h-place', placeOf(e));
    const ac = el('td', 'h-act');
    const rb = el('button', 'mini', 'Replay');
    rb.type = 'button';
    rb.title = 'Open the HUD replay at ' + t.toLocaleString();
    rb.setAttribute('aria-label', 'Replay on the HUD at ' + t.toLocaleString() + ': ' + e.name);
    rb.addEventListener('click', () => onReplay(e.t));
    ac.append(rb);
    if (e.action === 'blocked' && e.name && api) {
      const ab = el('button', 'mini', 'Allow');
      ab.type = 'button';
      ab.title = 'Add an allow rule for ' + e.name + ', overriding whatever blocked it';
      ab.setAttribute('aria-label', 'Allow ' + e.name);
      ab.addEventListener('click', () => allowDomain(e, ab));
      ac.append(ab);
    }
    tr.append(tc, dc, dom, ty, rc, pc, ac);
    return tr;
  }

  function paintResults() {
    results.replaceChildren();
    if (phase === 'unavailable') { results.append(unavailableCard('History')); return; }
    if (phase === 'locked') return;
    if (phase === 'error') { results.append(emptyState('Could not load history', error ? error.message : '', button('Try again', 'ghost', run))); return; }
    if (phase === 'loading' && !entries.length) { results.append(el('p', 'muted pad', 'Loading…')); return; }
    const shown = onlyShadow ? entries.filter((e) => e.shadow) : entries;
    if (entries.length && !shown.length) { results.append(emptyState('No would-have-blocked queries here', 'None of the loaded queries carry a shadow result. Load older entries or widen the range.', hasMore ? button('Load older', 'ghost', loadOlder) : null)); return; }
    if (!entries.length) { results.append(emptyState('Nothing recorded for these filters', 'Widen the time range, or clear the device, result or domain filter.')); return; }
    const sum = el('div', 'res-sum');
    sum.append(el('span', 'muted small', 'Showing ' + shown.length.toLocaleString() + (onlyShadow ? ' shadow' : '') + ' queries, newest first, back to ' + new Date(entries[entries.length - 1].t).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' })));
    results.append(sum);
    const wrap = el('div', 'h-scroll');
    const tb = el('table', 'h-table');
    const th = el('thead');
    const hr = el('tr');
    for (const h of ['Time', 'Device', 'Domain', 'Type', 'Result', 'Place', '']) hr.append(el('th', '', h));
    th.append(hr);
    const body = el('tbody');
    for (const e of shown) body.append(rowEl(e));
    tb.append(th, body);
    wrap.append(tb);
    results.append(wrap);
    const foot = el('div', 'res-foot');
    if (hasMore) {
      const more = button(loadingMore ? 'Loading…' : 'Load older', 'ghost', loadOlder, 'down');
      more.disabled = loadingMore;
      foot.append(more);
    } else foot.append(el('span', 'muted small', 'That is everything in this range.'));
    results.append(foot);
  }

  function paintAll() { results.hidden = phase === 'locked'; paintMeta(); paintNotice(); paintLock(); paintResults(); controls.classList.toggle('dim', phase === 'locked'); }

  // ------------------------------------------------------------- loading
  const params = (toMs) => {
    const r = rangeFor(st.range, Date.now(), st.custom);
    return buildQuery({ from: r.from, to: toMs ?? r.to, client: st.device, q: st.q, action: st.action, limit: PAGE });
  };

  async function run() {
    const g = ++gen;
    phase = 'loading';
    entries = []; hasMore = false;
    paintAll();
    try {
      const r = await mgmt.history(params());
      if (g !== gen) return;
      const n = normalizeResponse(r);
      meta = { source: n.source, span: retainedSpan(n), skipped: n.skipped };
      entries = n.entries;
      hasMore = entries.length >= PAGE;
      cursorTo = hasMore ? entries[entries.length - 1].t : 0;
      phase = 'ready';
    } catch (e) {
      if (g !== gen) return;
      if (e.status === 423) { phase = 'locked'; meta = { source: 'encrypted', span: null, skipped: 0 }; }
      else if (unavailable(e)) phase = 'unavailable';
      else { phase = 'error'; error = e; }
    }
    paintAll();
  }

  async function loadOlder() {
    if (loadingMore || !hasMore) return;
    loadingMore = true;
    paintResults();
    const g = gen;
    try {
      let to = cursorTo;
      for (let tries = 0; tries < 4; tries++) {
        const n = normalizeResponse(await mgmt.history(params(to)));
        if (g !== gen) return;
        const m = mergeOlder(entries, n.entries);
        entries = m.entries;
        hasMore = n.entries.length >= PAGE;
        if (m.added > 0 || !n.entries.length) { cursorTo = entries[entries.length - 1].t; break; }
        to -= 1; // a whole page shared one millisecond: step past it
        cursorTo = to;
      }
      if (!hasMore) cursorTo = 0;
    } catch (e) {
      if (e.status === 423) { phase = 'locked'; } else notify('Could not load older entries: ' + e.message);
    }
    loadingMore = false;
    paintAll();
  }

  async function loadSettings() {
    if (settings) return;
    try { settings = await mgmt.settings(); } catch { settings = {}; }
  }

  async function loadDevices() {
    try {
      const r = await mgmt.devices({ sort: 'name', offset: 0, limit: 500 });
      devices = Array.isArray(r && r.devices) ? r.devices : [];
      dl.replaceChildren();
      for (const d of devices) { const o = el('option'); o.value = d.name; dl.append(o); }
    } catch { /* the device filter still accepts an IP */ }
  }

  return {
    async show() {
      if (!started) { started = true; paintAll(); loadDevices(); }
      await loadSettings();
      run();
    },
    // Opens the screen filtered to one device (from the device drawer).
    forDevice({ ip, name }) {
      if (!started) { started = true; paintAll(); loadDevices(); }
      setDevice(ip, name || ip);
    },
    async showFor(d) { this.forDevice(d); await loadSettings(); run(); },
  };
}
