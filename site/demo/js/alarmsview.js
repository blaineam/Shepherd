// The Alarms screen: a filterable list with severity/state, single and bulk
// acknowledge/resolve/mute/delete, and a Rules sub-view for mute rules. Mirrors
// the structure of the Devices and Upstreams screens (panel-lite cards, a
// bulkbar for the selection, openMenu for per-action choices). Alarm text
// (title, body, evidence) comes from the server, so it is placed with
// textContent throughout.
import { el } from './dom.js?v=65858b99';
import { icon, iconButton, button, segmented, emptyState, unavailableCard, confirmDialog, openMenu, relTime } from './ui.js?v=4d208003';
import { unavailable } from './mgmt.js?v=288370f7';
import { Selection } from './selection.js?v=209c4209';
import { pushSupport, permissionLine, urlBase64ToUint8Array, subscribeBody, defaultDeviceName, deviceLine, isThisBrowser, ntfyStatusLine, ntfyFields, ntfySaveBody, suggestTopic, NTFY_STEPS } from './push.js?v=3cd5ae11';
import {
  SEVERITIES, STATES, severityLabel, severityBadgeClass, stateLabel,
  MUTE_PRESETS, MUTE_SCOPES, bulkSummary, ruleMatchSummary, feedLine, matchLine,
  hoursOf, deliveryLine, digestFromForm,
} from './alarms.js?v=a5e2e2d9';

const PAGE_SIZE = 50;

function splitList(s) {
  return String(s || '').split(',').map((x) => x.trim()).filter(Boolean);
}

function labelWrap(label, input) {
  const l = el('label', 'fl');
  l.append(el('span', '', label), input);
  return l;
}

export function createAlarms({ root, mgmt, notify, toaster }) {
  let view = 'alarms'; // or 'rules'
  let filters = { severity: '', state: '', text: '', archived: false };
  let items = [];
  let total = 0;
  let loadError = null;
  let rules = [];
  let rulesError = null;
  let started = false;
  let timer = 0;
  const sel = new Selection();

  // ------------------------------------------------------------- skeleton
  root.replaceChildren();
  const head = el('div', 'pg-head');
  const title = el('h2', 'pg-title');
  title.append(el('span', '', 'Alarms'), el('span', 'pg-count mono', ''));
  const countEl = title.lastChild;

  const viewSeg = segmented(
    [{ id: 'alarms', label: 'Alarms' }, { id: 'rules', label: 'Rules' }, { id: 'push', label: 'Notifications' }, { id: 'threats', label: 'Threat feeds' }], view,
    (id) => {
      view = id;
      paintAll();
      if (id === 'rules') loadRules();
      else if (id === 'push') { loadPush(); loadPrefs(); }
      else if (id === 'threats') loadThreats();
      else load(true);
    }, 'Alarms view',
  );

  const sevSel = el('select');
  sevSel.setAttribute('aria-label', 'Minimum severity');
  sevSel.append(el('option', '', 'Any severity'));
  for (const s of SEVERITIES) { const o = el('option', '', severityLabel(s)); o.value = s; sevSel.append(o); }
  sevSel.addEventListener('change', () => { filters.severity = sevSel.value; resetAndLoad(); });

  const stateSel = el('select');
  stateSel.setAttribute('aria-label', 'State');
  stateSel.append(el('option', '', 'Any state'));
  for (const s of STATES) { const o = el('option', '', stateLabel(s)); o.value = s; stateSel.append(o); }
  stateSel.addEventListener('change', () => { filters.state = stateSel.value; resetAndLoad(); });

  const searchBox = el('div', 'sbox');
  searchBox.append(icon('search', 15, 'sbox-ico'));
  const input = el('input');
  input.type = 'search';
  input.placeholder = 'Search title, body, domain or device';
  input.setAttribute('aria-label', 'Search alarms');
  input.autocomplete = 'off';
  input.spellcheck = false;
  searchBox.append(input);
  let searchTimer = 0;
  input.addEventListener('input', () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => { filters.text = input.value.trim(); resetAndLoad(); }, 220);
  });

  // Archived alarms are dismissed from the default view (see docs/ALARMS.md);
  // this toggle is the only way to bring them back into the list.
  const archCb = el('input');
  archCb.type = 'checkbox';
  archCb.setAttribute('aria-label', 'Show archived alarms');
  archCb.addEventListener('change', () => { filters.archived = archCb.checked; resetAndLoad(); });
  const archToggle = el('label', 'al-archtoggle');
  archToggle.append(archCb, el('span', '', 'Show archived'));

  head.append(title, viewSeg.root, sevSel, stateSel, searchBox, archToggle);

  const main = el('div', 'al-main');
  const wrap = el('section', 'al-tablewrap panel-lite');
  const thead = el('div', 'al-row al-thead');
  thead.setAttribute('role', 'row');
  const allBox = el('input');
  allBox.type = 'checkbox';
  allBox.setAttribute('aria-label', 'Select all loaded alarms');
  allBox.addEventListener('change', () => {
    if (allBox.checked) sel.selectPage(items.map((a) => a.id));
    else sel.clear();
    paintRows();
    paintBulk();
  });
  const cSelH = el('div', 'c-sel');
  cSelH.append(allBox);
  thead.append(cSelH, el('div', 'al-sev', 'Severity'), el('div', 'al-title', 'Alarm'), el('div', 'al-dev', 'Device'), el('div', 'al-state', 'State'), el('div', 'al-seen', 'Last seen'), el('div', 'al-acts', ''));
  for (const c of thead.children) c.setAttribute('role', 'columnheader');

  const scroll = el('div', 'al-scroll');
  scroll.setAttribute('role', 'table');
  scroll.setAttribute('aria-label', 'Alarms');
  const rowsEl = el('div', 'al-rows');
  const emptyEl = el('div', 'al-empty');
  emptyEl.hidden = true;
  const loadMoreWrap = el('div', 'al-loadmore');
  const loadMoreBtn = button('Load more', 'ghost', () => loadMore());
  loadMoreWrap.append(loadMoreBtn);
  loadMoreWrap.hidden = true;
  scroll.append(rowsEl, emptyEl, loadMoreWrap);
  const bulk = el('div', 'bulkbar');
  bulk.hidden = true;
  bulk.setAttribute('role', 'toolbar');
  bulk.setAttribute('aria-label', 'Bulk actions');
  wrap.append(thead, scroll, bulk);

  const rulesWrap = el('section', 'al-rules-wrap panel-lite');
  rulesWrap.hidden = true;
  const pushWrap = el('section', 'al-rules-wrap panel-lite');
  pushWrap.hidden = true;
  const prefsWrap = el('section', 'al-rules-wrap panel-lite');
  prefsWrap.hidden = true;
  const threatsWrap = el('section', 'al-rules-wrap panel-lite');
  threatsWrap.hidden = true;
  main.append(wrap, rulesWrap, pushWrap, prefsWrap, threatsWrap);
  root.append(head, main);

  // ------------------------------------------------------------- loading
  function serverFilter() {
    const f = {};
    if (filters.severity) f.min_severity = filters.severity;
    if (filters.state) f.states = [filters.state];
    if (filters.text) f.text = filters.text;
    if (filters.archived) f.include_archived = true;
    return f;
  }

  async function load(reset) {
    if (reset) items = [];
    try {
      const r = await mgmt.alarms({
        min_severity: filters.severity || undefined, states: filters.state || undefined, text: filters.text || undefined,
        include_archived: filters.archived ? '1' : undefined, offset: items.length, limit: PAGE_SIZE,
      });
      const got = Array.isArray(r.alarms) ? r.alarms : [];
      items = reset ? got : items.concat(got);
      total = Number.isFinite(r.total) ? r.total : items.length;
      loadError = null;
    } catch (e) {
      loadError = e;
      if (reset) items = [];
    }
    sel.setTotal(total);
    sel.forget(sel.allMatches ? [] : [...sel.ids].filter((id) => !items.some((a) => a.id === id)));
    paintRows();
    paintBulk();
    countEl.textContent = total ? String(total) : '';
  }

  function resetAndLoad() { sel.clear(); load(true); }
  async function loadMore() { await load(false); }

  async function loadRules() {
    try {
      const r = await mgmt.alarmRules();
      rules = Array.isArray(r.rules) ? r.rules : [];
      rulesError = null;
    } catch (e) {
      rulesError = e;
    }
    paintRules();
  }

  // ------------------------------------------------------------- rows
  function rowNode(a) {
    const row = el('div', 'al-row' + (a.state === 'muted' ? ' muted' : '') + (a.archived ? ' archived' : '') + (sel.has(a.id) ? ' sel' : ''));
    row.setAttribute('role', 'row');

    const cSel = el('div', 'c-sel');
    const cb = el('input');
    cb.type = 'checkbox';
    cb.checked = sel.has(a.id);
    cb.setAttribute('aria-label', 'Select ' + a.title);
    cb.addEventListener('change', () => { sel.set(a.id, cb.checked); row.classList.toggle('sel', cb.checked); paintBulk(); });
    cSel.append(cb);

    const sevCell = el('div', 'al-sev');
    sevCell.append(el('span', severityBadgeClass(a.severity), severityLabel(a.severity)));

    const titleCell = el('div', 'al-title');
    titleCell.append(el('span', 'nm', a.title));
    if (a.body) titleCell.append(el('span', 'sub', a.body));
    else if (a.count > 1) titleCell.append(el('span', 'sub', a.count + ' occurrences'));

    const devCell = el('div', 'al-dev mono', a.device_id || '—');
    const stateCell = el('div', 'al-state', stateLabel(a.state));
    const seenCell = el('div', 'al-seen', relTime(a.last_seen));

    const actsCell = el('div', 'al-acts');
    if (a.state === 'new') actsCell.append(iconButton('check', 'Acknowledge', () => act(() => mgmt.patchAlarm(a.id, 'acknowledged'), 'Acknowledged')));
    if (a.state !== 'resolved') actsCell.append(iconButton('shield', 'Resolve', () => act(() => mgmt.patchAlarm(a.id, 'resolved'), 'Resolved')));
    if (a.state !== 'resolved') {
      const muteBtn = iconButton('tag', 'Mute…', (e) => muteMenu(e.currentTarget, a.id));
      muteBtn.setAttribute('aria-haspopup', 'true');
      actsCell.append(muteBtn);
    }
    actsCell.append(a.archived
      ? iconButton('refresh', 'Unarchive', () => archiveOne(a.id, false))
      : iconButton('archive', 'Archive', () => archiveOne(a.id, true)));
    actsCell.append(iconButton('trash', 'Delete', () => deleteOne(a.id), 'danger-i'));

    row.append(cSel, sevCell, titleCell, devCell, stateCell, seenCell, actsCell);
    for (const c of row.children) c.setAttribute('role', 'cell');
    return row;
  }

  function paintRows() {
    rowsEl.replaceChildren();
    if (!items.length) {
      emptyEl.hidden = false;
      loadMoreWrap.hidden = true;
      emptyEl.replaceChildren(
        loadError
          ? (unavailable(loadError) ? unavailableCard('Alarms') : emptyState('Could not load alarms', loadError.message, button('Try again', 'ghost', () => load(true))))
          : emptyState('No alarms', 'Nothing matches these filters right now.'),
      );
      return;
    }
    emptyEl.hidden = true;
    for (const a of items) rowsEl.append(rowNode(a));
    loadMoreWrap.hidden = items.length >= total;
  }

  // ------------------------------------------------------------- bulk actions
  function selector() {
    return sel.allMatches ? { filter: serverFilter(), all: true } : { ids: [...sel.ids] };
  }

  function opVerb(op) {
    switch (op) {
      case 'acknowledge': return 'Acknowledged';
      case 'resolve': return 'Resolved';
      case 'delete': return 'Deleted';
      case 'mute': return 'Muted';
      case 'archive': return 'Archived';
      case 'unarchive': return 'Unarchived';
      default: return 'Updated';
    }
  }

  async function runBulk(op, extra = {}) {
    try {
      const res = await mgmt.alarmsBulk({ ...selector(), op, ...extra });
      const opts = res && res.handle ? { action: { label: 'Undo', run: async () => { await mgmt.undoAlarms(res.handle); await load(true); } } } : {};
      toaster.show(bulkSummary(opVerb(op), res), opts);
      sel.clear();
      await load(true);
    } catch (e) {
      notify('Could not update the selection: ' + e.message);
    }
  }

  function bulkMuteMenu(anchor) {
    openMenu(anchor, MUTE_SCOPES.map((scope) => ({
      label: scope.label,
      onSelect: () => runBulk('mute', { mute: { by: scope.id, duration: (scope.id === 'alarm' ? MUTE_PRESETS[0] : MUTE_PRESETS[1]).spec } }),
    })), { label: 'Mute' });
  }

  function muteMenu(anchor, id) {
    openMenu(anchor, MUTE_PRESETS.map((p) => ({ label: p.label, onSelect: () => act(() => mgmt.muteAlarm(id, p.spec), 'Muted') })), { label: 'Mute' });
  }

  function paintBulk() {
    const n = sel.count();
    bulk.hidden = n === 0;
    wrap.classList.toggle('has-bulk', n > 0);
    if (!n) { bulk.replaceChildren(); return; }
    bulk.replaceChildren();
    const label = el('span', 'bulk-n');
    label.append(el('strong', 'mono', String(n)), document.createTextNode(' selected'));
    const ackB = button('Acknowledge', 'bb', () => runBulk('acknowledge'), 'check');
    const resB = button('Resolve', 'bb', () => runBulk('resolve'), 'shield');
    const muteB = button('Mute', 'bb', (e) => bulkMuteMenu(e.currentTarget), 'tag');
    muteB.setAttribute('aria-haspopup', 'true');
    // Viewing archived alarms (the "Show archived" toggle) flips this to
    // Unarchive, since that is almost always what a selection there wants.
    const archB = filters.archived
      ? button('Unarchive', 'bb', () => runBulk('unarchive'), 'refresh')
      : button('Archive', 'bb', () => runBulk('archive'), 'archive');
    const delB = button('Delete', 'bb danger', async () => {
      const ok = await confirmDialog({ title: 'Delete ' + n + ' alarm' + (n === 1 ? '' : 's') + '?', body: 'This cannot be undone.', confirm: 'Delete', danger: true });
      if (ok) runBulk('delete');
    }, 'trash');
    const clear = iconButton('x', 'Clear selection', () => { sel.clear(); paintRows(); paintBulk(); }, 'bulk-x');
    bulk.append(label, ackB, resB, muteB, archB, delB, clear);
  }

  // ------------------------------------------------------------- single-row actions
  async function act(fn, verb) {
    try {
      await fn();
      notify(verb + ' 1 alarm');
      await load(true);
    } catch (e) {
      notify('Could not update the alarm: ' + e.message);
    }
  }

  async function deleteOne(id) {
    const ok = await confirmDialog({ title: 'Delete this alarm?', body: 'This cannot be undone.', confirm: 'Delete', danger: true });
    if (ok) await act(() => mgmt.deleteAlarm(id), 'Deleted');
  }

  // Archive reuses the bulk endpoint with a single-ID selector, the same way
  // every other batch op works, rather than a dedicated single-alarm route.
  async function archiveOne(id, archive) {
    await act(() => mgmt.alarmsBulk({ ids: [id], op: archive ? 'archive' : 'unarchive' }), archive ? 'Archived' : 'Unarchived');
  }

  // ------------------------------------------------------------- rules
  function ruleRow(r) {
    const row = el('div', 'al-rule');
    const main = el('div', 'al-rule-main');
    main.append(el('span', 'al-rule-name', r.name || '(unnamed rule)'));
    const summary = ruleMatchSummary(r.match) + (r.reason ? ' — ' + r.reason : '');
    main.append(el('span', 'al-rule-match', summary));
    row.append(main);
    row.append(el('span', 'muted small', r.expires_at ? 'until ' + new Date(r.expires_at).toLocaleString() : 'forever'));
    row.append(iconButton('trash', 'Remove rule', () => removeRule(r.id), 'danger-i'));
    return row;
  }

  function ruleForm() {
    const form = el('form', 'al-rule-form');
    const nameIn = el('input');
    nameIn.placeholder = 'e.g. Quiet the test camera';
    const typesIn = el('input');
    typesIn.placeholder = 'new-device, upstream-down';
    const devIn = el('input');
    devIn.placeholder = 'Device IDs, comma separated';
    const domIn = el('input');
    domIn.placeholder = 'Domains, comma separated';
    const presetSel = el('select');
    for (const p of MUTE_PRESETS) { const o = el('option', '', p.label); o.value = p.id; presetSel.append(o); }
    const reasonIn = el('input');
    reasonIn.placeholder = 'Reason (optional)';
    const row1 = el('div', 'row');
    row1.append(labelWrap('Name', nameIn), labelWrap('Types', typesIn));
    const row2 = el('div', 'row');
    row2.append(labelWrap('Devices', devIn), labelWrap('Domains', domIn));
    const row3 = el('div', 'row');
    row3.append(labelWrap('Duration', presetSel), labelWrap('Reason', reasonIn));
    const submit = button('Create rule', 'primary');
    submit.type = 'submit';
    const err = el('p', 'err small');
    form.append(row1, row2, row3, submit, err);
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      err.textContent = '';
      const match = { types: splitList(typesIn.value), device_ids: splitList(devIn.value), domains: splitList(domIn.value) };
      const preset = MUTE_PRESETS.find((p) => p.id === presetSel.value) || MUTE_PRESETS[0];
      try {
        await mgmt.createAlarmRule({ name: nameIn.value.trim(), match, duration: preset.spec, reason: reasonIn.value.trim() });
        notify('Mute rule created');
        nameIn.value = typesIn.value = devIn.value = domIn.value = reasonIn.value = '';
        await loadRules();
        await load(true);
      } catch (ex) {
        err.textContent = ex.message;
      }
    });
    return form;
  }

  async function removeRule(id) {
    const ok = await confirmDialog({ title: 'Remove this mute rule?', body: 'Alarms it muted return to the new state.', confirm: 'Remove', danger: true });
    if (!ok) return;
    try {
      await mgmt.deleteAlarmRule(id);
      notify('Mute rule removed');
      await loadRules();
      await load(true);
    } catch (e) {
      notify('Could not remove the rule: ' + e.message);
    }
  }

  function paintRules() {
    rulesWrap.replaceChildren();
    const h = el('div', 'card-h');
    h.append(el('h3', 'card-t', 'Mute rules'));
    rulesWrap.append(h);
    if (rulesError) {
      rulesWrap.append(unavailable(rulesError) ? unavailableCard('Mute rules') : emptyState('Could not load rules', rulesError.message, button('Try again', 'ghost', loadRules)));
      return;
    }
    rulesWrap.append(ruleForm());
    if (!rules.length) {
      rulesWrap.append(emptyState('No mute rules', 'Create one above, or mute alarms from the list.'));
      return;
    }
    const list = el('div', 'al-rules');
    for (const r of rules) list.append(ruleRow(r));
    rulesWrap.append(list);
  }

  // ------------------------------------------------------------- delivery
  // The alarm preferences' delivery part (docs/ALARMS.md "When"): which
  // severities go out at once and when the digest carries the rest. The
  // whole preferences object is read and written back with just these
  // fields changed, so nothing else is disturbed.
  let prefs = null;
  let prefsError = null;

  async function loadPrefs() {
    try {
      prefs = (await mgmt.alarmPrefs()).preferences;
      prefsError = null;
    } catch (e) { prefsError = e; }
    paintPrefs();
  }

  function paintPrefs() {
    prefsWrap.replaceChildren();
    const h = el('div', 'card-h');
    h.append(el('h3', 'card-t', 'Delivery'));
    prefsWrap.append(h);
    if (prefsError) {
      prefsWrap.append(unavailable(prefsError) ? unavailableCard('Delivery settings') : emptyState('Could not load delivery settings', prefsError.message, button('Try again', 'ghost', loadPrefs)));
      return;
    }
    if (!prefs) return;
    prefsWrap.append(el('p', 'al-push-line muted', deliveryLine(prefs)));

    const form = el('form', 'al-prefs');
    const minSel = el('select');
    for (const sv of SEVERITIES) { const o = el('option', '', severityLabel(sv)); o.value = sv; minSel.append(o); }
    minSel.value = prefs.immediate_min || 'high';
    form.append(labelWrap('Send at once from', minSel));

    const d = prefs.digest || {};
    const onSel = el('select');
    for (const [v, t] of [['on', 'On: lower alarms are gathered'], ['off', 'Off: everything is sent at once']]) { const o = el('option', '', t); o.value = v; onSel.append(o); }
    onSel.value = d.enabled ? 'on' : 'off';
    form.append(labelWrap('Digest', onSel));

    const modeSel = el('select');
    for (const [v, t] of [['every', 'Every so many hours'], ['at', 'At a time of day']]) { const o = el('option', '', t); o.value = v; modeSel.append(o); }
    modeSel.value = d.at ? 'at' : 'every';
    const modeRow = labelWrap('Digest timing', modeSel);
    form.append(modeRow);

    const hours = el('input');
    hours.type = 'number'; hours.min = '0.02'; hours.step = '0.5';
    hours.value = String(hoursOf(d.every) || 6);
    const hoursRow = labelWrap('Hours between digests', hours);
    form.append(hoursRow);

    const at = el('input');
    at.type = 'time'; at.value = d.at || '08:00';
    const atRow = labelWrap('Digest time', at);
    form.append(atRow);

    const tz = el('input');
    tz.type = 'text'; tz.placeholder = 'Server\'s local zone'; tz.value = prefs.timezone || '';
    tz.setAttribute('autocomplete', 'off');
    form.append(labelWrap('Time zone (IANA name)', tz));

    const sync = () => {
      const on = onSel.value === 'on';
      modeRow.hidden = !on;
      hoursRow.hidden = !on || modeSel.value !== 'every';
      atRow.hidden = !on || modeSel.value !== 'at';
    };
    onSel.addEventListener('change', sync);
    modeSel.addEventListener('change', sync);
    sync();

    const acts = el('div', 'al-push-acts');
    const savePrefs = async () => {
      const r = digestFromForm({ enabled: onSel.value === 'on', mode: modeSel.value, hours: hours.value, at: at.value });
      if (r.error) { notify(r.error); return; }
      save.disabled = true;
      try {
        prefs = (await mgmt.setAlarmPrefs({ ...prefs, immediate_min: minSel.value, digest: r.digest, timezone: tz.value.trim() })).preferences;
        notify('Delivery settings saved');
        paintPrefs();
      } catch (e) { notify('Could not save: ' + e.message); save.disabled = false; }
    };
    const save = button('Save delivery settings', 'primary', savePrefs);
    acts.append(save);
    form.append(acts);
    form.addEventListener('submit', (ev) => { ev.preventDefault(); savePrefs(); });
    prefsWrap.append(form);
  }

  // ------------------------------------------------------------- notifications
  // Web Push for this browser. The server keeps the subscriptions; this
  // browser's own is recognised by the id the server gave it at subscribe
  // time, kept in localStorage so a reload still knows.
  let push = null;
  let pushError = null;
  let pushBusy = false;
  const THIS_KEY = 'shepherd.push.id';
  const thisID = () => { try { return localStorage.getItem(THIS_KEY) || ''; } catch { return ''; } };
  const setThisID = (v) => { try { if (v) localStorage.setItem(THIS_KEY, v); else localStorage.removeItem(THIS_KEY); } catch { /* ignore */ } };
  const env = () => ({
    secureContext: !!window.isSecureContext,
    hasServiceWorker: 'serviceWorker' in navigator,
    hasPushManager: typeof PushManager !== 'undefined',
    hasNotification: typeof Notification !== 'undefined',
    ios: /iPhone|iPad|iPod/.test(navigator.userAgent),
    standalone: !!(window.navigator.standalone || (window.matchMedia && window.matchMedia('(display-mode: standalone)').matches)),
  });

  async function loadPush() {
    try {
      push = await mgmt.pushStatus();
      pushError = null;
    } catch (e) { pushError = e; }
    // ntfy is loaded with it: it is the other half of the Notifications
    // card and delivers even where Web Push cannot (an iPhone in Lockdown
    // Mode, a portal without HTTPS).
    await loadNtfy();
    paintPush();
  }

  async function subscribeThisBrowser() {
    pushBusy = true;
    paintPush();
    try {
      const perm = await Notification.requestPermission();
      if (perm !== 'granted') throw new Error('notifications were not allowed');
      const reg = await navigator.serviceWorker.register('sw.js');
      await navigator.serviceWorker.ready;
      let sub = await reg.pushManager.getSubscription();
      if (!sub) sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: urlBase64ToUint8Array(push.public_key) });
      const d = await mgmt.pushSubscribe(subscribeBody(sub.toJSON(), defaultDeviceName(navigator.userAgent)));
      setThisID(d.id);
      notify('This browser now receives Shepherd\'s notifications');
    } catch (e) {
      notify('Could not subscribe: ' + e.message);
    }
    pushBusy = false;
    await loadPush();
  }

  async function unsubscribeThisBrowser() {
    pushBusy = true;
    paintPush();
    try {
      const reg = await navigator.serviceWorker.getRegistration();
      const sub = reg ? await reg.pushManager.getSubscription() : null;
      if (sub) await sub.unsubscribe();
      const id = thisID();
      if (id) await mgmt.pushRemove(id).catch(() => {});
      setThisID('');
      notify('This browser no longer receives notifications');
    } catch (e) { notify('Could not unsubscribe: ' + e.message); }
    pushBusy = false;
    await loadPush();
  }

  async function sendTest() {
    try {
      await mgmt.pushTest();
      notify('Test notification sent to every subscribed browser and to ntfy');
    } catch (e) { notify('Could not send a test: ' + e.message); }
  }

  async function renameDevice(d) {
    const name = window.prompt('Name for this browser', d.name || '');
    if (name == null) return;
    try {
      await mgmt.pushRename(d.id, name.trim());
      await loadPush();
    } catch (e) { notify(e.message); }
  }

  async function removeDevice(d) {
    const ok = await confirmDialog({ title: 'Stop notifying ' + (d.name || 'this browser') + '?', body: 'It can subscribe again from its own Alarms screen.', confirm: 'Remove', danger: true });
    if (!ok) return;
    try {
      await mgmt.pushRemove(d.id);
      if (isThisBrowser(d, thisID())) setThisID('');
      await loadPush();
    } catch (e) { notify(e.message); }
  }

  // ntfy is set up here, not in shepherd.toml: the server is one only the
  // owner can name, and no feature of Shepherd should need a text editor
  // (docs/ALARMS.md). Stored credentials are never sent back, so a blank
  // token or password field means "keep the stored one".
  let ntfy = null;
  let ntfyError = null;

  async function loadNtfy() {
    try {
      ntfy = await mgmt.ntfy();
      ntfyError = null;
    } catch (e) { ntfyError = e; }
  }

  function suggestedTopic() {
    let bytes = [];
    try { bytes = Array.from(crypto.getRandomValues(new Uint8Array(8))); } catch { /* the default topic name still works */ }
    return suggestTopic(bytes);
  }

  function ntfyGuide() {
    const box = el('details', 'al-ntfy');
    box.open = !(ntfy && ntfy.enabled);
    box.append(el('summary', '', 'Set up ntfy (phone notifications without Web Push)'));
    if (ntfyError) {
      box.append(el('p', 'err small', ntfyError.message));
      return box;
    }
    const line = ntfyStatusLine(ntfy || {});
    box.append(el('p', 'al-push-line ' + line.tone, line.text));
    if (ntfy && ntfy.source) box.append(el('p', 'muted small', 'Set from ' + ntfy.source + '.'));
    if (ntfy && !ntfy.available) box.append(el('p', 'warn small', 'The alarm engine is off in shepherd.toml ([alarms]), so nothing is delivered until it is on.'));
    const steps = el('ol', 'al-ntfy-steps');
    for (const t of NTFY_STEPS) steps.append(el('li', '', t));
    box.append(steps);
    box.append(ntfyForm());
    box.append(el('p', 'muted small', 'A public server needs no account. Self-hosting, or a server that needs a login? Use the token, or the username and password. More in docs/ALARMS.md.'));
    return box;
  }

  function ntfyForm() {
    const doc = ntfy || {};
    const f = el('form', 'cust-form al-ntfy-form');
    f.autocomplete = 'off';
    const input = (label, value, type = 'text', placeholder) => {
      const i = el('input');
      i.type = type;
      i.value = value || '';
      i.placeholder = placeholder === undefined ? label : placeholder;
      i.autocomplete = type === 'password' ? 'new-password' : 'off';
      i.spellcheck = false;
      i.setAttribute('aria-label', label);
      return i;
    };
    const pre = ntfyFields(doc, suggestedTopic());
    const server = input('ntfy server', pre.server);
    const topic = input('Topic', pre.topic);
    const username = input('Username (only if your server needs one)', pre.username);
    const token = input('Access token', '', 'password', pre.tokenPlaceholder);
    const password = input('Password', '', 'password', pre.passwordPlaceholder);
    const r1 = el('div', 'cf-row');
    r1.append(server, topic);
    const r2 = el('div', 'cf-row');
    r2.append(token, username, password);
    const save = button(doc.configured ? 'Save changes' : 'Save and send a test', 'primary');
    save.type = 'submit';
    const acts = el('div', 'cf-row');
    acts.append(save);
    if (doc.configured) {
      acts.append(button('Send a test notification', 'ghost', testNtfy));
      acts.append(button(doc.enabled ? 'Switch off' : 'Switch on', 'ghost', () => setNtfyEnabled(!doc.enabled)));
      acts.append(button('Forget server', 'ghost', forgetNtfy));
    }
    const err = el('p', 'err small');
    err.setAttribute('role', 'status');
    f.append(r1, r2, acts, err);
    f.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const body = ntfySaveBody({ server: server.value, topic: topic.value, username: username.value,
        token: token.value, password: password.value, enabled: true }, doc);
      err.textContent = '';
      save.disabled = true;
      save.textContent = 'Sending a test…';
      try {
        ntfy = await mgmt.saveNtfy(body);
        notify('ntfy saved; a test notification was sent');
        paintPush();
      } catch (e) {
        err.textContent = e.message;
        save.disabled = false;
        save.textContent = doc.configured ? 'Save changes' : 'Save and send a test';
      }
    });
    return f;
  }

  async function testNtfy() {
    try {
      await mgmt.testNtfy();
      notify('Test notification published to ntfy');
    } catch (e) { notify(e.message); }
  }

  async function setNtfyEnabled(on) {
    try {
      ntfy = await mgmt.setNtfyEnabled(on);
      notify(on ? 'ntfy delivery is on' : 'ntfy delivery is off; the server is kept');
      paintPush();
    } catch (e) { notify(e.message); }
  }

  async function forgetNtfy() {
    const ok = await confirmDialog({ title: 'Forget this ntfy server?', body: 'The server, topic and any token are removed. Alarms stop being published to it until you set one again.', confirm: 'Forget', danger: true });
    if (!ok) return;
    try {
      ntfy = await mgmt.forgetNtfy();
      notify('ntfy server forgotten');
      paintPush();
    } catch (e) { notify(e.message); }
  }

  function paintPush() {
    paintPushBody();
    if (!pushError) pushWrap.append(ntfyGuide());
  }

  function paintPushBody() {
    pushWrap.replaceChildren();
    const h = el('div', 'card-h');
    h.append(el('h3', 'card-t', 'Notifications'));
    pushWrap.append(h);
    if (pushError) {
      pushWrap.append(unavailable(pushError) ? unavailableCard('Notifications') : emptyState('Could not load notification settings', pushError.message, button('Try again', 'ghost', loadPush)));
      return;
    }
    if (!push) return;
    if (!push.enabled) {
      pushWrap.append(el('p', 'al-push-line muted', 'Web Push is turned off in shepherd.toml ([alarms.push]). ntfy, set up below, still delivers.'));
      return;
    }
    const support = pushSupport(env());
    const mine = (push.devices || []).find((d) => isThisBrowser(d, thisID()));
    if (!support.ok) {
      pushWrap.append(el('p', 'al-push-line warn', support.reason));
    } else {
      const perm = permissionLine(typeof Notification !== 'undefined' ? Notification.permission : 'default');
      pushWrap.append(el('p', 'al-push-line ' + (mine ? 'good' : perm.tone), mine ? 'This browser receives Shepherd\'s notifications.' : perm.text));
    }
    const acts = el('div', 'al-push-acts');
    if (support.ok && !mine) {
      const b = button('Notify this browser', 'primary', subscribeThisBrowser);
      b.disabled = pushBusy;
      acts.append(b);
    }
    if (mine) {
      const b = button('Stop notifying this browser', 'ghost', unsubscribeThisBrowser);
      b.disabled = pushBusy;
      acts.append(b);
    }
    acts.append(button('Send a test notification', 'ghost', sendTest));
    pushWrap.append(acts);

    const devs = push.devices || [];
    if (!devs.length) {
      pushWrap.append(emptyState('No browser is subscribed yet', 'Subscribe each phone or computer from its own copy of this screen, over the HTTPS portal.'));
      return;
    }
    const list = el('div', 'al-push-devs list-rows');
    for (const d of devs) {
      const line = deviceLine(d);
      const row = el('div', 'list-row');
      const main = el('div', 'lr-main');
      main.append(el('div', 'lr-name', line.name + (isThisBrowser(d, thisID()) ? ' (this browser)' : '')));
      main.append(el('p', 'lr-desc ' + (line.tone === 'warn' ? 'warn' : 'muted'), line.text));
      const actsRow = el('div', 'up-acts');
      actsRow.append(iconButton('pencil', 'Rename ' + line.name, () => renameDevice(d)), iconButton('trash', 'Remove ' + line.name, () => removeDevice(d), 'danger-i'));
      row.append(main, actsRow);
      list.append(row);
    }
    pushWrap.append(list);
    pushWrap.append(el('p', 'muted small', 'On an iPhone or iPad, Shepherd must be added to the Home Screen and opened from there. A phone in Lockdown Mode never shows Web Push; use ntfy there.'));
  }

  // ------------------------------------------------------------- threat feeds
  let threats = null;
  let threatsError = null;
  let refreshingFeeds = false;

  async function loadThreats() {
    try {
      threats = await mgmt.threats();
      threatsError = null;
    } catch (e) { threatsError = e; }
    paintThreats();
  }

  async function refreshFeeds() {
    refreshingFeeds = true;
    paintThreats();
    try {
      await mgmt.refreshThreats();
      notify('Threat feeds refreshed');
    } catch (e) { notify('Could not refresh the feeds: ' + e.message); }
    refreshingFeeds = false;
    await loadThreats();
  }

  function paintThreats() {
    threatsWrap.replaceChildren();
    const h = el('div', 'card-h');
    h.append(el('h3', 'card-t', 'Threat feeds'));
    if (threats && threats.enabled) {
      const b = button(refreshingFeeds ? 'Refreshing…' : 'Refresh now', 'ghost', refreshFeeds);
      b.disabled = refreshingFeeds;
      h.append(b);
    }
    threatsWrap.append(h);
    if (threatsError) {
      threatsWrap.append(unavailable(threatsError) ? unavailableCard('Threat feeds') : emptyState('Could not load the threat feeds', threatsError.message, button('Try again', 'ghost', loadThreats)));
      return;
    }
    if (!threats) return;
    if (!threats.enabled) {
      threatsWrap.append(el('p', 'al-push-line muted', 'Threat feeds are turned off in shepherd.toml ([threats]).'));
      return;
    }
    threatsWrap.append(el('p', 'muted small', 'Every lookup, blocked or not, is checked against these lists of malware hosts, botnet controllers and hijacked networks. A match raises a threat-match alarm naming the device. ' + Number(threats.loaded || 0).toLocaleString() + ' indicators loaded.'));
    const feeds = el('div', 'al-push-devs list-rows');
    for (const f of threats.feeds || []) {
      const line = feedLine(f);
      const row = el('div', 'list-row');
      const main = el('div', 'lr-main');
      main.append(el('div', 'lr-name', f.name || f.id));
      main.append(el('p', 'lr-desc muted small', (f.describes ? 'Lists ' + f.describes + '. ' : '') + line.text));
      const meta = el('div', 'lr-meta');
      meta.append(el('span', 'badge ' + (line.tone === 'warn' ? 'warn' : line.tone === 'good' ? 'good' : 'muted'), f.kind === 'ip' ? 'addresses' : 'names'));
      main.append(meta);
      row.append(main);
      feeds.append(row);
    }
    threatsWrap.append(feeds);

    const matches = threats.matches || [];
    const mh = el('div', 'card-h');
    mh.append(el('h3', 'card-t', 'Recent matches' + (matches.length ? ' (' + matches.length + ')' : '')));
    threatsWrap.append(mh);
    if (!matches.length) {
      threatsWrap.append(emptyState('No device has reached for anything on these feeds', 'That is the good outcome. Matches also appear as alarms.'));
      return;
    }
    const list = el('div', 'al-push-devs list-rows');
    for (const m of matches) {
      const line = matchLine(m);
      const row = el('div', 'list-row');
      const main = el('div', 'lr-main');
      main.append(el('div', 'lr-name', line.who));
      main.append(el('p', 'lr-desc', line.text));
      main.append(el('p', 'lr-desc muted small', m.time ? relTime(m.time) : ''));
      row.append(main);
      list.append(row);
    }
    threatsWrap.append(list);
  }

  // ------------------------------------------------------------- view switching
  function paintAll() {
    wrap.hidden = view !== 'alarms';
    rulesWrap.hidden = view !== 'rules';
    pushWrap.hidden = view !== 'push';
    prefsWrap.hidden = view !== 'push';
    threatsWrap.hidden = view !== 'threats';
    sevSel.hidden = stateSel.hidden = searchBox.hidden = archToggle.hidden = view !== 'alarms';
  }

  return {
    async show() {
      paintAll();
      if (!started) {
        started = true;
        await Promise.all([load(true), loadRules()]);
      } else {
        await load(true);
        if (view === 'rules') await loadRules();
      }
      clearInterval(timer);
      timer = setInterval(() => {
        if (root.hidden || view !== 'alarms' || document.activeElement === input) return;
        load(true);
      }, 5000);
    },
    hide() { clearInterval(timer); },
  };
}
