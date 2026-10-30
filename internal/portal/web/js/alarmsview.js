// The Alarms screen: a filterable list with severity/state, single and bulk
// acknowledge/resolve/mute/delete, and a Rules sub-view for mute rules. Mirrors
// the structure of the Devices and Upstreams screens (panel-lite cards, a
// bulkbar for the selection, openMenu for per-action choices). Alarm text
// (title, body, evidence) comes from the server, so it is placed with
// textContent throughout.
import { el } from './dom.js';
import { icon, iconButton, button, segmented, emptyState, unavailableCard, confirmDialog, openMenu, relTime } from './ui.js';
import { unavailable } from './mgmt.js';
import { Selection } from './selection.js';
import {
  SEVERITIES, STATES, severityLabel, severityBadgeClass, stateLabel,
  MUTE_PRESETS, MUTE_SCOPES, bulkSummary, ruleMatchSummary,
} from './alarms.js';

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
    [{ id: 'alarms', label: 'Alarms' }, { id: 'rules', label: 'Rules' }], view,
    (id) => {
      view = id;
      paintAll();
      if (id === 'rules') loadRules();
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
  main.append(wrap, rulesWrap);
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

  // ------------------------------------------------------------- view switching
  function paintAll() {
    wrap.hidden = view !== 'alarms';
    rulesWrap.hidden = view !== 'rules';
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
