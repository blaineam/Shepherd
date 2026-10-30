// The Devices screen: a searchable, virtually scrolled table with bulk
// actions, a group panel and a detail drawer. Names, vendors and tags come from
// the network, so everything is placed with textContent.
import { el } from './dom.js';
import { createDeviceList } from './devlist.js';
import { Selection } from './selection.js';
import { parseQuery, stringifyQuery, addFilter, removeFilter, formatFilter, hasGroupFilter, FILTER_HELP } from './search.js';
import { applyBulkLocal, planUndo, describeBulk, parseTags, normTag } from './bulk.js';
import { TYPES, typeLabel, typeIcon, GROUP_COLORS } from './devtypes.js';
import { icon, iconButton, button, chip, segmented, emptyState, openPopover, openMenu, confirmDialog, relTime, unavailableCard, debounce } from './ui.js';
import { unavailable } from './mgmt.js';
import { TIMER_CHOICES, MODES, deviceMode, countdown, countdownShort, modePatch, applyModeLocal } from './wander.js';
import { createImportModal } from './importview.js';

const OVER = 6;
const rowHeight = () => (window.matchMedia && window.matchMedia('(max-width: 760px)').matches ? 88 : 56);

export function createDevices({ root, mgmt, notify, toaster, renderBlocking, onOpenHistory, onGroupsChanged = () => {} }) {
  let groups = [];
  let allTotal = null;
  let chips = []; // committed filters: [{key,value,neg}]
  let sort = 'recent';
  let active = -1;
  let renaming = null;
  let drawerId = null;
  let drawerRestore = null;
  const sel = new Selection();
  const groupName = (id) => (groups.find((g) => g.id === id) || {}).name || id;
  const groupById = (id) => groups.find((g) => g.id === id);

  // ------------------------------------------------------------- skeleton
  root.replaceChildren();
  const head = el('div', 'pg-head');
  const title = el('h2', 'pg-title');
  title.append(el('span', '', 'Devices'), el('span', 'pg-count mono', ''));
  const countEl = title.lastChild;

  const sbox = el('div', 'sbox');
  sbox.append(icon('search', 15, 'sbox-ico'));
  const chipsEl = el('span', 'sbox-chips');
  const input = el('input');
  input.type = 'search';
  input.placeholder = 'Search name, vendor, address, or type  group:kids  seen:1h';
  input.setAttribute('aria-label', 'Search devices');
  input.autocomplete = 'off';
  input.spellcheck = false;
  const helpBtn = iconButton('help', 'Search filters help', null, 'sbox-help');
  helpBtn.setAttribute('aria-haspopup', 'dialog');
  helpBtn.setAttribute('aria-expanded', 'false');
  sbox.append(chipsEl, input, helpBtn);

  const sortSeg = segmented([{ id: 'recent', label: 'Recent' }, { id: 'name', label: 'Name' }], sort, (id) => { sort = id; resetList(); }, 'Sort devices');
  const groupsToggle = button('Groups', 'ghost only-md', null, 'users');
  groupsToggle.setAttribute('aria-pressed', 'false');
  const importModal = createImportModal({
    mgmt, notify,
    onImported: () => { loadGroups().catch(() => {}); list.refresh(); onGroupsChanged(); },
  });
  const importBtn = button('Import', 'ghost only-md', () => importModal.open(), 'import');
  head.append(title, sbox, sortSeg.root, groupsToggle, importBtn);

  const main = el('div', 'dv-main');
  const side = el('aside', 'dv-groups panel-lite');
  side.setAttribute('aria-label', 'Groups');
  const wrap = el('section', 'dv-tablewrap panel-lite');
  const banner = el('div', 'dv-banner');
  banner.hidden = true;
  banner.setAttribute('role', 'status');

  const thead = el('div', 'dv-row dv-thead');
  thead.setAttribute('role', 'row');
  const allBox = el('input');
  allBox.type = 'checkbox';
  allBox.setAttribute('aria-label', 'Select all loaded devices');
  const cSelH = el('div', 'c-sel');
  cSelH.append(allBox);
  thead.append(cSelH, el('div', 'c-name', 'Device'), el('div', 'c-ip', 'Addresses'), el('div', 'c-grp', 'Groups'), el('div', 'c-seen', 'Last seen'), el('div', 'c-exc', 'Mode'));
  for (const c of thead.children) c.setAttribute('role', 'columnheader');
  const scroll = el('div', 'dv-scroll');
  scroll.tabIndex = 0;
  scroll.setAttribute('role', 'table');
  scroll.setAttribute('aria-label', 'Devices');
  const sizer = el('div', 'dv-sizer');
  const rowsEl = el('div', 'dv-rows');
  sizer.append(rowsEl);
  const emptyEl = el('div', 'dv-empty');
  emptyEl.hidden = true;
  scroll.append(sizer, emptyEl);
  const bulk = el('div', 'bulkbar');
  bulk.hidden = true;
  bulk.setAttribute('role', 'toolbar');
  bulk.setAttribute('aria-label', 'Bulk actions');
  wrap.append(banner, thead, scroll, bulk);
  main.append(side, wrap);

  const drawer = el('aside', 'drawer');
  drawer.hidden = true;
  drawer.setAttribute('aria-label', 'Device details');
  const scrim = el('div', 'drawer-scrim');
  scrim.hidden = true;
  root.append(head, main, scrim, drawer);

  // ------------------------------------------------------------- list
  const list = createDeviceList({
    fetchPage: (p) => mgmt.devices(p),
    pageSize: 100,
    onChange: () => { sel.setTotal(list.total); layout(); paintMeta(); },
  });

  const currentQuery = () => {
    const live = parseQuery(input.value);
    return stringifyQuery({ text: live.text, filters: [...chips, ...live.filters] });
  };

  function resetList() {
    sel.clear();
    active = -1;
    list.reset(currentQuery(), sort);
    paintBulk();
  }
  const resetSoon = debounce(resetList, 140);

  // ------------------------------------------------------------- chips and search
  function paintChips() {
    chipsEl.replaceChildren();
    chips.forEach((f, i) => chipsEl.append(chip(formatFilter(f), { cls: f.neg ? 'neg' : '', onRemove: () => { chips = removeFilter({ text: '', filters: chips }, i).filters; paintChips(); paintGroups(); resetList(); input.focus(); } })));
  }
  function commitInput() {
    const p = parseQuery(input.value);
    if (!p.filters.length) return;
    chips = [...chips, ...p.filters.filter((f) => !chips.some((c) => formatFilter(c) === formatFilter(f)))];
    input.value = p.text;
    paintChips();
    paintGroups();
  }
  input.addEventListener('input', () => { resetSoon(); });
  input.addEventListener('keydown', (e) => {
    if (e.key === ' ' && /[a-z]+:\S+$/i.test(input.value)) { e.preventDefault(); commitInput(); input.value = input.value ? input.value + ' ' : ''; resetList(); }
    else if (e.key === 'Enter') { commitInput(); resetList(); }
    else if (e.key === 'Backspace' && !input.value && chips.length) { chips = chips.slice(0, -1); paintChips(); paintGroups(); resetList(); }
    else if (e.key === 'Escape' && (input.value || chips.length)) { input.value = ''; chips = []; paintChips(); paintGroups(); resetList(); }
    else if (e.key === 'ArrowDown') { e.preventDefault(); focusIndex(Math.max(0, active)); }
  });
  input.addEventListener('blur', () => { if (parseQuery(input.value).filters.length) { commitInput(); resetList(); } });

  helpBtn.addEventListener('click', () => {
    openPopover(helpBtn, (panel, close) => {
      panel.classList.add('help-pop');
      panel.append(el('h3', '', 'Search filters'), el('p', 'muted small', 'Type words to match names, vendors, types, tags and addresses. Add filters with key:value. A leading minus negates, like -group:guests. Quote values with spaces.'));
      const ul = el('ul', 'help-list');
      for (const h of FILTER_HELP) {
        const li = el('li');
        const b = el('button', 'help-ex mono', h.example);
        b.type = 'button';
        b.addEventListener('click', () => { close(); input.value = (input.value ? input.value.trimEnd() + ' ' : '') + h.example + ' '; input.focus(); commitInput(); input.focus(); resetList(); });
        li.append(b, el('span', 'muted small', h.text));
        ul.append(li);
      }
      panel.append(ul);
    }, { align: 'end', label: 'Search filter help' });
  });

  groupsToggle.addEventListener('click', () => {
    const on = !side.classList.contains('open');
    side.classList.toggle('open', on);
    groupsToggle.setAttribute('aria-pressed', on ? 'true' : 'false');
  });

  // ------------------------------------------------------------- groups panel
  let editingGroup = null;
  function toggleGroupFilter(g) {
    const q = { text: '', filters: chips };
    const idx = hasGroupFilter(q, g.name);
    chips = idx >= 0 ? removeFilter(q, idx).filters : addFilter(q, 'group', g.name).filters;
    paintChips(); paintGroups(); resetList();
  }
  function quickFilter(key, value, label) {
    const on = chips.findIndex((f) => f.key === key && f.value === value && !f.neg);
    const b = el('button', 'qf', label);
    b.type = 'button';
    b.setAttribute('aria-pressed', on >= 0 ? 'true' : 'false');
    b.addEventListener('click', () => {
      chips = on >= 0 ? removeFilter({ text: '', filters: chips }, on).filters : addFilter({ text: '', filters: chips }, key, value).filters;
      paintChips(); paintGroups(); resetList();
    });
    return b;
  }

  function swatches(current, onPick) {
    const row = el('div', 'swatches');
    row.setAttribute('role', 'group');
    row.setAttribute('aria-label', 'Group color');
    for (const c of GROUP_COLORS) {
      const b = el('button', 'sw-btn');
      b.type = 'button';
      b.style.background = c;
      b.setAttribute('aria-label', 'Color ' + c);
      b.setAttribute('aria-pressed', c === current ? 'true' : 'false');
      b.addEventListener('click', () => { for (const x of row.children) x.setAttribute('aria-pressed', 'false'); b.setAttribute('aria-pressed', 'true'); onPick(c); });
      row.append(b);
    }
    return row;
  }

  function paintGroups() {
    side.replaceChildren();
    const h = el('h3', 'ph');
    h.append(el('span', '', 'Groups'));
    side.append(h);

    const all = el('button', 'g-row' + (!chips.some((f) => f.key === 'group') ? ' on' : ''));
    all.type = 'button';
    all.append(icon('users', 14), el('span', 'g-name', 'All devices'), el('span', 'g-n mono', allTotal == null ? '' : allTotal.toLocaleString()));
    all.addEventListener('click', () => { chips = chips.filter((f) => f.key !== 'group'); paintChips(); paintGroups(); resetList(); });
    side.append(all);

    for (const g of groups) {
      const on = hasGroupFilter({ text: '', filters: chips }, g.name) >= 0;
      const row = el('div', 'g-line');
      const b = el('button', 'g-row' + (on ? ' on' : ''));
      b.type = 'button';
      b.setAttribute('aria-pressed', on ? 'true' : 'false');
      const dot = el('i', 'cdot');
      dot.style.background = g.color;
      b.append(dot, el('span', 'g-name', g.name), el('span', 'g-n mono', String(g.count ?? 0)));
      b.title = 'Show only ' + g.name;
      b.addEventListener('click', () => toggleGroupFilter(g));
      const edit = iconButton('pencil', 'Edit group ' + g.name, () => { editingGroup = editingGroup === g.id ? null : g.id; paintGroups(); });
      row.append(b, edit);
      side.append(row);
      if (editingGroup === g.id) side.append(groupEditor(g));
    }
    if (!groups.length) side.append(el('p', 'muted small g-hint', 'No groups yet. Create one, then select devices and add them in bulk.'));

    const qh = el('h3', 'ph ph2');
    qh.append(el('span', '', 'Quick filters'));
    const qf = el('div', 'qfs');
    qf.append(quickFilter('seen', '1h', 'Active now'), quickFilter('unnamed', 'true', 'Unnamed'), quickFilter('excluded', 'true', 'Excluded'), quickFilter('wandering', 'true', 'Wandering'));
    side.append(qh, qf);

    const form = el('form', 'g-new');
    const gi = el('input');
    gi.placeholder = 'New group';
    gi.maxLength = 40;
    gi.setAttribute('aria-label', 'New group name');
    const add = button('Add', 'ghost');
    add.type = 'submit';
    form.append(gi, add);
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const name = gi.value.trim();
      if (!name) return;
      try { await createGroup(name); gi.value = ''; } catch (err) { notify(err.message); }
    });
    side.append(form);
  }

  function groupEditor(g) {
    const box = el('div', 'g-edit');
    const name = el('input');
    name.value = g.name;
    name.maxLength = 40;
    name.setAttribute('aria-label', 'Group name');
    let color = g.color;
    const sw = swatches(color, (c) => { color = c; });
    const row = el('div', 'g-edit-actions');
    const save = button('Save', 'primary', async () => {
      try {
        const r = await mgmt.patchGroup(g.id, { name: name.value.trim() || g.name, color });
        const was = g.name;
        Object.assign(g, r, { count: g.count });
        chips = chips.map((f) => (f.key === 'group' && f.value.toLowerCase() === was.toLowerCase() ? { ...f, value: g.name } : f));
        editingGroup = null; paintChips(); paintGroups(); onGroupsChanged(); list.refresh();
      } catch (err) { notify(err.message); }
    });
    const del = button('Delete', 'danger', async () => {
      const ok = await confirmDialog({ title: 'Delete group ' + g.name + '?', body: 'The ' + (g.count || 0) + ' device(s) in it stay on your network and are only removed from the group. Blocking settings for this group are deleted.', confirm: 'Delete group', danger: true });
      if (!ok) return;
      try {
        await mgmt.deleteGroup(g.id);
        chips = chips.filter((f) => !(f.key === 'group' && f.value.toLowerCase() === g.name.toLowerCase()));
        editingGroup = null; await loadGroups(); onGroupsChanged(); paintChips(); resetList();
      } catch (err) { notify(err.message); }
    });
    row.append(save, del);
    box.append(name, sw, row);
    return box;
  }

  async function createGroup(name, color) {
    const g = await mgmt.createGroup(name, color || GROUP_COLORS[groups.length % GROUP_COLORS.length]);
    groups = [...groups, { count: 0, ...g }];
    paintGroups(); onGroupsChanged();
    return g;
  }

  async function loadGroups() {
    const r = await mgmt.groups();
    groups = Array.isArray(r && r.groups) ? r.groups : [];
    paintGroups();
  }

  // ------------------------------------------------------------- rows
  const slots = [];
  const icoCache = new Map();
  function typeIco(t) {
    const n = typeIcon(t);
    return icon(n, 20);
  }

  function makeSlot() {
    const row = el('div', 'dv-row');
    row.setAttribute('role', 'row');
    row.tabIndex = -1;
    const cSel = el('div', 'c-sel');
    const cb = el('input');
    cb.type = 'checkbox';
    cSel.append(cb);
    const cName = el('div', 'c-name');
    const ico = el('span', 'dv-ico');
    const nameWrap = el('div', 'nm-wrap');
    const nm = el('span', 'nm');
    const sub = el('span', 'sub');
    nameWrap.append(nm, sub);
    const pen = iconButton('pencil', 'Rename', null, 'dv-pen');
    cName.append(ico, nameWrap, pen);
    const cIp = el('div', 'c-ip mono');
    const cGrp = el('div', 'c-grp');
    const cSeen = el('div', 'c-seen');
    const cExc = el('div', 'c-exc');
    const mb = el('button', 'mode-btn');
    mb.type = 'button';
    mb.setAttribute('aria-haspopup', 'menu');
    cExc.append(mb);
    const wb = el('span', 'wbadge', 'Wandering');
    wb.hidden = true;
    nameWrap.after(wb);
    row.append(cSel, cName, cIp, cGrp, cSeen, cExc);
    for (const c of row.children) c.setAttribute('role', 'cell');
    const s = { row, cb, ico, nm, sub, pen, cIp, cGrp, cSeen, mb, wb, nameWrap, _i: -1, _d: null, _sig: '' };
    return s;
  }

  function bindSlot(s, d, i) {
    s._i = i;
    s._d = d;
    s.row.dataset.i = String(i);
    s.row.setAttribute('aria-rowindex', String(i + 2));
    s.row.classList.remove('loading');
    const on = sel.has(d.id);
    s.row.classList.toggle('sel', on);
    s.row.setAttribute('aria-selected', on ? 'true' : 'false');
    s.cb.checked = on;
    s.cb.setAttribute('aria-label', 'Select ' + d.name);
    if (s._type !== d.type) { s._type = d.type; s.ico.replaceChildren(typeIco(d.type)); s.ico.title = typeLabel(d.type); }
    const isRen = renaming && renaming.id === d.id;
    if (!isRen) {
      if (s.nm.textContent !== d.name) s.nm.textContent = d.name;
    }
    const sub = [d.vendor, typeLabel(d.type)].filter(Boolean).join(' · ');
    if (s.sub.textContent !== sub) s.sub.textContent = sub;
    s.pen.setAttribute('aria-label', 'Rename ' + d.name);
    const ips = (d.ips || []).join('  ');
    if (s.cIp.textContent !== ips) { s.cIp.textContent = ips; s.cIp.title = ips; }
    const sig = (d.groups || []).join(',') + '|' + groups.map((g) => g.color + g.name).join(',');
    if (s._sig !== sig) {
      s._sig = sig;
      s.cGrp.replaceChildren();
      const gs = (d.groups || []).map(groupById).filter(Boolean);
      for (const g of gs.slice(0, 2)) s.cGrp.append(chip(g.name, { color: g.color }));
      if (gs.length > 2) s.cGrp.append(el('span', 'tchip more', '+' + (gs.length - 2)));
    }
    const seen = relTime(d.last_seen);
    if (s.cSeen.textContent !== seen) { s.cSeen.textContent = seen; s.cSeen.title = d.last_seen ? new Date(d.last_seen).toLocaleString() : ''; }
    const mode = deviceMode(d);
    const short = countdownShort(d);
    const mt = mode === 'wandering' ? 'Wandering' + (short ? ' ' + short : '') : mode === 'excluded' ? 'Excluded' : 'Protected';
    if (s.mb.textContent !== mt) s.mb.textContent = mt;
    s.mb.className = 'mode-btn m-' + mode;
    s.mb.setAttribute('aria-label', 'Mode for ' + d.name + ': ' + mt + '. Change');
    s.wb.hidden = mode !== 'wandering';
    s.row.classList.toggle('excl', mode === 'excluded');
    s.row.classList.toggle('wand', mode === 'wandering');
    s.row.tabIndex = i === active ? 0 : -1;
  }

  function bindPlaceholder(s, i) {
    s._i = i; s._d = null; s._sig = ''; s._type = null;
    s.row.dataset.i = String(i);
    s.row.classList.add('loading');
    s.row.classList.remove('sel', 'excl');
    s.row.tabIndex = -1;
    s.nm.textContent = '';
    s.sub.textContent = '';
    s.cIp.textContent = ''; s.cGrp.replaceChildren(); s.cSeen.textContent = ''; s.ico.replaceChildren();
    s.cb.checked = false;
  }

  let rh = rowHeight();
  function render() {
    const total = list.total;
    const vh = scroll.clientHeight || 600;
    const first = Math.max(0, Math.floor(scroll.scrollTop / rh) - OVER);
    const need = Math.min(Math.max(total, 0) - first, Math.ceil(vh / rh) + OVER * 2);
    while (slots.length < need) { const s = makeSlot(); slots.push(s); rowsEl.append(s.row); }
    for (let k = 0; k < slots.length; k++) {
      const s = slots[k];
      const i = first + k;
      if (k >= need || i >= total) { if (!s.row.hidden) s.row.hidden = true; continue; }
      s.row.hidden = false;
      const d = list.get(i);
      if (renaming && s._d && renaming.id === s._d.id && (!d || d.id !== s._d.id)) finishRename(true);
      s.row.style.transform = 'translateY(' + i * rh + 'px)';
      s.row.style.height = rh + 'px';
      if (d) bindSlot(s, d, i); else bindPlaceholder(s, i);
    }
    list.ensure(first, first + need);
  }

  function layout() {
    rh = rowHeight();
    sizer.style.height = Math.max(0, list.total) * rh + 'px';
    scroll.setAttribute('aria-rowcount', String(list.total + 1));
    const e = list.error;
    emptyEl.hidden = true;
    if (e && !list.total) {
      emptyEl.hidden = false;
      emptyEl.replaceChildren(unavailable(e) ? unavailableCard('Device management') : emptyState('Could not load devices', e.message));
    } else if (list.ready && list.total === 0) {
      emptyEl.hidden = false;
      const filtered = !!currentQuery();
      emptyEl.replaceChildren(filtered
        ? emptyState('No devices match', 'Try removing a filter, or check the spelling.', button('Clear search', 'ghost', () => { input.value = ''; chips = []; paintChips(); paintGroups(); resetList(); }))
        : emptyState('No devices seen yet', 'Devices appear here as soon as they make a DNS query through Shepherd.'));
    }
    render();
    paintBanner();
    paintBulk();
  }

  let raf = 0;
  scroll.addEventListener('scroll', () => { if (!raf) raf = requestAnimationFrame(() => { raf = 0; render(); }); }, { passive: true });
  window.addEventListener('resize', () => { if (!root.hidden) layout(); });

  function paintMeta() {
    countEl.textContent = list.ready ? list.total.toLocaleString() : '';
    if (!currentQuery() && list.ready && !list.error) { allTotal = list.total; }
  }

  // ------------------------------------------------------------- selection
  function loadedIds() { return list.loaded().map((d) => d.id); }

  function paintBanner() {
    const n = sel.count();
    const loaded = list.loaded().length;
    const st = sel.pageState(loadedIds());
    allBox.checked = sel.allMatches || st === 'all';
    allBox.indeterminate = !sel.allMatches && st === 'some';
    banner.replaceChildren();
    if (sel.allMatches) {
      banner.hidden = false;
      banner.append(el('span', '', 'All ' + sel.total.toLocaleString() + ' matching devices are selected'), button('Clear selection', 'linkbtn', () => { sel.clear(); renderAll(); }));
    } else if (st === 'all' && list.total > loaded && n === loaded) {
      banner.hidden = false;
      banner.append(el('span', '', n.toLocaleString() + ' loaded devices selected'), button('Select all ' + list.total.toLocaleString() + ' matching', 'linkbtn', () => { sel.selectAllMatches(list.total); renderAll(); }));
    } else banner.hidden = true;
  }

  function renderAll() { render(); paintBanner(); paintBulk(); }

  allBox.addEventListener('change', () => {
    if (sel.allMatches || sel.pageState(loadedIds()) === 'all') sel.clear(); else sel.selectPage(loadedIds());
    renderAll();
  });

  function rowToggle(i, shift) {
    const d = list.get(i);
    if (!d) return;
    if (shift) sel.range(list.orderedIds(), i); else sel.toggle(d.id, i);
    renderAll();
  }

  rowsEl.addEventListener('click', (e) => {
    const row = e.target.closest('.dv-row');
    if (!row) return;
    const i = Number(row.dataset.i);
    const d = list.get(i);
    if (!d) return;
    active = i;
    if (e.target.closest('.c-sel')) {
      // The model decides the state; render() writes it back to the checkbox.
      rowToggle(i, e.shiftKey);
      return;
    }
    if (e.target.closest('.dv-pen')) { startRename(row, d); return; }
    if (e.target.closest('.mode-btn')) { modeMenu(e.target.closest('.mode-btn'), d); return; }
    if (e.target.closest('.c-exc')) return;
    if (e.target.closest('.rename-in')) return;
    openDrawer(d.id, row);
  });
  rowsEl.addEventListener('dblclick', (e) => {
    const nm = e.target.closest('.nm');
    if (!nm) return;
    const row = nm.closest('.dv-row');
    const d = list.get(Number(row.dataset.i));
    if (d) startRename(row, d);
  });

  function focusIndex(i) {
    if (list.total === 0) return;
    i = Math.max(0, Math.min(list.total - 1, i));
    active = i;
    const top = i * rh;
    if (top < scroll.scrollTop) scroll.scrollTop = top;
    else if (top + rh > scroll.scrollTop + scroll.clientHeight) scroll.scrollTop = top + rh - scroll.clientHeight;
    render();
    const s = slots.find((x) => x._i === i && !x.row.hidden);
    if (s) s.row.focus({ preventScroll: true });
  }
  scroll.addEventListener('focus', (e) => { if (e.target === scroll) focusIndex(active < 0 ? 0 : active); });
  rowsEl.addEventListener('keydown', (e) => {
    const row = e.target.closest('.dv-row');
    if (!row || e.target !== row) return;
    const i = Number(row.dataset.i);
    const page = Math.max(1, Math.floor(scroll.clientHeight / rh) - 1);
    switch (e.key) {
      case 'ArrowDown': e.preventDefault(); focusIndex(i + 1); break;
      case 'ArrowUp': e.preventDefault(); focusIndex(i - 1); break;
      case 'PageDown': e.preventDefault(); focusIndex(i + page); break;
      case 'PageUp': e.preventDefault(); focusIndex(i - page); break;
      case 'Home': e.preventDefault(); focusIndex(0); break;
      case 'End': e.preventDefault(); focusIndex(list.total - 1); break;
      case ' ': e.preventDefault(); rowToggle(i, e.shiftKey); focusIndex(i); break;
      case 'Enter': { e.preventDefault(); const d = list.get(i); if (d) openDrawer(d.id, row); break; }
      case 'F2': { const d = list.get(i); if (d) startRename(row, d); break; }
      default: break;
    }
  });
  document.addEventListener('keydown', (e) => {
    if (root.hidden) return;
    if (e.key === '/' && !/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement && document.activeElement.tagName)) { e.preventDefault(); input.focus(); }
    else if (e.key === 'Escape' && drawerId && !document.querySelector('.pop, .dlg-overlay')) closeDrawer();
  });

  // ------------------------------------------------------------- rename
  function startRename(row, d) {
    if (renaming) finishRename(true);
    const s = slots.find((x) => x.row === row);
    if (!s) return;
    const inp = el('input', 'rename-in');
    inp.value = d.alias || d.name;
    inp.maxLength = 64;
    inp.setAttribute('aria-label', 'Device name');
    s.nm.replaceWith(inp);
    renaming = { id: d.id, input: inp, slot: s, original: d.alias || '' };
    inp.focus();
    inp.select();
    inp.addEventListener('keydown', (e) => {
      e.stopPropagation();
      if (e.key === 'Enter') { e.preventDefault(); finishRename(true); }
      else if (e.key === 'Escape') { e.preventDefault(); finishRename(false); }
    });
    inp.addEventListener('blur', () => { if (renaming && renaming.input === inp) finishRename(true); });
  }
  function finishRename(commit) {
    if (!renaming) return;
    const r = renaming;
    renaming = null;
    const v = r.input.value.trim();
    r.input.replaceWith(r.slot.nm);
    r.slot.row.focus({ preventScroll: true });
    if (commit && v !== r.original && v !== (r.slot._d && r.slot._d.name)) patchDevice(r.id, { alias: v }).catch(() => {});
    else render();
  }

  // ------------------------------------------------------------- editing
  async function patchDevice(id, patch, checkbox) {
    const held = list.loaded().find((d) => d.id === id);
    const before = held ? { ...held } : null;
    list.patch(id, (d) => {
      const n = applyModeLocal(d, patch);
      if (patch.alias !== undefined) { n.alias = patch.alias; n.name = patch.alias || d.name; }
      for (const k of ['notes', 'type', 'tags']) if (patch[k] !== undefined) n[k] = patch[k];
      return n;
    });
    render();
    try {
      const r = await mgmt.patchDevice(id, patch);
      if (r && r.id) list.patch(id, () => r);
      render();
      if (drawerId === id) paintDrawer(r || list.patch(id, (d) => d));
      return r;
    } catch (err) {
      if (before && before.id) list.patch(id, () => before);
      render();
      notify('Could not save: ' + err.message);
      throw err;
    }
  }

  // ------------------------------------------------------------- mode
  function modeMenu(anchor, d) {
    const cur = deviceMode(d);
    const items = [
      { label: 'Protected', ico: cur === 'protected' ? 'check' : 'shield', hint: 'filtered', onSelect: () => patchDevice(d.id, modePatch('protected')).catch(() => {}) },
      { sep: true }, { heading: 'Wandering: not filtered, still watched' },
      ...TIMER_CHOICES.map((t) => ({ label: t.label, ico: cur === 'wandering' ? undefined : undefined, onSelect: () => patchDevice(d.id, modePatch('wandering', t.minutes)).catch(() => {}) })),
      { sep: true },
      { label: 'Excluded', ico: cur === 'excluded' ? 'check' : undefined, hint: 'left alone', onSelect: () => patchDevice(d.id, modePatch('excluded')).catch(() => {}) },
    ];
    openMenu(anchor, items, { label: 'Mode for ' + d.name });
  }

  function wanderMenu(anchor) {
    const items = [
      { heading: 'Wander for the selection' },
      ...TIMER_CHOICES.map((t) => ({ label: t.label, onSelect: () => runBulk({ op: 'set_wandering', wandering: true, ...(t.minutes > 0 ? { wandering_minutes: t.minutes } : {}) }) })),
      { sep: true },
      { label: 'Stop wandering (protect again)', ico: 'shield', onSelect: () => runBulk({ op: 'set_wandering', wandering: false }) },
    ];
    openMenu(anchor, items, { label: 'Set wandering' });
  }

  // ------------------------------------------------------------- bulk
  async function runBulk(req, { confirmDelete = false } = {}) {
    const n = sel.count();
    if (!n) return;
    if (confirmDelete) {
      const ok = await confirmDialog({
        title: 'Delete ' + (n === 1 ? 'this device' : n.toLocaleString() + ' devices') + '?',
        body: 'They are forgotten along with their names, tags and blocking settings. A device that talks to Shepherd again will reappear as a new, unnamed device. This cannot be undone.',
        confirm: 'Delete', danger: true,
      });
      if (!ok) return;
    }
    let before;
    let ids;
    try {
      if (sel.allMatches) {
        before = await list.fetchAll();
        const ex = sel.excluded;
        before = before.filter((d) => !ex.has(d.id));
        ids = before.map((d) => d.id);
      } else {
        ids = [...sel.ids];
        const held = new Map(list.loaded().map((d) => [d.id, d]));
        before = ids.map((id) => held.get(id)).filter(Boolean);
      }
    } catch (err) { notify('Could not read the selection: ' + err.message); return; }
    if (!ids.length) return;
    for (const id of ids) list.patch(id, (d) => applyBulkLocal(d, req));
    render();
    try {
      const r = await mgmt.bulk({ ids, ...req });
      const changed = Number.isFinite(r && r.changed) ? r.changed : ids.length;
      const plan = planUndo(req, before);
      const msg = describeBulk(req, changed, groupName);
      if (req.op === 'delete') { list.remove(ids); sel.forget(ids); }
      sel.clear();
      toaster.show(msg, plan && plan.length ? { action: { label: 'Undo', run: async () => { for (const p of plan) await mgmt.bulk(p); await loadGroups(); await list.refresh(); onGroupsChanged(); } } } : {});
      await loadGroups();
      await list.refresh();
      onGroupsChanged();
    } catch (err) {
      for (const d of before) list.patch(d.id, () => d);
      notify('Bulk change failed: ' + err.message);
    }
    renderAll();
  }

  function groupMenu(anchor, op) {
    const items = groups.map((g) => ({ label: g.name, color: g.color, onSelect: () => runBulk({ op, group_id: g.id }) }));
    if (op === 'assign_group') {
      items.push({ sep: true }, { label: 'New group…', ico: 'plus', onSelect: () => newGroupForSelection(anchor) });
    }
    openMenu(anchor, items, { label: op === 'assign_group' ? 'Add to group' : 'Remove from group', empty: 'No groups yet' });
  }

  function newGroupForSelection(anchor) {
    openPopover(anchor, (panel, close) => {
      const f = el('form', 'pop-form');
      const gi = el('input');
      gi.placeholder = 'Group name';
      gi.maxLength = 40;
      gi.setAttribute('aria-label', 'New group name');
      let color = GROUP_COLORS[groups.length % GROUP_COLORS.length];
      f.append(el('label', 'pop-l', 'New group'), gi, swatches(color, (c) => { color = c; }), button('Create and add', 'primary'));
      f.lastChild.type = 'submit';
      f.addEventListener('submit', async (e) => {
        e.preventDefault();
        if (!gi.value.trim()) return;
        try { const g = await createGroup(gi.value.trim(), color); close(); await runBulk({ op: 'assign_group', group_id: g.id }); } catch (err) { notify(err.message); }
      });
      panel.append(f);
    }, { label: 'New group' });
  }

  function tagsPopover(anchor) {
    openPopover(anchor, (panel, close) => {
      const f = el('form', 'pop-form');
      const add = el('input');
      add.placeholder = 'guest, travel';
      add.setAttribute('aria-label', 'Tags to add');
      const rm = el('input');
      rm.placeholder = 'old-tag';
      rm.setAttribute('aria-label', 'Tags to remove');
      const go = button('Apply', 'primary');
      go.type = 'submit';
      f.append(el('label', 'pop-l', 'Add tags'), add, el('label', 'pop-l', 'Remove tags'), rm, go, el('p', 'muted small', 'Separate tags with commas.'));
      f.addEventListener('submit', (e) => {
        e.preventDefault();
        const a = parseTags(add.value), r = parseTags(rm.value);
        if (!a.length && !r.length) return;
        close();
        runBulk({ op: 'set_tags', add_tags: a, remove_tags: r });
      });
      panel.append(f);
    }, { label: 'Tags' });
  }

  function paintBulk() {
    const n = sel.count();
    bulk.hidden = n === 0;
    wrap.classList.toggle('has-bulk', n > 0);
    if (!n) { bulk.replaceChildren(); return; }
    bulk.replaceChildren();
    const label = el('span', 'bulk-n');
    label.append(el('strong', 'mono', n.toLocaleString()), document.createTextNode(' selected'));
    const g1 = button('Add to group', 'bb', (e) => groupMenu(e.currentTarget, 'assign_group'), 'users');
    const g2 = button('Remove from group', 'bb', (e) => groupMenu(e.currentTarget, 'remove_group'));
    const ex = button('Exclude', 'bb', () => runBulk({ op: 'set_excluded', excluded: true }));
    const inc = button('Include', 'bb', () => runBulk({ op: 'set_excluded', excluded: false }));
    const wd = button('Wandering', 'bb', (e) => wanderMenu(e.currentTarget), 'refresh');
    const tg = button('Tags', 'bb', (e) => tagsPopover(e.currentTarget), 'tag');
    const del = button('Delete', 'bb danger', () => runBulk({ op: 'delete' }, { confirmDelete: true }), 'trash');
    const clear = iconButton('x', 'Clear selection', () => { sel.clear(); renderAll(); }, 'bulk-x');
    for (const b of [g1, g2, tg, wd]) b.setAttribute('aria-haspopup', 'true');
    bulk.append(label, g1, g2, wd, ex, inc, tg, del, clear);
  }

  // ------------------------------------------------------------- drawer
  function openDrawer(id, fromRow) {
    drawerId = id;
    drawerRestore = fromRow || null;
    drawer.hidden = false;
    scrim.hidden = false;
    document.body.classList.add('drawer-open');
    const d = (list.loaded().find((x) => x.id === id));
    paintDrawer(d || { id, name: '…', names: {}, ips: [], macs: [], groups: [], tags: [] });
    mgmt.device(id).then((full) => { if (drawerId === id && full && full.id) { list.patch(id, () => full); paintDrawer(full); } }).catch(() => {});
    const x = drawer.querySelector('.drawer-x');
    if (x) x.focus();
  }
  function closeDrawer() {
    drawerId = null;
    drawer.hidden = true;
    scrim.hidden = true;
    document.body.classList.remove('drawer-open');
    if (drawerRestore && document.contains(drawerRestore)) drawerRestore.focus({ preventScroll: true });
    drawerRestore = null;
  }
  scrim.addEventListener('click', closeDrawer);

  const field = (k, v, cls = '') => { const r = el('div', 'dr-row'); r.append(el('span', 'dr-k', k)); const vv = el('span', 'dr-v ' + cls); if (v instanceof Node) vv.append(v); else vv.textContent = v; r.append(vv); return r; };
  const section = (t) => { const s = el('section', 'dr-sec'); s.append(el('h3', 'ph', t)); return s; };

  // Common ports named for display; anything not listed just shows its
  // number. Kept in step with internal/portscan's own list by eye, not by a
  // shared source: it is cosmetic, the server's list is authoritative.
  const PORT_NAMES = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3', 111: 'rpcbind',
    135: 'RPC', 139: 'NetBIOS', 143: 'IMAP', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 515: 'LPD',
    548: 'AFP', 554: 'RTSP', 587: 'SMTP', 631: 'IPP', 873: 'rsync', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL',
    1723: 'PPTP', 1883: 'MQTT', 2049: 'NFS', 2375: 'Docker', 2376: 'Docker', 3000: 'Web admin', 3306: 'MySQL',
    3389: 'RDP', 5000: 'Web admin', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 8000: 'Web admin',
    8080: 'Web admin', 8443: 'Web admin', 8888: 'Web admin', 9100: 'Printing',
  };
  const portLabel = (p) => (PORT_NAMES[p] ? p + ' (' + PORT_NAMES[p] + ')' : String(p));

  // renderPorts fetches and paints one device's port-scan panel into holder,
  // with a manual "Scan now" button. It guards every repaint on the drawer
  // still showing this same device, since its own fetch and scan calls are
  // asynchronous and the drawer can move to another device or close first.
  function renderPorts(holder, id) {
    let data = null;
    let scanning = false;
    let failed = null;

    function paint() {
      if (drawerId !== id || !holder.isConnected) return;
      holder.replaceChildren();
      if (failed) {
        holder.append(unavailable(failed) ? el('p', 'muted small', 'Port scanning is not available on this version.') : el('p', 'err small', failed.message));
        return;
      }
      const head = el('div', 'dr-ports-head');
      head.append(el('span', 'muted small', data && data.last_scanned ? 'Last scanned ' + relTime(data.last_scanned) : 'Never scanned'));
      const btn = button(scanning ? 'Scanning…' : 'Scan now', 'ghost', scan, 'refresh');
      btn.disabled = scanning;
      head.append(btn);
      holder.append(head);
      const open = ((data && data.ports) || []).filter((p) => p.open);
      if (!open.length) {
        holder.append(el('p', 'muted small', scanning ? 'Scanning…' : 'No open ports found.'));
        return;
      }
      const list = el('div', 'dr-chips');
      for (const p of open) {
        const cls = 'port-chip' + (p.risky ? ' risky' : '') + (p.newly_opened ? ' new' : '');
        const c = el('span', cls);
        c.append(document.createTextNode(portLabel(p.port)));
        if (p.newly_opened) c.append(el('span', 'port-flag', 'NEW'));
        const why = [p.risky ? p.risk_note : '', p.newly_opened ? 'Newly opened since the last scan' : ''].filter(Boolean).join(' — ');
        if (why) c.title = why;
        list.append(c);
      }
      holder.append(list);
    }

    function scan() {
      scanning = true;
      paint();
      mgmt.scanPorts(id).then((r) => {
        scanning = false;
        const found = ((r && r.devices) || []).find((x) => x.device_id === id);
        if (found) data = found;
        paint();
      }).catch((e) => { scanning = false; failed = e; paint(); });
    }

    paint();
    mgmt.portscanDevice(id).then((d) => { data = d; paint(); }).catch((e) => { failed = e; paint(); });
  }

  function paintDrawer(d) {
    const keepScroll = drawer.scrollTop;
    drawer.replaceChildren();
    const top = el('div', 'dr-head');
    const ico = el('span', 'dv-ico big');
    ico.append(icon(typeIcon(d.type), 26));
    const hw = el('div', 'dr-title');
    const nameInput = el('input', 'dr-name');
    nameInput.value = d.alias || d.name || '';
    nameInput.setAttribute('aria-label', 'Device name');
    nameInput.maxLength = 64;
    nameInput.placeholder = d.name || 'Name this device';
    nameInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') nameInput.blur(); else if (e.key === 'Escape') { nameInput.value = d.alias || d.name || ''; nameInput.blur(); } });
    nameInput.addEventListener('change', () => { const v = nameInput.value.trim(); if (v !== (d.alias || '')) patchDevice(d.id, { alias: v }).catch(() => {}); });
    hw.append(nameInput, el('span', 'muted small', [d.vendor, typeLabel(d.type)].filter(Boolean).join(' · ')));
    const x = iconButton('x', 'Close details', closeDrawer, 'drawer-x');
    top.append(ico, hw, x);
    drawer.append(top);

    // Names
    const names = d.names || {};
    const sNames = section('Names');
    const used = d.alias ? 'alias' : names.mdns ? 'mdns' : names.hostname ? 'hostname' : names.rdns ? 'rdns' : 'derived';
    sNames.append(field('Shown as', d.name || '', 'strong'));
    sNames.append(field('Your name', d.alias || 'Not set', d.alias ? '' : 'muted'));
    sNames.append(field('mDNS', names.mdns || 'None heard', names.mdns ? 'mono' : 'muted'));
    sNames.append(field('Hostname', names.hostname || 'None heard', names.hostname ? 'mono' : 'muted'));
    sNames.append(field('Reverse DNS', names.rdns || 'None', names.rdns ? 'mono' : 'muted'));
    const why = { alias: 'You named this device.', mdns: 'Taken from the name the device announces on the local network (mDNS).', hostname: 'Taken from the hostname the device reports.', rdns: 'Taken from a reverse DNS lookup of its address.', derived: 'No name was found, so it is described by its vendor and type.' }[used];
    sNames.append(el('p', 'muted small', why));
    drawer.append(sNames);

    // Hardware
    const sHw = section('Hardware');
    sHw.append(field('Vendor', d.vendor || 'Unknown', d.vendor ? '' : 'muted'));
    const typeSel = el('select');
    typeSel.setAttribute('aria-label', 'Device type');
    for (const t of TYPES) { const o = el('option', '', typeLabel(t)); o.value = t; typeSel.append(o); }
    if (d.type && !TYPES.includes(d.type)) { const o = el('option', '', typeLabel(d.type)); o.value = d.type; typeSel.append(o); }
    typeSel.value = d.type || 'unknown';
    typeSel.addEventListener('change', () => patchDevice(d.id, { type: typeSel.value }).catch(() => {}));
    sHw.append(field('Type', typeSel));
    if (d.type_reason) sHw.append(el('p', 'muted small', 'Why: ' + d.type_reason));
    sHw.append(field('MAC', (d.macs || []).join('\n') || 'Unknown', 'mono pre'));
    drawer.append(sHw);

    // Network
    const sNet = section('Network');
    sNet.append(field('Addresses', (d.ips || []).join('\n') || 'None', 'mono pre'));
    sNet.append(field('First seen', d.first_seen ? new Date(d.first_seen).toLocaleString() : 'Unknown'));
    sNet.append(field('Last seen', d.last_seen ? new Date(d.last_seen).toLocaleString() + '  (' + relTime(d.last_seen) + ')' : 'Unknown'));
    drawer.append(sNet);

    // Ports and exposure
    const sPorts = section('Ports');
    const portsHolder = el('div', 'dr-ports');
    sPorts.append(portsHolder);
    drawer.append(sPorts);
    renderPorts(portsHolder, d.id);

    // Groups
    const sG = section('Groups');
    const gl = el('div', 'dr-chips');
    for (const id of d.groups || []) {
      const g = groupById(id);
      gl.append(chip(g ? g.name : id, { color: g ? g.color : '', onRemove: () => runOne({ op: 'remove_group', group_id: id }, d) }));
    }
    if (!(d.groups || []).length) gl.append(el('span', 'muted small', 'Not in any group'));
    sG.append(gl);
    const free = groups.filter((g) => !(d.groups || []).includes(g.id));
    const addG = button('Add to group', 'ghost', (e) => openMenu(e.currentTarget, [...free.map((g) => ({ label: g.name, color: g.color, onSelect: () => runOne({ op: 'assign_group', group_id: g.id }, d) })), ...(free.length ? [{ sep: true }] : []), { label: 'New group…', ico: 'plus', onSelect: () => newGroupForDevice(addG, d) }]), 'plus');
    sG.append(addG);
    drawer.append(sG);

    // Tags
    const sT = section('Tags');
    const tl = el('div', 'dr-chips');
    for (const t of d.tags || []) tl.append(chip(t, { onRemove: () => patchDevice(d.id, { tags: (d.tags || []).filter((x) => x !== t) }).catch(() => {}) }));
    if (!(d.tags || []).length) tl.append(el('span', 'muted small', 'No tags'));
    const tf = el('form', 'inline-add');
    const ti = el('input');
    ti.placeholder = 'Add a tag';
    ti.setAttribute('aria-label', 'Add a tag');
    ti.maxLength = 32;
    const tb = button('Add', 'ghost');
    tb.type = 'submit';
    tf.append(ti, tb);
    tf.addEventListener('submit', (e) => { e.preventDefault(); const nt = normTag(ti.value); if (!nt || (d.tags || []).includes(nt)) { ti.value = ''; return; } patchDevice(d.id, { tags: [...(d.tags || []), nt] }).catch(() => {}); });
    sT.append(tl, tf);
    drawer.append(sT);

    // Notes
    const sN = section('Notes');
    const notes = el('textarea');
    notes.rows = 3;
    notes.maxLength = 1000;
    notes.value = d.notes || '';
    notes.placeholder = 'Anything worth remembering about this device';
    notes.setAttribute('aria-label', 'Notes');
    notes.addEventListener('change', () => patchDevice(d.id, { notes: notes.value }).catch(() => {}));
    sN.append(notes);
    drawer.append(sN);

    // Mode
    const sM = section('Mode');
    const cur = deviceMode(d);
    const seg = segmented(MODES.map((m) => ({ id: m.id, label: m.label })), cur, (id) => {
      if (id === 'wandering') { timerRow.hidden = false; seg.set('wandering'); modeText.textContent = MODES[1].text; return; }
      timerRow.hidden = true;
      patchDevice(d.id, modePatch(id)).catch(() => {});
    }, 'Device mode');
    const modeText = el('p', 'muted small', MODES.find((m) => m.id === cur).text);
    const timerRow = el('div', 'timer-row');
    timerRow.hidden = cur !== 'wandering';
    const tsel = el('select');
    tsel.setAttribute('aria-label', 'How long to wander');
    for (const t of TIMER_CHOICES) { const o = el('option', '', t.label); o.value = String(t.minutes); tsel.append(o); }
    tsel.value = '0';
    const go = button(cur === 'wandering' ? 'Change timer' : 'Start wandering', 'primary', () => patchDevice(d.id, modePatch('wandering', Number(tsel.value))).catch(() => {}));
    timerRow.append(tsel, go);
    sM.append(seg.root);
    if (cur === 'wandering') sM.append(el('p', 'wander-left', 'Wandering, ' + countdown(d)));
    sM.append(modeText, timerRow);
    drawer.append(sM);

    // Blocking
    const sB = section('Blocking for this device');
    const holder = el('div', 'dr-block');
    if (deviceMode(d) === 'wandering') sB.append(el('p', 'wander-left small', 'Not applied while wandering. These settings come back when the device is protected again.'));
    sB.append(holder);
    drawer.append(sB);
    if (renderBlocking) renderBlocking(holder, d);

    // Actions
    const sA = el('section', 'dr-sec dr-actions');
    const first = (d.ips || [])[0];
    sA.append(button('View history', 'ghost', () => { closeDrawer(); onOpenHistory({ ip: first || '', name: d.name, id: d.id }); }, 'history'));
    sA.append(button('Delete device', 'ghost danger', async () => {
      const ok = await confirmDialog({ title: 'Delete ' + d.name + '?', body: 'It is forgotten with its name, tags and blocking settings. It will reappear as a new device the next time it makes a DNS query.', confirm: 'Delete', danger: true });
      if (!ok) return;
      try { await mgmt.deleteDevice(d.id); list.remove([d.id]); sel.forget([d.id]); closeDrawer(); await loadGroups(); layout(); } catch (err) { notify(err.message); }
    }, 'trash'));
    drawer.append(sA);
    drawer.scrollTop = keepScroll;
  }

  async function runOne(req, d) {
    const prev = { ...d };
    list.patch(d.id, (x) => applyBulkLocal(x, req));
    const cur = list.loaded().find((x) => x.id === d.id) || applyBulkLocal(d, req);
    render(); paintDrawer(cur);
    try { await mgmt.bulk({ ids: [d.id], ...req }); await loadGroups(); onGroupsChanged(); }
    catch (err) { list.patch(d.id, () => prev); render(); paintDrawer(prev); notify(err.message); }
  }
  function newGroupForDevice(anchor, d) {
    openPopover(anchor, (panel, close) => {
      const f = el('form', 'pop-form');
      const gi = el('input');
      gi.placeholder = 'Group name';
      gi.maxLength = 40;
      gi.setAttribute('aria-label', 'New group name');
      const go = button('Create and add', 'primary');
      go.type = 'submit';
      f.append(el('label', 'pop-l', 'New group'), gi, go);
      f.addEventListener('submit', async (e) => { e.preventDefault(); if (!gi.value.trim()) return; try { const g = await createGroup(gi.value.trim()); close(); await runOne({ op: 'assign_group', group_id: g.id }, d); } catch (err) { notify(err.message); } });
      panel.append(f);
    }, { label: 'New group' });
  }

  // ------------------------------------------------------------- public
  let started = false;
  setInterval(() => { if (!root.hidden && started) render(); }, 20000);
  return {
    async show() {
      if (!started) {
        started = true;
        paintChips();
        paintGroups();
        try { await loadGroups(); } catch (e) { if (!unavailable(e)) notify('Could not load groups: ' + e.message); }
        resetList();
      } else {
        try { await loadGroups(); } catch { /* keep the old groups */ }
        list.refresh();
      }
      layout();
    },
    // Applies a filter chip (used by deep links), e.g. from the history screen.
    filterBy(key, value) { chips = addFilter({ text: '', filters: chips }, key, value).filters; paintChips(); paintGroups(); resetList(); },
    openDevice: (id) => openDrawer(id, null),
    reloadGroups: loadGroups,
    get groups() { return groups; },
    focusSearch: () => input.focus(),
    refresh: () => list.refresh(),
  };
}
