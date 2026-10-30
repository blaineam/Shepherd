// The Blocking screen: pick a scope (network, a group or a device), then turn
// apps, categories and blocklists on or off for it, add domain rules and policy
// switches. Inherited settings are shown, not hidden. Edits are optimistic.
import { el } from './dom.js';
import { icon, iconButton, button, toggle, segmented, emptyState, confirmDialog, relTime, unavailableCard, debounce } from './ui.js';
import { NETWORK, sameScope, scopeLabel, itemStatus, nextItemValue, rulesView, switchView, effectiveSummary, inheritedSources, dataFor, normalizeDomain } from './scope.js';
import { groupCatalog, listStatus, fmtCount, sources, safeHref, bundleProgress, matchesQuery } from './catalog.js';
import { unavailable } from './mgmt.js';

const TABS = [['apps', 'Apps and categories'], ['lists', 'Blocklists'], ['custom', 'Your lists'], ['rules', 'Domain rules'], ['switches', 'Settings']];

export function createBlocking({ root, mgmt, store, notify, getGroups, onOpenDevice }) {
  let scope = NETWORK;
  let scopeGroups = []; // group ids when scope is a device
  let deviceNames = {};
  let tab = 'apps';
  let query = '';
  let loadError = null;
  let started = false;

  root.replaceChildren();
  const head = el('div', 'pg-head');
  const title = el('h2', 'pg-title');
  title.append(el('span', '', 'Blocking'));
  head.append(title);

  const scopeBox = el('section', 'bk-scope panel-lite');
  scopeBox.setAttribute('aria-label', 'Blocking scope');
  const body = el('div', 'bk-body');
  const bar = el('div', 'bk-bar');
  const content = el('div', 'bk-content');
  root.append(head, scopeBox, body);
  body.append(bar, content);

  // ------------------------------------------------------------- scope picker
  const groups = () => getGroups() || [];
  const labelOf = (s) => scopeLabel(s, { groups: groups(), devices: deviceNames });

  function paintScope() {
    scopeBox.replaceChildren();
    const top = el('div', 'bk-scope-top');
    const lab = el('span', 'k', 'Applies to');
    const seg = segmented([{ id: 'network', label: 'Whole network' }, { id: 'group', label: 'A group' }, { id: 'device', label: 'One device' }], scope.kind, (k) => {
      if (k === 'network') setScope(NETWORK);
      else if (k === 'group') { const g = groups()[0]; if (g) setScope({ kind: 'group', id: g.id }); else { notify('Create a group on the Devices screen first.'); seg.set(scope.kind); } }
      else { scope = { kind: 'device', id: '' }; scopeGroups = []; paintScope(); const i = scopeBox.querySelector('.combo input'); if (i) i.focus(); }
    }, 'Scope kind');
    top.append(lab, seg.root);

    if (scope.kind === 'group') {
      const sel = el('select');
      sel.setAttribute('aria-label', 'Group');
      for (const g of groups()) { const o = el('option', '', g.name + ' (' + (g.count ?? 0) + ')'); o.value = g.id; sel.append(o); }
      sel.value = scope.id;
      sel.addEventListener('change', () => setScope({ kind: 'group', id: sel.value }));
      top.append(sel);
    } else if (scope.kind === 'device') {
      top.append(deviceCombo());
    }
    scopeBox.append(top);

    if (scope.kind === 'device' && !scope.id) {
      scopeBox.append(el('p', 'bk-desc muted', 'Search for a device by name, vendor or address, then choose it.'));
      return;
    }
    const desc = el('p', 'bk-desc');
    if (scope.kind === 'network') desc.textContent = 'These settings apply to every device. Groups and single devices can add to them, never remove them.';
    else if (scope.kind === 'group') {
      const g = groups().find((x) => x.id === scope.id);
      desc.textContent = 'Applies to ' + (g ? (g.count ?? 0) + ' device' + (g.count === 1 ? '' : 's') + ' in ' + g.name : 'this group') + ', on top of the network settings.';
    } else desc.textContent = 'Applies only to ' + labelOf(scope) + ', on top of the network' + (scopeGroups.length ? ' and group' : '') + ' settings.';
    scopeBox.append(desc);
    if (store.ready) scopeBox.append(summaryRow());
  }

  function summaryRow() {
    const s = effectiveSummary(store.policy, store.catalog, scope, scopeGroups);
    const row = el('div', 'bk-sum');
    const bits = [];
    const add = (n, w, w2) => { if (n) bits.push(n + ' ' + (n === 1 ? w : w2 || w + 's')); };
    add(s.apps, 'app'); add(s.categories, 'category', 'categories'); add(s.lists, 'blocklist'); add(s.custom, 'custom list');
    add(s.blockRules, 'block rule'); add(s.allowRules, 'allow rule');
    const main = el('div', 'bk-sum-main');
    main.append(el('strong', '', bits.length ? 'Effective here: ' : 'Nothing is blocked here yet'));
    if (bits.length) main.append(el('span', 'mono', bits.join(', ')));
    row.append(main);
    const src = inheritedSources(store.policy, scope, scopeGroups);
    if (scope.kind !== 'network') {
      const inh = el('div', 'bk-inh');
      if (src.length) {
        inh.append(el('span', 'k', 'Inherited from'));
        for (const x of src) inh.append(el('span', 'srcchip', labelOf(x.scope) + ' · ' + (x.items + x.rules)));
      } else inh.append(el('span', 'muted small', 'Nothing inherited. Everything set at the network level or in groups would show up here.'));
      row.append(inh);
    }
    if (s.switches.length) { const sw = el('div', 'bk-inh'); sw.append(el('span', 'k', 'Switches on'), ...s.switches.map((t) => el('span', 'srcchip', t))); row.append(sw); }
    return row;
  }

  function deviceCombo() {
    const wrap = el('div', 'combo');
    const input = el('input');
    input.type = 'search';
    input.placeholder = 'Find a device…';
    input.setAttribute('role', 'combobox');
    input.setAttribute('aria-expanded', 'false');
    input.setAttribute('aria-autocomplete', 'list');
    input.setAttribute('aria-label', 'Device');
    input.autocomplete = 'off';
    if (scope.id) input.value = labelOf(scope);
    const ul = el('ul', 'combo-list');
    ul.setAttribute('role', 'listbox');
    ul.hidden = true;
    let items = [], idx = -1;
    const show = (list) => {
      items = list; idx = -1;
      ul.replaceChildren();
      ul.hidden = !list.length;
      input.setAttribute('aria-expanded', list.length ? 'true' : 'false');
      list.forEach((d, i) => {
        const li = el('li');
        li.setAttribute('role', 'option');
        li.append(el('span', 'grow', d.name), el('span', 'muted mono small', (d.ips || [])[0] || ''));
        li.addEventListener('mousedown', (e) => { e.preventDefault(); pick(d); });
        ul.append(li);
      });
    };
    const mark = () => { [...ul.children].forEach((li, i) => li.setAttribute('aria-selected', i === idx ? 'true' : 'false')); };
    const pick = (d) => { deviceNames[d.id] = d.name; scopeGroups = d.groups || []; show([]); setScope({ kind: 'device', id: d.id }); };
    const search = debounce(async () => {
      try { const r = await mgmt.devices({ q: input.value.trim(), sort: 'recent', offset: 0, limit: 8 }); show(r.devices || []); } catch (e) { show([]); if (!unavailable(e)) notify(e.message); }
    }, 160);
    input.addEventListener('input', search);
    input.addEventListener('focus', () => { if (!scope.id) search(); input.select(); });
    input.addEventListener('blur', () => { setTimeout(() => show([]), 120); if (scope.id) input.value = labelOf(scope); });
    input.addEventListener('keydown', (e) => {
      if (e.key === 'ArrowDown') { e.preventDefault(); idx = Math.min(items.length - 1, idx + 1); mark(); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); idx = Math.max(0, idx - 1); mark(); }
      else if (e.key === 'Enter' && items[idx]) { e.preventDefault(); pick(items[idx]); }
      else if (e.key === 'Escape') show([]);
    });
    wrap.append(input, ul);
    return wrap;
  }

  function setScope(s, name, groupIds) {
    scope = { kind: s.kind, id: s.id || '' };
    if (name && s.kind === 'device') deviceNames[s.id] = name;
    if (groupIds) scopeGroups = groupIds;
    else if (s.kind === 'device' && s.id && !scopeGroups.length) {
      mgmt.device(s.id).then((d) => { if (sameScope(scope, s)) { deviceNames[s.id] = d.name; scopeGroups = d.groups || []; repaint(); } }).catch(() => {});
    } else if (s.kind !== 'device') scopeGroups = [];
    repaint();
  }

  // ------------------------------------------------------------- tabs and search
  function paintBar() {
    bar.replaceChildren();
    const sb = el('div', 'sbox bk-search');
    sb.append(icon('search', 15, 'sbox-ico'));
    const inp = el('input');
    inp.type = 'search';
    inp.placeholder = 'Search every app, category and list';
    inp.setAttribute('aria-label', 'Search the catalog');
    inp.value = query;
    inp.autocomplete = 'off';
    inp.addEventListener('input', () => { query = inp.value.trim(); paintContent(); });
    sb.append(inp);
    const tabs = el('div', 'subtabs');
    tabs.setAttribute('role', 'tablist');
    for (const [id, label] of TABS) {
      const b = el('button', '', label);
      b.type = 'button';
      b.setAttribute('role', 'tab');
      b.setAttribute('aria-selected', !query && tab === id ? 'true' : 'false');
      b.addEventListener('click', () => { tab = id; query = ''; paintBar(); paintContent(); });
      tabs.append(b);
    }
    const ctx = el('span', 'bk-ctx');
    ctx.append(el('span', 'k', 'Editing'), el('strong', '', scope.kind === 'device' && !scope.id ? '\u2026' : labelOf(scope)));
    bar.append(sb, tabs, ctx);
  }

  function repaint() {
    paintScope();
    if (started) { const i = bar.querySelector('.bk-ctx strong'); if (i) i.textContent = scope.kind === 'device' && !scope.id ? '\u2026' : labelOf(scope); }
    paintContent();
  }

  // Redraws the content keeping scroll position and keyboard focus.
  function paintContent() {
    const focusKey = document.activeElement && document.activeElement.dataset ? document.activeElement.dataset.key : '';
    const st = root.scrollTop;
    const inSearch = document.activeElement && document.activeElement.closest && document.activeElement.closest('.bk-search');
    content.replaceChildren();
    if (loadError) { content.append(unavailable(loadError) ? unavailableCard('Blocking policy') : emptyState('Could not load blocking settings', loadError.message, button('Try again', 'ghost', () => load(true)))); return; }
    if (!store.ready) { content.append(el('p', 'muted', 'Loading…')); return; }
    if (scope.kind === 'device' && !scope.id) { content.append(emptyState('Choose a device', 'Pick a device above to see and change what is blocked for it alone.')); return; }
    if (query) paintSearch(); else if (tab === 'apps') paintApps(); else if (tab === 'lists') paintLists(); else if (tab === 'custom') paintCustom(); else if (tab === 'rules') paintRules(); else paintSwitches();
    root.scrollTop = st;
    if (focusKey && !inSearch) { const t = content.querySelector('[data-key="' + CSS.escape(focusKey) + '"]'); if (t) t.focus({ preventScroll: true }); }
  }

  // ------------------------------------------------------------- item widgets
  const isBlocked = (id) => itemStatus(store.policy, store.catalog, scope, scopeGroups, id).effective;

  async function setItem(id, on, name) {
    const st = itemStatus(store.policy, store.catalog, scope, scopeGroups, id);
    try { await store.setItem(scope, id, nextItemValue(st, on)); }
    catch (e) { notify('Could not change ' + name + ': ' + e.message); }
  }

  function badges(st) {
    const out = [];
    for (const i of st.inherited) out.push(el('span', 'badge inh', (i.via ? i.via.name + ' in ' : '') + labelOf(i.scope)));
    if (!st.here) for (const b of st.via) out.push(el('span', 'badge via', 'via ' + b.name));
    return out;
  }

  function itemToggle(e, st) {
    const locked = st.inherited.length > 0;
    const why = st.inherited.length ? 'Blocked by ' + labelOf(st.inherited[0].scope) + '. Change it there.' : st.via.length ? 'Included in ' + st.via[0].name + '. Switch off to carve it out.' : '';
    const t = toggle({ checked: st.effective, label: 'Block ' + e.name + ' for ' + labelOf(scope), disabled: locked, title: why, onChange: (v) => setItem(e.id, v, e.name) });
    t.input.dataset.key = 'item:' + e.id;
    return t.root;
  }

  function tile(e) {
    const st = itemStatus(store.policy, store.catalog, scope, scopeGroups, e.id);
    const t = el('div', 'tile-app' + (st.effective ? ' on' : '') + (st.effective && !st.here ? ' inh' : ''));
    const top = el('div', 'ta-top');
    top.append(el('span', 'ta-name', e.name), itemToggle(e, st));
    t.append(top, el('p', 'ta-desc', e.description));
    const foot = el('div', 'ta-foot');
    if (e.includes && e.includes.length) foot.append(el('span', 'muted small', 'Covers ' + e.includes.length + ' items'));
    else if (e.approx_entries) foot.append(el('span', 'muted small mono', e.approx_entries + ' hosts'));
    foot.append(...badges(st));
    t.append(foot);
    return t;
  }

  function sectionHead(name, bundle, entries) {
    const h = el('div', 'cat-head');
    h.append(el('h3', '', name));
    const prog = bundleProgress(bundle, entries, isBlocked);
    h.append(el('span', 'cat-prog mono', prog.on + ' of ' + prog.total + ' blocked'));
    h.append(el('span', 'grow'));
    if (bundle) {
      const st = itemStatus(store.policy, store.catalog, scope, scopeGroups, bundle.id);
      const lock = st.inherited.length > 0;
      const lbl = el('span', 'muted small', 'Block all');
      h.append(lbl);
      const t = toggle({ checked: st.effective, label: 'Block all ' + name + ' for ' + labelOf(scope), disabled: lock, title: lock ? 'Blocked by ' + labelOf(st.inherited[0].scope) : '', onChange: (v) => setItem(bundle.id, v, bundle.name) });
      t.input.dataset.key = 'item:' + bundle.id;
      h.append(t.root);
    }
    return h;
  }

  function listRow(e) {
    const st = itemStatus(store.policy, store.catalog, scope, scopeGroups, e.id);
    const ls = listStatus(store.policy, e.id);
    const row = el('div', 'list-row' + (st.effective ? ' on' : ''));
    row.append(itemToggle(e, st));
    const main = el('div', 'lr-main');
    const nm = el('div', 'lr-name');
    nm.append(el('span', '', e.name));
    if (e.recommended) nm.append(el('span', 'badge rec', 'Recommended'));
    nm.append(...badges(st));
    main.append(nm, el('p', 'lr-desc', e.description));
    const meta = el('div', 'lr-meta');
    const count = ls && ls.count ? ls.count : e.approx_entries;
    if (count) meta.append(el('span', 'mono', fmtCount(count) + ' entries'));
    if (e.license) { const lb = el('span', 'badge lic', e.license); lb.title = e.license; meta.append(lb); }
    if (ls && Number.isFinite(ls.updated)) meta.append(el('span', 'muted small', 'Updated ' + relTime(ls.updated)));
    if (ls && ls.error) { const b = el('span', 'badge bad', 'Error'); b.title = ls.error; meta.append(b, el('span', 'err-text small', ls.error)); }
    const href = safeHref(e.homepage);
    if (href) { const a = el('a', 'ext'); a.href = href; a.target = '_blank'; a.rel = 'noopener noreferrer'; a.append(el('span', '', 'Project'), icon('link', 12)); meta.append(a); }
    main.append(meta);
    row.append(main);
    return row;
  }

  // ------------------------------------------------------------- tabs
  function paintApps() {
    const g = groupCatalog(store.catalog, '');
    if (!g.apps.length) { content.append(emptyState('No apps in the catalog', 'This server has no app entries yet.')); return; }
    content.append(intro('Block whole apps and services for ' + (scope.kind === 'network' ? 'everyone' : labelOf(scope)) + '. Each tile blocks the app’s known domains. Turn on “Block all” to take a whole category.'));
    const withApps = new Set(g.apps.map((x) => x.category));
    for (const sec of g.apps) {
      const s = el('section', 'cat');
      s.append(sectionHead(sec.category, sec.bundle, sec.entries.filter((e) => !(e.includes && e.includes.length))));
      const grid = el('div', 'tiles-grid');
      for (const e of sec.entries) grid.append(tile(e));
      s.append(grid);
      content.append(s);
    }
    const only = store.catalog.entries.filter((e) => e.kind === 'category' && !withApps.has(e.category));
    if (only.length) {
      const s = el('section', 'cat');
      const h = el('div', 'cat-head');
      h.append(el('h3', '', 'Whole categories'), el('span', 'cat-prog muted', 'one switch for a group of blocklists'));
      s.append(h);
      const grid = el('div', 'tiles-grid');
      for (const e of only) grid.append(tile(e));
      s.append(grid);
      content.append(s);
    }
  }

  function paintLists() {
    const g = groupCatalog(store.catalog, '');
    const head = el('div', 'lists-head');
    head.append(intro('Blocklists are community-maintained collections of domains. Turn on the ones you want; Shepherd downloads and refreshes them.'));
    head.append(button('Refresh all', 'ghost', async (ev) => { const b = ev.currentTarget; b.disabled = true; try { await store.refreshLists(); notify('Refreshing lists. Counts update in a moment.'); } catch (e) { notify(e.message); } b.disabled = false; }, 'refresh'));
    content.append(head);
    if (!g.lists.length) content.append(emptyState('No blocklists in the catalog', 'This server has no list entries yet.'));
    for (const sec of g.lists) {
      const s = el('section', 'cat');
      const h = el('div', 'cat-head');
      h.append(el('h3', '', sec.category));
      s.append(h);
      const wrap = el('div', 'list-rows');
      for (const e of sec.entries) wrap.append(listRow(e));
      s.append(wrap);
      content.append(s);
    }
    const src = sources(store.catalog);
    if (src.length) {
      const f = el('section', 'attrib');
      f.append(el('h3', '', 'Sources and licenses'), el('p', 'muted small', 'Lists belong to their maintainers and keep their own licenses. Shepherd links to each project.'));
      const ul = el('ul', 'attrib-list');
      for (const s of src) {
        const li = el('li');
        const href = safeHref(s.homepage);
        if (href) { const a = el('a'); a.href = href; a.target = '_blank'; a.rel = 'noopener noreferrer'; a.textContent = s.name; li.append(a); } else li.append(el('span', '', s.name));
        if (s.license) li.append(el('span', 'badge', s.license));
        ul.append(li);
      }
      f.append(ul);
      content.append(f);
    }
  }

  function paintCustom() {
    content.append(intro('Add your own list by URL or by pasting domains. A list can be switched on for the network, a group or a single device like any other.'));
    content.append(customForm());
    const cl = store.policy.custom_lists;
    const wrap = el('div', 'list-rows');
    if (!cl.length) wrap.append(emptyState('No custom lists yet', 'Lists you add appear here.'));
    for (const c of cl) {
      const e = { id: c.id, name: c.name };
      const st = itemStatus(store.policy, store.catalog, scope, scopeGroups, c.id);
      const ls = listStatus(store.policy, c.id);
      const row = el('div', 'list-row' + (st.effective ? ' on' : ''));
      row.append(itemToggle(e, st));
      const main = el('div', 'lr-main');
      const nm = el('div', 'lr-name');
      nm.append(el('span', '', c.name), el('span', 'badge', c.category || 'Other'), ...badges(st));
      main.append(nm);
      const meta = el('div', 'lr-meta');
      meta.append(el('span', 'mono', fmtCount(c.count || 0) + ' entries'), el('span', 'muted small', c.inline ? 'Pasted text' : c.url || ''));
      if (ls && ls.error) { meta.append(el('span', 'badge bad', 'Error'), el('span', 'err-text small', ls.error)); }
      main.append(meta);
      const rm = iconButton('trash', 'Remove list ' + c.name, async () => {
        const ok = await confirmDialog({ title: 'Remove ' + c.name + '?', body: 'It is switched off everywhere it was on (network, groups and devices).', confirm: 'Remove list', danger: true });
        if (!ok) return;
        try { await store.delCustom(c.id); } catch (err) { notify(err.message); }
      }, 'danger-i');
      row.append(main, rm);
      wrap.append(row);
    }
    content.append(wrap);
  }

  function customForm() {
    const f = el('form', 'cust-form panel-lite');
    let mode = 'url';
    const name = el('input');
    name.placeholder = 'List name';
    name.maxLength = 60;
    name.required = true;
    name.setAttribute('aria-label', 'List name');
    const cat = el('select');
    cat.setAttribute('aria-label', 'Category');
    for (const c of [...store.catalog.categories, 'Other']) { const o = el('option', '', c); o.value = c; cat.append(o); }
    cat.value = 'Other';
    const url = el('input');
    url.type = 'url';
    url.placeholder = 'https://example.com/blocklist.txt';
    url.setAttribute('aria-label', 'List URL');
    const text = el('textarea');
    text.rows = 4;
    text.placeholder = 'One domain per line, or a hosts file. Lines starting with # are ignored.';
    text.setAttribute('aria-label', 'Pasted domains');
    text.hidden = true;
    const seg = segmented([{ id: 'url', label: 'From a URL' }, { id: 'paste', label: 'Paste text' }], mode, (m) => { mode = m; url.hidden = m !== 'url'; text.hidden = m !== 'paste'; }, 'Source');
    const go = button('Add list', 'primary');
    go.type = 'submit';
    const row = el('div', 'cf-row');
    row.append(name, cat);
    const err = el('p', 'err small');
    f.append(seg.root, row, url, text, go, err);
    f.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      err.textContent = '';
      const body = { name: name.value.trim(), category: cat.value };
      if (mode === 'url') { if (!/^https?:\/\//i.test(url.value.trim())) { err.textContent = 'Enter an http or https address.'; return; } body.url = url.value.trim(); }
      else { if (!text.value.trim()) { err.textContent = 'Paste at least one domain.'; return; } body.inline = text.value; }
      go.disabled = true;
      try { await store.addCustom(body); name.value = ''; url.value = ''; text.value = ''; notify('Added ' + body.name + '. Switch it on below.'); paintContent(); } catch (e) { err.textContent = e.message; }
      go.disabled = false;
    });
    return f;
  }

  function paintRules() {
    content.append(intro('Rules for single domains. They also cover subdomains. An allow rule at a more specific level (device over group over network) wins over a block from a broader one.'));
    const f = el('form', 'rule-add panel-lite');
    const d = el('input');
    d.placeholder = 'example.com';
    d.required = true;
    d.setAttribute('aria-label', 'Domain');
    d.autocomplete = 'off';
    d.spellcheck = false;
    const k = el('select');
    k.setAttribute('aria-label', 'Rule type');
    for (const [v, l] of [['block', 'Block'], ['allow', 'Allow']]) { const o = el('option', '', l); o.value = v; k.append(o); }
    const go = button('Add rule', 'primary');
    go.type = 'submit';
    const err = el('p', 'err small');
    f.append(d, k, go, err);
    f.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      err.textContent = '';
      const dom = normalizeDomain(d.value);
      if (!dom) { err.textContent = 'That does not look like a domain name.'; return; }
      try { await store.addRule(scope, k.value, dom); d.value = ''; paintScope(); paintContent(); d.focus(); } catch (e) { err.textContent = e.message; }
    });
    content.append(f);
    const rules = rulesView(store.policy, scope, scopeGroups);
    const ul = el('ul', 'rule-list');
    if (!rules.length) ul.append(el('li', 'muted', 'No rules at this level or above.'));
    for (const r of rules) {
      const li = el('li', r.here ? '' : 'inh');
      li.append(el('span', 'act ' + (r.kind === 'block' ? 'blocked' : 'allowed'), r.kind), el('span', 'grow mono', r.domain));
      if (r.here) {
        li.append(iconButton('trash', 'Remove ' + r.kind + ' rule for ' + r.domain, async () => { try { await store.delRule(scope, r.kind, r.domain); paintScope(); } catch (e) { notify(e.message); } }));
      } else li.append(el('span', 'badge inh', 'From ' + labelOf(r.scope)));
      ul.append(li);
    }
    content.append(ul);
  }

  function paintSwitches() {
    content.append(intro('Switches change how Shepherd answers for specific services. They apply on top of the lists.'));
    const list = el('div', 'list-rows');
    const sw = store.policy.switches;
    if (!sw.length) list.append(emptyState('No settings available', 'This server has no policy switches.'));
    for (const s of sw) {
      const v = switchView(store.policy, scope, scopeGroups, s.name);
      const locked = v.inherited.length > 0;
      const row = el('div', 'list-row' + (v.effective ? ' on' : ''));
      const t = toggle({ checked: v.effective, label: s.title || s.name, disabled: locked, title: locked ? 'Turned on by ' + labelOf(v.inherited[0]) + '. Change it there.' : '', onChange: async (on) => { try { await store.setSwitch(scope, s.name, on ? true : null); paintScope(); } catch (e) { notify(e.message); } } });
      t.input.dataset.key = 'sw:' + s.name;
      row.append(t.root);
      const main = el('div', 'lr-main');
      const nm = el('div', 'lr-name');
      nm.append(el('span', '', s.title || s.name));
      for (const i of v.inherited) nm.append(el('span', 'badge inh', labelOf(i)));
      main.append(nm, el('p', 'lr-desc', s.description || ''));
      row.append(main);
      list.append(row);
    }
    content.append(list);
  }

  function paintSearch() {
    const g = groupCatalog(store.catalog, query);
    const bundles = store.catalog.entries.filter((e) => e.kind === 'category' && matchesQuery(e, query));
    const total = g.appCount + g.listCount + bundles.length;
    const h = el('div', 'search-head');
    h.append(el('strong', '', total + ' result' + (total === 1 ? '' : 's') + ' for “' + query + '”'));
    content.append(h);
    if (!total) { content.append(emptyState('Nothing matches', 'Try a shorter word, an app name or a category like Gaming.')); return; }
    if (g.apps.length) {
      const s = el('section', 'cat');
      s.append(el('div', 'cat-head', null));
      s.firstChild.append(el('h3', '', 'Apps and services'));
      const grid = el('div', 'tiles-grid');
      for (const sec of g.apps) for (const e of sec.entries) grid.append(tile(e));
      s.append(grid);
      content.append(s);
    }
    if (bundles.length) {
      const s = el('section', 'cat');
      s.append(el('div', 'cat-head'));
      s.firstChild.append(el('h3', '', 'Whole categories'));
      const grid = el('div', 'tiles-grid');
      for (const e of bundles) grid.append(tile(e));
      s.append(grid);
      content.append(s);
    }
    if (g.lists.length) {
      const s = el('section', 'cat');
      s.append(el('div', 'cat-head'));
      s.firstChild.append(el('h3', '', 'Blocklists'));
      const wrap = el('div', 'list-rows');
      for (const sec of g.lists) for (const e of sec.entries) wrap.append(listRow(e));
      s.append(wrap);
      content.append(s);
    }
  }

  const intro = (t) => el('p', 'intro muted', t);

  // ------------------------------------------------------------- lifecycle
  async function load(force) {
    loadError = null;
    try { await store.load(force); } catch (e) { loadError = e; }
    repaint();
  }

  store.subscribe(() => { if (!root.hidden) { if (store.ready) paintScope(); paintContent(); } });

  return {
    async show() {
      if (!started) { started = true; paintBar(); }
      // Repaint immediately with whatever we have, then refresh.
      repaint();
      await load(store.ready);
    },
    setScope(s, name, groupIds) { if (!started) { started = true; paintBar(); } setScope(s, name, groupIds); },
    get scope() { return scope; },
    onGroupsChanged() { if (scope.kind === 'group' && !groups().some((g) => g.id === scope.id)) scope = NETWORK; if (started && !root.hidden) { store.invalidate(); load(false); } },
  };
}

// The compact policy card in the device drawer.
export function createDevicePolicy({ store, notify, openBlocking }) {
  return function render(holder, device) {
    const scope = { kind: 'device', id: device.id };
    const groupIds = device.groups || [];
    holder.replaceChildren();
    if (!store.ready) {
      holder.append(el('p', 'muted small', 'Loading…'));
      store.load().then(() => { if (holder.isConnected) render(holder, device); }).catch((e) => { holder.replaceChildren(unavailable(e) ? el('p', 'muted small', 'Blocking is not available on this version.') : el('p', 'err small', e.message)); });
      return;
    }
    const cat = store.catalog, pol = store.policy;
    const byId = new Map(cat.entries.map((e) => [e.id, e]));
    for (const c of pol.custom_lists) byId.set(c.id, { id: c.id, name: c.name, kind: 'custom' });
    const sum = effectiveSummary(pol, cat, scope, groupIds);
    const line = el('p', 'dr-sum');
    line.append(el('strong', 'mono', String(sum.here)), document.createTextNode(' set here, '), el('strong', 'mono', String(sum.inherited)), document.createTextNode(' inherited from network and groups.'));
    holder.append(line);
    const mine = Object.entries(dataFor(pol, scope).items).filter(([, v]) => v).map(([id]) => byId.get(id)).filter(Boolean);
    const chips = el('div', 'dr-chips');
    for (const e of mine) {
      const c = el('span', 'tchip');
      c.append(el('span', 'tchip-t', e.name));
      const x = el('button', 'tchip-x');
      x.type = 'button';
      x.setAttribute('aria-label', 'Stop blocking ' + e.name + ' for this device');
      x.append(icon('x', 11));
      x.addEventListener('click', async () => { try { await store.setItem(scope, e.id, null); render(holder, device); } catch (err) { notify(err.message); } });
      c.append(x);
      chips.append(c);
    }
    if (!mine.length) chips.append(el('span', 'muted small', 'Nothing blocked for this device alone.'));
    holder.append(chips);

    const f = el('form', 'inline-add');
    const inp = el('input');
    inp.placeholder = 'Block an app for this device';
    inp.setAttribute('aria-label', 'Block an app or list for this device');
    const dl = el('datalist');
    dl.id = 'dr-apps-' + device.id;
    inp.setAttribute('list', dl.id);
    for (const e of cat.entries) if (e.kind !== 'category') { const o = el('option'); o.value = e.name; dl.append(o); }
    const go = button('Block', 'ghost');
    go.type = 'submit';
    f.append(inp, dl, go);
    f.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const v = inp.value.trim().toLowerCase();
      const e = cat.entries.find((x) => x.name.toLowerCase() === v);
      if (!e) { notify('Pick a name from the list of apps and blocklists.'); return; }
      try { await store.setItem(scope, e.id, true); render(holder, device); } catch (err) { notify(err.message); }
    });
    holder.append(f);
    holder.append(button('Open full blocking settings', 'ghost wide', () => openBlocking({ kind: 'device', id: device.id }, device), 'shield'));
  };
}
