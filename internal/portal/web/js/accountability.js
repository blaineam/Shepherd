// The Accountability screen: add or remove a trusted contact, and subscribe
// them to a group or device plus a set of watched catalog items. Reuses the
// same panel, list-row and toggle look as the Blocking screen; the scope and
// item pickers here are deliberately simpler than scope.js's (that module
// computes blocking-policy "effective" status, which has no meaning for a
// subscription) rather than a mismatched reuse of it.
import { el } from './dom.js';
import { button, iconButton, toggle, emptyState, confirmDialog } from './ui.js';
import { unavailable } from './mgmt.js';

const DETAILS = [['summary', 'Summary — category and roughly when, never a domain'], ['detailed', 'Detailed — also names the exact domain']];
const MODES = [['digest', 'Digest — one rollup per window'], ['immediate', 'Immediate — sent promptly, bursts still combined']];
const TRIGGERS = [['any', 'Any access — disclosure, whether or not it was blocked'], ['blocked_only', 'Blocked only']];

export function createAccountability({ root, mgmt, notify, getGroups }) {
  let contacts = [];
  let subsByContact = new Map();
  let catalog = { entries: [] };
  let devices = [];
  let loadError = null;
  let started = false;

  root.replaceChildren();
  const head = el('div', 'pg-head');
  const title = el('h2', 'pg-title');
  title.append(el('span', '', 'Accountability'));
  head.append(title);
  const lead = el('p', 'intro muted', 'Email a trusted contact when a device in a group or scope they chose accesses a category they chose, whether or not it was blocked. Nothing is watched until a subscription exists below.');
  const content = el('div', 'acct-content');
  root.append(head, lead, content);

  function itemName(id) {
    if (id === '*') return 'Anything watched';
    const e = catalog.entries.find((x) => x.id === id);
    return e ? e.name : id;
  }

  function scopeLabel(scope) {
    const pool = scope.kind === 'group' ? getGroups() || [] : devices;
    const found = pool.find((x) => x.id === scope.id);
    const name = found ? found.name : scope.id || '…';
    return name + ' (' + (scope.kind === 'group' ? 'group' : 'device') + ')';
  }

  function paint() {
    content.replaceChildren();
    if (loadError) {
      // A 404 here almost always means the feature exists but is not
      // configured (no SMTP relay set in shepherd.toml), not that the
      // server predates it — api_accountability.go says so explicitly in
      // the response body. Show that real reason instead of the generic
      // "update the server" copy unavailableCard would give, which reads
      // as broken/stuck rather than "needs configuration."
      content.append(unavailable(loadError)
        ? emptyState('Accountability is not available', loadError.message || 'This Shepherd does not have that part of the API yet.')
        : emptyState('Could not load accountability settings', loadError.message, button('Try again', 'ghost', () => load(true))));
      return;
    }
    content.append(contactForm());
    if (!contacts.length) {
      content.append(emptyState('No contacts yet', 'Add a trusted contact above, then subscribe them to a group or device.'));
      return;
    }
    for (const c of contacts) content.append(contactCard(c));
  }

  function contactForm() {
    const f = el('form', 'cf-row panel-lite');
    const name = el('input');
    name.placeholder = 'Name';
    name.required = true;
    name.maxLength = 200;
    name.autocomplete = 'off';
    name.setAttribute('aria-label', 'Contact name');
    const email = el('input');
    email.type = 'email';
    email.placeholder = 'Email address';
    email.required = true;
    email.autocomplete = 'off';
    email.setAttribute('aria-label', 'Contact email');
    const go = button('Add contact', 'primary');
    go.type = 'submit';
    const err = el('p', 'err small');
    f.append(name, email, go, err);
    f.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      err.textContent = '';
      go.disabled = true;
      try {
        await mgmt.addContact(name.value.trim(), email.value.trim());
        name.value = '';
        email.value = '';
        await load(true);
      } catch (e) { err.textContent = e.message; }
      go.disabled = false;
    });
    return f;
  }

  function contactCard(c) {
    const card = el('section', 'cat');
    const h = el('div', 'cat-head');
    h.append(el('h3', '', c.name), el('span', 'muted small', c.email), el('span', 'grow'));
    h.append(iconButton('trash', 'Remove ' + c.name, async () => {
      const ok = await confirmDialog({ title: 'Remove ' + c.name + '?', body: 'Every subscription of theirs is removed too, and they stop receiving email right away.', confirm: 'Remove contact', danger: true });
      if (!ok) return;
      try { await mgmt.deleteContact(c.id); await load(true); } catch (e) { notify(e.message); }
    }, 'danger-i'));
    card.append(h);
    const subs = subsByContact.get(c.id) || [];
    const list = el('div', 'list-rows');
    if (!subs.length) list.append(emptyState('No subscriptions yet', ''));
    for (const s of subs) list.append(subscriptionRow(c, s));
    card.append(list);
    card.append(subscriptionForm(c));
    return card;
  }

  function subscriptionRow(c, s) {
    const row = el('div', 'list-row');
    const main = el('div', 'lr-main');
    main.append(el('div', 'lr-name', scopeLabel(s.scope)));
    main.append(el('p', 'lr-desc', (s.items || []).map(itemName).join(', ')));
    const meta = el('div', 'lr-meta');
    meta.append(el('span', 'badge', s.detail), el('span', 'badge', s.mode), el('span', 'badge', s.trigger));
    if (s.mode === 'digest' && s.digest_interval_seconds) meta.append(el('span', 'muted small', Math.round(s.digest_interval_seconds / 3600) + 'h window'));
    main.append(meta);
    row.append(main);
    row.append(iconButton('trash', 'Remove this subscription', async () => {
      try { await mgmt.deleteSubscription(s.id); await load(true); } catch (e) { notify(e.message); }
    }, 'danger-i'));
    return row;
  }

  function selectFrom(pairs, value) {
    const sel = el('select');
    for (const [v, l] of pairs) { const o = el('option', '', l); o.value = v; sel.append(o); }
    sel.value = value;
    return sel;
  }

  function subscriptionForm(c) {
    const f = el('form', 'cust-form panel-lite');
    const scopeRow = el('div', 'cf-row');
    const kindSel = selectFrom([['group', 'A group'], ['device', 'A device']], 'group');
    kindSel.setAttribute('aria-label', 'Scope kind');
    const idSel = el('select');
    idSel.setAttribute('aria-label', 'Group or device');
    function fillIdSel() {
      idSel.replaceChildren();
      const pool = kindSel.value === 'group' ? (getGroups() || []) : devices;
      if (!pool.length) idSel.append(el('option', '', kindSel.value === 'group' ? 'No groups yet' : 'No devices yet'));
      for (const p of pool) { const o = el('option', '', p.name); o.value = p.id; idSel.append(o); }
    }
    fillIdSel();
    kindSel.addEventListener('change', fillIdSel);
    scopeRow.append(kindSel, idSel);

    const wildcard = toggle({ label: 'Watch anything this scope touches', onChange: (on) => { grid.hidden = on; } });
    const wildRow = el('label', 'acct-item-row');
    wildRow.append(wildcard.root, el('span', '', 'Watch anything this scope touches'));
    const grid = el('div', 'acct-items');
    const checks = [];
    for (const e of catalog.entries) {
      const t = toggle({ label: 'Watch ' + e.name });
      const row = el('label', 'acct-item-row');
      row.append(t.root, el('span', '', e.name));
      grid.append(row);
      checks.push({ id: e.id, input: t.input });
    }

    const settingsRow = el('div', 'cf-row');
    const detailSel = selectFrom(DETAILS, 'summary');
    detailSel.setAttribute('aria-label', 'Detail level');
    const modeSel = selectFrom(MODES, 'digest');
    modeSel.setAttribute('aria-label', 'Delivery mode');
    const triggerSel = selectFrom(TRIGGERS, 'any');
    triggerSel.setAttribute('aria-label', 'Trigger');
    settingsRow.append(detailSel, modeSel, triggerSel);

    const intervalRow = el('div', 'cf-row');
    const interval = el('input');
    interval.type = 'number';
    interval.min = '0';
    interval.placeholder = 'Digest window in hours (blank = daily)';
    interval.setAttribute('aria-label', 'Digest window in hours');
    intervalRow.append(interval);
    const syncInterval = () => { intervalRow.hidden = modeSel.value !== 'digest'; };
    modeSel.addEventListener('change', syncInterval);
    syncInterval();

    const go = button('Add subscription', 'ghost');
    go.type = 'submit';
    const err = el('p', 'err small');
    f.append(el('p', 'muted small', 'New subscription'), scopeRow, wildRow, grid, settingsRow, intervalRow, go, err);
    f.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      err.textContent = '';
      if (!idSel.value) { err.textContent = kindSel.value === 'group' ? 'Create a group on the Devices screen first.' : 'No devices are known yet.'; return; }
      const items = wildcard.input.checked ? ['*'] : checks.filter((x) => x.input.checked).map((x) => x.id);
      if (!items.length) { err.textContent = 'Choose at least one item to watch, or "Watch anything".'; return; }
      const body = {
        contact_id: c.id, scope: { kind: kindSel.value, id: idSel.value }, items,
        detail: detailSel.value, mode: modeSel.value, trigger: triggerSel.value,
      };
      if (modeSel.value === 'digest' && interval.value) body.digest_interval_seconds = Math.round(Number(interval.value) * 3600);
      go.disabled = true;
      try {
        await mgmt.addSubscription(body);
        await load(true);
      } catch (e) { err.textContent = e.message; }
      go.disabled = false;
    });
    return f;
  }

  async function ensureDevices() {
    if (devices.length) return;
    try { const r = await mgmt.devices({ limit: 200 }); devices = r.devices || []; } catch { /* best effort: the form still works with an empty list */ }
  }

  async function load(force) {
    loadError = null;
    try {
      if (force || !catalog.entries.length) catalog = await mgmt.catalog();
      await ensureDevices();
      const cs = await mgmt.contacts();
      contacts = cs.contacts || [];
      const next = new Map();
      for (const c of contacts) {
        const r = await mgmt.subscriptions(c.id);
        next.set(c.id, r.subscriptions || []);
      }
      subsByContact = next;
    } catch (e) { loadError = e; }
    paint();
  }

  return {
    async show() {
      started = true;
      await load(true);
    },
    onGroupsChanged() { if (started && !root.hidden) paint(); },
  };
}
