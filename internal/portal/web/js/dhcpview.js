// The DHCP screen: what DHCP mode is doing, what it would hand out, the
// current leases, the address reservations, and a plainly worded account of
// what turning it on will do.
//
// Every name, address and hostname here comes from a device on the network or
// from the owner's typing, so all text is set with textContent.
import { el } from './dom.js';
import { button, emptyState, unavailableCard, confirmDialog, relTime } from './ui.js';
import { unavailable } from './mgmt.js';
import { validateReservation, validateRange, suggestRange, rangeSummary, conflictTone, modeLabel, stateSummary, consequences, sortLeases, filterLeases, leaseBody, originLabel, normalizeMAC } from './dhcp.js';

// inPool is the note beside a reserved address that sits inside the dynamic
// range. Not a problem; worth saying.
const inPool = (ip, set) => {
  const n = (a) => a.split('.').reduce((acc, p) => acc * 256 + Number(p), 0);
  try { return n(set.pool_start) <= n(ip) && n(ip) <= n(set.pool_end); } catch { return false; }
};

export function createDhcp({ root, mgmt, notify, onOpenDevice }) {
  let data = null;
  let loadError = null;
  let query = '';
  let editing = ''; // MAC of the reservation being edited, '' for the add form

  root.replaceChildren();
  const head = el('div', 'pg-head stack');
  const title = el('h2', 'pg-title');
  title.append(el('span', '', 'DHCP'));
  head.append(title, el('p', 'pg-sub muted',
    'Shepherd can serve this network\'s addresses, and route the devices it leases through itself so both directions of their '
    + 'traffic are measured rather than estimated. It is off until you turn it on, and it has three positions rather than two: '
    + 'off, watching (it listens and cannot answer), and serving. Read docs/DHCP.md before serving: this is the one setting here '
    + 'that can take the house off the internet.'));
  const body = el('div', 'rp-body');
  root.append(head, body);

  const stateCard = el('section', 'card');
  const whatCard = el('section', 'card');
  const settingsCard = el('section', 'card');
  const rangeCard = el('section', 'card');
  const resCard = el('section', 'card');
  const leaseCard = el('section', 'card');

  const cardHead = (t, extra) => { const h = el('div', 'card-h'); h.append(el('h3', 'card-t', t)); if (extra) h.append(extra); return h; };
  const kvList = () => {
    const kv = el('dl', 'nh-kv');
    kv.row = (k, v, cls = '') => { kv.append(el('dt', '', k)); kv.append(el('dd', cls, v)); return kv; };
    return kv;
  };

  // ---- what it is doing now ---------------------------------------------
  function paintState() {
    const s = data.status || {};
    stateCard.replaceChildren(cardHead('State'));
    const sum = stateSummary(data);
    stateCard.append(el('p', 'rp-tone-' + sum.tone, sum.text));

    const kv = kvList();
    kv.row('Mode', modeLabel(s.mode), s.mode === 'off' ? 'muted' : '');
    kv.row('Listening', s.listening ? 'yes' : 'no', s.listening ? 'good' : 'muted');
    kv.row('Leases held', String(s.leases || 0));
    kv.row('Routed through Shepherd', String(s.routed_count || 0));
    // Only while the mode is on: with it off nothing has asked the kernel
    // anything, and "unavailable" would read as a fault rather than as a
    // question nobody put.
    if (s.nat && s.mode !== 'off') {
      kv.row('Kernel NAT', s.nat.available ? 'ready' : (s.nat.error || 'unavailable'), s.nat.available ? 'good' : 'rp-tone-warn');
    }
    if (s.error) kv.row('Problem', s.error, 'err');
    stateCard.append(kv);

    // The confirmation. A typed phrase, because the mistake this guards
    // against is one somebody makes at midnight and discovers at breakfast.
    if (s.mode === 'serve' && !s.confirmed) {
      const f = el('form', 'rp-form');
      f.append(el('p', 'small',
        'shepherd.toml asks for serving, and Shepherd will not serve until you confirm here that this is the network you mean. '
        + 'Type ' + (data.confirm_phrase || 'serve dhcp') + ' to confirm.'));
      const input = el('input', 'mono');
      input.setAttribute('aria-label', 'Confirmation phrase');
      input.placeholder = data.confirm_phrase || 'serve dhcp';
      const go = button('Confirm', 'primary');
      go.type = 'submit';
      const row = el('div', 'rp-form-row');
      row.append(input, go);
      const err = el('p', 'err small');
      err.setAttribute('role', 'status');
      f.append(row, err);
      f.addEventListener('submit', async (e) => {
        e.preventDefault();
        err.textContent = '';
        try {
          data = await mgmt.dhcpConfirm(true, input.value);
          paint();
          notify('Shepherd may now serve DHCP on this network.');
        } catch (x) { err.textContent = x.message || String(x); }
      });
      stateCard.append(f);
    } else if (s.confirmed) {
      const row = el('div', 'rp-form-row');
      row.append(button('Withdraw permission to serve', 'ghost', async () => {
        const ok = await confirmDialog({
          title: 'Stop serving DHCP?',
          body: 'Devices keep the addresses they hold until those leases run out, and nothing hands out new ones. '
            + 'Turn your router\'s DHCP back on first unless you mean the network to have no DHCP server.',
          confirm: 'Withdraw', danger: true,
        });
        if (!ok) return;
        try { data = await mgmt.dhcpConfirm(false, ''); paint(); } catch (x) { notify(x.message || String(x), true); }
      }));
      stateCard.append(row);
    }

    // The kill switch, in the idiom of Watch mode's: one button, immediate,
    // and it stays pulled across restarts.
    if (s.disarmed) {
      const p = el('p', 'rp-tone-warn small',
        'The kill switch is pulled' + (s.disarmed_reason ? ': ' + s.disarmed_reason : '') + '. Nothing is routed through Shepherd. '
        + 'Leases carry on, with the router\'s own address as the gateway.');
      const row = el('div', 'rp-form-row');
      row.append(button('Re-arm routing', 'primary', async () => {
        try { data = await mgmt.dhcpRearm(); paint(); notify('Routing re-armed.'); } catch (x) { notify(x.message || String(x), true); }
      }));
      stateCard.append(p, row);
    } else if (s.routing) {
      const row = el('div', 'rp-form-row');
      row.append(button('Stop routing now', 'danger', async () => {
        const ok = await confirmDialog({
          title: 'Stop routing every device?',
          body: 'Shepherd stops being the gateway at once and the kernel\'s rules are removed. Every device goes back to the router '
            + 'at its next renewal, which is within a lease interval; devices keep their addresses throughout. This stays off across '
            + 'restarts until you re-arm it here.',
          confirm: 'Stop routing', danger: true,
        });
        if (!ok) return;
        try { data = await mgmt.dhcpKill('stopped from the portal'); paint(); notify('Routing stopped.'); } catch (x) { notify(x.message || String(x), true); }
      }));
      stateCard.append(row);
    }

    // Another DHCP server. This is the most important thing this screen can
    // say, so it says it with the addresses and a way to clear it.
    const peers = s.peers || [];
    if (peers.length) {
      const warn = el('div', 'rp-note');
      warn.append(el('p', 'rp-tone-warn',
        'Another DHCP server has answered on this network. Shepherd will not serve while that is true, because two servers hand out '
        + 'addresses unpredictably.'));
      const ul = el('ul', 'small');
      for (const p of peers) {
        const li = el('li', 'mono');
        li.append(el('span', '', p.server + ' — ' + p.count + ' repl' + (p.count === 1 ? 'y' : 'ies') + ', last ' + relTime(p.last)));
        ul.append(li);
      }
      warn.append(ul);
      const row = el('div', 'rp-form-row');
      row.append(button('I have turned it off — clear this', 'ghost', async () => {
        try { data = await mgmt.dhcpForgetPeers(); paint(); } catch (x) { notify(x.message || String(x), true); }
      }));
      warn.append(row);
      stateCard.append(warn);
    }
  }

  // ---- what turning it on does ------------------------------------------
  function paintWhat() {
    whatCard.replaceChildren(cardHead('What turning this on does'));
    const dl = el('dl', 'dhcp-what');
    for (const c of consequences(data.settings || {})) {
      dl.append(el('dt', '', c.title));
      dl.append(el('dd', 'muted small', c.body));
    }
    whatCard.append(dl);
  }

  function paintSettings() {
    settingsCard.replaceChildren(cardHead('What it hands out'));
    const set = data.settings || {};
    const kv = kvList();
    kv.row('Network', set.subnet || '—', 'mono');
    kv.row('Shepherd', set.server_ip || '—', 'mono');
    kv.row('Router', set.gateway || '—', 'mono');
    kv.row('Pool', set.pool_start ? set.pool_start + ' – ' + set.pool_end + ' (' + set.pool_size + ' addresses)' : '—', 'mono');
    kv.row('Resolvers', (set.dns || []).join(', ') || '—', 'mono');
    if (set.domain) kv.row('Search domain', set.domain, 'mono');
    kv.row('Lease time', set.lease_seconds ? Math.round(set.lease_seconds / 60) + ' minutes' : '—');
    settingsCard.append(kv);
    const chosen = data.range && data.range.chosen;
    settingsCard.append(el('p', 'muted small rp-note',
      (chosen
        ? 'These come from the range you chose below, which overrides the [dhcp] block in shepherd.toml with no restart. '
        : 'These come from the [dhcp] block in shepherd.toml, filled in from the interface where the file leaves them empty. '
          + 'Change them there, or choose a range below. ')
      + 'The lease time is short on purpose: it is how quickly a device stops being routed when Shepherd decides it should not be.'));
  }

  // ---- the range this LAN uses -------------------------------------------
  //
  // Shepherd is not the router here, so a range the router does not itself
  // use cannot be served. The whole value of this card is saying that
  // plainly, with the address the router would have to move to, rather than
  // letting somebody find out at two in the morning.
  function paintRange() {
    rangeCard.replaceChildren(cardHead('Range'));
    const rv = data.range || {};
    const conflicts = data.conflicts || [];
    const sum = rangeSummary(rv, conflicts);
    rangeCard.append(el('p', 'rp-tone-' + sum.tone, sum.text));

    if (conflicts.length) {
      const ul = el('ul', 'dhcp-conflicts');
      for (const c of conflicts) {
        const li = el('li', 'rp-tone-' + conflictTone(c.severity));
        li.append(el('strong', '', c.severity === 'blocking' ? 'Must change: ' : 'Worth knowing: '));
        li.append(el('span', '', c.detail));
        ul.append(li);
      }
      rangeCard.append(ul);
    }

    const f = el('form', 'rp-form');
    const fields = {};
    const mk = (key, label, placeholder, cls = 'mono') => {
      const i = el('input', cls);
      i.setAttribute('aria-label', label);
      i.placeholder = placeholder;
      i.value = rv[key] || '';
      fields[key] = i;
      return i;
    };
    const subnet = mk('subnet', 'LAN range', '192.0.2.0/24');
    const row1 = el('div', 'rp-form-row');
    row1.append(subnet);
    // Picking a /24 fills the rest the way nearly every home router does,
    // so the common case is one field and a glance rather than five fields.
    row1.append(button('Fill the rest', 'ghost', () => {
      const s2 = suggestRange(subnet.value, rv);
      if (!s2) { err.textContent = 'Give a /24 to fill the rest from, or type each address yourself.'; return; }
      err.textContent = '';
      for (const [k, v] of Object.entries(s2)) if (fields[k]) fields[k].value = v;
    }));
    const row2 = el('div', 'rp-form-row');
    row2.append(mk('server_ip', 'Shepherd\'s address in the new range', 'Shepherd, e.g. 192.0.2.20'));
    row2.append(mk('gateway', 'The router\'s address in the new range', 'router, e.g. 192.0.2.1'));
    const row3 = el('div', 'rp-form-row');
    row3.append(mk('pool_start', 'First address to hand out', 'pool from, e.g. 192.0.2.100'));
    row3.append(mk('pool_end', 'Last address to hand out', 'pool to, e.g. 192.0.2.200'));
    const save = button(rv.chosen ? 'Save range' : 'Use this range', 'primary');
    save.type = 'submit';
    const actions = el('div', 'rp-form-row');
    actions.append(save);
    if (rv.chosen) {
      actions.append(button('Back to the interface\'s own range', 'ghost', async () => {
        const ok = await confirmDialog({
          title: 'Stop using the chosen range?',
          body: 'Shepherd goes back to what shepherd.toml and this host\'s interface say. Devices move at their next renewal.',
          confirm: 'Clear it',
        });
        if (!ok) return;
        try { data = await mgmt.dhcpSetRange({ subnet: '' }); paint(); notify('Back to the interface\'s own range.'); } catch (x) { notify(x.message || String(x), true); }
      }));
    }
    const err = el('p', 'err small');
    err.setAttribute('role', 'status');
    f.append(row1, row2, row3, actions, err);
    f.append(el('p', 'muted small rp-note',
      'Shepherd serves the addresses; your router still routes them. So a range only works once the router uses it too — '
      + 'change the router\'s own LAN to match, and Shepherd will say here when the two agree. Saving a range that does not '
      + 'fit yet is fine and is the point: it tells you exactly what to change. Nothing is served until it fits.'));
    f.addEventListener('submit', async (e) => {
      e.preventDefault();
      err.textContent = '';
      const body = {};
      for (const [k, i] of Object.entries(fields)) body[k] = i.value;
      const check = validateRange(body);
      if (!check.ok) { err.textContent = check.error; return; }
      try {
        data = await mgmt.dhcpSetRange(check.value);
        paint();
        notify('Range saved.');
      } catch (x) { err.textContent = x.message || String(x); }
    });
    rangeCard.append(f);
  }

  // ---- reservations ------------------------------------------------------
  function reservationForm(existing) {
    const f = el('form', 'rp-form');
    const mac = el('input', 'mono');
    mac.setAttribute('aria-label', 'MAC address');
    mac.placeholder = '02:00:5e:01:02:03';
    const ip = el('input', 'mono');
    ip.setAttribute('aria-label', 'Reserved address');
    ip.placeholder = 'address (optional)';
    const host = el('input', '');
    host.setAttribute('aria-label', 'Hostname');
    host.placeholder = 'hostname (optional)';
    const note = el('input', '');
    note.setAttribute('aria-label', 'Note');
    note.placeholder = 'note (optional)';
    if (existing) {
      mac.value = existing.mac || '';
      mac.readOnly = true;
      ip.value = existing.ip || '';
      host.value = existing.hostname || '';
      note.value = existing.note || '';
    }
    const save = button(existing ? 'Save' : 'Reserve', 'primary');
    save.type = 'submit';
    const row = el('div', 'rp-form-row');
    row.append(mac, ip, host, note, save);
    if (existing) row.append(button('Cancel', 'ghost', () => { editing = ''; paint(); }));
    const err = el('p', 'err small');
    err.setAttribute('role', 'status');
    f.append(row, err);
    if (!existing) {
      f.append(el('p', 'muted small rp-note',
        'A reserved address must sit outside the pool Shepherd hands out from, or it could be given to two devices; the form refuses '
        + 'one that does not. Leaving the address empty reserves only a hostname, which is still useful. Deleting a reservation leaves '
        + 'the device\'s current lease alone — it expires on its own.'));
    }
    f.addEventListener('submit', async (e) => {
      e.preventDefault();
      err.textContent = '';
      const check = validateReservation({ mac: mac.value, ip: ip.value, hostname: host.value, note: note.value }, data.settings || {});
      if (!check.ok) { err.textContent = check.error; return; }
      try {
        data = await mgmt.dhcpSetReservation(check.value);
        editing = '';
        paint();
        notify(check.note ? 'Reservation saved. ' + check.note : 'Reservation saved for ' + check.value.mac + '.');
      } catch (x) { err.textContent = x.message || String(x); }
    });
    return f;
  }

  function paintReservations() {
    resCard.replaceChildren(cardHead('Reservations'));
    const list = data.reservations || [];
    if (!list.length) {
      resCard.append(emptyState('No reservations', 'A reservation pins one piece of hardware to one address, whatever else is going on. '
        + 'Add one here, or use "Reserve this address" on a lease below.'));
    } else {
      const table = el('table', 'dhcp-tbl');
      const thead = el('thead');
      const hr = el('tr');
      for (const h of ['Hardware', 'Address', 'Hostname', 'Note', '']) hr.append(el('th', '', h));
      thead.append(hr);
      const tbody = el('tbody');
      for (const r of list) {
        if (editing === r.mac) {
          const tr = el('tr');
          const td = el('td');
          td.colSpan = 5;
          td.append(reservationForm(r));
          tr.append(td);
          tbody.append(tr);
          continue;
        }
        const tr = el('tr');
        tr.append(el('td', 'mono', r.mac));
        const addr = el('td', 'mono');
        addr.append(el('span', '', r.ip || 'name only'));
        if (r.ip && data.settings && data.settings.pool_start && inPool(r.ip, data.settings)) {
          addr.append(el('span', 'muted small', ' in the pool, held back for this device'));
        }
        tr.append(addr);
        tr.append(el('td', '', r.hostname || '—'));
        tr.append(el('td', 'muted small', r.note || ''));
        const actions = el('td', 'dhcp-act');
        actions.append(button('Edit', 'ghost', () => { editing = r.mac; paint(); }));
        actions.append(button('Remove', 'ghost', async () => {
          const ok = await confirmDialog({
            title: 'Remove the reservation for ' + r.mac + '?',
            body: 'The device keeps the address it currently holds until that lease expires, then gets one from the pool.',
            confirm: 'Remove', danger: true,
          });
          if (!ok) return;
          try { data = await mgmt.dhcpDeleteReservation(r.mac); paint(); } catch (x) { notify(x.message || String(x), true); }
        }));
        tr.append(actions);
        tbody.append(tr);
      }
      table.append(thead, tbody);
      resCard.append(table);
    }
    if (!editing) resCard.append(reservationForm(null));
  }

  // ---- leases ------------------------------------------------------------
  function paintLeases() {
    const search = el('input', 'dhcp-search');
    search.type = 'search';
    search.placeholder = 'Filter leases';
    search.setAttribute('aria-label', 'Filter leases');
    search.value = query;
    search.addEventListener('input', () => { query = search.value; paintLeases(); });
    leaseCard.replaceChildren(cardHead('Leases', search));

    const rows = sortLeases(filterLeases(data.leases || [], query));
    if (!rows.length) {
      leaseCard.append(emptyState(
        query ? 'Nothing matches' : 'No leases yet',
        query ? 'No lease matches that.' : 'Shepherd has not seen a DHCP exchange on this network yet. In watching mode it learns '
          + 'every lease your router hands out, so this fills in as devices renew.',
      ));
      return;
    }
    const table = el('table', 'dhcp-tbl');
    const thead = el('thead');
    const hr = el('tr');
    for (const h of ['Address', 'Hardware', 'Name', 'Gateway it was given', 'Expires', '']) hr.append(el('th', '', h));
    thead.append(hr);
    const tbody = el('tbody');
    for (const l of rows) {
      const tr = el('tr');
      if (l.expired) tr.classList.add('muted');
      tr.append(el('td', 'mono', l.ip || '—'));
      const hw = el('td', 'mono');
      hw.append(el('span', '', l.mac));
      hw.append(el('span', 'muted small', ' ' + originLabel(l.origin)));
      tr.append(hw);
      const name = el('td');
      name.append(el('span', '', l.hostname || '—'));
      if (l.device_id && onOpenDevice) {
        name.append(button('Device', 'ghost', () => onOpenDevice(l.device_id)));
      }
      tr.append(name);
      const gw = el('td', 'mono');
      gw.append(el('span', l.routed ? 'good' : '', l.router || '—'));
      if (l.routed) gw.append(el('span', 'muted small', ' through Shepherd'));
      else if (l.reason) gw.append(el('span', 'muted small', ' — ' + l.reason));
      tr.append(gw);
      tr.append(el('td', 'muted small', l.expired ? 'expired ' + relTime(l.expires) : relTime(l.expires)));
      const act = el('td', 'dhcp-act');
      const already = (data.reservations || []).some((r) => r.mac === normalizeMAC(l.mac));
      if (!already) {
        act.append(button('Reserve this address', 'ghost', async () => {
          const b = leaseBody(l);
          const check = validateReservation(b, data.settings || {});
          if (!check.ok) { notify(check.error, true); return; }
          try { data = await mgmt.dhcpSetReservation(check.value); paint(); notify('Reserved ' + b.ip + ' for ' + b.mac + '.'); } catch (x) { notify(x.message || String(x), true); }
        }));
      }
      tr.append(act);
      tbody.append(tr);
    }
    table.append(thead, tbody);
    leaseCard.append(table);
  }

  function paint() {
    if (loadError) {
      body.replaceChildren(unavailable(loadError) ? unavailableCard('DHCP mode') : emptyState('Could not load', loadError.message || String(loadError)));
      return;
    }
    if (!data) { body.replaceChildren(el('p', 'muted', 'Loading…')); return; }
    if (data.available === false) {
      body.replaceChildren(stateCard, whatCard);
      paintState();
      paintWhat();
      stateCard.append(el('p', 'muted small rp-note', data.reason || ''));
      return;
    }
    body.replaceChildren(stateCard, whatCard, settingsCard, rangeCard, resCard, leaseCard);
    paintState();
    paintWhat();
    paintSettings();
    paintRange();
    paintReservations();
    paintLeases();
  }

  async function load() {
    try {
      data = await mgmt.dhcp();
      loadError = null;
    } catch (e) {
      loadError = e;
    }
    paint();
  }

  return {
    show() { paint(); return load(); },
    hide() { /* nothing polls, so there is nothing to stop */ },
    reload: load,
  };
}
