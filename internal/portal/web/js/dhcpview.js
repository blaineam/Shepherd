// The DHCP screen: what DHCP mode is doing, what it would hand out, the
// current leases, the address reservations, and a plainly worded account of
// what turning it on will do.
//
// Every name, address and hostname here comes from a device on the network or
// from the owner's typing, so all text is set with textContent.
import { el } from './dom.js';
import { button, emptyState, unavailableCard, confirmDialog, relTime } from './ui.js';
import { unavailable } from './mgmt.js';
import { validateReservation, modeLabel, stateSummary, consequences, sortLeases, filterLeases, leaseBody, originLabel, normalizeMAC } from './dhcp.js';

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
    if (s.nat) {
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
    settingsCard.append(el('p', 'muted small rp-note',
      'These come from the [dhcp] block in shepherd.toml, filled in from the interface where the file leaves them empty, so changing '
      + 'them needs an edit and a restart. The lease time is short on purpose: it is how quickly a device stops being routed when '
      + 'Shepherd decides it should not be.'));
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
        notify('Reservation saved for ' + check.value.mac + '.');
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
        tr.append(el('td', 'mono', r.ip || 'name only'));
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
    body.replaceChildren(stateCard, whatCard, settingsCard, resCard, leaseCard);
    paintState();
    paintWhat();
    paintSettings();
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
