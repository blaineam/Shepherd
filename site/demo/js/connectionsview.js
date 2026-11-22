// The Connections card on the Router screen: every router and firewall
// Shepherd can read, side by side, each with its own connect form, switch
// and disconnect. They used to be split between this screen and Bandwidth,
// and only one could be set up at a time; now a Firewalla and an eero
// account can both be connected, which is what syncing names between them
// needs.
//
// Every string that came from the server is placed with textContent. No
// credential is ever held here longer than the form it was typed into.
import { el } from './dom.js?v=65858b99';
import { button, confirmDialog } from './ui.js?v=4d208003';
import { KINDS, connectionState, bandwidthNote, toggleLabel } from './connections.js?v=1bf85ac9';
import { nameSyncSummary } from './traffic.js?v=f5163a4b';

export function createConnections({ mgmt, notify, onChanged = () => {} }) {
  const root = el('section', 'card bk-card cn');
  let conns = null;
  let loadError = null;
  let busy = false;
  // Which connection's form is open, and the eero sign-in in progress:
  // null, or { sessionId, networks } once a code has been sent.
  let open = '';
  let signin = null;
  // What the owner has typed so far, kept across repaints.
  const draft = { login: '', code: '', url: '', user: '', pass: '', site: '', msp: '', token: '', box: '', aurl: '', akey: '', asite: '' };
  const flags = { self: false, aself: false };

  function field(key, attrs) {
    const input = el('input');
    Object.assign(input, attrs);
    input.value = draft[key];
    input.addEventListener('input', () => { draft[key] = input.value; });
    return input;
  }
  function check(key, label) {
    const wrap = el('label', 'switch');
    const box = el('input');
    box.type = 'checkbox';
    box.checked = flags[key];
    box.addEventListener('change', () => { flags[key] = box.checked; });
    wrap.append(box, el('span', '', label));
    return wrap;
  }

  async function load() {
    try {
      conns = await mgmt.connections();
      loadError = null;
    } catch (e) {
      loadError = e;
    }
    paint();
  }

  const run = async (fn) => {
    if (busy) return;
    busy = true;
    paint();
    try { await fn(); } catch (e) { notify(e.message); }
    busy = false;
    await load();
  };

  // done closes the form, clears what was typed and tells the screen.
  const done = (said) => {
    open = '';
    signin = null;
    for (const k of Object.keys(draft)) draft[k] = '';
    notify(said);
    onChanged();
  };

  // ---------------------------------------------------------------- forms
  function firewallaForm() {
    const form = el('form', 'ru-form ru-grid');
    const msp = field('msp', { type: 'text', placeholder: 'mydomain.firewalla.net', autocomplete: 'off', required: true });
    const token = field('token', { type: 'password', placeholder: 'personal access token', autocomplete: 'off', required: true });
    const box = field('box', { type: 'text', placeholder: 'box ID (optional, default all)', autocomplete: 'off' });
    const go = el('button', '', 'Connect');
    go.disabled = busy;
    form.append(msp, token, box, go);
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      run(async () => {
        await mgmt.firewallaConnect({ base_url: msp.value.trim(), token: token.value, box: box.value.trim() });
        done('Shepherd is now reading your Firewalla');
      });
    });
    const parts = [];
    // Running on the box itself, Shepherd can read it with nothing to
    // type: the box serves its own API on its loopback address.
    if (conns && conns.local_firewalla) {
      const use = button('Use this box', 'primary', () => run(async () => {
        await mgmt.firewallaLocalConnect();
        done('Shepherd is now reading this Firewalla box directly');
      }));
      use.disabled = busy;
      const acts = el('div', 'ru-acts');
      acts.append(use);
      parts.push(
        el('p', 'muted small ru-note', 'This Shepherd is running on a Firewalla box, so it can read the box directly: no MSP account, no token, and traffic shows as it happens instead of minutes later. It uses the API the box serves to its own app, which is not published and can change with a firmware update.'),
        acts,
        el('h4', 'ru-sub', 'Or connect through MSP'),
      );
    }
    const note = el('p', 'muted small ru-note', 'Make a personal access token in your MSP portal. A Read Only token is enough to read; renaming devices, rules and syncing names to the Firewalla need one that can write. It is kept on this machine and sent only to firewalla.net.');
    return [...parts, note, form];
  }

  function unifiAPIForm() {
    const form = el('form', 'ru-form ru-grid');
    const url = field('aurl', { type: 'text', placeholder: 'https://192.0.2.10', required: true, autocomplete: 'off' });
    const key = field('akey', { type: 'password', placeholder: 'API key', required: true, autocomplete: 'off' });
    const site = field('asite', { type: 'text', placeholder: 'site (default)', autocomplete: 'off' });
    const go = el('button', '', 'Connect');
    go.disabled = busy;
    form.append(url, key, site, check('aself', 'Accept its self-signed certificate'), go);
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      run(async () => {
        await mgmt.backendUniFiConnect({ base_url: url.value.trim(), api_key: key.value, site: site.value.trim(), allow_self_signed: flags.aself });
        done('Shepherd is now reading your UniFi console');
      });
    });
    const note = el('p', 'muted small ru-note', 'Make an API key under Settings, Control Plane, Integrations in UniFi Network (version 9 or newer). Shepherd lists your clients and firewall policies, and can pause, resume or delete a policy and block a client once you allow changes. UniFi reports no request log and cannot rename a device from outside.');
    return [note, form];
  }

  function unifiForm() {
    const form = el('form', 'ru-form ru-grid');
    const url = field('url', { type: 'text', placeholder: 'https://192.0.2.10 or https://unifi.example.com:8443', required: true });
    const user = field('user', { type: 'text', placeholder: 'controller username', autocomplete: 'username', required: true });
    const pass = field('pass', { type: 'password', placeholder: 'password', autocomplete: 'current-password', required: true });
    const site = field('site', { type: 'text', placeholder: 'site (default)' });
    const go = el('button', '', 'Connect');
    go.disabled = busy;
    form.append(url, user, pass, site, check('self', 'Accept its self-signed certificate'), go);
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      run(async () => {
        await mgmt.unifiConnect({ base_url: url.value.trim(), username: user.value.trim(), password: pass.value, site: site.value.trim(), allow_self_signed: flags.self });
        done('Shepherd is now reading bandwidth from your UniFi controller');
      });
    });
    const note = el('p', 'muted small ru-note', 'A UniFi controller keeps real byte counts per device, so its figures are measurements rather than estimates. Shepherd only reads.');
    return [note, form];
  }

  // eero has no token to paste: it sends a code to the account's email or
  // phone, then asks which network to read.
  function eeroForm() {
    const note = el('p', 'muted small ru-note', 'eero publishes no API, so Shepherd uses the one its own app uses. It is unofficial and can stop working without notice. Your sign-in is kept on this machine and can be forgotten at any time.');
    if (!signin) {
      const form = el('form', 'ru-form');
      const input = field('login', { type: 'text', placeholder: 'eero account email or phone', autocomplete: 'username', required: true });
      const go = el('button', '', 'Send me a code');
      go.disabled = busy;
      form.append(input, go);
      form.addEventListener('submit', (ev) => {
        ev.preventDefault();
        const login = input.value.trim();
        if (!login) return;
        run(async () => {
          const r = await mgmt.importEeroStart(login);
          signin = { sessionId: r.session_id, networks: null };
          draft.code = '';
          notify('eero sent a verification code');
        });
      });
      return [note, form];
    }
    if (!signin.networks) {
      const form = el('form', 'ru-form');
      const input = field('code', { type: 'text', inputMode: 'numeric', placeholder: 'verification code', autocomplete: 'one-time-code', required: true });
      const go = el('button', '', 'Verify');
      go.disabled = busy;
      const cancel = button('Cancel', 'ghost', () => run(async () => {
        const id = signin.sessionId;
        signin = null;
        draft.login = ''; draft.code = '';
        await mgmt.importEeroCancel(id);
      }));
      form.append(input, go, cancel);
      form.addEventListener('submit', (ev) => {
        ev.preventDefault();
        const code = input.value.trim();
        if (!code) return;
        run(async () => {
          const r = await mgmt.importEeroVerify(signin.sessionId, code);
          signin = { sessionId: r.session_id, networks: r.networks || [] };
        });
      });
      return [note, form];
    }
    const wrap = el('div', 'ru-form');
    if (!signin.networks.length) {
      wrap.append(el('p', 'muted small', 'This account has no networks Shepherd can read.'));
      return [note, wrap];
    }
    const sel = el('select');
    sel.setAttribute('aria-label', 'Which network to read');
    for (const n of signin.networks) {
      const o = el('option', '', n.name || n.id);
      o.value = n.id;
      sel.append(o);
    }
    const go = button('Use this network', 'primary', () => run(async () => {
      await mgmt.routerUsageConnect(signin.sessionId, sel.value);
      done('Your eero account is connected');
    }));
    go.disabled = busy;
    wrap.append(sel, go);
    return [note, wrap];
  }

  const FORMS = { firewalla: firewallaForm, unifi_api: unifiAPIForm, unifi: unifiForm, eero: eeroForm };
  const API = {
    firewalla: { enabled: (on) => mgmt.firewallaEnabled(on), forget: () => mgmt.firewallaForget() },
    unifi_api: { enabled: (on) => mgmt.backendUniFiEnabled(on), forget: () => mgmt.backendUniFiForget() },
    unifi: { enabled: (on) => mgmt.unifiEnabled(on), forget: () => mgmt.unifiForget() },
    eero: { enabled: (on) => mgmt.routerUsageEnabled(on), forget: () => mgmt.routerUsageForget() },
  };

  // ------------------------------------------------------------------ rows
  function row(kind) {
    const c = (conns && conns[kind.id]) || {};
    const li = el('li', 'cn-row');
    const top = el('div', 'cn-top');
    const text = el('div', 'cn-text');
    text.append(el('strong', 'cn-title', kind.title), el('span', 'muted small', kind.what));
    const acts = el('div', 'cn-acts');
    if (c.connected) {
      const label = toggleLabel(kind.id, c);
      const toggle = button(label, c.enabled ? 'ghost' : 'primary', () => run(async () => {
        await API[kind.id].enabled(!c.enabled);
        onChanged();
      }));
      toggle.disabled = busy;
      const forget = button('Disconnect', 'ghost', async () => {
        const ok = await confirmDialog({
          title: 'Disconnect ' + kind.title + '?',
          body: 'Shepherd forgets the credential and stops reading. Nothing changes on the ' + kind.title + ' itself.',
          confirm: 'Disconnect',
        });
        if (!ok) return;
        run(async () => {
          await API[kind.id].forget();
          notify(kind.title + ' has been disconnected');
          onChanged();
        });
      });
      forget.disabled = busy;
      acts.append(toggle, forget);
      // eero's profiles (a person's or a room's devices) map onto
      // Shepherd's groups. Names are the name sync's job, below.
      if (kind.id === 'eero' && c.network) {
        const groups = button('Copy profiles into groups', 'ghost', () => run(async () => {
          const plan = await mgmt.routerUsageSyncNames(false, true);
          if (!plan.changed) { notify(nameSyncSummary(plan, false)); return; }
          const ok = await confirmDialog({ title: 'Copy eero profiles into groups?', body: nameSyncSummary(plan, false) + ' Names you have set in Shepherd are kept.', confirm: 'Copy' });
          if (!ok) return;
          notify(nameSyncSummary(await mgmt.routerUsageSyncNames(false, false), true));
          onChanged();
        }));
        groups.disabled = busy;
        acts.append(groups);
      }
    } else {
      const isOpen = open === kind.id;
      const b = button(isOpen ? 'Cancel' : 'Connect', isOpen ? 'ghost' : 'primary', () => {
        open = isOpen ? '' : kind.id;
        if (isOpen) signin = null;
        paint();
      });
      b.disabled = busy;
      acts.append(b);
    }
    top.append(text, acts);
    li.append(top);
    const st = connectionState(kind.id, conns);
    const p = el('p', 'ru-line cn-state ' + st.tone, st.text);
    p.setAttribute('role', 'status');
    li.append(p);
    if (!c.connected && open === kind.id) {
      const form = el('div', 'cn-form');
      form.append(...FORMS[kind.id]());
      li.append(form);
    }
    return li;
  }

  function paint() {
    const h = el('div', 'card-h');
    h.append(el('h3', 'card-t', 'Connections'), el('span', 'muted small', 'more than one can be connected'));
    root.replaceChildren(h);
    if (loadError) { root.append(el('p', 'ru-line bad', 'Could not load the connections: ' + loadError.message)); return; }
    if (!conns) { root.append(el('p', 'muted', 'Loading.')); return; }
    if (!conns.available) { root.append(el('p', 'ru-line muted', 'This build cannot connect to a router or firewall.')); return; }
    const ul = el('ul', 'cn-list');
    for (const kind of KINDS) ul.append(row(kind));
    root.append(ul);
    const note = bandwidthNote(conns);
    if (note) root.append(el('p', 'muted small ru-note', note));
  }

  paint();
  return {
    root,
    load,
    // refresh reloads unless the owner is typing in one of the forms, whose
    // caret a repaint would take.
    refresh() { if (!busy && !root.contains(document.activeElement)) return load(); return Promise.resolve(); },
    get connections() { return conns; },
  };
}
