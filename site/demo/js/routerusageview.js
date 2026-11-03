// The "read bandwidth from your router" section of the Bandwidth screen.
// Watch mode measures by steering traffic through Shepherd; this is the
// passive alternative for a network that will not tolerate that. The
// sign-in reuses the eero import flow (api_import.go), and the token it
// produces is kept by the server, never held here.
//
// Every string that came from the server is placed with textContent.
import { el } from './dom.js?v=65858b99';
import { button } from './ui.js?v=c9bbb094';
import { routerConnection, nameSyncSummary } from './traffic.js?v=cd821019';

export function createRouterUsage({ mgmt, notify, onChanged = () => {} }) {
  const root = el('section', 'card ru');
  // null when signed out; otherwise { sessionId, networks } mid sign-in.
  let signin = null;
  let busy = false;
  let router = null;
  // What the owner has typed so far. The Bandwidth screen polls every two
  // seconds, and a repaint replaces the input element, so without this the
  // field empties itself under them mid-word.
  const draft = { login: '', code: '', url: '', user: '', pass: '', site: '' };
  // Which router the owner is setting up, before one is connected.
  let kind = 'eero';
  let selfSigned = false;
  // The name sync: null when idle, otherwise the preview awaiting a yes.
  let names = null;
  let overwrite = false;

  // field builds an input that remembers what is in it across repaints.
  function field(key, attrs) {
    const input = el('input');
    Object.assign(input, attrs);
    input.value = draft[key];
    input.addEventListener('input', () => { draft[key] = input.value; });
    return input;
  }

  const run = async (fn) => {
    if (busy) return;
    busy = true;
    paint();
    try {
      await fn();
    } catch (e) {
      notify(e.message);
    }
    busy = false;
    paint();
  };

  function head() {
    const h = el('div', 'card-h');
    h.append(el('h3', 'card-t', 'Read from your router'));
    return h;
  }

  // ------------------------------------------------------------- sign-in
  function signInForm() {
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
    return form;
  }

  function codeForm() {
    const form = el('form', 'ru-form');
    const input = field('code', { type: 'text', inputMode: 'numeric', placeholder: 'verification code', autocomplete: 'one-time-code', required: true });
    const go = el('button', '', 'Verify');
    go.disabled = busy;
    const cancel = button('Cancel', 'ghost', () => run(async () => {
      const id = signin.sessionId;
      signin = null;
      draft.login = '';
      draft.code = '';
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
        draft.login = '';
        draft.code = '';
      });
    });
    return form;
  }

  function networkPicker() {
    const wrap = el('div', 'ru-form');
    const sel = el('select');
    sel.setAttribute('aria-label', 'Which network to read');
    for (const n of signin.networks) {
      const o = el('option', '', n.name || n.id);
      o.value = n.id;
      sel.append(o);
    }
    const go = button('Use this network', 'primary', () => run(async () => {
      const id = sel.value;
      const sessionId = signin.sessionId;
      signin = null;
      router = await mgmt.routerUsageConnect(sessionId, id);
      notify('Shepherd is now reading bandwidth from your eero');
      onChanged();
    }));
    go.disabled = busy || !signin.networks.length;
    if (!signin.networks.length) {
      wrap.append(el('p', 'muted small', 'This account has no networks Shepherd can read.'));
      return wrap;
    }
    wrap.append(sel, go);
    return wrap;
  }

  // ---------------------------------------------------------------- unifi
  // A controller needs no verification code, just an account on it, so
  // this is one form. A read-only account is enough; Shepherd only reads.
  function unifiForm() {
    const form = el('form', 'ru-form ru-grid');
    const url = field('url', { type: 'text', placeholder: 'https://192.0.2.10 or https://unifi.example.com:8443', required: true });
    const user = field('user', { type: 'text', placeholder: 'controller username', autocomplete: 'username', required: true });
    const pass = field('pass', { type: 'password', placeholder: 'password', autocomplete: 'current-password', required: true });
    const site = field('site', { type: 'text', placeholder: 'site (default)' });
    const over = el('label', 'switch');
    const box = el('input');
    box.type = 'checkbox';
    box.checked = selfSigned;
    box.addEventListener('change', () => { selfSigned = box.checked; });
    over.append(box, el('span', '', 'Accept its self-signed certificate'));
    const go = el('button', '', 'Connect');
    go.disabled = busy;
    form.append(url, user, pass, site, over, go);
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      run(async () => {
        router = await mgmt.unifiConnect({
          base_url: url.value.trim(), username: user.value.trim(),
          password: pass.value, site: site.value.trim(), allow_self_signed: selfSigned,
        });
        draft.url = ''; draft.user = ''; draft.pass = ''; draft.site = '';
        notify('Shepherd is now reading bandwidth from your UniFi controller');
        onChanged();
      });
    });
    return form;
  }

  function kindPicker() {
    const wrap = el('div', 'ru-kinds');
    for (const [id, label] of [['eero', 'eero'], ['unifi', 'UniFi']]) {
      const b = button(label, id === kind ? 'primary' : 'ghost', () => { kind = id; names = null; paint(); });
      b.disabled = busy;
      wrap.append(b);
    }
    return wrap;
  }

  // --------------------------------------------------------- device names
  // eero already knows what the household calls each device, and the kept
  // sign-in means asking costs no new verification code. The owner's own
  // names win unless they say otherwise, and nothing is written until
  // they have seen what would change.
  function nameSync() {
    const wrap = el('div', 'ru-names');
    wrap.append(el('h4', 'ru-sub', 'Device names'));
    wrap.append(el('p', 'muted small ru-note',
      'Copy the names and profiles from your eero into Shepherd. Names you have set here are kept unless you ask for them to be replaced.'));

    const over = el('label', 'switch');
    const box = el('input');
    box.type = 'checkbox';
    box.checked = overwrite;
    box.disabled = busy;
    box.addEventListener('change', () => {
      overwrite = box.checked;
      // The preview is about to be wrong, so take it away and ask again.
      names = null;
      run(async () => { names = await mgmt.routerUsageSyncNames(overwrite, true); });
    });
    over.append(box, el('span', '', 'Also replace names I have set myself'));
    wrap.append(over);

    if (!names) {
      const go = button('Check what would change', 'ghost', () =>
        run(async () => { names = await mgmt.routerUsageSyncNames(overwrite, true); }));
      go.disabled = busy;
      const acts = el('div', 'ru-acts');
      acts.append(go);
      wrap.append(acts);
      return wrap;
    }
    wrap.append(el('p', 'ru-line ' + (names.changed ? 'good' : 'muted'), nameSyncSummary(names, false)));
    const acts = el('div', 'ru-acts');
    if (names.changed) {
      const apply = button('Apply', 'primary', () => run(async () => {
        const done = await mgmt.routerUsageSyncNames(overwrite, false);
        names = null;
        notify(nameSyncSummary(done, true));
        onChanged();
      }));
      apply.disabled = busy;
      acts.append(apply);
    }
    const cancel = button(names.changed ? 'Cancel' : 'Close', 'ghost', () => { names = null; paint(); });
    cancel.disabled = busy;
    acts.append(cancel);
    wrap.append(acts);
    for (const warn of names.warnings || []) wrap.append(el('p', 'muted small', warn));
    return wrap;
  }

  // ------------------------------------------------------------ connected
  function controls() {
    const wrap = el('div', 'ru-acts');
    const isUniFi = router.source === 'unifi';
    const toggle = button(router.enabled ? 'Stop reading' : 'Start reading', router.enabled ? 'ghost' : 'primary', () =>
      run(async () => {
        router = isUniFi ? await mgmt.unifiEnabled(!router.enabled) : await mgmt.routerUsageEnabled(!router.enabled);
        onChanged();
      }));
    toggle.disabled = busy;
    const forget = button('Disconnect', 'ghost', () => run(async () => {
      router = isUniFi ? await mgmt.unifiForget() : await mgmt.routerUsageForget();
      notify(isUniFi ? 'The controller has been forgotten' : 'The eero sign-in has been forgotten');
      onChanged();
    }));
    forget.disabled = busy;
    wrap.append(toggle, forget);
    return wrap;
  }

  // ----------------------------------------------------------------- paint
  function paint() {
    root.replaceChildren(head());
    const line = routerConnection(router);
    root.append(el('p', 'ru-line ' + line.tone, line.text));
    if (!router || !router.available) return;

    root.append(el('p', 'muted small ru-note',
      'Shepherd asks your router what each device has moved. Nothing is put in the path of your traffic, so this works where Watch mode cannot. It reads only; no setting on your router is changed.'));

    if (router.connected && !signin) {
      root.append(controls());
      const st = router.status || {};
      if (st.needs_sign_in) {
        root.append(el('p', 'muted small', 'Signing in again keeps the network you already chose.'), signInForm());
        return;
      }
      // Syncing names is eero's; UniFi's client list has no profiles.
      if (router.source !== 'unifi') root.append(nameSync());
      return;
    }
    if (!signin) {
      root.append(kindPicker());
      if (kind === 'unifi') {
        root.append(el('p', 'muted small ru-note',
          'A UniFi controller keeps real byte counts per device, so its figures are measurements rather than estimates. A read-only account on the controller is enough.'));
        root.append(unifiForm());
        return;
      }
      root.append(signInForm());
    } else if (!signin.networks) {
      root.append(codeForm());
    } else {
      root.append(networkPicker());
    }
    root.append(el('p', 'muted small ru-note',
      'eero publishes no API for this, so Shepherd uses the one its own app uses. It is unofficial and can stop working without notice. Your sign-in is kept on this machine and can be forgotten at any time.'));
  }

  paint();
  return {
    root,
    // render is called with the router object from GET /api/traffic on
    // every poll, so the status line stays live without its own timer.
    render(next) {
      router = next;
      if (busy) return;
      // Repainting while the owner is typing in this section would take
      // the caret with it, so only the status line moves until they are
      // done. field() keeps what they have typed either way.
      if (root.contains(document.activeElement)) {
        const line = routerConnection(router);
        const p = root.querySelector('.ru-line');
        if (p) {
          p.textContent = line.text;
          p.className = 'ru-line ' + line.tone;
        }
        return;
      }
      paint();
    },
  };
}
