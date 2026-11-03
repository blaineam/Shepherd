// The "read bandwidth from your router" section of the Bandwidth screen.
// Watch mode measures by steering traffic through Shepherd; this is the
// passive alternative for a network that will not tolerate that. The
// sign-in reuses the eero import flow (api_import.go), and the token it
// produces is kept by the server, never held here.
//
// Every string that came from the server is placed with textContent.
import { el } from './dom.js';
import { button } from './ui.js';
import { routerConnection } from './traffic.js';

export function createRouterUsage({ mgmt, notify, onChanged = () => {} }) {
  const root = el('section', 'card ru');
  // null when signed out; otherwise { sessionId, networks } mid sign-in.
  let signin = null;
  let busy = false;
  let router = null;

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
    const input = el('input');
    input.type = 'text';
    input.placeholder = 'eero account email or phone';
    input.autocomplete = 'username';
    input.required = true;
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
        notify('eero sent a verification code');
      });
    });
    return form;
  }

  function codeForm() {
    const form = el('form', 'ru-form');
    const input = el('input');
    input.type = 'text';
    input.inputMode = 'numeric';
    input.placeholder = 'verification code';
    input.autocomplete = 'one-time-code';
    input.required = true;
    const go = el('button', '', 'Verify');
    go.disabled = busy;
    const cancel = button('Cancel', 'ghost', () => run(async () => {
      const id = signin.sessionId;
      signin = null;
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

  // ------------------------------------------------------------ connected
  function controls() {
    const wrap = el('div', 'ru-acts');
    const toggle = button(router.enabled ? 'Stop reading' : 'Start reading', router.enabled ? 'ghost' : 'primary', () =>
      run(async () => {
        router = await mgmt.routerUsageEnabled(!router.enabled);
        onChanged();
      }));
    toggle.disabled = busy;
    const forget = button('Disconnect', 'ghost', () => run(async () => {
      router = await mgmt.routerUsageForget();
      notify('The eero sign-in has been forgotten');
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
      }
      return;
    }
    if (!signin) {
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
      if (!busy) paint();
    },
  };
}
