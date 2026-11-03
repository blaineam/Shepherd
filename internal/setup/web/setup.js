// The first-run setup page's behaviour. Plain modules, no build step and
// nothing loaded from the internet, which is the same rule the portal's own
// front end follows.
//
// Every value that came from the host (an address, an interface name, an
// error from a resolver) goes into the page through textContent, never
// innerHTML.

const $ = (id) => document.getElementById(id);

// token is the one-time token from the address Shepherd printed. It is kept
// in memory and sent as a header: nothing stores it in the browser, and it
// leaves the address bar as soon as the page has read it.
const token = new URLSearchParams(location.search).get('token') || '';
try {
  history.replaceState(null, '', location.pathname);
} catch { /* an address bar that keeps the token is not worth failing over */ }

const headers = { 'Content-Type': 'application/json', 'X-Shepherd-Setup': token };

async function call(path, opts = {}) {
  const res = await fetch(path, { headers, ...opts });
  const text = await res.text();
  if (!res.ok) throw new Error(text.trim() || res.statusText);
  return text ? JSON.parse(text) : {};
}

const get = (path) => call(path);
const post = (path, body) => call(path, { method: 'POST', body: JSON.stringify(body || {}) });

let state = null;
let measured = null;      // the ranked measurements, once they have been taken
let connectedRouter = '';

// ---------------------------------------------------------------- helpers

function result(id, text, cls) {
  const el = $(id);
  el.className = 'result' + (cls ? ' ' + cls : '');
  el.textContent = text;
}

function note(id, text, cls) {
  const el = $(id);
  el.className = 'note small' + (cls ? ' ' + cls : '');
  el.textContent = text;
}

// row builds one tick-box or radio with a title and a quieter second line.
function row(name, value, title, sub, type, checked) {
  const label = document.createElement('label');
  const input = document.createElement('input');
  input.type = type;
  input.name = name;
  input.value = value;
  input.checked = !!checked;
  const text = document.createElement('span');
  const strong = document.createElement('strong');
  strong.textContent = title;
  text.append(strong);
  if (sub) {
    const note = document.createElement('span');
    note.className = 'pnote';
    note.textContent = ' — ' + sub;
    text.append(note);
  }
  label.append(input, text);
  return label;
}

function addrRow(name, a, checked, type) {
  const label = document.createElement('label');
  const input = document.createElement('input');
  input.type = type;
  input.name = name;
  input.value = a.ip;
  input.checked = checked;
  const text = document.createElement('span');
  const ip = document.createElement('span');
  ip.className = 'ip';
  ip.textContent = a.ip;
  const iface = document.createElement('span');
  iface.className = 'iface';
  iface.textContent = a.interface ? '  ' + a.interface : '';
  text.append(ip, iface);
  label.append(input, text);
  return label;
}

const chosenAddrs = () => Array.from(document.querySelectorAll('input[name=addr]:checked')).map((i) => i.value);
const chosenCategories = () => Array.from(document.querySelectorAll('input[name=cat]:checked')).map((i) => i.value);

// upstreams is whatever the resolver step currently means: the typed list
// when there is one, otherwise the chosen candidate.
function upstreams() {
  const typed = $('custom').value.split('\n').map((s) => s.trim()).filter(Boolean);
  if (typed.length) return typed;
  const picked = document.querySelector('input[name=cand]:checked');
  if (!picked) return [];
  const all = (measured || state.candidates || []);
  const found = all.find((c) => c.id === picked.value);
  return found ? found.addrs : [];
}

// ------------------------------------------------------------ the questions

function drawCandidates(list, ranked) {
  const box = $('candidates');
  box.replaceChildren();
  list.forEach((c, i) => {
    let sub = c.note;
    if (ranked) {
      if (c.ok) sub += ' · ' + Math.round(c.median_ms) + 'ms';
      else if (c.lost >= c.probes) sub += ' · no answer' + (c.error ? ': ' + c.error : '');
      else sub += ' · lost ' + c.lost + ' of ' + c.probes + ' probes';
    }
    const checked = ranked ? !!c.recommended : i === 0;
    const label = row('cand', c.id, c.name + (ranked && c.recommended ? ' — recommended' : ''), sub, 'radio', checked);
    if (ranked && !c.ok) label.classList.add('dim');
    box.append(label);
  });
}

async function measure() {
  const btn = $('measure');
  btn.disabled = true;
  result('measure-result', 'Asking each one a few times…');
  try {
    const out = await post('/api/setup/upstream-rank');
    measured = out.results || [];
    drawCandidates(measured, true);
    const best = measured.find((m) => m.recommended);
    if (best) {
      result('measure-result', best.name + ' answered every probe in about ' + Math.round(best.median_ms)
        + 'ms, so it is picked. Choose another if you would rather.', 'good');
    } else {
      result('measure-result', 'None of them answered every probe from this host. Check this host\'s own '
        + 'internet access; you can still finish with one of them.', 'bad');
    }
  } catch (e) {
    result('measure-result', e.message, 'bad');
  }
  btn.disabled = false;
}

async function checkPort() {
  const port = Number($('dns-port').value);
  if (!port) return;
  try {
    const out = await post('/api/setup/port-check', { port, addrs: chosenAddrs() });
    if (out.free) {
      note('port-note', 'Nothing else is listening on port ' + port + '.');
      return;
    }
    note('port-note', 'Something already answers on port ' + port + ' at ' + (out.held || []).join(', ')
      + '. Stop it before finishing, or use another port.', 'warn');
  } catch (e) {
    note('port-note', e.message, 'warn');
  }
}

function draw() {
  $('data-dir').textContent = state.data_dir;
  if (state.data_dir_error) result('data-dir-state', 'cannot be used: ' + state.data_dir_error, 'bad');
  else result('data-dir-state', 'ready', 'good');
  $('dns-port').value = state.dns_port;
  $('portal-port').value = state.portal_port;

  const addrs = state.addrs || [];
  const box = $('addrs');
  box.replaceChildren();
  if (!addrs.length) {
    const p = document.createElement('p');
    p.className = 'warn';
    p.textContent = state.addrs_error
      ? 'This host\'s addresses could not be read: ' + state.addrs_error
      : 'This host has no LAN address right now, so only loopback can answer. Bring the interface up and reload if you meant to serve the network.';
    box.append(p);
  }
  // Every address starts ticked: that is the answer that cannot leave a
  // device without DNS.
  for (const a of addrs) box.append(addrRow('addr', a, true, 'checkbox'));

  const portalBox = $('portal-addrs');
  portalBox.replaceChildren();
  portalBox.append(addrRow('portal', { ip: '127.0.0.1', interface: 'this host only — reach it over an SSH tunnel' }, true, 'radio'));
  for (const a of addrs) portalBox.append(addrRow('portal', a, false, 'radio'));

  drawCandidates(state.candidates || [], false);

  if (state.config_exists) {
    const warn = $('exists');
    warn.hidden = false;
    warn.textContent = state.config_path + ' already exists. Finishing replaces it and keeps the old one as '
      + state.config_path + '.bak.';
  }
  if (!state.dns_port_free) {
    note('port-note', 'Something already answers on port 53 on at least one of these addresses. If that is the '
      + 'resolver Shepherd replaces, stop it before finishing; if you are keeping it, use another port (5353 is '
      + 'the usual one).', 'warn');
  }
  $('load').hidden = true;
  $('form').hidden = false;
  // The measurement starts by itself: it is the whole reason this step is
  // not a list of names to guess between.
  measure();
}

// ------------------------------------------------------------------- finish

async function finish(ev) {
  ev.preventDefault();
  const portal = document.querySelector('input[name=portal]:checked');
  const body = {
    dns_listen: chosenAddrs(),
    dns_port: Number($('dns-port').value),
    upstreams: upstreams(),
    portal_host: portal ? portal.value : '127.0.0.1',
    portal_port: Number($('portal-port').value),
    router_connected: connectedRouter,
  };
  // Loopback is the honest answer when this host has no LAN address: it is
  // what Shepherd will actually be able to bind.
  if (!body.dns_listen.length && !(state.addrs || []).length) body.dns_listen = ['127.0.0.1'];
  const btn = $('finish');
  btn.disabled = true;
  result('finish-result', 'Writing ' + state.config_path + '…');
  try {
    const out = await post('/api/setup/finish', body);
    $('form').hidden = true;
    $('after').hidden = false;
    $('a-written').textContent = 'Wrote ' + (out.absolute || out.written) + '.';
    $('r-addr').textContent = body.dns_listen[0] + (body.dns_port === 53 ? '' : ' port ' + body.dns_port);
    $('r-self').textContent = body.dns_listen[0];
    $('a-token-file').textContent = out.token_file;
    waitForShepherd();
  } catch (e) {
    btn.disabled = false;
    result('finish-result', e.message, 'bad');
  }
}

// -------------------------------------------------- after Shepherd is up

async function waitForShepherd() {
  for (let i = 0; i < 120; i++) {
    try {
      const out = await get('/api/setup/running');
      if (out.running) {
        $('a-waiting').textContent = 'Shepherd is up.';
        $('a-waiting').className = 'result good';
        drawCategoriesApplied(out);
        $('a-verify').hidden = false;
        $('a-token').hidden = false;
        if (out.portal) {
          const link = $('a-portal');
          link.href = out.portal;
          link.textContent = 'Open the portal (' + out.portal + ')';
        }
        loadToken();
        verify();
        return;
      }
    } catch { /* setup is still the only thing up; keep waiting */ }
    await new Promise((r) => setTimeout(r, 1000));
  }
  $('a-waiting').textContent = 'Shepherd has not reported in. It may have failed to start — check its log.';
  $('a-waiting').className = 'result bad';
}

// drawCategoriesApplied sends the categories chosen before the write, now
// that there is a running policy to put them in.
async function drawCategoriesApplied(running) {
  const ids = chosenCategories();
  if (!ids.length || !running.can_block) return;
  try {
    await post('/api/setup/categories', { ids });
  } catch (e) {
    note('cat-note', 'Those categories could not be switched on: ' + e.message + '. The portal\'s Blocking screen can do it.', 'warn');
  }
}

async function verify() {
  const btn = $('verify');
  btn.disabled = true;
  result('verify-result', 'Asking Shepherd…');
  try {
    const out = await post('/api/setup/verify');
    if (!out.ready) {
      result('verify-result', 'Shepherd is not running yet.', 'warn');
      btn.disabled = false;
      return;
    }
    const rows = $('verify-rows');
    rows.replaceChildren();
    for (const c of out.checks || []) {
      const div = document.createElement('div');
      div.className = 'check ' + (c.answers && c.resolve && c.blocks ? 'good' : 'bad');
      const addr = document.createElement('code');
      addr.textContent = c.addr + ' ' + c.proto;
      const said = document.createElement('span');
      said.textContent = c.answers
        ? (c.resolve ? ' resolves' : ' answered but could not resolve') + (c.blocks ? ' and blocks' : ', does not block')
        : ' no answer' + (c.detail ? ': ' + c.detail : '');
      div.append(addr, said);
      rows.append(div);
    }
    if (out.ok) {
      result('verify-result', 'Every listener resolves what it should and blocks what it should.', 'good');
    } else {
      result('verify-result', 'Not everything is answering yet. Give it a few seconds and check again; if an '
        + 'address stays silent, something else may hold that port.', 'bad');
    }
    $('a-router').hidden = false;
  } catch (e) {
    result('verify-result', e.message, 'bad');
  }
  btn.disabled = false;
}

async function loadToken() {
  try {
    const out = await get('/api/setup/token');
    $('token').value = out.token;
  } catch (e) {
    result('verify-result', e.message, 'bad');
  }
}

function wireToken() {
  $('token-show').addEventListener('click', () => {
    const f = $('token');
    const shown = f.type === 'text';
    f.type = shown ? 'password' : 'text';
    $('token-show').textContent = shown ? 'Show' : 'Hide';
  });
  $('token-copy').addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText($('token').value);
      result('verify-result', 'Token copied.', 'good');
    } catch {
      $('token').type = 'text';
      $('token-show').textContent = 'Hide';
    }
  });
  $('token-saved').addEventListener('change', (e) => { $('token-ok').disabled = !e.target.checked; });
  $('token-ok').addEventListener('click', () => {
    $('a-router').hidden = false;
    $('a-router').scrollIntoView({ behavior: 'smooth', block: 'start' });
  });
}

// ------------------------------------------------------------------- router

function routerChanged() {
  const picked = document.querySelector('input[name=router]:checked');
  const which = picked ? picked.value : 'skip';
  $('unifi').hidden = which !== 'unifi';
  $('eero-note').hidden = which !== 'eero';
}

function drawRouterChoice() {
  const radios = $('router-choice');
  radios.replaceChildren();
  if (!state.can_router) {
    const p = document.createElement('p');
    p.className = 'note';
    p.textContent = 'This build cannot read a router, so there is nothing to connect.';
    radios.append(p);
    return;
  }
  for (const [value, text] of [['skip', 'Skip for now'], ['unifi', 'A UniFi controller'], ['eero', 'An eero network']]) {
    const label = row('router', value, text, '', 'radio', value === 'skip');
    label.querySelector('input').addEventListener('change', routerChanged);
    radios.append(label);
  }
}

async function connectUniFi() {
  const btn = $('u-connect');
  btn.disabled = true;
  result('u-result', 'Reading the controller once to check it…');
  try {
    const out = await post('/api/setup/router', {
      base_url: $('u-url').value,
      username: $('u-user').value,
      password: $('u-pass').value,
      site: $('u-site').value,
      allow_self_signed: $('u-self').checked,
    });
    btn.disabled = false;
    if (!out.ok) {
      result('u-result', out.error, 'bad');
      return;
    }
    result('u-result', 'Connected. The Bandwidth screen fills in as it polls.', 'good');
    connectedRouter = 'unifi';
  } catch (e) {
    btn.disabled = false;
    result('u-result', e.message, 'bad');
  }
}

async function allDone() {
  result('done-result', 'Closing…');
  try {
    await post('/api/setup/done');
  } catch { /* the listener going away mid-request is the expected ending */ }
  result('done-result', 'Setup is closed. Shepherd keeps running.', 'good');
  $('all-done').disabled = true;
}

// --------------------------------------------------------------------- load

async function load() {
  try {
    state = await get('/api/setup/state');
  } catch (e) {
    $('load').textContent = 'Could not read this host: ' + e.message;
    return;
  }
  draw();
  drawCategories();
  drawRouterChoice();
  wireToken();
  $('dns-port').addEventListener('change', checkPort);
  $('measure').addEventListener('click', measure);
  $('verify').addEventListener('click', verify);
  $('u-connect').addEventListener('click', connectUniFi);
  $('all-done').addEventListener('click', allDone);
  $('form').addEventListener('submit', finish);
}

function drawCategories() {
  const box = $('categories');
  box.replaceChildren();
  const cats = state.categories || [];
  if (!cats.length) {
    note('cat-note', 'The catalog is not available, so there is nothing to switch on here. The portal\'s Blocking screen has all of it.');
    return;
  }
  for (const c of cats) box.append(row('cat', c.id, c.name, c.description, 'checkbox', c.suggested));
  note('cat-note', 'The ticked ones are what a new install usually wants. Everything else — per device, per '
    + 'group, schedules, the rest of the catalog — is on the portal\'s Blocking screen.');
}

load();
