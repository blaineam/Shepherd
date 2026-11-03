// The first-run setup page's behaviour. Plain modules, no build step and
// nothing loaded from the internet, which is the same rule the portal's own
// front end follows.
//
// Every value that came from the host (an address, an interface name, an
// error from a resolver) goes into the page through textContent, never
// innerHTML.

const $ = (id) => document.getElementById(id);

// post sends JSON and returns the parsed answer, throwing the server's own
// message so it can be shown to the person who pressed the button.
// token is the one-time token from the address Shepherd printed. It is kept
// in memory and sent as a header: nothing stores it in the browser, and it
// leaves the address bar as soon as the page has read it.
const token = new URLSearchParams(location.search).get('token') || '';
try {
  history.replaceState(null, '', location.pathname);
} catch { /* an address bar that keeps the token is not worth failing over */ }

async function post(path, body) {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Shepherd-Setup': token },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(text.trim() || res.statusText);
  return text ? JSON.parse(text) : {};
}

let state = null;

// chosenAddrs is every DNS address ticked, in the order they were offered.
const chosenAddrs = () => Array.from(document.querySelectorAll('input[name=addr]:checked')).map((i) => i.value);

// upstreams is whatever the resolver step currently means: the typed list
// when there is one, otherwise the chosen preset.
function upstreams() {
  const typed = $('custom').value.split('\n').map((s) => s.trim()).filter(Boolean);
  if (typed.length) return typed;
  const picked = document.querySelector('input[name=preset]:checked');
  if (!picked) return [];
  return state.presets[Number(picked.value)].addrs;
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

  const presets = $('presets');
  presets.replaceChildren();
  (state.presets || []).forEach((p, i) => {
    const label = document.createElement('label');
    const input = document.createElement('input');
    input.type = 'radio';
    input.name = 'preset';
    input.value = String(i);
    input.checked = i === 0;
    const text = document.createElement('span');
    const name = document.createElement('strong');
    name.textContent = p.name + ' (' + p.addrs.join(', ') + ')';
    const note = document.createElement('span');
    note.className = 'pnote';
    note.textContent = ' — ' + p.note;
    text.append(name, note);
    label.append(input, text);
    presets.append(label);
  });

  const choices = [['skip', 'Skip for now'], ['unifi', 'A UniFi controller'], ['eero', 'An eero network']];
  const radios = $('router-choice');
  radios.replaceChildren();
  if (!state.can_router) {
    const p = document.createElement('p');
    p.className = 'note';
    p.textContent = 'This build cannot read a router, so there is nothing to connect.';
    radios.append(p);
  } else {
    for (const [value, text] of choices) {
      const label = document.createElement('label');
      const input = document.createElement('input');
      input.type = 'radio';
      input.name = 'router';
      input.value = value;
      input.checked = value === 'skip';
      input.addEventListener('change', routerChanged);
      const span = document.createElement('span');
      span.textContent = text;
      label.append(input, span);
      radios.append(label);
    }
  }

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
}

function note(id, text, cls) {
  const el = $(id);
  el.className = 'note small' + (cls ? ' ' + cls : '');
  el.textContent = text;
}

function result(id, text, cls) {
  const el = $(id);
  el.className = 'result' + (cls ? ' ' + cls : '');
  el.textContent = text;
}

function routerChanged() {
  const picked = document.querySelector('input[name=router]:checked');
  const which = picked ? picked.value : 'skip';
  $('unifi').hidden = which !== 'unifi';
  $('eero-note').hidden = which !== 'eero';
}

// A changed port is checked against the chosen addresses right away, while
// it can still be acted on.
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

async function testUpstreams() {
  const list = upstreams();
  if (!list.length) {
    result('up-result', 'Choose a preset or type at least one resolver.', 'bad');
    return;
  }
  const btn = $('test-up');
  btn.disabled = true;
  result('up-result', 'Testing ' + list.length + (list.length === 1 ? ' resolver…' : ' resolvers…'));
  const bad = [];
  const times = [];
  for (const addr of list) {
    try {
      const out = await post('/api/setup/upstream-test', { addr });
      if (out.ok) times.push(addr + ' ' + out.ms + 'ms');
      else bad.push(addr + ': ' + out.error);
    } catch (e) {
      bad.push(addr + ': ' + e.message);
    }
  }
  btn.disabled = false;
  if (bad.length) {
    result('up-result', 'No answer from ' + bad.join('; ') + '. You can still finish with these, but check '
      + 'this host\'s own internet access first.', 'bad');
    return;
  }
  result('up-result', 'All answered: ' + times.join(', '), 'good');
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

let connectedRouter = '';

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
    $('done-written').textContent = 'Wrote ' + (out.absolute || out.written) + '. Shepherd is starting on it now.';
    $('done-dig').textContent = 'dig ' + out.dig + ' example.com';
    const link = $('done-portal');
    link.textContent = out.portal;
    link.href = out.portal;
    $('done-token').textContent = out.token_file;
    $('done').hidden = false;
  } catch (e) {
    btn.disabled = false;
    result('finish-result', e.message, 'bad');
  }
}

async function load() {
  try {
    const res = await fetch('/api/setup/state', { headers: { 'X-Shepherd-Setup': token } });
    if (!res.ok) throw new Error((await res.text()).trim() || res.statusText);
    state = await res.json();
  } catch (e) {
    $('load').textContent = 'Could not read this host: ' + e.message;
    return;
  }
  draw();
  $('dns-port').addEventListener('change', checkPort);
  $('test-up').addEventListener('click', testUpstreams);
  $('u-connect').addEventListener('click', connectUniFi);
  $('form').addEventListener('submit', finish);
}

load();
