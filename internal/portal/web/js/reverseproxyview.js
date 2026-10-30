// The Reverse proxy screen: the listener's state and certificate, an add
// form, and the list of proxied hosts with enable, edit and remove. Every
// name and address comes from the server or the owner's typing, so all
// text is set with textContent and links are built as properties.
import { el } from './dom.js';
import { button, iconButton, toggle, emptyState, unavailableCard, confirmDialog } from './ui.js';
import { unavailable } from './mgmt.js';
import { parseTarget, formatTarget, hostWarnings, sortHosts, filterHosts, certSummary, hostBody, publicURL } from './reverseproxy.js';

export function createReverseProxy({ root, mgmt, notify }) {
  let status = null;
  let hosts = [];
  let loadError = null;
  let query = '';
  let editing = '';

  root.replaceChildren();
  const head = el('div', 'pg-head stack');
  const title = el('h2', 'pg-title');
  title.append(el('span', '', 'Reverse proxy'));
  head.append(title, el('p', 'pg-sub muted', 'Serve your other self-hosted services under their own names, over HTTPS with one wildcard certificate. Each request is forwarded by its name to the backend you set here, WebSockets included. A name not listed here gets a plain 404, never this portal.'));
  const body = el('div', 'rp-body');
  root.append(head, body);

  const statusCard = el('section', 'card');
  const addCard = el('section', 'card');
  const listCard = el('section', 'card');

  const cardHead = (t, extra) => { const h = el('div', 'card-h'); h.append(el('h3', 'card-t', t)); if (extra) h.append(extra); return h; };

  function paintStatus() {
    statusCard.replaceChildren(cardHead('Listener'));
    const kv = el('dl', 'nh-kv');
    const row = (k, v, cls = '') => { kv.append(el('dt', '', k)); kv.append(el('dd', cls, v)); };
    const cert = certSummary(status);
    row('State', status.enabled ? 'On' : 'Off', status.enabled ? 'good' : 'muted');
    row('Address', status.listen || '—', 'mono');
    row('Certificate for', status.wildcard || 'no domain set', 'mono');
    if (status.enabled) row('Certificate', cert.text, 'rp-tone-' + cert.tone);
    statusCard.append(kv);
    if (!status.enabled) {
      statusCard.append(el('p', 'muted small rp-note', 'The listener is off. Hosts added here are saved now and start answering once [reverseproxy] is enabled in shepherd.toml (with a domain and a Cloudflare token) and Shepherd restarts. Read docs/REVERSEPROXY.md before moving real traffic over.'));
    }
  }

  // A domain field, a backend field and the verify switch, shared by the
  // add form and the inline editor. Returns the pieces plus read().
  function hostFields(h) {
    const domain = el('input', 'mono');
    domain.placeholder = 'jellyfin.example.com';
    domain.setAttribute('aria-label', 'Public name');
    domain.autocomplete = 'off';
    domain.spellcheck = false;
    domain.value = h ? h.domain : '';
    const target = el('input', 'mono');
    target.placeholder = 'http://127.0.0.1:8096';
    target.setAttribute('aria-label', 'Backend address');
    target.autocomplete = 'off';
    target.spellcheck = false;
    target.value = h ? formatTarget(h) : '';
    const skip = toggle({ checked: h ? !!h.skip_tls_verify : false, label: 'Accept any backend certificate', title: 'For an https backend with a self-signed certificate. Off means the backend\'s certificate must be valid for its address.' });
    const skipWrap = el('div', 'rp-skip small');
    skipWrap.append(skip.root, el('span', '', 'Accept any backend certificate'));
    const syncSkip = () => { const t = parseTarget(target.value); skipWrap.hidden = !(t.ok && t.scheme === 'https'); };
    target.addEventListener('input', syncSkip);
    syncSkip();
    const err = el('p', 'err small');
    err.setAttribute('role', 'status');
    const read = (enabled) => {
      const r = hostBody({ domain: domain.value, target: target.value, skipVerify: skip.input.checked, enabled });
      err.textContent = r.ok ? '' : r.error;
      if (!r.ok) (r.field === 'domain' ? domain : target).focus();
      return r;
    };
    const reset = () => { domain.value = ''; target.value = ''; skip.input.checked = false; syncSkip(); };
    return { domain, target, skipWrap, err, read, reset };
  }

  function paintAdd() {
    addCard.replaceChildren(cardHead('Add a proxy host'));
    const f = el('form', 'rp-form');
    const fields = hostFields(null);
    const add = button('Add', 'primary');
    add.type = 'submit';
    const row = el('div', 'rp-form-row');
    row.append(fields.domain, el('span', 'rp-arrow muted', '→'), fields.target, add);
    f.append(row, fields.skipWrap, fields.err);
    f.addEventListener('submit', async (e) => {
      e.preventDefault();
      const r = fields.read(true);
      if (!r.ok) return;
      add.disabled = true;
      try {
        const h = await mgmt.addProxyHost(r.body);
        hosts = sortHosts([...hosts, h]);
        fields.reset();
        paintList();
        notify('Added ' + h.domain);
      } catch (er) { fields.err.textContent = er.message; }
      add.disabled = false;
    });
    addCard.append(f);
  }

  function hostRow(h) {
    if (editing === h.id) return editRow(h);
    const row = el('div', 'list-row' + (h.enabled ? '' : ' rp-off'));
    const tg = toggle({ checked: h.enabled, label: (h.enabled ? 'Disable ' : 'Enable ') + h.domain, onChange: (on, input) => setEnabled(h, on, input) });
    const main = el('div', 'lr-main');
    const name = el('div', 'lr-name');
    const link = el('a', 'mono', h.domain);
    link.href = publicURL(h.domain, status && status.listen);
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    name.append(link);
    main.append(name, el('p', 'lr-desc mono', '→\u00a0' + formatTarget(h)));
    const meta = el('div', 'lr-meta');
    if (!h.enabled) meta.append(el('span', 'badge', 'Off: answers 404'));
    if (h.target_scheme === 'https') meta.append(el('span', 'badge enc', 'HTTPS backend'));
    for (const w of hostWarnings(h, status && status.wildcard)) {
      const b = el('span', 'badge warn', w.label);
      b.title = w.title;
      meta.append(b);
    }
    if (meta.childNodes.length) main.append(meta);
    const acts = el('div', 'up-acts');
    acts.append(
      iconButton('pencil', 'Edit ' + h.domain, () => { editing = h.id; paintList(); }),
      iconButton('trash', 'Remove ' + h.domain, () => removeHost(h), 'danger-i'),
    );
    row.append(tg.root, main, acts);
    return row;
  }

  function editRow(h) {
    const row = el('form', 'list-row rp-edit');
    const fields = hostFields(h);
    const save = button('Save', 'primary');
    save.type = 'submit';
    const cancel = button('Cancel', 'ghost', () => { editing = ''; paintList(); });
    const main = el('div', 'lr-main');
    const line = el('div', 'rp-form-row');
    line.append(fields.domain, el('span', 'rp-arrow muted', '→'), fields.target, save, cancel);
    main.append(line, fields.skipWrap, fields.err);
    row.append(main);
    row.addEventListener('submit', async (e) => {
      e.preventDefault();
      const r = fields.read(h.enabled);
      if (!r.ok) return;
      save.disabled = true;
      try {
        const upd = await mgmt.updateProxyHost(h.id, r.body);
        hosts = sortHosts(hosts.map((x) => (x.id === h.id ? upd : x)));
        editing = '';
        paintList();
        notify('Saved ' + upd.domain);
      } catch (er) { fields.err.textContent = er.message; save.disabled = false; }
    });
    queueMicrotask(() => fields.domain.focus());
    return row;
  }

  async function setEnabled(h, on, input) {
    input.disabled = true;
    try {
      const upd = await mgmt.updateProxyHost(h.id, { domain: h.domain, target_scheme: h.target_scheme, target_host: h.target_host, target_port: h.target_port, skip_tls_verify: h.skip_tls_verify, enabled: on });
      hosts = hosts.map((x) => (x.id === h.id ? upd : x));
      paintList();
    } catch (e) {
      input.checked = !on;
      input.disabled = false;
      notify('Could not change ' + h.domain + ': ' + e.message);
    }
  }

  async function removeHost(h) {
    const ok = await confirmDialog({ title: 'Remove ' + h.domain + '?', body: 'Requests for this name get a 404 from the next one on. The backend itself is not touched.', confirm: 'Remove', danger: true });
    if (!ok) return;
    try {
      await mgmt.deleteProxyHost(h.id);
      hosts = hosts.filter((x) => x.id !== h.id);
      paintList();
      notify('Removed ' + h.domain);
    } catch (e) { notify(e.message); }
  }

  const search = el('input');
  search.type = 'search';
  search.placeholder = 'Filter';
  search.setAttribute('aria-label', 'Filter proxy hosts');
  search.addEventListener('input', () => { query = search.value; paintList(); });

  function paintList() {
    listCard.replaceChildren(cardHead('Proxy hosts' + (hosts.length ? ' (' + hosts.length + ')' : ''), hosts.length > 5 ? search : null));
    if (!hosts.length) {
      listCard.append(emptyState('No proxy hosts yet', 'Add a public name and the backend it should reach above.'));
      return;
    }
    const shown = filterHosts(hosts, query);
    if (!shown.length) { listCard.append(emptyState('Nothing matches', '')); return; }
    const list = el('div', 'list-rows');
    for (const h of shown) list.append(hostRow(h));
    listCard.append(list);
  }

  function paintAll() {
    body.replaceChildren();
    if (loadError) {
      body.append(unavailable(loadError) ? unavailableCard('The reverse proxy') : emptyState('Could not load the reverse proxy', loadError.message, button('Try again', 'ghost', load)));
      return;
    }
    if (!status) return;
    body.append(statusCard, addCard, listCard);
    paintStatus();
    paintAdd();
    paintList();
  }

  async function load() {
    try {
      const [st, list] = await Promise.all([mgmt.reverseProxy(), mgmt.proxyHosts()]);
      status = st;
      hosts = sortHosts(list.hosts);
      loadError = null;
    } catch (e) { loadError = e; }
    paintAll();
  }

  return {
    show() { return load(); },
    hide() { editing = ''; },
  };
}
