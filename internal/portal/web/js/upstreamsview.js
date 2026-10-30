// The Upstreams screen: resolver health, order, an add box that tests before
// adding, presets, and the bootstrap resolvers. Addresses and errors come from
// the server, so all text is set with textContent.
import { el } from './dom.js';
import { icon, iconButton, button, emptyState, unavailableCard, confirmDialog } from './ui.js';
import { classifyAddr, KIND_LABEL, isEncrypted, move, presetVariants, parseBootstrap, healthLabel } from './upstreams.js';
import { unavailable } from './mgmt.js';
import { fmtNum } from './format.js';

export function createUpstreams({ root, mgmt, notify }) {
  let data = null;
  let loadError = null;
  let timer = 0;
  let dragFrom = -1;
  let started = false;
  let busy = false;

  root.replaceChildren();
  const head = el('div', 'pg-head stack');
  const title = el('h2', 'pg-title');
  title.append(el('span', '', 'Upstreams'));
  head.append(title, el('p', 'pg-sub muted', 'Where Shepherd sends the queries it does not block. The first healthy resolver in the list is used; the others take over automatically.'));
  const grid = el('div', 'up-grid');
  const colA = el('div', 'up-col');
  const colB = el('div', 'up-col');
  grid.append(colA, colB);
  root.append(head, grid);

  const listCard = el('section', 'card up-card');
  const addCard = el('section', 'card up-card');
  const presetCard = el('section', 'card up-card');
  const bootCard = el('section', 'card up-card');
  const noteCard = el('section', 'card up-card note');
  colA.append(listCard, bootCard, noteCard);
  colB.append(addCard, presetCard);

  const cardHead = (t, sub) => { const h = el('div', 'card-h'); const hh = el('h3', 'card-t', t); h.append(hh); if (sub) h.append(el('span', 'muted small', sub)); return h; };

  // ------------------------------------------------------------- resolver list
  function paintList() {
    listCard.replaceChildren(cardHead('Resolvers', data ? data.upstreams.length + ' configured' : ''));
    if (!data) return;
    const ul = el('ul', 'up-list');
    ul.setAttribute('aria-label', 'Resolvers in priority order');
    const only = data.upstreams.length <= 1;
    data.upstreams.forEach((u, i) => {
      const li = el('li', 'up-item' + (u.healthy ? '' : ' bad'));
      li.draggable = true;
      li.dataset.i = String(i);
      const grip = el('span', 'grip');
      grip.append(icon('grip', 16));
      grip.title = 'Drag to reorder';
      const dot = el('span', u.healthy ? 'dot' : 'dot bad');
      dot.title = u.healthy ? 'Healthy' : 'Failing';
      const main = el('div', 'up-main');
      const line = el('div', 'up-line');
      line.append(el('span', 'up-addr mono', u.config), el('span', 'badge kind' + (isEncrypted(u.kind) ? ' enc' : ''), KIND_LABEL[u.kind] || String(u.kind || '').toUpperCase()));
      if (isEncrypted(u.kind)) { const l = icon('lock', 12, 'enc-ico'); l.setAttribute('aria-label', 'Encrypted'); line.append(l); }
      const stats = el('div', 'up-stats');
      stats.append(el('span', 'mono ' + (u.healthy ? 'good' : 'badtxt'), healthLabel(u)));
      if (u.consecutive_failures) stats.append(el('span', 'muted small', u.consecutive_failures + ' failure' + (u.consecutive_failures === 1 ? '' : 's') + ' in a row'));
      if (Number.isFinite(u.queries)) stats.append(el('span', 'muted small', fmtNum(u.queries) + ' queries' + (u.errors ? ', ' + fmtNum(u.errors) + ' errors' : '')));
      main.append(line, stats);
      if (u.last_error) main.append(el('div', 'up-err small', u.last_error));
      const acts = el('div', 'up-acts');
      const upB = iconButton('up', 'Move ' + u.config + ' up', () => reorder(i, i - 1));
      const dnB = iconButton('down', 'Move ' + u.config + ' down', () => reorder(i, i + 1));
      upB.disabled = i === 0; dnB.disabled = i === data.upstreams.length - 1;
      const rm = iconButton('trash', 'Remove ' + u.config, () => removeOne(u), 'danger-i');
      rm.disabled = only;
      if (only) rm.title = 'At least one resolver is required';
      acts.append(upB, dnB, rm);
      li.append(grip, el('span', 'up-n mono', String(i + 1)), dot, main, acts);

      li.addEventListener('dragstart', (e) => { dragFrom = i; li.classList.add('drag'); if (e.dataTransfer) { e.dataTransfer.effectAllowed = 'move'; e.dataTransfer.setData('text/plain', u.config); } });
      li.addEventListener('dragend', () => { dragFrom = -1; li.classList.remove('drag'); for (const x of ul.children) x.classList.remove('over'); });
      li.addEventListener('dragover', (e) => { if (dragFrom < 0) return; e.preventDefault(); for (const x of ul.children) x.classList.toggle('over', x === li && dragFrom !== i); });
      li.addEventListener('drop', (e) => { e.preventDefault(); const from = dragFrom; dragFrom = -1; if (from >= 0 && from !== i) reorder(from, i); });
      ul.append(li);
    });
    listCard.append(ul);
  }

  async function reorder(from, to) {
    if (!data || busy) return;
    const prev = data.upstreams;
    const next = move(prev, from, to);
    if (next === prev) return;
    data = { ...data, upstreams: next };
    paintList();
    try { adopt(await mgmt.setUpstreams(next.map((u) => u.config))); }
    catch (e) { data = { ...data, upstreams: prev }; paintList(); notify('Could not reorder: ' + e.message); }
  }

  async function removeOne(u) {
    const ok = await confirmDialog({ title: 'Remove this resolver?', body: u.config + ' will no longer be used. You can add it again later.', confirm: 'Remove', danger: true });
    if (!ok) return;
    try { adopt(await mgmt.removeUpstream(u.config)); } catch (e) { notify(e.message); }
  }

  // ------------------------------------------------------------- add box
  function paintAdd() {
    addCard.replaceChildren(cardHead('Add a resolver'));
    const f = el('form', 'up-add');
    const input = el('input', 'mono');
    input.placeholder = 'IP, tls://host or https://host/dns-query';
    input.setAttribute('aria-label', 'Resolver address');
    input.autocomplete = 'off';
    input.spellcheck = false;
    const hint = el('p', 'hint small muted', 'Plain IP, tcp://ip, tls://host (DoT) or https://host/dns-query (DoH).');
    hint.setAttribute('aria-live', 'polite');
    const result = el('div', 'probe');
    result.setAttribute('role', 'status');
    result.hidden = true;
    const row = el('div', 'up-add-row');
    const test = button('Test', 'ghost', null, 'refresh');
    test.type = 'button';
    const add = button('Add', 'primary');
    add.type = 'submit';
    row.append(input, test, add);
    f.append(row, hint, result);

    const paintHint = () => {
      const c = classifyAddr(input.value);
      hint.className = 'hint small ' + (!input.value.trim() ? 'muted' : c.ok ? 'good' : 'badtxt');
      hint.textContent = c.ok ? c.hint : c.error || c.hint;
      result.hidden = true;
    };
    input.addEventListener('input', paintHint);

    async function probe() {
      const addr = input.value.trim();
      const c = classifyAddr(addr);
      if (!c.ok) { paintHint(); input.focus(); return null; }
      result.hidden = false;
      result.className = 'probe wait';
      result.textContent = 'Testing ' + addr + '…';
      test.disabled = add.disabled = true;
      try {
        const r = await mgmt.testUpstream(addr);
        result.className = 'probe ' + (r.ok ? 'ok' : 'fail');
        result.textContent = r.ok ? 'Reachable. ' + (r.rtt_ms ? Math.round(r.rtt_ms) + ' ms' : '') + (r.rcode ? ' (' + r.rcode + ')' : '') : 'Failed: ' + (r.error || 'no answer');
        return r;
      } catch (e) {
        result.className = 'probe fail';
        result.textContent = unavailable(e) ? 'Testing is not available on this version.' : 'Test failed: ' + e.message;
        return unavailable(e) ? { ok: true, untested: true } : { ok: false };
      } finally { test.disabled = add.disabled = false; }
    }
    test.addEventListener('click', probe);
    f.addEventListener('submit', async (e) => {
      e.preventDefault();
      const addr = input.value.trim();
      const r = await probe();
      if (!r) return;
      if (!r.ok) {
        const go = await confirmDialog({ title: 'Add it anyway?', body: addr + ' did not answer the test. Shepherd would mark it unhealthy and use the others. Encrypted resolvers often fail on networks that block them.', confirm: 'Add anyway' });
        if (!go) return;
      }
      try { adopt(await mgmt.addUpstream(addr)); input.value = ''; paintHint(); notify('Added ' + addr); } catch (err) { result.hidden = false; result.className = 'probe fail'; result.textContent = err.message; }
    });
    addCard.append(f);
  }

  // ------------------------------------------------------------- presets
  function paintPresets() {
    presetCard.replaceChildren(cardHead('Public resolvers', 'one tap to add'));
    if (!data) return;
    const have = new Set(data.upstreams.map((u) => u.config));
    if (!data.presets.length) { presetCard.append(el('p', 'muted small', 'This server offers no presets. Add any address above.')); return; }
    const wrap = el('div', 'presets');
    for (const p of data.presets) {
      const c = el('div', 'preset');
      const h = el('div', 'pr-head');
      h.append(el('strong', '', p.name));
      if (p.filtering && p.filtering !== 'none') h.append(el('span', 'badge', 'Filters ' + p.filtering));
      c.append(h, el('p', 'pr-desc muted small', p.description || ''));
      if (p.notes) c.append(el('p', 'pr-note muted small', p.notes));
      const vs = el('div', 'pr-vars');
      for (const v of presetVariants(p)) {
        const added = have.has(v.addr);
        const b = button(added ? v.label + ' added' : v.label, 'ghost mini-b' + (isEncrypted(v.kind) ? ' enc' : ''), async () => {
          b.disabled = true;
          try { adopt(await mgmt.addUpstream(v.addr)); notify('Added ' + p.name + ' (' + v.label + ')'); } catch (e) { notify(e.message); b.disabled = false; }
        }, added ? 'check' : isEncrypted(v.kind) ? 'lock' : 'plus');
        b.disabled = added;
        b.title = v.addr;
        vs.append(b);
      }
      c.append(vs);
      wrap.append(c);
    }
    presetCard.append(wrap);
  }

  // ------------------------------------------------------------- bootstrap
  function paintBoot() {
    bootCard.replaceChildren(cardHead('Bootstrap resolvers'));
    bootCard.append(el('p', 'muted small', 'Used only to look up the address of hostnames in tls:// and https:// upstreams, before the encrypted connection exists. Use plain IPs, one or two.'));
    const f = el('form', 'inline-add');
    const inp = el('input', 'mono');
    inp.value = data ? data.bootstrap.join(', ') : '';
    inp.setAttribute('aria-label', 'Bootstrap resolver IPs');
    inp.placeholder = '9.9.9.9, 1.1.1.1';
    const save = button('Save', 'ghost');
    save.type = 'submit';
    const err = el('p', 'err small');
    f.append(inp, save);
    f.addEventListener('submit', async (e) => {
      e.preventDefault();
      err.textContent = '';
      const p = parseBootstrap(inp.value);
      if (p.bad.length) { err.textContent = p.bad[0] + ' is not an IP address.'; return; }
      if (!p.servers.length) { err.textContent = 'Enter at least one IP address.'; return; }
      try { adopt(await mgmt.setBootstrap(p.servers)); notify('Bootstrap resolvers saved'); } catch (er) { err.textContent = er.message; }
    });
    bootCard.append(f, err);
  }

  function paintNote() {
    noteCard.replaceChildren(cardHead('Encrypted upstreams'));
    noteCard.append(el('p', 'muted', 'DNS over TLS (port 853) and DNS over HTTPS (port 443) keep your queries private from the network between you and the resolver. Some networks, hotels and captive portals block them. Shepherd checks every resolver continuously and fails over to the next healthy one automatically, so a blocked resolver slows nothing down. If you travel with Shepherd, keep one plain resolver as a last resort.'));
  }

  // ------------------------------------------------------------- data
  function adopt(r) {
    if (!r || !Array.isArray(r.upstreams)) return;
    data = { upstreams: r.upstreams, presets: Array.isArray(r.presets) ? r.presets : (data ? data.presets : []), bootstrap: Array.isArray(r.bootstrap) ? r.bootstrap : (data ? data.bootstrap : []) };
    loadError = null;
    paintAll(false);
  }

  function paintAll(full = true) {
    if (loadError) {
      for (const c of [listCard, addCard, presetCard, bootCard, noteCard]) c.replaceChildren();
      listCard.append(unavailable(loadError) ? unavailableCard('Upstream management') : emptyState('Could not load upstreams', loadError.message, button('Try again', 'ghost', load)));
      return;
    }
    paintList();
    paintPresets();
    if (full) { paintAdd(); paintBoot(); paintNote(); }
    else if (document.activeElement && !bootCard.contains(document.activeElement)) paintBoot();
  }

  async function load() {
    try { adopt2(await mgmt.upstreams()); } catch (e) { if (!data) loadError = e; paintAll(!started || !!loadError); }
  }
  function adopt2(r) { const first = !data; adopt(r); if (first) { paintAdd(); paintBoot(); paintNote(); } }

  return {
    async show() {
      if (!started) { started = true; paintAdd(); paintBoot(); paintNote(); }
      await load();
      clearInterval(timer);
      timer = setInterval(() => { if (!root.hidden && dragFrom < 0 && !busy && !document.hidden) mgmt.upstreams().then((r) => { data = { ...data, upstreams: r.upstreams, presets: r.presets || data.presets }; paintList(); paintPresets(); }).catch(() => {}); }, 4000);
    },
    hide() { clearInterval(timer); },
  };
}
