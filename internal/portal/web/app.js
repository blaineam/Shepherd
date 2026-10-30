// Names, devices and reasons come from the network, so every value is placed
// with textContent, never innerHTML.
(() => {
  const $ = (s) => document.querySelector(s);
  const el = (tag, cls, text) => {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  };
  const MAX_ROWS = 400;
  let last = 0;
  let rows = [];
  let filter = '';
  let timers = [];
  const stopPolling = () => { timers.forEach(clearInterval); timers = []; };

  async function api(path, opts = {}) {
    const res = await fetch(path, {
      credentials: 'same-origin',
      ...opts,
      headers: { 'X-Shepherd': '1', 'Content-Type': 'application/json', ...(opts.headers || {}) },
    });
    if (res.status === 401) { stopPolling(); $('#login').hidden = false; throw new Error('unauthorized'); }
    if (!res.ok) throw new Error((await res.text()).trim() || res.statusText);
    return res.status === 202 ? null : res.json();
  }

  const fmtNum = (n) => Number(n || 0).toLocaleString();
  function fmtUptime(s) {
    const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
    return (d ? d + 'd ' : '') + (h || d ? h + 'h ' : '') + m + 'm up';
  }

  function fillList(id, items, build) {
    const ul = $(id);
    ul.replaceChildren();
    if (!items.length) { const li = el('li'); li.append(el('span', 'muted', 'Nothing yet')); ul.append(li); return; }
    items.forEach((it) => ul.append(build(it)));
  }

  function renderStatus(s) {
    $('#version').textContent = s.version;
    $('#uptime').textContent = fmtUptime(s.uptime_seconds);
    $('#t-total').textContent = fmtNum(s.stats.total);
    $('#t-blocked').textContent = fmtNum(s.stats.blocked);
    $('#t-pct').textContent = s.stats.total ? (100 * s.stats.blocked / s.stats.total).toFixed(1) + '% of queries' : '';
    $('#t-cached').textContent = fmtNum(s.stats.cached);
    $('#t-errors').textContent = fmtNum(s.stats.errors);
    $('#t-listed').textContent = fmtNum(s.listed_domains);
    $('#p-relay').checked = !!s.policies['apple-private-relay'];

    fillList('#upstreams', s.upstreams, (u) => {
      const li = el('li');
      li.append(el('span', u.healthy ? 'dot' : 'dot bad'));
      const name = el('span', 'grow', u.addr);
      name.title = u.last_error || '';
      li.append(name, el('span', 'num', u.rtt_ms ? u.rtt_ms.toFixed(0) + ' ms' : '-'));
      return li;
    });
    fillList('#lists', s.lists, (l) => {
      const li = el('li');
      li.append(el('span', l.error ? 'dot bad' : 'dot'));
      const name = el('span', 'grow', l.name);
      name.title = l.error || l.url;
      li.append(name, el('span', 'num', l.error ? 'rejected' : fmtNum(l.count)));
      return li;
    });
    const countRow = (c) => {
      const li = el('li');
      li.append(el('span', 'grow', c.key), el('span', 'num', fmtNum(c.n)));
      return li;
    };
    fillList('#top-clients', s.stats.top_clients, countRow);
    fillList('#top-blocked', s.stats.top_blocked, countRow);
  }

  function renderRules(r) {
    const items = [...r.block.map((d) => ({ kind: 'block', d })), ...r.allow.map((d) => ({ kind: 'allow', d }))];
    fillList('#rules', items, (it) => {
      const li = el('li');
      li.append(el('span', 'act ' + (it.kind === 'block' ? 'blocked' : 'allowed'), it.kind), el('span', 'grow', it.d));
      const rm = el('button', 'mini', 'remove');
      rm.onclick = () => rule('DELETE', it.kind, it.d);
      li.append(rm);
      return li;
    });
    $('#p-relay').checked = !!r.policies['apple-private-relay'];
  }

  async function rule(method, kind, domain) {
    const q = new URLSearchParams({ kind, domain });
    const r = method === 'DELETE'
      ? await api('/api/rules?' + q, { method })
      : await api('/api/rules', { method, body: JSON.stringify({ kind, domain }) });
    renderRules(r);
  }

  function renderRows() {
    const f = filter.toLowerCase();
    const body = $('#rows');
    body.replaceChildren();
    for (const e of rows) {
      if (f && !(`${e.client} ${e.name} ${e.action} ${e.reason || ''}`.toLowerCase().includes(f))) continue;
      const tr = el('tr');
      const time = new Date(e.time).toLocaleTimeString();
      tr.append(el('td', 'muted', time), el('td', '', e.client), el('td', 'dom', e.name), el('td', 'muted', e.type));
      const res = el('td');
      const pill = el('span', 'act ' + e.action, e.action);
      if (e.reason) pill.title = e.reason;
      res.append(pill);
      if (e.reason && e.action !== 'error') res.append(' ', el('span', 'muted small', e.reason));
      tr.append(res, el('td', 'muted', e.upstream || ''), el('td', 'num', e.ms.toFixed(1)));
      const act = el('td');
      const b = el('button', 'mini', e.action === 'blocked' ? 'allow' : 'block');
      b.onclick = () => rule('POST', e.action === 'blocked' ? 'allow' : 'block', e.name).catch((err) => alert(err.message));
      act.append(b);
      tr.append(act);
      body.append(tr);
    }
  }

  async function pollQueries() {
    try {
      const r = await api('/api/queries?limit=200&after=' + last);
      if (r.entries.length) {
        rows = r.entries.slice().reverse().concat(rows).slice(0, MAX_ROWS);
        last = r.last;
        renderRows();
      }
      $('#live').textContent = 'live';
      $('#live').className = 'pill live';
    } catch (e) {
      if (e.message !== 'unauthorized') { $('#live').textContent = 'offline'; $('#live').className = 'pill down'; }
    }
  }
  async function pollStatus() {
    try { renderStatus(await api('/api/status')); } catch (e) { /* shown by pollQueries */ }
  }

  $('#filter').addEventListener('input', (e) => { filter = e.target.value; renderRows(); });
  $('#rule-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    try { await rule('POST', $('#rule-kind').value, $('#rule-domain').value); $('#rule-domain').value = ''; }
    catch (err) { alert(err.message); }
  });
  $('#refresh').addEventListener('click', () => api('/api/lists/refresh', { method: 'POST' }).then(pollStatus));
  $('#p-relay').addEventListener('change', async (e) => {
    try { renderRules(await api('/api/policies', { method: 'POST', body: JSON.stringify({ name: 'apple-private-relay', enabled: e.target.checked }) })); }
    catch (err) { alert(err.message); e.target.checked = !e.target.checked; }
  });
  $('#login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      await api('/api/login', { method: 'POST', body: JSON.stringify({ token: $('#token').value }) });
      $('#login').hidden = true;
      $('#login-err').textContent = '';
      start();
    } catch (err) { $('#login-err').textContent = 'That token did not work.'; }
  });

  function start() {
    stopPolling();
    pollStatus(); pollQueries();
    api('/api/rules').then(renderRules).catch(() => {});
    timers = [setInterval(pollQueries, 1000), setInterval(pollStatus, 3000)];
  }
  start();
})();
