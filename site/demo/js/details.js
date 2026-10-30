// The Details view: everything the original dashboard did (stat tiles, live
// query table with per-row allow/block, upstream and blocklist health, user
// rules, the Private Relay switch, top devices and top blocked). Names,
// devices and reasons come from the network, so every value is placed with
// textContent, never innerHTML.
import { $, el } from './dom.js';
import { fmtNum, fmtUptime } from './format.js';

export function createDetails({ api, getRows, notify, onRulesChanged = () => {}, names = null }) {
  let filter = '';

  function fillList(id, items, build) {
    const ul = $(id);
    ul.replaceChildren();
    if (!items || !items.length) { const li = el('li'); li.append(el('span', 'muted', 'Nothing yet')); ul.append(li); return; }
    items.forEach((it) => ul.append(build(it)));
  }

  function renderStatus(s) {
    $('#version').textContent = s.version || '';
    $('#uptime').textContent = fmtUptime(s.uptime_seconds || 0);
    const st = s.stats || {};
    $('#d-total').textContent = fmtNum(st.total);
    $('#d-blocked').textContent = fmtNum(st.blocked);
    $('#d-pct').textContent = st.total ? (100 * st.blocked / st.total).toFixed(1) + '% of queries' : '';
    $('#d-cached').textContent = fmtNum(st.cached);
    $('#d-errors').textContent = fmtNum(st.errors);
    $('#d-listed').textContent = fmtNum(s.listed_domains);
    $('#p-relay').checked = !!(s.policies && s.policies['apple-private-relay']);

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
      name.title = l.error || l.url || '';
      li.append(name, el('span', 'num', l.error ? 'rejected' : fmtNum(l.count)));
      return li;
    });
    const countRow = (c) => {
      const li = el('li');
      const label = names && names.has(c.key) ? names.label(c.key) : c.key;
      const nm = el('span', 'grow', label);
      if (label !== c.key) nm.title = c.key;
      li.append(nm, el('span', 'num', fmtNum(c.n)));
      return li;
    };
    fillList('#top-clients', st.top_clients, countRow);
    fillList('#top-blocked', st.top_blocked, countRow);
  }

  function renderRules(r) {
    const items = [...(r.block || []).map((d) => ({ kind: 'block', d })), ...(r.allow || []).map((d) => ({ kind: 'allow', d }))];
    fillList('#rules', items, (it) => {
      const li = el('li');
      li.append(el('span', 'act ' + (it.kind === 'block' ? 'blocked' : 'allowed'), it.kind), el('span', 'grow', it.d));
      const rm = el('button', 'mini', 'remove');
      rm.addEventListener('click', () => rule('DELETE', it.kind, it.d).catch((err) => notify(err.message)));
      li.append(rm);
      return li;
    });
    $('#p-relay').checked = !!(r.policies && r.policies['apple-private-relay']);
  }

  async function rule(method, kind, domain) {
    const q = new URLSearchParams({ kind, domain });
    const r = method === 'DELETE'
      ? await api('/api/rules?' + q, { method })
      : await api('/api/rules', { method, body: JSON.stringify({ kind, domain }) });
    renderRules(r);
    onRulesChanged(r);
    return r;
  }

  function renderRows() {
    const f = filter.toLowerCase();
    const body = $('#rows');
    body.replaceChildren();
    const rows = getRows();
    let shown = 0;
    for (const e of rows) {
      if (f && !(`${e.device || ''} ${e.client} ${e.name} ${e.action} ${e.reason || ''}`.toLowerCase().includes(f))) continue;
      if (++shown > 300) break;
      const tr = el('tr');
      const time = new Date(e.t).toLocaleTimeString();
      const dev = el('td', '', e.device || e.client);
      if (e.device) dev.title = e.client;
      tr.append(el('td', 'muted', time), dev, el('td', 'dom', e.name), el('td', 'muted', e.type || ''));
      const res = el('td');
      const pill = el('span', 'act ' + e.action, e.action);
      if (e.reason) pill.title = e.reason;
      res.append(pill);
      if (e.wandering) res.append(' ', el('span', 'wbadge', 'wandering'));
      if (e.shadow) res.append(' ', el('span', 'muted small shadow-note', 'would have blocked: ' + e.shadow));
      else if (e.reason && e.action !== 'error' && e.reason !== 'wandering') res.append(' ', el('span', 'muted small', e.reason));
      tr.append(res, el('td', 'muted', e.upstream || ''), el('td', 'num', Number(e.ms || 0).toFixed(1)));
      const act = el('td');
      const kind = e.action === 'blocked' ? 'allow' : 'block';
      const b = el('button', 'mini', kind);
      b.addEventListener('click', () => rule('POST', kind, e.name).catch((err) => notify(err.message)));
      act.append(b);
      tr.append(act);
      body.append(tr);
    }
  }

  $('#filter').addEventListener('input', (e) => { filter = e.target.value; renderRows(); });
  $('#rule-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    try { await rule('POST', $('#rule-kind').value, $('#rule-domain').value); $('#rule-domain').value = ''; }
    catch (err) { notify(err.message); }
  });
  $('#refresh').addEventListener('click', () => api('/api/lists/refresh', { method: 'POST' }).catch((err) => notify(err.message)));
  $('#p-relay').addEventListener('change', async (e) => {
    try { renderRules(await api('/api/policies', { method: 'POST', body: JSON.stringify({ name: 'apple-private-relay', enabled: e.target.checked }) })); }
    catch (err) { notify(err.message); e.target.checked = !e.target.checked; }
  });

  return { renderStatus, renderRules, renderRows, rule, refreshRules: () => api('/api/rules').then(renderRules).catch(() => {}) };
}
