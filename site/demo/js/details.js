// The System view: software updates, blocklist health, the user's own
// allow and block rules and the Private Relay switch. The query totals, live
// list and top lists that used to share this screen live on the Map,
// History and Bandwidth screens. Names and reasons come from the network,
// so every value is placed with textContent, never innerHTML.
import { $, el } from './dom.js';
import { fmtNum, fmtUptime } from './format.js';
import { updateLine, rollbackLine, dataDirLine, overBudget } from './update.js';

export function createDetails({ api, notify, onRulesChanged = () => {} }) {
  function fillList(id, items, build) {
    const ul = $(id);
    ul.replaceChildren();
    if (!items || !items.length) { const li = el('li'); li.append(el('span', 'muted', 'Nothing yet')); ul.append(li); return; }
    items.forEach((it) => ul.append(build(it)));
  }

  // The Software card (docs/UPDATE.md): where this build stands against
  // the latest release, and the one button that applies it.
  let updateInfo = null;
  function renderUpdate(u) {
    updateInfo = u;
    const line = updateLine(u);
    const lineEl = $('#sw-line');
    lineEl.textContent = line.text;
    lineEl.className = 'sw-line ' + line.tone;
    const s = (u && u.status) || {};
    const reason = $('#sw-reason');
    reason.textContent = s.available && !s.can_apply && s.reason ? 'Cannot update from here: ' + s.reason : '';
    reason.hidden = !reason.textContent;
    const rb = $('#sw-rollback');
    rb.textContent = rollbackLine(u);
    rb.hidden = !rb.textContent;
    const dd = $('#sw-data');
    dd.textContent = dataDirLine(u);
    dd.hidden = !dd.textContent;
    dd.className = overBudget(u) ? 'small warn' : 'muted small';
    $('#sw-apply').hidden = !(s.available && s.can_apply && !s.applying && !s.applied);
    $('#sw-check').hidden = !(u && u.enabled);
  }
  $('#sw-check').addEventListener('click', async () => {
    $('#sw-check').disabled = true;
    try { renderUpdate(await api('/api/update/check', { method: 'POST', body: '{}' })); } catch (e) { notify('Could not check: ' + e.message); }
    $('#sw-check').disabled = false;
  });
  $('#sw-apply').addEventListener('click', async () => {
    const s = (updateInfo && updateInfo.status) || {};
    if (!window.confirm('Install ' + (s.latest_version || 'the update') + ' and restart Shepherd? The current binary is kept and comes back on its own if the new one does not stay up.')) return;
    $('#sw-apply').disabled = true;
    try {
      await api('/api/update/apply', { method: 'POST', body: '{}' });
      notify('Update installed; Shepherd is restarting');
      renderUpdate({ enabled: true, status: { ...s, applied: s.latest_version } });
    } catch (e) { notify('Could not update: ' + e.message); $('#sw-apply').disabled = false; }
  });
  async function loadUpdate() {
    try { renderUpdate(await api('/api/update')); } catch { renderUpdate(null); }
  }

  function renderStatus(s) {
    $('#version').textContent = s.version || '';
    $('#uptime').textContent = fmtUptime(s.uptime_seconds || 0);
    $('#p-relay').checked = !!(s.policies && s.policies['apple-private-relay']);

    fillList('#lists', s.lists, (l) => {
      const li = el('li');
      li.append(el('span', l.error ? 'dot bad' : 'dot'));
      const name = el('span', 'grow', l.name);
      name.title = l.error || l.url || '';
      li.append(name, el('span', 'num', l.error ? 'rejected' : fmtNum(l.count)));
      return li;
    });
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

  return {
    loadUpdate, renderStatus, renderRules, rule, refreshRules: () => api('/api/rules').then(renderRules).catch(() => {}) };
}
