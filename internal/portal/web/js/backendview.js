// The Router screen: the connections to the owner's router or firewall,
// the device-name sync across them, and the dashboard over whichever one
// is running: what it sees (requests, alarms, devices) and the controls
// over what it enforces (rules, names). Reading is always available; every
// change is switched on separately, previewed, and confirmed. All text from the server is placed with textContent.
import { el } from './dom.js';
import { button, emptyState, confirmDialog } from './ui.js';
import { unavailable } from './mgmt.js';
import { fmtDateTime } from './format.js';
import { createConnections } from './connectionsview.js';
import { createNameSync } from './namesyncview.js';
import { can, productName, statusLine, blockSpecFromFlow, ruleSummary, requestLine, auditLine, DAY_NAMES, scheduleText, scheduleFor, scheduleBody, scheduleProblem } from './backend.js';

export function createBackend({ root, mgmt, notify }) {
  let data = null;
  let loadError = null;
  let timer = 0;
  let busy = false;
  let started = false;
  // The rule form the owner is filling in, and the preview awaiting a yes.
  // Which rule's schedule form is open, and what is in it.
  let schedOpen = '';
  const sched = { days: new Set([1, 2, 3, 4, 5]), start: '21:00', end: '07:00' };
  // The device the request list is narrowed to, and what came back.
  let flowDevice = '';
  let flowsFiltered = null;
  const draft = { action: 'block', target_type: 'domain', target: '', scope_type: '', scope: '', block_connections: false };

  root.replaceChildren();
  const head = el('div', 'pg-head stack');
  const title = el('h2', 'pg-title');
  const titleText = el('span', '', 'Router');
  title.append(titleText);
  head.append(title, el('p', 'pg-sub muted', 'What your router or firewall sees, and the controls over what it enforces. Reading is always on; changes are off until you allow them.'));
  const body = el('div', 'bk-body');
  root.append(head, body);
  // Connecting or disconnecting changes what the dashboard and the name
  // sync have to work with, so both are reloaded.
  const connections = createConnections({ mgmt, notify, onChanged: () => { names.reset(); groups.reset(); load(); } });
  const names = createNameSync({ mgmt, notify, onChanged: () => { load(); } });
  // Groups are offered only where the connected product has them.
  const groups = createNameSync({ mgmt, notify, onChanged: () => { load(); }, kind: 'groups' });

  async function load() {
    try {
      data = await mgmt.backend();
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
    paint();
  };

  // act confirms a change in words, then sends it. The server refuses a
  // write that does not say confirm:true, so this is the only way through.
  async function act({ title: t, text, confirm, danger, send, done }) {
    if (!(await confirmDialog({ title: t, body: text, confirm, danger }))) return;
    await run(async () => {
      const r = await send();
      if (r && typeof r === 'object' && 'devices' in r) data = r;
      else data = await mgmt.backend();
      notify(done);
    });
  }

  const card = (heading, sub) => {
    const c = el('section', 'card bk-card');
    const h = el('div', 'card-h');
    h.append(el('h3', 'card-t', heading));
    if (sub) h.append(el('span', 'muted small', sub));
    c.append(h);
    return c;
  };

  function header() {
    const c = card(productName(data) + ' dashboard');
    const line = statusLine(data);
    const p = el('p', 'ru-line ' + line.tone, line.text);
    p.setAttribute('role', 'status');
    c.append(p);
    if (!data || !data.running) return c;
    const acts = el('div', 'ru-acts');
    const refresh = button('Refresh', 'ghost', () => run(async () => { data = await mgmt.backendRefresh(); }));
    refresh.disabled = busy;
    acts.append(refresh);
    const sw = el('label', 'switch');
    const box = el('input');
    box.type = 'checkbox';
    box.checked = !!data.writes;
    box.disabled = busy;
    box.addEventListener('change', async () => {
      if (box.checked) {
        const ok = await confirmDialog({
          title: 'Allow changes to your ' + productName(data) + '?',
          body: 'Shepherd will be able to pause, resume and delete rules and, where the product allows it, add rules, rename or block devices and dismiss alarms. Each one still asks you first. The credential must allow writing for them to work.',
          confirm: 'Allow changes',
        });
        if (!ok) { box.checked = false; return; }
      }
      run(async () => { data = await mgmt.backendWrites(box.checked); names.reset(); groups.reset(); });
    });
    sw.append(box, el('span', '', 'Allow changes'));
    acts.append(sw);
    c.append(acts);
    return c;
  }

  // ----------------------------------------------------------------- rules
  function rulesCard() {
    const rules = data.rules || [];
    const c = card('Rules', rules.length + ' on your ' + productName(data));
    if (!rules.length) c.append(el('p', 'muted small', 'No rules.'));
    const ul = el('ul', 'up-list');
    for (const r of rules) {
      const li = el('li', 'up-item' + (r.Paused ? ' muted' : ''));
      li.append(el('span', 'up-addr', ruleSummary(r, data.devices)));
      if (r.Paused) li.append(el('span', 'muted small', 'paused'));
      if (can(data, 'rules:write')) {
        const pause = button(r.Paused ? 'Resume' : 'Pause', 'ghost', () => act({
          title: (r.Paused ? 'Resume' : 'Pause') + ' this rule?', text: ruleSummary(r, data.devices),
          confirm: r.Paused ? 'Resume' : 'Pause',
          send: () => (r.Paused ? mgmt.backendRuleResume(r.ID) : mgmt.backendRulePause(r.ID)),
          done: r.Paused ? 'Rule resumed' : 'Rule paused',
        }));
        const del = button('Delete', 'ghost', () => act({
          title: 'Delete this rule?', text: ruleSummary(r, data.devices) + '. This cannot be undone from Shepherd.',
          confirm: 'Delete', danger: true, send: () => mgmt.backendRuleDelete(r.ID), done: 'Rule deleted',
        }));
        pause.disabled = busy; del.disabled = busy;
        li.append(pause, del);
        if (can(data, 'rules:schedule') && !scheduleFor(data.schedules, r.ID)) {
          const sb = button('Schedule', 'ghost', () => { schedOpen = schedOpen === r.ID ? '' : r.ID; paint(); });
          sb.disabled = busy;
          li.append(sb);
        }
      }
      ul.append(li);
      const sc = scheduleFor(data.schedules, r.ID);
      if (sc) ul.append(scheduleLine(sc));
      if (schedOpen === r.ID) ul.append(scheduleForm(r));
    }
    c.append(ul);
    if (can(data, 'rules:create')) c.append(ruleForm());
    return c;
  }

  // A scheduled rule is enforced only inside its window; Shepherd pauses
  // and resumes it to match.
  function scheduleLine(sc) {
    const li = el('li', 'up-item small');
    li.append(el('span', 'muted', scheduleText(sc)));
    const rm = button('Remove schedule', 'ghost', () => act({
      title: 'Remove this schedule?', text: scheduleText(sc) + '. The rule stays as it is now; you choose what happens to it.',
      confirm: 'Remove', send: () => mgmt.backendScheduleDelete(sc.id), done: 'Schedule removed',
    }));
    rm.disabled = busy;
    li.append(rm);
    return li;
  }

  function scheduleForm(rule) {
    const li = el('li', 'up-item');
    const form = el('form', 'ru-form');
    form.append(el('span', 'muted small', 'Enforce this rule only:'));
    const boxes = el('span', 'bk-days');
    DAY_NAMES.forEach((name, i) => {
      const lab = el('label', 'switch');
      const cb = el('input');
      cb.type = 'checkbox'; cb.checked = sched.days.has(i);
      cb.addEventListener('change', () => { if (cb.checked) sched.days.add(i); else sched.days.delete(i); });
      lab.append(cb, el('span', '', name));
      boxes.append(lab);
    });
    const start = el('input'); start.type = 'time'; start.value = sched.start; start.setAttribute('aria-label', 'From');
    start.addEventListener('input', () => { sched.start = start.value; });
    const end = el('input'); end.type = 'time'; end.value = sched.end; end.setAttribute('aria-label', 'Until');
    end.addEventListener('input', () => { sched.end = end.value; });
    const go = el('button', '', 'Save schedule');
    const cancel = button('Cancel', 'ghost', () => { schedOpen = ''; paint(); });
    form.append(boxes, el('span', 'muted small', 'from'), start, el('span', 'muted small', 'until'), end, go, cancel);
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      const problem = scheduleProblem(sched.days, sched.start, sched.end);
      if (problem) { notify(problem); return; }
      const tz = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
      const body = scheduleBody(rule.ID, sched.days, sched.start, sched.end, tz);
      act({
        title: 'Schedule this rule?', text: ruleSummary(rule, data.devices) + '. ' + scheduleText({ ...body }) + '. Shepherd will pause the rule outside this window and resume it inside.',
        confirm: 'Save schedule', send: () => mgmt.backendScheduleAdd(body), done: 'Schedule saved',
      }).then(() => { schedOpen = ''; paint(); });
    });
    li.append(form);
    return li;
  }

  function ruleForm() {
    const form = el('form', 'ru-form ru-grid');
    form.append(el('h4', 'ru-sub', 'Add a rule'));
    const action = el('select');
    action.setAttribute('aria-label', 'Action');
    for (const a of ['block', 'allow']) { const o = el('option', '', a === 'block' ? 'Block' : 'Allow'); o.value = a; action.append(o); }
    action.value = draft.action;
    action.addEventListener('change', () => { draft.action = action.value; });
    const type = el('select');
    type.setAttribute('aria-label', 'What to match');
    for (const t of data.target_types || ['domain', 'ip']) { const o = el('option', '', t); o.value = t; type.append(o); }
    type.value = draft.target_type;
    type.addEventListener('change', () => { draft.target_type = type.value; });
    const target = el('input');
    target.type = 'text'; target.placeholder = 'example.com'; target.required = true; target.value = draft.target;
    target.setAttribute('aria-label', 'Target');
    target.addEventListener('input', () => { draft.target = target.value; });
    const scope = el('select');
    scope.setAttribute('aria-label', 'Which device');
    const all = el('option', '', 'Every device'); all.value = ''; scope.append(all);
    for (const d of data.devices || []) {
      if (!d.MAC) continue;
      const o = el('option', '', d.Name || d.MAC); o.value = d.MAC; scope.append(o);
    }
    scope.value = draft.scope;
    scope.addEventListener('change', () => { draft.scope = scope.value; draft.scope_type = scope.value ? 'device' : ''; });
    const go = el('button', '', 'Review');
    go.disabled = busy;
    form.append(action, type, target, scope, go);
    form.addEventListener('submit', (ev) => { ev.preventDefault(); reviewRule({ ...draft, target: draft.target.trim() }, true); });
    return form;
  }

  // reviewRule asks the server what the rule would do, then asks the owner.
  async function reviewRule(spec, fromForm) {
    let preview;
    try {
      preview = await mgmt.backendRulePreview(spec);
    } catch (e) { notify(e.message); return; }
    const warn = preview.network_wide ? ' It applies to every device on your network.' : '';
    await act({
      title: 'Add this rule?', text: preview.summary + '.' + warn, confirm: 'Add rule', danger: preview.network_wide && spec.action === 'block',
      send: () => mgmt.backendRuleCreate(spec),
      done: 'Rule added',
    });
    if (fromForm) draft.target = '';
  }

  // -------------------------------------------------------------- requests
  function requestsCard() {
    const flows = (flowDevice && flowsFiltered ? flowsFiltered : (data.flows || [])).slice(0, 40);
    const c = card('Recent requests', flowDevice ? 'for one device' : 'newest first');
    const pick = el('select');
    pick.setAttribute('aria-label', 'Show requests from');
    const every = el('option', '', 'All devices'); every.value = ''; pick.append(every);
    for (const d of data.devices || []) {
      if (!d.MAC) continue;
      const o = el('option', '', d.Name || d.MAC); o.value = d.MAC; pick.append(o);
    }
    pick.value = flowDevice;
    pick.disabled = busy;
    pick.addEventListener('change', () => run(async () => {
      flowDevice = pick.value;
      flowsFiltered = flowDevice ? (await mgmt.backendFlows({ device: flowDevice, limit: 100 })).flows : null;
    }));
    c.append(pick);
    if (!flows.length) { c.append(el('p', 'muted small', flowDevice ? 'No requests from this device.' : 'Nothing yet.')); return c; }
    const ul = el('ul', 'up-list');
    for (const f of flows) {
      const line = requestLine(f);
      const li = el('li', 'up-item' + (line.blocked ? ' bad' : ''));
      li.append(el('span', 'muted small mono', fmtDateTime(new Date(f.Time).getTime()).slice(-8)), el('span', 'up-addr', line.what), el('span', 'muted small', line.who + (line.blocked ? ' (blocked)' : '')));
      const spec = blockSpecFromFlow(f);
      if (spec && !line.blocked && can(data, 'rules:create')) {
        const b = button('Block', 'ghost', () => reviewRule(spec, false));
        b.disabled = busy;
        li.append(b);
      }
      ul.append(li);
    }
    c.append(ul);
    return c;
  }

  // ---------------------------------------------------------------- alarms
  function alarmsCard() {
    const alarms = data.alarms || [];
    const c = card('Alarms', alarms.length + ' active');
    if (!alarms.length) { c.append(el('p', 'muted small', 'No active alarms.')); return c; }
    const ul = el('ul', 'up-list');
    for (const a of alarms) {
      const li = el('li', 'up-item');
      li.append(el('span', 'muted small', a.Type), el('span', 'up-addr', a.Message));
      if (can(data, 'alarms:dismiss')) {
        const b = button('Dismiss', 'ghost', () => act({
          title: 'Dismiss this alarm?', text: a.Message, confirm: 'Dismiss',
          send: () => mgmt.backendAlarmDismiss(a.Box, a.ID), done: 'Alarm dismissed',
        }));
        b.disabled = busy;
        li.append(b);
      }
      ul.append(li);
    }
    c.append(ul);
    return c;
  }

  // --------------------------------------------------------------- devices
  function devicesCard() {
    const devs = data.devices || [];
    const c = card('Devices', devs.length + ' known');
    if (!devs.length) { c.append(el('p', 'muted small', 'No devices.')); return c; }
    const ul = el('ul', 'up-list');
    for (const d of devs) {
      const li = el('li', 'up-item');
      li.append(el('span', d.Online && !d.Blocked ? 'dot' : 'dot bad'), el('span', 'up-addr', d.Name || d.MAC || d.Native), el('span', 'muted small', [d.IP, d.Group].filter(Boolean).join(' · ')));
      if (d.Blocked) li.append(el('span', 'muted small', 'blocked'));
      if (can(data, 'devices:block') && d.Native) {
        const name = d.Name || d.Native;
        const bl = d.Blocked
          ? button('Unblock', 'ghost', () => act({
            title: 'Unblock this device?', text: name + ' can use the network again.',
            confirm: 'Unblock', send: () => mgmt.backendBlock(d.Box, d.Native, false), done: 'Device unblocked',
          }))
          : button('Block', 'ghost', () => act({
            title: 'Block this device?', text: name + ' loses its network access. Shepherd keeps it on this list so you can unblock it here.',
            confirm: 'Block', danger: true, send: () => mgmt.backendBlock(d.Box, d.Native, true), done: 'Device blocked',
          }));
        bl.disabled = busy;
        li.append(bl);
      }
      if (can(data, 'devices:rename') && d.Native) {
        const b = button('Rename', 'ghost', async () => {
          const name = window.prompt('New name (up to 32 characters)', d.Name || '');
          if (name === null || !name.trim()) return;
          await act({
            title: 'Rename this device?', text: (d.Name || d.Native) + ' becomes ' + name.trim() + ' on your ' + productName(data) + '.', confirm: 'Rename',
            send: () => mgmt.backendRename(d.Box, d.Native, name.trim()), done: 'Device renamed',
          });
        });
        b.disabled = busy;
        li.append(b);
      }
      ul.append(li);
    }
    c.append(ul);
    return c;
  }

  function auditCard() {
    const rows = data.audit || [];
    if (!rows.length) return null;
    const c = card('Changes made from Shepherd', 'newest first');
    const ul = el('ul', 'up-list');
    for (const a of rows.slice(0, 25)) {
      const li = el('li', 'up-item small' + (a.error ? ' bad' : ''));
      li.append(el('span', 'muted mono', fmtDateTime(new Date(a.time).getTime()).slice(-8)), el('span', '', auditLine({ action: a.action, target: a.target, Error: a.error })));
      ul.append(li);
    }
    c.append(ul);
    return c;
  }

  function paint() {
    // Connections first: it is what everything below depends on, and where
    // someone with nothing connected has to start.
    const parts = [connections.root, names.root];
    if (loadError) {
      // A server with no dashboard has nothing more to show than the
      // connections; that is not an error worth a card.
      if (!unavailable(loadError)) parts.push(emptyState('Could not load the dashboard', loadError.message));
      body.replaceChildren(...parts);
      return;
    }
    if (!data) { body.replaceChildren(...parts, el('p', 'muted', 'Loading.')); return; }
    if (can(data, 'groups')) parts.splice(2, 0, groups.root);
    if (data.connected) parts.push(header());
    if (data.running) {
      const grid = el('div', 'up-grid');
      const a = el('div', 'up-col');
      const b = el('div', 'up-col');
      if (can(data, 'rules')) a.append(rulesCard());
      if (can(data, 'flows')) a.append(requestsCard());
      if (can(data, 'alarms')) b.append(alarmsCard());
      if (can(data, 'devices')) b.append(devicesCard());
      const au = auditCard();
      if (au) b.append(au);
      grid.append(a, b);
      parts.push(grid);
    }
    body.replaceChildren(...parts);
  }

  return {
    root,
    async show() {
      started = true;
      await Promise.all([load(), connections.load(), names.load(), groups.load()]);
      clearInterval(timer);
      timer = setInterval(() => {
        if (!started || busy || root.contains(document.activeElement)) return;
        load();
        connections.refresh();
      }, 15000);
    },
    hide() { started = false; clearInterval(timer); timer = 0; names.hide(); groups.hide(); },
  };
}
