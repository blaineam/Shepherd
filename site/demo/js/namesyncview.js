// The Device names card on the Router screen: one name per device across
// Shepherd and every connected router or firewall. The first sync keeps
// the most readable name for each device; after that an edit anywhere is
// written everywhere. Nothing is written until the owner has seen the
// preview. Every string from the server is placed with textContent.
import { el } from './dom.js?v=65858b99';
import { button, confirmDialog } from './ui.js?v=4d208003';
import { fmtDateTime } from './format.js?v=86b54455';
import { changeLine, reportSummary, sourceLine, headline, logLine } from './namesync.js?v=a716d68f';

const SHOWN = 60;

// The card comes in two kinds over the same engine: device names, and
// which group each device is in. COPY is what differs on the screen.
const COPY = {
  names: {
    title: 'Device names', sub: 'one name everywhere',
    note: 'Devices are matched by MAC address across Shepherd and everything connected above. The first sync keeps the most readable name for each device: one somebody typed beats a hostname, and a MAC address or "Unknown" never replaces anything. After that, a name changed in any one place is written to the others.',
    count: (n) => n + (n === 1 ? ' name' : ' names'),
    confirm: 'Write these names?',
    keep: 'Shepherd will check every two minutes and write a name edited in one place to all the others, without asking each time.',
    many: 'the first sync can rename many devices at once.',
    api: (mgmt) => ({ status: mgmt.names, preview: mgmt.namesPreview, sync: mgmt.namesSync, auto: mgmt.namesAuto }),
  },
  groups: {
    title: 'Device groups', sub: 'one group everywhere',
    note: 'Which group each device is in, kept the same in Shepherd and on a router or firewall that has device groups (a Firewalla read on the box itself). A group that exists in only one place is made in the other. A router keeps a device in one group at a time, so a device in several Shepherd groups is offered in the first; Quarantine and a group called Unassigned mean "not sorted yet" and are not synced. Taking a device out of its group in one place takes it out in the other.',
    count: (n) => n + (n === 1 ? ' device' : ' devices'),
    confirm: 'Move these devices?',
    keep: 'Shepherd will check every two minutes and move a device in the other place when it is moved in one, without asking each time.',
    many: 'the first sync can move many devices at once.',
    api: (mgmt) => ({ status: mgmt.groupSync, preview: mgmt.groupSyncPreview, sync: mgmt.groupSyncRun, auto: mgmt.groupSyncAuto }),
  },
};

export function createNameSync({ mgmt, notify, onChanged = () => {}, kind = 'names' }) {
  const copy = COPY[kind] || COPY.names;
  const api = copy.api(mgmt);
  const root = el('section', 'card bk-card ns');
  let status = null;
  let loadError = null;
  let preview = null;
  let busy = false;
  let poll = 0;
  let showAll = false;

  async function load() {
    try {
      status = await api.status();
      loadError = null;
    } catch (e) {
      loadError = e;
    }
    // A sync runs in the background; watch it until it is done.
    clearTimeout(poll);
    if (status && status.running) poll = setTimeout(async () => { await load(); if (!status || !status.running) onChanged(); }, 2000);
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

  const check = () => run(async () => { preview = await api.preview(); showAll = false; });

  function changes(report) {
    const list = report.changes || [];
    const ul = el('ul', 'up-list ns-list');
    for (const c of (showAll ? list : list.slice(0, SHOWN))) {
      const line = changeLine(c, report, kind);
      const li = el('li', 'up-item ns-item');
      const main = el('div', 'ns-main');
      main.append(el('strong', 'up-addr', line.name), el('span', 'muted small', line.why));
      li.append(main);
      if (line.was) li.append(el('span', 'muted small ns-was', 'now ' + line.was));
      if (line.to) li.append(el('span', 'small ns-to', (report.dry_run ? 'write to ' : 'written to ') + line.to));
      if (line.held) li.append(el('span', 'small ns-held', 'waiting for ' + line.held));
      if (line.failed) li.append(el('span', 'small ns-failed', line.failed));
      ul.append(li);
    }
    const wrap = el('div');
    wrap.append(ul);
    if (!showAll && list.length > SHOWN) {
      wrap.append(button('Show all ' + list.length, 'ghost', () => { showAll = true; paint(); }));
    }
    return wrap;
  }

  function report(rep, heading) {
    const wrap = el('div', 'ns-report');
    wrap.append(el('h4', 'ru-sub', heading));
    const sum = reportSummary(rep, kind);
    wrap.append(el('p', 'ru-line ' + sum.tone, sum.text));
    for (const s of rep.sources || []) {
      const line = sourceLine(s);
      wrap.append(el('p', 'small ns-src ' + line.tone, line.text));
    }
    if ((rep.changes || []).length) wrap.append(changes(rep));
    return wrap;
  }

  function paint() {
    const h = el('div', 'card-h');
    h.append(el('h3', 'card-t', copy.title), el('span', 'muted small', copy.sub));
    root.replaceChildren(h);
    if (loadError) { root.append(el('p', 'ru-line bad', 'Could not load: ' + loadError.message)); return; }
    if (!status) { root.append(el('p', 'muted', 'Loading.')); return; }
    const head = headline(status, kind);
    const p = el('p', 'ru-line ' + head.tone, head.text);
    p.setAttribute('role', 'status');
    root.append(p);
    if (!status.available) return;
    root.append(el('p', 'muted small ru-note', copy.note));

    const acts = el('div', 'ru-acts');
    const look = button(preview ? 'Check again' : 'Check what would change', preview ? 'ghost' : 'primary', check);
    look.disabled = busy || status.running;
    acts.append(look);
    if (preview) {
      const writes = preview.written || 0;
      const go = button(writes ? 'Sync ' + copy.count(writes) + ' now' : 'Sync now', 'primary', async () => {
        const ok = await confirmDialog({
          title: copy.confirm,
          body: reportSummary(preview, kind).text + ' Each change is listed below and is recorded, with what it replaced, under Recent changes.',
          confirm: 'Sync now',
        });
        if (!ok) return;
        run(async () => { status = await api.sync(); preview = null; await load(); });
      });
      go.disabled = busy || status.running || !writes;
      acts.append(go);
    }
    const sw = el('label', 'switch');
    const box = el('input');
    box.type = 'checkbox';
    box.checked = !!status.auto;
    box.disabled = busy;
    box.addEventListener('change', async () => {
      if (box.checked) {
        const ok = await confirmDialog({
          title: 'Keep ' + (kind === 'groups' ? 'groups' : 'names') + ' in sync?',
          body: copy.keep + (preview ? '' : ' Check what would change first if you have not: ' + copy.many),
          confirm: 'Keep in sync',
        });
        if (!ok) { box.checked = false; return; }
      }
      run(async () => { status = await api.auto(box.checked); await load(); });
    });
    sw.append(box, el('span', '', 'Keep in sync'));
    acts.append(sw);
    root.append(acts);

    if (preview) root.append(report(preview, 'What a sync would do'));
    else if (status.last) root.append(report(status.last, 'Last sync, ' + fmtDateTime(new Date(status.last.time).getTime())));

    const log = status.log || [];
    if (log.length) {
      const det = el('details', 'ns-log');
      det.append(el('summary', 'small', 'Recent changes (' + log.length + ')'));
      const ul = el('ul', 'up-list');
      for (const e of log.slice(0, 50)) {
        const li = el('li', 'up-item small');
        li.append(el('span', 'muted mono', fmtDateTime(new Date(e.time).getTime())), el('span', '', logLine(e, kind)));
        ul.append(li);
      }
      det.append(ul);
      root.append(det);
    }
  }

  paint();
  return {
    root,
    load,
    // The connections changed, so an old preview no longer describes them.
    reset() { preview = null; return load(); },
    hide() { clearTimeout(poll); poll = 0; },
  };
}
