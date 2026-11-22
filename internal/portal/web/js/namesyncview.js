// The Device names card on the Router screen: one name per device across
// Shepherd and every connected router or firewall. The first sync keeps
// the most readable name for each device; after that an edit anywhere is
// written everywhere. Nothing is written until the owner has seen the
// preview. Every string from the server is placed with textContent.
import { el } from './dom.js';
import { button, confirmDialog } from './ui.js';
import { fmtDateTime } from './format.js';
import { changeLine, reportSummary, sourceLine, headline, logLine } from './namesync.js';

const SHOWN = 60;

export function createNameSync({ mgmt, notify, onChanged = () => {} }) {
  const root = el('section', 'card bk-card ns');
  let status = null;
  let loadError = null;
  let preview = null;
  let busy = false;
  let poll = 0;
  let showAll = false;

  async function load() {
    try {
      status = await mgmt.names();
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

  const check = () => run(async () => { preview = await mgmt.namesPreview(); showAll = false; });

  function changes(report) {
    const list = report.changes || [];
    const ul = el('ul', 'up-list ns-list');
    for (const c of (showAll ? list : list.slice(0, SHOWN))) {
      const line = changeLine(c, report);
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
    const sum = reportSummary(rep);
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
    h.append(el('h3', 'card-t', 'Device names'), el('span', 'muted small', 'one name everywhere'));
    root.replaceChildren(h);
    if (loadError) { root.append(el('p', 'ru-line bad', 'Could not load: ' + loadError.message)); return; }
    if (!status) { root.append(el('p', 'muted', 'Loading.')); return; }
    const head = headline(status);
    const p = el('p', 'ru-line ' + head.tone, head.text);
    p.setAttribute('role', 'status');
    root.append(p);
    if (!status.available) return;
    root.append(el('p', 'muted small ru-note',
      'Devices are matched by MAC address across Shepherd and everything connected above. The first sync keeps the most readable name for each device: one somebody typed beats a hostname, and a MAC address or "Unknown" never replaces anything. After that, a name changed in any one place is written to the others.'));

    const acts = el('div', 'ru-acts');
    const look = button(preview ? 'Check again' : 'Check what would change', preview ? 'ghost' : 'primary', check);
    look.disabled = busy || status.running;
    acts.append(look);
    if (preview) {
      const writes = preview.written || 0;
      const go = button(writes ? 'Sync ' + writes + (writes === 1 ? ' name' : ' names') + ' now' : 'Sync now', 'primary', async () => {
        const ok = await confirmDialog({
          title: 'Write these names?',
          body: reportSummary(preview).text + ' Each change is listed below and is recorded, with the name it replaced, under Recent changes.',
          confirm: 'Sync now',
        });
        if (!ok) return;
        run(async () => { status = await mgmt.namesSync(); preview = null; await load(); });
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
          title: 'Keep names in sync?',
          body: 'Shepherd will check every two minutes and write a name edited in one place to all the others, without asking each time.' + (preview ? '' : ' Check what would change first if you have not: the first sync can rename many devices at once.'),
          confirm: 'Keep in sync',
        });
        if (!ok) { box.checked = false; return; }
      }
      run(async () => { status = await mgmt.namesAuto(box.checked); await load(); });
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
        li.append(el('span', 'muted mono', fmtDateTime(new Date(e.time).getTime())), el('span', '', logLine(e)));
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
