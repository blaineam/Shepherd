// The "Import" modal on the Devices screen: eero login (phone or email, then
// the code eero sends), a CSV file upload, a dry-run preview and an apply
// step. Everything from either source is untrusted third-party text and is
// only ever placed with textContent (see dom.js's el and ui.js's chip/field).
import { el } from './dom.js';
import { button, iconButton, segmented } from './ui.js';
import { validLogin, validCode, reportRows, reportTitle } from './import.js';

export function createImportModal({ mgmt, notify, onImported }) {
  let overlay = null;
  let box = null;
  let step = 'source'; // source | eero-login | eero-code | eero-network | csv | preview | done
  let source = 'eero'; // 'eero' | 'csv'
  let busy = false;

  let sessionId = null;
  let networks = [];
  let networkId = '';
  let csvText = '';
  let csvName = '';
  let overwrite = false;
  let report = null;
  let error = '';

  function reset() {
    step = 'source'; source = 'eero'; busy = false;
    sessionId = null; networks = []; networkId = ''; csvText = ''; csvName = ''; overwrite = false; report = null; error = '';
  }

  function onKey(e) { if (e.key === 'Escape' && !busy) close(); }

  function close() {
    if (sessionId) mgmt.importEeroCancel(sessionId).catch(() => {});
    if (overlay) overlay.remove();
    document.removeEventListener('keydown', onKey, true);
    overlay = null; box = null;
    reset();
  }

  async function run(fn) {
    if (busy) return;
    busy = true; error = ''; render();
    try { await fn(); } catch (err) { error = err.message || String(err); }
    busy = false; render();
  }

  function startOver() {
    const keep = sessionId;
    sessionId = null; networks = []; networkId = ''; csvText = ''; csvName = ''; report = null; error = '';
    step = 'source';
    render();
    if (keep) mgmt.importEeroCancel(keep).catch(() => {});
  }

  // ------------------------------------------------------------- steps
  function sourcePicker() {
    const body = el('div', 'imp-body');
    body.append(el('p', 'muted small', 'Bring in device names and groups from somewhere else, once. Nothing changes until you review a preview.'));
    const seg = segmented([{ id: 'eero', label: 'eero' }, { id: 'csv', label: 'CSV file' }], source, (id) => { source = id; render(); }, 'Import source');
    body.append(seg.root);
    if (source === 'eero') {
      body.append(el('p', 'muted small', 'Unofficial and unverified against a real eero account: it uses eero’s undocumented app API. Nothing is changed until you confirm the preview. See docs/IMPORT.md.'));
    } else {
      body.append(el('p', 'muted small', 'A CSV with mac, ip, name, vendor, type, groups, tags, excluded and notes columns (by header name, in any order). Export Shepherd’s own devices from the Devices screen as a starting point.'));
    }
    const actions = el('div', 'dlg-actions');
    actions.append(button('Cancel', 'ghost', close), button('Continue', 'primary', () => { step = source === 'eero' ? 'eero-login' : 'csv'; render(); }));
    body.append(actions);
    return body;
  }

  function eeroLoginStep() {
    const body = el('div', 'imp-body');
    const form = el('form', 'imp-form');
    const label = el('label', 'pop-l', 'eero account email or phone number');
    const input = el('input');
    input.placeholder = 'owner@example.com';
    input.autocomplete = 'off';
    input.setAttribute('aria-label', 'eero account email or phone number');
    form.append(label, input);
    if (error) form.append(el('p', 'imp-err', error));
    const actions = el('div', 'dlg-actions');
    const back = button('Back', 'ghost', () => { step = 'source'; render(); });
    const go = button(busy ? 'Sending…' : 'Send code', 'primary');
    go.type = 'submit'; go.disabled = busy;
    actions.append(back, go);
    form.append(actions);
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      if (!validLogin(input.value)) { error = 'Enter the email address or phone number on the eero account.'; render(); return; }
      run(async () => {
        const r = await mgmt.importEeroStart(input.value.trim());
        sessionId = r.session_id;
        step = 'eero-code';
      });
    });
    body.append(form);
    return body;
  }

  function eeroCodeStep() {
    const body = el('div', 'imp-body');
    body.append(el('p', 'muted small', 'eero sent a verification code.'));
    const form = el('form', 'imp-form');
    const label = el('label', 'pop-l', 'Verification code');
    const input = el('input');
    input.inputMode = 'numeric';
    input.autocomplete = 'one-time-code';
    input.setAttribute('aria-label', 'Verification code');
    form.append(label, input);
    if (error) form.append(el('p', 'imp-err', error));
    const actions = el('div', 'dlg-actions');
    actions.append(button('Start over', 'ghost', startOver));
    const go = button(busy ? 'Verifying…' : 'Verify', 'primary');
    go.type = 'submit'; go.disabled = busy;
    actions.append(go);
    form.append(actions);
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      if (!validCode(input.value)) { error = 'Enter the code eero sent.'; render(); return; }
      run(async () => {
        const r = await mgmt.importEeroVerify(sessionId, input.value.trim());
        networks = Array.isArray(r.networks) ? r.networks : [];
        if (networks.length === 0) { error = 'This eero account has no networks.'; return; }
        if (networks.length === 1) { networkId = networks[0].id; await preview(); return; }
        step = 'eero-network';
      });
    });
    body.append(form);
    return body;
  }

  function eeroNetworkStep() {
    const body = el('div', 'imp-body');
    const form = el('form', 'imp-form');
    form.append(el('label', 'pop-l', 'Network'));
    const sel = el('select');
    sel.setAttribute('aria-label', 'Network');
    for (const n of networks) { const o = el('option', '', n.name || n.id); o.value = n.id; sel.append(o); }
    sel.value = networkId || networks[0].id;
    form.append(sel, overwriteToggle());
    if (error) form.append(el('p', 'imp-err', error));
    const actions = el('div', 'dlg-actions');
    actions.append(button('Start over', 'ghost', startOver));
    const go = button(busy ? 'Loading…' : 'Preview', 'primary');
    go.type = 'submit'; go.disabled = busy;
    actions.append(go);
    form.append(actions);
    form.addEventListener('submit', (e) => { e.preventDefault(); networkId = sel.value; run(preview); });
    body.append(form);
    return body;
  }

  function overwriteToggle() {
    const label = el('label', 'chk-row');
    const cb = el('input');
    cb.type = 'checkbox';
    cb.checked = overwrite;
    cb.addEventListener('change', () => { overwrite = cb.checked; });
    label.append(cb, el('span', '', 'Overwrite names you already set'));
    return label;
  }

  function csvStep() {
    const body = el('div', 'imp-body');
    const form = el('form', 'imp-form');
    form.append(el('label', 'pop-l', 'CSV file'));
    const file = el('input');
    file.type = 'file';
    file.accept = '.csv,text/csv';
    file.setAttribute('aria-label', 'CSV file');
    const nameEl = el('p', 'muted small', csvName || 'No file chosen');
    file.addEventListener('change', async () => {
      const f = file.files && file.files[0];
      if (!f) return;
      csvText = await f.text();
      csvName = f.name;
      nameEl.textContent = csvName;
    });
    form.append(file, nameEl, overwriteToggle());
    if (error) form.append(el('p', 'imp-err', error));
    const actions = el('div', 'dlg-actions');
    actions.append(button('Back', 'ghost', () => { step = 'source'; render(); }));
    const go = button(busy ? 'Loading…' : 'Preview', 'primary');
    go.type = 'submit'; go.disabled = busy;
    actions.append(go);
    form.append(actions);
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      if (!csvText) { error = 'Choose a CSV file.'; render(); return; }
      run(async () => { report = await mgmt.importCSVPreview(csvText, overwrite); step = 'preview'; });
    });
    body.append(form);
    return body;
  }

  async function preview() {
    report = source === 'eero' ? await mgmt.importEeroPreview(sessionId, networkId, overwrite) : await mgmt.importCSVPreview(csvText, overwrite);
    step = 'preview';
  }

  function reportList(cls) {
    const list = el('div', cls);
    for (const row of reportRows(report)) {
      const r = el('div', 'imp-row');
      r.append(el('span', '', row.label), el('span', 'mono', String(row.count)));
      list.append(r);
    }
    return list;
  }

  function notesList(label, items) {
    if (!items || !items.length) return null;
    const sec = el('div', 'imp-notes');
    sec.append(el('h4', 'ph', label + ' (' + items.length + ')'));
    const ul = el('ul', 'imp-ul');
    for (const t of items.slice(0, 20)) ul.append(el('li', '', t));
    if (items.length > 20) ul.append(el('li', 'muted', '…and ' + (items.length - 20) + ' more'));
    sec.append(ul);
    return sec;
  }

  function previewStep() {
    const body = el('div', 'imp-body');
    body.append(el('p', '', reportTitle(report)));
    body.append(reportList('imp-rows'));
    const warn = notesList('Warnings', report && report.warnings);
    const conf = notesList('Conflicts', report && report.conflicts);
    const rowErr = notesList('Row problems', report && report.row_errors);
    for (const n of [conf, warn, rowErr]) if (n) body.append(n);
    if (error) body.append(el('p', 'imp-err', error));
    const actions = el('div', 'dlg-actions');
    actions.append(button('Start over', 'ghost', startOver));
    const apply = button(busy ? 'Applying…' : 'Apply', 'primary', () => run(async () => {
      report = source === 'eero' ? await mgmt.importEeroApply(sessionId) : await mgmt.importCSVApply(csvText, overwrite);
      sessionId = null;
      step = 'done';
    }));
    apply.disabled = busy;
    actions.append(apply);
    body.append(actions);
    return body;
  }

  function doneStep() {
    const body = el('div', 'imp-body');
    body.append(el('p', '', reportTitle(report)));
    body.append(reportList('imp-rows'));
    const warn = notesList('Warnings', report && report.warnings);
    if (warn) body.append(warn);
    if (report && report.changed) onImported();
    const actions = el('div', 'dlg-actions');
    actions.append(button('Import more', 'ghost', startOver), button('Close', 'primary', close));
    body.append(actions);
    return body;
  }

  const STEPS = {
    source: sourcePicker, 'eero-login': eeroLoginStep, 'eero-code': eeroCodeStep,
    'eero-network': eeroNetworkStep, csv: csvStep, preview: previewStep, done: doneStep,
  };

  function render() {
    if (!box) return;
    box.replaceChildren();
    const top = el('div', 'imp-top');
    top.append(el('h2', '', 'Import devices'));
    top.append(iconButton('x', 'Close import', close, 'imp-x'));
    box.append(top, (STEPS[step] || sourcePicker)());
  }

  return {
    open() {
      if (overlay) return;
      reset();
      overlay = el('div', 'overlay dlg-overlay');
      box = el('div', 'modal dlg imp-modal');
      box.setAttribute('role', 'dialog');
      box.setAttribute('aria-modal', 'true');
      box.setAttribute('aria-label', 'Import devices');
      overlay.append(box);
      overlay.addEventListener('pointerdown', (e) => { if (e.target === overlay && !busy) close(); });
      document.addEventListener('keydown', onKey, true);
      document.body.append(overlay);
      render();
      const first = box.querySelector('input, select, button');
      if (first) first.focus();
    },
  };
}
