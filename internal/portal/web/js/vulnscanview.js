// The Vulnerabilities screen: every signature match found across every
// scanned device, flattened to one row per finding (worst severity first),
// with a severity/state filter, free-text search and a manual "Scan all".
// Mirrors the structure of the Alarms screen (panel-lite table, mobile card
// reflow) minus its bulk-action bar: there is no per-finding mutation API —
// a finding resolves itself the next time a scan no longer sees it — so
// there is nothing to select and act on in bulk. The device drawer's own
// Vulnerabilities panel (devices.js) stays the quick, per-device summary
// with its own "Scan now"; this page is the cross-network, searchable view,
// and clicking a row opens that same device's drawer rather than
// duplicating the finding detail rendering a second time.
import { el } from './dom.js';
import { icon, button, segmented, emptyState, unavailableCard, relTime } from './ui.js';
import { unavailable } from './mgmt.js';
import { SEVERITIES, severityLabel, severityBadgeClass } from './alarms.js';
import { flattenFindings, matchRow, scanSummary, findingTooltip } from './vulnscan.js';

const STATES = [['active', 'Active'], ['resolved', 'Resolved']];

export function createVulnscan({ root, mgmt, notify, toaster, onOpenDevice = () => {} }) {
  let filters = { severity: '', state: 'active', text: '' };
  let devices = []; // raw GET /api/vulnscan/devices response
  let loadError = null;
  let scanning = false;
  let started = false;
  let timer = 0;

  // ------------------------------------------------------------- skeleton
  root.replaceChildren();
  const head = el('div', 'pg-head');
  const title = el('h2', 'pg-title');
  title.append(el('span', '', 'Vulnerabilities'), el('span', 'pg-count mono', ''));
  const countEl = title.lastChild;

  const stateSeg = segmented(
    [...STATES, ['', 'Any']].map(([id, label]) => ({ id, label })), filters.state,
    (id) => { filters.state = id; paintRows(); },
    'Finding state',
  );

  const sevSel = el('select');
  sevSel.setAttribute('aria-label', 'Minimum severity');
  sevSel.append(el('option', '', 'Any severity'));
  for (const s of SEVERITIES) { const o = el('option', '', severityLabel(s)); o.value = s; sevSel.append(o); }
  sevSel.addEventListener('change', () => { filters.severity = sevSel.value; paintRows(); });

  const searchBox = el('div', 'sbox');
  searchBox.append(icon('search', 15, 'sbox-ico'));
  const input = el('input');
  input.type = 'search';
  input.placeholder = 'Search device, finding or evidence';
  input.setAttribute('aria-label', 'Search vulnerabilities');
  input.autocomplete = 'off';
  input.spellcheck = false;
  searchBox.append(input);
  let searchTimer = 0;
  input.addEventListener('input', () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => { filters.text = input.value.trim(); paintRows(); }, 220);
  });

  const scanBtn = button('Scan all', 'ghost', () => scanAll(), 'refresh');
  head.append(title, stateSeg.root, sevSel, searchBox, scanBtn);

  const wrap = el('section', 'vs-tablewrap panel-lite');
  const thead = el('div', 'vs-row vs-thead');
  thead.setAttribute('role', 'row');
  thead.append(el('div', 'vs-sev', 'Severity'), el('div', 'vs-find', 'Finding'), el('div', 'vs-dev', 'Device'), el('div', 'vs-state', 'State'));
  for (const c of thead.children) c.setAttribute('role', 'columnheader');

  const scroll = el('div', 'vs-scroll');
  scroll.setAttribute('role', 'table');
  scroll.setAttribute('aria-label', 'Vulnerabilities');
  const rowsEl = el('div', 'vs-rows');
  const emptyEl = el('div', 'vs-empty');
  emptyEl.hidden = true;
  scroll.append(rowsEl, emptyEl);
  wrap.append(thead, scroll);
  root.append(head, wrap);

  // ------------------------------------------------------------- loading
  async function load() {
    try {
      const r = await mgmt.vulnscanDevices();
      devices = Array.isArray(r && r.devices) ? r.devices : [];
      loadError = null;
    } catch (e) {
      loadError = e;
      devices = [];
    }
    paintRows();
  }

  async function scanAll() {
    if (scanning) return;
    scanning = true;
    scanBtn.disabled = true;
    scanBtn.firstChild && (scanBtn.firstChild.textContent ? null : null);
    const label = scanBtn.querySelector('span');
    if (label) label.textContent = 'Scanning…';
    try {
      const r = await mgmt.scanVulns();
      devices = Array.isArray(r && r.devices) ? mergeScan(devices, r.devices) : devices;
      loadError = null;
      toaster.show(scanSummary(r));
      paintRows();
    } catch (e) {
      notify(unavailable(e) ? 'Vulnerability scanning is not available on this version.' : 'Scan failed: ' + e.message);
    } finally {
      scanning = false;
      scanBtn.disabled = false;
      if (label) label.textContent = 'Scan all';
    }
  }

  // mergeScan replaces only the devices a scan actually covered (POST
  // /api/vulnscan/scan with no device_id still only returns devices that
  // had a port scan to deepen), keeping the rest of the last-known list.
  function mergeScan(current, scanned) {
    const by = new Map(current.map((d) => [d.device_id, d]));
    for (const d of scanned) by.set(d.device_id, d);
    return [...by.values()];
  }

  // ------------------------------------------------------------- rows
  function rowNode(row) {
    const f = row.finding;
    const r = el('div', 'vs-row' + (f.active ? '' : ' resolved'));
    r.setAttribute('role', 'row');
    r.tabIndex = 0;
    r.setAttribute('role', 'button');
    r.setAttribute('aria-label', 'Open ' + row.deviceName);

    const sevCell = el('div', 'vs-sev');
    sevCell.append(el('span', severityBadgeClass(f.severity), severityLabel(f.severity)));
    if (f.newly_found) sevCell.append(el('span', 'port-flag vs-new', 'NEW'));

    const findCell = el('div', 'vs-find');
    findCell.append(el('span', 'nm', f.name));
    if (f.description) findCell.append(el('span', 'sub', f.description));
    const why = findingTooltip(f);
    if (why) findCell.title = why;

    const devCell = el('div', 'vs-dev');
    devCell.append(el('span', 'nm', row.deviceName));
    devCell.append(el('span', 'sub mono', row.ip + (f.port ? '  ·  port ' + f.port : '')));

    const stateCell = el('div', 'vs-state');
    stateCell.append(el('span', '', f.active ? 'Active' : 'Resolved'));
    stateCell.append(el('span', 'muted small', relTime(f.active ? f.last_seen : (f.resolved_at || f.last_seen))));

    r.append(sevCell, findCell, devCell, stateCell);
    for (const c of r.children) c.setAttribute('role', 'cell');
    r.addEventListener('click', () => onOpenDevice(row.deviceId));
    r.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onOpenDevice(row.deviceId); } });
    return r;
  }

  function paintRows() {
    rowsEl.replaceChildren();
    if (loadError) {
      emptyEl.hidden = false;
      wrap.classList.add('vs-unavail');
      emptyEl.replaceChildren(
        unavailable(loadError) ? unavailableCard('Vulnerability scanning') : emptyState('Could not load vulnerabilities', loadError.message, button('Try again', 'ghost', load)),
      );
      countEl.textContent = '';
      return;
    }
    wrap.classList.remove('vs-unavail');
    const all = flattenFindings(devices);
    const rows = all.filter((r) => matchRow(r, filters));
    countEl.textContent = all.length ? String(all.filter((r) => r.finding.active).length) + ' active' : '';
    if (!rows.length) {
      emptyEl.hidden = false;
      emptyEl.replaceChildren(
        !devices.length
          ? emptyState('No vulnerability scans yet', 'Run "Scan all" to deepen every port scan already on file into named, concrete findings.', button('Scan all', 'ghost', () => scanAll()))
          : emptyState('Nothing matches these filters', 'Try a wider severity, a different state, or clearing the search.'),
      );
      return;
    }
    emptyEl.hidden = true;
    for (const row of rows) rowsEl.append(rowNode(row));
  }

  return {
    async show() {
      if (!started) { started = true; await load(); }
      else await load();
      clearInterval(timer);
      timer = setInterval(() => { if (!root.hidden && document.activeElement !== input && !scanning) load(); }, 10000);
    },
    hide() { clearInterval(timer); },
  };
}
