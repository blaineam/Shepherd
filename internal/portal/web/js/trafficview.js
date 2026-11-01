// The Bandwidth screen: how much each device, each group and the whole
// network moves over the wire, right now and over time. Live numbers poll
// while the screen is visible; history is fetched on demand for the chosen
// range and scope.
//
// Every string that came from the server is placed with textContent.
import { el } from './dom.js';
import { button, emptyState, unavailableCard, segmented } from './ui.js';
import { unavailable } from './mgmt.js';
import {
  RANGE_PRESETS, rangeWindow, scopeOptions, scopeLabel, fillSeries, sumPoints, areaPaths, axisLabels, timeLabels,
  shareOf, statusHeadline, liveRows, DOWNLOAD_CAVEAT, fmtBytes, fmtBitsPerSecond,
} from './traffic.js';

const POLL_MS = 2000;
const NS = 'http://www.w3.org/2000/svg';
function svg(tag, attrs) {
  const e = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, String(v));
  return e;
}

export function createTraffic({ root, mgmt, notify, onOpenDevice = null }) {
  let status = null;
  let loadError = null;
  let timer = 0;
  let busy = false;
  let range = RANGE_PRESETS[1];
  let scope = 'network';
  let groups = [];
  let devices = [];
  let series = null; // { bucket, from, to, points }
  let top = null;
  let historyError = null;

  root.replaceChildren();
  const head = el('div', 'pg-head stack');
  const title = el('h2', 'pg-title');
  title.append(el('span', '', 'Bandwidth'));
  head.append(title, el('p', 'pg-sub muted', 'How much each device, each group and the whole network moves over the wire, live and over time. Measured by Watch mode as it relays each device’s traffic, so it costs the network nothing.'));
  const body = el('div', 'tf-body');
  root.append(head, body);

  const liveCard = el('section', 'card');
  const historyCard = el('section', 'card');
  const topCard = el('section', 'card');

  const cardHead = (t, extra) => {
    const h = el('div', 'card-h');
    h.append(el('h3', 'card-t', t));
    if (extra) h.append(extra);
    return h;
  };

  // ------------------------------------------------------------------ live
  function paintLive() {
    liveCard.replaceChildren(cardHead('Right now'));
    const line = statusHeadline(status);
    liveCard.append(el('p', 'tf-headline ' + line.tone, line.text));
    const live = status.live || {};
    const tiles = el('div', 'wm-tiles');
    const tile = (label, value, sub) => {
      const t = el('div', 'wm-tile');
      t.append(el('div', 'wm-tile-v', value), el('div', 'wm-tile-k', label));
      if (sub) t.append(el('div', 'wm-tile-s muted', sub));
      tiles.append(t);
    };
    tile('Download now', fmtBitsPerSecond(live.down_bytes_per_second), 'estimated');
    tile('Upload now', fmtBitsPerSecond(live.up_bytes_per_second), 'measured');
    tile('Since Watch mode started', fmtBytes(Number(live.bytes_received_est) || 0) + ' down', fmtBytes(Number(live.bytes_relayed) || 0) + ' up');
    liveCard.append(tiles);

    const rows = liveRows(status);
    if (rows.length) {
      const list = el('div', 'list-rows tf-live');
      for (const d of rows) {
        const clickable = !!(onOpenDevice && d.device_id);
        const row = el(clickable ? 'button' : 'div', 'list-row wm-row');
        if (clickable) {
          row.type = 'button';
          row.setAttribute('aria-label', 'Open ' + (d.name || d.device_id) + ' on the Devices screen');
          row.addEventListener('click', () => onOpenDevice(d.device_id));
        }
        const main = el('div', 'lr-main');
        main.append(el('div', 'lr-name', d.name || d.device_id || 'Unknown device'));
        main.append(el('p', 'lr-desc mono', fmtBitsPerSecond(d.down_bytes_per_second) + ' down  ·  ' + fmtBitsPerSecond(d.up_bytes_per_second) + ' up'));
        main.append(el('p', 'lr-desc mono muted small', fmtBytes(Number(d.bytes_received_est) || 0) + ' down · ' + fmtBytes(Number(d.bytes_relayed) || 0) + ' up since watched'));
        row.append(main);
        list.append(row);
      }
      liveCard.append(list);
    }
    liveCard.append(el('p', 'muted small wm-note', DOWNLOAD_CAVEAT));
  }

  // --------------------------------------------------------------- history
  const rangeSeg = segmented(RANGE_PRESETS.map((p) => ({ id: p.id, label: p.label })), range.id, (id) => {
    range = RANGE_PRESETS.find((p) => p.id === id) || RANGE_PRESETS[1];
    loadHistory().catch(() => {});
  }, 'Time range');
  const scopeSel = el('select', 'tf-scope');
  scopeSel.setAttribute('aria-label', 'Show bandwidth for');
  scopeSel.addEventListener('change', () => { scope = scopeSel.value; loadHistory().catch(() => {}); });
  function paintScopeOptions() {
    scopeSel.replaceChildren();
    for (const o of scopeOptions(groups, devices)) {
      const opt = el('option', '', (o.kind === 'group' ? 'Group: ' : o.kind === 'device' ? 'Device: ' : '') + o.label);
      opt.value = o.id;
      scopeSel.append(opt);
    }
    if (![...scopeSel.options].some((o) => o.value === scope)) scope = 'network';
    scopeSel.value = scope;
  }

  const chart = svg('svg', { viewBox: '0 0 600 140', class: 'tf-svg', 'aria-hidden': 'true' });
  const downPath = svg('path', { d: '', class: 'tf-down' });
  const upPath = svg('path', { d: '', class: 'tf-up' });
  chart.append(downPath, upPath);
  const yAxis = el('div', 'tf-yaxis mono muted small');
  const xAxis = el('div', 'tf-xaxis mono muted small');
  const chartEmpty = el('p', 'muted small tf-chart-empty', 'Nothing recorded for this range yet.');
  const chartWrap = el('div', 'tf-chart-wrap');
  chartWrap.append(yAxis, chart, chartEmpty);
  const legend = el('div', 'tf-legend small');
  const totals = el('dl', 'nh-kv');

  function paintHistory() {
    const controls = el('div', 'tf-controls');
    controls.append(el('span', 'muted small', 'Range'), rangeSeg.root, el('span', 'muted small', 'Show'), scopeSel);
    historyCard.replaceChildren(cardHead('Over time', controls));
    if (historyError) {
      historyCard.append(emptyState('Could not load history', historyError.message, button('Try again', 'ghost', () => loadHistory())));
      return;
    }
    if (!series) return;
    const filled = fillSeries(series.points, series.from, series.to, series.bucket);
    const paths = areaPaths(filled, series.bucket);
    downPath.setAttribute('d', paths.down);
    upPath.setAttribute('d', paths.up);
    const any = filled.some((p) => p.up > 0 || p.down > 0);
    chartEmpty.hidden = any;
    chart.hidden = !any;
    yAxis.hidden = !any;
    yAxis.replaceChildren(...axisLabels(paths.max).map((t) => el('span', '', t)));
    xAxis.replaceChildren(...timeLabels(filled, series.bucket).map((t) => el('span', '', t)));
    xAxis.hidden = !any;
    legend.replaceChildren(
      el('span', 'tf-key tf-key-down', 'Download (estimated)'),
      el('span', 'tf-key tf-key-up', 'Upload'),
      el('span', 'muted', 'Average rate per ' + series.bucket),
    );
    const sum = sumPoints(filled);
    totals.replaceChildren();
    const kv = (k, v) => { totals.append(el('dt', '', k)); totals.append(el('dd', 'mono', v)); };
    kv('Downloaded', fmtBytes(sum.down));
    kv('Uploaded', fmtBytes(sum.up));
    kv('Showing', scopeLabel(scope, groups, devices));
    historyCard.append(chartWrap, xAxis, legend, totals);
  }

  // ------------------------------------------------------------------- top
  function paintTop() {
    topCard.replaceChildren(cardHead('Who used the most'));
    if (!top) return;
    const net = top.network || {};
    const netTotal = (Number(net.down) || 0) + (Number(net.up) || 0);
    if (!netTotal) {
      topCard.append(el('p', 'muted small', 'Nothing recorded for this range yet.'));
      return;
    }
    const grid = el('div', 'tf-top');
    const table = (title, rows, idKey, clickable) => {
      const box = el('div', 'tf-top-box');
      box.append(el('h4', 'tf-top-t', title));
      if (!rows.length) { box.append(el('p', 'muted small', 'None.')); grid.append(box); return; }
      const list = el('div', 'list-rows');
      for (const r of rows) {
        const total = (Number(r.down) || 0) + (Number(r.up) || 0);
        const can = clickable && onOpenDevice && r[idKey];
        const row = el(can ? 'button' : 'div', 'list-row wm-row tf-row');
        if (can) {
          row.type = 'button';
          row.setAttribute('aria-label', 'Open ' + (r.name || r[idKey]) + ' on the Devices screen');
          row.addEventListener('click', () => onOpenDevice(r[idKey]));
        }
        const main = el('div', 'lr-main');
        main.append(el('div', 'lr-name', r.name || r[idKey] || 'Unknown'));
        main.append(el('p', 'lr-desc mono', fmtBytes(Number(r.down) || 0) + ' down · ' + fmtBytes(Number(r.up) || 0) + ' up'));
        const bar = el('div', 'tf-bar');
        const fill = el('div', 'tf-bar-fill');
        fill.style.width = Math.max(1, Math.round((total / netTotal) * 100)) + '%';
        bar.append(fill);
        main.append(bar);
        const meta = el('div', 'lr-meta');
        meta.append(el('span', 'badge muted', shareOf(total, netTotal)));
        row.append(main, meta);
        list.append(row);
      }
      box.append(list);
      grid.append(box);
    };
    table('Devices', top.devices || [], 'device_id', true);
    table('Groups', top.groups || [], 'group_id', false);
    topCard.append(el('p', 'muted small', 'Of ' + fmtBytes(netTotal) + ' across the whole network in this range: ' + fmtBytes(Number(net.down) || 0) + ' down, ' + fmtBytes(Number(net.up) || 0) + ' up.'));
    topCard.append(grid);
  }

  // The body is built once and the live card repainted on each poll, so
  // the chart, the scope picker and the scroll position survive polling.
  let built = false;
  function paintAll() {
    if (loadError) {
      body.replaceChildren(unavailable(loadError) ? unavailableCard('Bandwidth') : emptyState('Could not load bandwidth', loadError.message, button('Try again', 'ghost', load)));
      built = false;
      return;
    }
    if (!status) return;
    if (!built) {
      body.replaceChildren(liveCard, historyCard, topCard);
      built = true;
      paintHistory();
      paintTop();
    }
    paintLive();
  }

  async function load() {
    if (busy) return;
    busy = true;
    try {
      status = await mgmt.traffic();
      loadError = null;
    } catch (e) { loadError = e; }
    busy = false;
    paintAll();
  }

  async function loadScopes() {
    try {
      const [g, d] = await Promise.all([mgmt.groups(), mgmt.devices({ limit: 500 })]);
      groups = g.groups || g || [];
      devices = (d.devices || []).map((x) => ({ id: x.id, name: x.name || x.alias || x.hostname || x.id }));
    } catch { groups = []; devices = []; }
    paintScopeOptions();
  }

  async function loadHistory() {
    const w = rangeWindow(range);
    try {
      const [s, t] = await Promise.all([
        mgmt.trafficSeries({ from: w.from, to: w.to, scope }),
        mgmt.trafficTop({ from: w.from, to: w.to, limit: 12 }),
      ]);
      series = { bucket: s.bucket, from: s.from || w.from, to: s.to || w.to, points: s.points || [] };
      top = t;
      historyError = null;
    } catch (e) {
      historyError = e;
      series = null;
      top = null;
      notify('Could not load bandwidth history: ' + e.message);
    }
    if (status && !loadError) { paintHistory(); paintTop(); }
  }

  function startPolling() {
    stopPolling();
    timer = setInterval(() => { load().catch(() => {}); }, POLL_MS);
  }
  function stopPolling() {
    if (timer) clearInterval(timer);
    timer = 0;
  }

  return {
    async show() {
      startPolling();
      await load();
      await loadScopes();
      await loadHistory();
    },
    hide() { stopPolling(); built = false; },
  };
}
