// The Bandwidth screen: how much each device, each group and the whole
// network moves over the wire, right now and over time, plus the Watch mode
// controls that make the measuring possible. Live numbers poll while the
// screen is visible and feed a rolling chart; history is fetched on demand
// for the chosen range and scope.
//
// Every string that came from the server is placed with textContent.
import { el } from './dom.js';
import { button, emptyState, unavailableCard, segmented } from './ui.js';
import { unavailable } from './mgmt.js';
import {
  RANGE_PRESETS, rangeWindow, scopeOptions, scopeLabel, fillSeries, sumPoints, bucketRate, timeLabels,
  shareOf, statusHeadline, liveRows, DOWNLOAD_CAVEAT, fmtBytes, fmtBitsPerSecond,
  niceCeil, yTicks, lineArea, nearestIndex, pushSample, shareSlices, arcPath, rateStats,
} from './traffic.js';

const POLL_MS = 2000;
const LIVE_SAMPLES = 90; // three minutes at the poll rate
const TREND_DEVICES = 6;
const NS = 'http://www.w3.org/2000/svg';
function svg(tag, attrs) {
  const e = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, String(v));
  return e;
}

// One chart: shaded download and upload areas with gridlines on round
// numbers, a caption, and (when hover is wanted) a crosshair that reads out
// the bucket under the pointer. `points` are {time, up, down} per bucket.
function rateChart({ points, bucket, height = 180, hover = true, ticks = 4, timeText = null }) {
  const W = 600;
  const down = points.map((p) => bucketRate(p.down, bucket));
  const up = points.map((p) => bucketRate(p.up, bucket));
  const top = niceCeil(Math.max(0, ...down, ...up));
  const geo = { width: W, height, pad: 6 };
  const wrap = el('div', 'tf-chart-wrap');
  const yaxis = el('div', 'tf-yaxis mono muted small');
  const plot = el('div', 'tf-plot');
  const s = svg('svg', { viewBox: '0 0 ' + W + ' ' + height, class: 'tf-svg', preserveAspectRatio: 'none', 'aria-hidden': 'true' });
  s.style.height = height + 'px';
  const defs = svg('defs');
  for (const [id, cls] of [['tfd', 'tf-grad-down'], ['tfu', 'tf-grad-up']]) {
    const g = svg('linearGradient', { id: id + height + (hover ? 'h' : 'n'), x1: 0, y1: 0, x2: 0, y2: 1 });
    g.append(svg('stop', { offset: '0%', class: cls, 'stop-opacity': .55 }), svg('stop', { offset: '100%', class: cls, 'stop-opacity': .02 }));
    defs.append(g);
  }
  s.append(defs);
  const yPos = (v) => 6 + (height - 12) - (v / top) * (height - 12);
  const tickVals = yTicks(top, ticks);
  for (const t of tickVals) s.append(svg('line', { x1: 0, x2: W, y1: yPos(t).toFixed(1), y2: yPos(t).toFixed(1), class: t === 0 ? 'tf-base' : 'tf-grid' }));
  const dl = lineArea(down, top, geo);
  const ul = lineArea(up, top, geo);
  const idx = (cls) => 'url(#' + (cls === 'down' ? 'tfd' : 'tfu') + height + (hover ? 'h' : 'n') + ')';
  s.append(svg('path', { d: dl.area, fill: idx('down'), stroke: 'none' }), svg('path', { d: ul.area, fill: idx('up'), stroke: 'none' }));
  s.append(svg('path', { d: dl.line, class: 'tf-line tf-line-down', fill: 'none' }), svg('path', { d: ul.line, class: 'tf-line tf-line-up', fill: 'none' }));
  for (const t of [...tickVals].reverse()) {
    const lab = el('span', '', t === 0 ? '0' : fmtBitsPerSecond(t / 8));
    lab.style.top = ((yPos(t) / height) * 100).toFixed(1) + '%';
    yaxis.append(lab);
  }
  plot.append(s);
  if (hover && points.length > 1) {
    const cross = el('div', 'tf-cross');
    const tip = el('div', 'tf-tip mono small');
    cross.hidden = true; tip.hidden = true;
    plot.append(cross, tip);
    const when = timeText || ((t) => new Date(t).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }));
    const move = (e) => {
      const r = plot.getBoundingClientRect();
      if (!r.width) return;
      const f = (e.clientX - r.left) / r.width;
      const i = nearestIndex(f, points.length);
      const x = points.length === 1 ? 0.5 : i / (points.length - 1);
      cross.style.left = (x * 100) + '%';
      tip.replaceChildren(el('div', 'tf-tip-t', when(points[i].time)),
        el('div', 'tf-tip-down', 'Down ' + fmtBitsPerSecond(down[i] / 8)),
        el('div', 'tf-tip-up', 'Up ' + fmtBitsPerSecond(up[i] / 8)));
      tip.style.left = Math.min(Math.max(x * 100, 14), 86) + '%';
      cross.hidden = false; tip.hidden = false;
    };
    plot.addEventListener('pointermove', move);
    plot.addEventListener('pointerdown', move);
    plot.addEventListener('pointerleave', () => { cross.hidden = true; tip.hidden = true; });
  }
  wrap.append(yaxis, plot);
  return { node: wrap, stats: { down: rateStats(down), up: rateStats(up) } };
}

// A tiny trend line for one device: download area with the upload line.
function sparkline(points, bucket) {
  const down = points.map((p) => bucketRate(p.down, bucket));
  const up = points.map((p) => bucketRate(p.up, bucket));
  const top = Math.max(1, ...down, ...up);
  const geo = { width: 160, height: 40, pad: 2 };
  const s = svg('svg', { viewBox: '0 0 160 40', class: 'tf-spark', preserveAspectRatio: 'none', 'aria-hidden': 'true' });
  const d = lineArea(down, top, geo);
  const u = lineArea(up, top, geo);
  s.append(svg('path', { d: d.area, class: 'tf-spark-down' }), svg('path', { d: d.line, class: 'tf-line tf-line-down', fill: 'none' }), svg('path', { d: u.line, class: 'tf-line tf-line-up', fill: 'none' }));
  return s;
}

export function createTraffic({ root, mgmt, notify, onOpenDevice = null, watch = null }) {
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
  let trends = [];
  let historyError = null;
  let live = [];

  root.replaceChildren();
  const head = el('div', 'pg-head stack');
  const title = el('h2', 'pg-title');
  title.append(el('span', '', 'Bandwidth'));
  head.append(title, el('p', 'pg-sub muted', 'How much each device, each group and the whole network moves over the wire, live and over time, measured by Watch mode as it relays each device’s traffic, so it costs the network nothing.'));
  const body = el('div', 'tf-body');
  root.append(head, body);

  const liveCard = el('section', 'card');
  const historyCard = el('section', 'card');
  const mixCard = el('section', 'card');
  const trendsCard = el('section', 'card');
  const watchCard = el('section', 'card');
  if (watch) watchCard.append(watch.root);

  const cardHead = (t, extra) => {
    const h = el('div', 'card-h');
    h.append(el('h3', 'card-t', t));
    if (extra) h.append(extra);
    return h;
  };
  const keyRow = () => el('div', 'tf-legend small');
  const keys = () => {
    const l = keyRow();
    l.append(el('span', 'tf-key tf-key-down', 'Download (estimated)'), el('span', 'tf-key tf-key-up', 'Upload'));
    return l;
  };

  // ------------------------------------------------------------------ live
  const liveChartHolder = el('div', 'tf-live-chart');
  const liveRowsHolder = el('div', 'list-rows tf-live');
  const tilesHolder = el('div', 'wm-tiles');
  const headline = el('p', 'tf-headline');
  const liveNote = el('p', 'muted small wm-note', DOWNLOAD_CAVEAT);
  liveCard.append(cardHead('Right now'), headline, tilesHolder, liveChartHolder, liveRowsHolder, liveNote);

  function paintLive() {
    const line = statusHeadline(status);
    headline.textContent = line.text;
    headline.className = 'tf-headline ' + line.tone;
    const lv = status.live || {};
    tilesHolder.replaceChildren();
    const tile = (label, value, sub, cls) => {
      const t = el('div', 'wm-tile ' + (cls || ''));
      t.append(el('div', 'wm-tile-v', value), el('div', 'wm-tile-k', label));
      if (sub) t.append(el('div', 'wm-tile-s muted', sub));
      tilesHolder.append(t);
    };
    tile('Download now', fmtBitsPerSecond(lv.down_bytes_per_second), 'estimated', 'tile-down');
    tile('Upload now', fmtBitsPerSecond(lv.up_bytes_per_second), 'measured', 'tile-up');
    tile('Since Watch mode started', fmtBytes(Number(lv.bytes_received_est) || 0) + ' down', fmtBytes(Number(lv.bytes_relayed) || 0) + ' up');

    live = pushSample(live, { time: Date.now(), down: (Number(lv.down_bytes_per_second) || 0) * 8, up: (Number(lv.up_bytes_per_second) || 0) * 8 }, LIVE_SAMPLES);
    liveChartHolder.replaceChildren();
    if (live.length > 2) {
      // Samples are already rates in bits per second; hand them over as
      // per-second "bytes" so bucketRate's x8 lands back on the same value.
      const pts = live.map((p) => ({ time: p.time, down: p.down / 8, up: p.up / 8 }));
      const c = rateChart({ points: pts, bucket: 'second', height: 110, hover: true, ticks: 2, timeText: (t) => new Date(t).toLocaleTimeString() });
      liveChartHolder.append(c.node, el('p', 'muted small tf-cap', 'The last ' + Math.max(1, Math.round((live.length * POLL_MS) / 60000 * 10) / 10) + ' minutes, one sample every 2 seconds.'));
    }

    const rows = liveRows(status);
    const busiest = Math.max(1, ...rows.map((d) => Math.max(Number(d.down_bytes_per_second) || 0, Number(d.up_bytes_per_second) || 0)));
    liveRowsHolder.replaceChildren();
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
      const bars = el('div', 'tf-duo');
      for (const [cls, v] of [['down', d.down_bytes_per_second], ['up', d.up_bytes_per_second]]) {
        const bar = el('div', 'tf-duo-bar');
        const fill = el('div', 'tf-duo-fill tf-duo-' + cls);
        fill.style.width = Math.min(100, Math.round(((Number(v) || 0) / busiest) * 100)) + '%';
        bar.append(fill);
        bars.append(bar, el('span', 'tf-duo-n mono small', (cls === 'down' ? '↓ ' : '↑ ') + fmtBitsPerSecond(v)));
      }
      main.append(bars);
      main.append(el('p', 'lr-desc mono muted small', fmtBytes(Number(d.bytes_received_est) || 0) + ' down · ' + fmtBytes(Number(d.bytes_relayed) || 0) + ' up since watched'));
      row.append(main);
      liveRowsHolder.append(row);
    }
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
    const any = filled.some((p) => p.up > 0 || p.down > 0);
    if (!any) {
      historyCard.append(el('p', 'muted small tf-chart-empty', 'Nothing recorded for this range yet.'));
      return;
    }
    const sum = sumPoints(filled);
    const sumRow = el('div', 'tf-sums');
    const stat = (k, v, cls) => { const d = el('div', 'tf-stat ' + (cls || '')); d.append(el('div', 'tf-stat-v', v), el('div', 'tf-stat-k muted small', k)); sumRow.append(d); };
    const chart = rateChart({ points: filled, bucket: series.bucket, height: 190 });
    stat('Downloaded', fmtBytes(sum.down), 'tf-stat-down');
    stat('Uploaded', fmtBytes(sum.up), 'tf-stat-up');
    stat('Peak download', fmtBitsPerSecond(chart.stats.down.peak / 8));
    stat('Peak upload', fmtBitsPerSecond(chart.stats.up.peak / 8));
    const xAxis = el('div', 'tf-xaxis mono muted small');
    xAxis.append(...timeLabels(filled, series.bucket).map((t) => el('span', '', t)));
    const cap = el('p', 'muted small tf-cap', 'Showing ' + scopeLabel(scope, groups, devices) + '. Average rate per ' + series.bucket + '; hover or touch the chart to read a point.');
    historyCard.append(sumRow, chart.node, xAxis, keys(), cap);
  }

  // ------------------------------------------------- where the bytes went
  const SLICE_CLASSES = ['sl0', 'sl1', 'sl2', 'sl3', 'sl4', 'sl5'];
  function paintMix() {
    mixCard.replaceChildren(cardHead('Where it goes'));
    if (!top) return;
    const net = top.network || {};
    const netTotal = (Number(net.down) || 0) + (Number(net.up) || 0);
    if (!netTotal) {
      mixCard.append(el('p', 'muted small', 'Nothing recorded for this range yet.'));
      return;
    }
    const grid = el('div', 'tf-mix');
    const slices = shareSlices((top.devices || []).map((d) => ({ ...d, value: (Number(d.down) || 0) + (Number(d.up) || 0) })), 5);

    const donutBox = el('div', 'tf-donut-box');
    const d = svg('svg', { viewBox: '0 0 120 120', class: 'tf-donut', role: 'img', 'aria-label': 'Share of traffic by device' });
    let at = 0;
    slices.forEach((sl, i) => {
      const p = svg('path', { d: arcPath(60, 60, 54, 34, at, at + sl.fraction), class: 'sl ' + (sl.item.other ? 'sl-other' : SLICE_CLASSES[i % SLICE_CLASSES.length]) });
      p.append(svg('title'));
      p.lastChild.textContent = (sl.item.name || sl.item.device_id || 'Unknown') + ': ' + shareOf(sl.value, netTotal) + ' · ' + fmtBytes(sl.value);
      d.append(p);
      at += sl.fraction;
    });
    const centre = el('div', 'tf-donut-c');
    centre.append(el('div', 'tf-donut-v', fmtBytes(netTotal)), el('div', 'muted small', 'total'));
    donutBox.append(d, centre);

    const legend = el('div', 'list-rows tf-mix-legend');
    slices.forEach((sl, i) => {
      const can = onOpenDevice && sl.item.device_id;
      const row = el(can ? 'button' : 'div', 'list-row wm-row tf-row');
      if (can) {
        row.type = 'button';
        row.setAttribute('aria-label', 'Open ' + (sl.item.name || sl.item.device_id) + ' on the Devices screen');
        row.addEventListener('click', () => onOpenDevice(sl.item.device_id));
      }
      const main = el('div', 'lr-main');
      const nm = el('div', 'lr-name');
      nm.append(el('span', 'tf-swatch ' + (sl.item.other ? 'sl-other' : SLICE_CLASSES[i % SLICE_CLASSES.length])), document.createTextNode(sl.item.name || sl.item.device_id || 'Unknown'));
      main.append(nm);
      if (!sl.item.other) main.append(el('p', 'lr-desc mono', fmtBytes(Number(sl.item.down) || 0) + ' down · ' + fmtBytes(Number(sl.item.up) || 0) + ' up'));
      const meta = el('div', 'lr-meta');
      meta.append(el('span', 'badge muted', shareOf(sl.value, netTotal)));
      row.append(main, meta);
      legend.append(row);
    });
    grid.append(donutBox, legend);

    const down = Number(net.down) || 0;
    const up = Number(net.up) || 0;
    const split = el('div', 'tf-split');
    const sd = el('div', 'tf-split-down'); sd.style.width = ((down / netTotal) * 100).toFixed(1) + '%';
    const su = el('div', 'tf-split-up'); su.style.width = ((up / netTotal) * 100).toFixed(1) + '%';
    split.append(sd, su);
    mixCard.append(grid, el('p', 'tf-top-t', 'Download against upload'), split,
      el('p', 'muted small tf-cap', fmtBytes(down) + ' down (' + shareOf(down, netTotal) + ') · ' + fmtBytes(up) + ' up (' + shareOf(up, netTotal) + ') across the whole network in this range.'));
    if (top.groups && top.groups.length) {
      const g = el('p', 'muted small tf-cap');
      g.textContent = 'By group: ' + top.groups.map((x) => (x.name || x.group_id) + ' ' + shareOf((Number(x.down) || 0) + (Number(x.up) || 0), netTotal)).join(' · ');
      mixCard.append(g);
    }
  }

  // ---------------------------------------------------- per-device trends
  function paintTrends() {
    trendsCard.replaceChildren(cardHead('Device trends'));
    if (!trends.length) {
      trendsCard.append(el('p', 'muted small', 'Nothing recorded for this range yet.'));
      return;
    }
    const grid = el('div', 'tf-trends');
    for (const t of trends) {
      const can = onOpenDevice && t.device.device_id;
      const card = el(can ? 'button' : 'div', 'tf-trend');
      if (can) {
        card.type = 'button';
        card.setAttribute('aria-label', 'Open ' + (t.device.name || t.device.device_id) + ' on the Devices screen');
        card.addEventListener('click', () => onOpenDevice(t.device.device_id));
      }
      const peak = rateStats(t.points.map((p) => bucketRate(p.down, t.bucket))).peak;
      card.append(el('div', 'tf-trend-n', t.device.name || t.device.device_id || 'Unknown'),
        sparkline(t.points, t.bucket),
        el('div', 'tf-trend-s mono small muted', fmtBytes(Number(t.device.down) || 0) + ' down · ' + fmtBytes(Number(t.device.up) || 0) + ' up'),
        el('div', 'tf-trend-s mono small muted', 'peak ' + fmtBitsPerSecond(peak / 8)));
      grid.append(card);
    }
    trendsCard.append(grid, keys());
  }

  // The body is built once and the live card repainted on each poll, so
  // the charts, the scope picker and the scroll position survive polling.
  let built = false;
  function paintAll() {
    if (loadError) {
      body.replaceChildren(unavailable(loadError) ? unavailableCard('Bandwidth') : emptyState('Could not load bandwidth', loadError.message, button('Try again', 'ghost', load)));
      built = false;
      return;
    }
    if (!status) return;
    if (!built) {
      body.replaceChildren(liveCard, historyCard, mixCard, trendsCard, watchCard);
      built = true;
      paintHistory();
      paintMix();
      paintTrends();
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
      const picks = (t.devices || []).filter((d) => d.device_id).slice(0, TREND_DEVICES);
      trends = (await Promise.all(picks.map(async (d) => {
        try {
          const r = await mgmt.trafficSeries({ from: w.from, to: w.to, scope: 'device:' + d.device_id });
          const bucket = r.bucket;
          return { device: d, bucket, points: fillSeries(r.points || [], r.from || w.from, r.to || w.to, bucket) };
        } catch { return null; }
      }))).filter(Boolean);
    } catch (e) {
      historyError = e;
      series = null;
      top = null;
      trends = [];
      notify('Could not load bandwidth history: ' + e.message);
    }
    if (status && !loadError) { paintHistory(); paintMix(); paintTrends(); }
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
      if (watch) watch.show();
      await load();
      await loadScopes();
      await loadHistory();
    },
    hide() { stopPolling(); built = false; live = []; if (watch) watch.hide(); },
  };
}
