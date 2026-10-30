// The Network screen: a top-level view (not a device-drawer panel — there
// is no "device" here, this is about the network as a whole), mirroring
// the structure of the Alarms/Upstreams screens. Deliberately simple for a
// first version: a current-status summary, a time-range picker, one small
// line chart per metric (latency, jitter, loss), and a bufferbloat card
// with its own history and a manual "run test now". All server text is
// placed with textContent; only the SVG chart coordinates (pure numbers
// from nethealth.js) are set as attributes.
import { el } from './dom.js';
import { button, segmented, emptyState, unavailableCard } from './ui.js';
import { unavailable } from './mgmt.js';
import { fmtDateTime } from './format.js';
import {
  gradeClass, gradeLabel, fmtMS, fmtMSValue, fmtLoss, reachabilityText, statusHeadline, chartPath, seriesToPoints, RANGE_PRESETS,
} from './nethealth.js';

const NS = 'http://www.w3.org/2000/svg';
function svg(tag, attrs) {
  const e = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, String(v));
  return e;
}

// metricChart builds one labeled line-chart card for one metric.
function metricChart(title, unitFmt) {
  const card = el('section', 'card nh-chart');
  const head = el('div', 'card-h');
  head.append(el('h3', 'card-t', title));
  const rangeLbl = el('span', 'muted small');
  head.append(rangeLbl);
  const chart = svg('svg', { viewBox: '0 0 600 120', class: 'nh-svg', 'aria-hidden': 'true' });
  const path = svg('path', { d: '', fill: 'none', stroke: 'currentColor', 'stroke-width': '2' });
  chart.append(path);
  const empty = el('p', 'muted small nh-chart-empty', 'Not enough data yet.');
  const wrap = el('div', 'nh-chart-wrap');
  wrap.append(chart, empty);
  card.append(head, wrap);
  return {
    root: card,
    paint(points, opts) {
      const { d, min, max } = chartPath(points, { width: 600, height: 120, pad: 6, ...opts });
      path.setAttribute('d', d);
      empty.hidden = points.length > 1;
      chart.hidden = points.length <= 1;
      rangeLbl.textContent = points.length > 1 ? unitFmt(min) + ' – ' + unitFmt(max) : '';
    },
  };
}

export function createNethealth({ root, mgmt, notify }) {
  let range = RANGE_PRESETS[0];
  let status = null;
  let statusError = null;
  let series = { latency: [], jitter: [], loss: [] };
  let bufferbloat = [];
  let bufferbloatError = null;
  let timer = 0;
  let probing = false;
  let runningBufferbloat = false;

  root.replaceChildren();
  const head = el('div', 'pg-head stack');
  const title = el('h2', 'pg-title');
  title.append(el('span', '', 'Network'));
  head.append(title, el('p', 'pg-sub muted', 'Latency, jitter, packet loss and reachability over time, plus an occasional bufferbloat check. Not just "is it up now" — is it reliable over the last few months.'));
  root.append(head);

  const body = el('div', 'nh-body');
  root.append(body);

  // ------------------------------------------------------------- status card
  const statusCard = el('section', 'card nh-status');
  const statusHead = el('div', 'card-h');
  statusHead.append(el('h3', 'card-t', 'Current status'));
  const probeBtn = button('Probe now', 'ghost', () => probeNow());
  statusHead.append(probeBtn);
  const statusLine = el('p', 'nh-status-line');
  const statusDetail = el('dl', 'nh-kv');
  statusCard.append(statusHead, statusLine, statusDetail);
  body.append(statusCard);

  function kv(dt, dd) {
    const d1 = el('dt', '', dt);
    const d2 = el('dd', 'mono', dd);
    return [d1, d2];
  }

  function paintStatus() {
    if (statusError) {
      statusLine.replaceChildren();
      statusDetail.replaceChildren();
      statusLine.append(unavailable(statusError) ? unavailableCard('Network health') : emptyState('Could not load network status', statusError.message, button('Try again', 'ghost', load)));
      probeBtn.disabled = true;
      return;
    }
    const cur = status && status.current;
    statusLine.textContent = statusHeadline(cur, !!(status && status.degraded));
    statusLine.className = 'nh-status-line' + (status && status.degraded ? ' bad' : cur && cur.reachable_targets === 0 ? ' bad' : '');
    statusDetail.replaceChildren();
    if (cur) {
      statusDetail.append(...kv('Latency', fmtMS(cur.latency_ms)));
      statusDetail.append(...kv('Jitter', fmtMS(cur.jitter_ms)));
      statusDetail.append(...kv('Loss', fmtLoss(cur.loss_pct)));
      statusDetail.append(...kv('Reachable', reachabilityText(cur.reachable_targets, cur.total_targets)));
      statusDetail.append(...kv('Checked', fmtDateTime(Date.parse(cur.time))));
    }
    probeBtn.disabled = probing || !(status && status.enabled !== undefined);
  }

  // ------------------------------------------------------------- range picker
  const rangeSeg = segmented(RANGE_PRESETS.map((p) => ({ id: p.id, label: p.label })), range.id, (id) => {
    range = RANGE_PRESETS.find((p) => p.id === id) || RANGE_PRESETS[0];
    loadSeries();
  }, 'Time range');
  const rangeWrap = el('div', 'nh-range');
  rangeWrap.append(el('span', 'muted small', 'Range'), rangeSeg.root);
  body.append(rangeWrap);

  // ------------------------------------------------------------- charts
  const latencyChart = metricChart('Latency', fmtMSValue);
  const jitterChart = metricChart('Jitter', fmtMSValue);
  const lossChart = metricChart('Packet loss', fmtLoss);
  const chartsGrid = el('div', 'nh-charts');
  chartsGrid.append(latencyChart.root, jitterChart.root, lossChart.root);
  body.append(chartsGrid);

  // ------------------------------------------------------------- bufferbloat card
  const bbCard = el('section', 'card nh-bufferbloat');
  const bbHead = el('div', 'card-h');
  bbHead.append(el('h3', 'card-t', 'Bufferbloat'));
  const bbBtn = button('Run test now', 'ghost', () => runBufferbloat());
  bbHead.append(bbBtn);
  const bbCurrent = el('div', 'nh-bb-current');
  const bbList = el('ul', 'list nh-bb-list');
  bbCard.append(bbHead, bbCurrent, bbList);
  body.append(bbCard);

  function paintBufferbloat() {
    bbCurrent.replaceChildren();
    bbList.replaceChildren();
    if (bufferbloatError) {
      bbCurrent.append(unavailable(bufferbloatError) ? unavailableCard('Bufferbloat') : emptyState('Could not load bufferbloat history', bufferbloatError.message));
      bbBtn.disabled = true;
      return;
    }
    bbBtn.disabled = runningBufferbloat;
    const latest = bufferbloat[bufferbloat.length - 1];
    if (!latest) {
      bbCurrent.append(el('p', 'muted small', status && status.bufferbloat_enabled ? 'No check has run yet.' : 'Off by default (generates real load against your own connection). Enabled in [nethealth] or run one manually.'));
    } else {
      const badge = el('span', gradeClass(latest.grade));
      badge.textContent = gradeLabel(latest.grade, latest.load_error);
      const detail = el('span', 'muted small', latest.load_error ? latest.load_error : fmtMSValue(latest.idle_ms) + ' idle, ' + fmtMSValue(latest.loaded_ms) + ' loaded (+' + fmtMSValue(latest.increase_ms) + ')');
      bbCurrent.append(badge, detail);
    }
    for (const b of [...bufferbloat].reverse().slice(0, 10)) {
      const li = el('li', '');
      const l1 = el('span', gradeClass(b.grade), b.load_error ? 'error' : b.grade || '—');
      const l2 = el('span', 'muted small', fmtDateTime(Date.parse(b.time)) + ' — ' + (b.load_error || fmtMSValue(b.increase_ms) + ' added'));
      li.append(l1, l2);
      bbList.append(li);
    }
  }

  // ------------------------------------------------------------- loading
  async function load() {
    try {
      status = await mgmt.nethealthStatus();
      statusError = null;
    } catch (e) {
      statusError = e;
    }
    paintStatus();
    await Promise.all([loadSeries(), loadBufferbloat()]);
  }

  async function loadSeries() {
    const to = new Date();
    const from = new Date(to.getTime() - range.hours * 3600 * 1000);
    try {
      const params = { from: from.toISOString(), to: to.toISOString() };
      const latencyRes = await mgmt.nethealthSeries(params);
      const pts = latencyRes.points || [];
      // Every Point the server returns — raw or rolled up — uses the same
      // avg_latency_ms/avg_jitter_ms/avg_loss_pct fields (internal/nethealth
      // /store.go's Point: a raw sample's own min/avg/max are just that one
      // value, so there is no separate bare-named field for the raw case).
      series = { latency: seriesToPoints(pts, 'avg_latency_ms'), jitter: seriesToPoints(pts, 'avg_jitter_ms'), loss: seriesToPoints(pts, 'avg_loss_pct') };
    } catch (e) {
      series = { latency: [], jitter: [], loss: [] };
    }
    latencyChart.paint(series.latency);
    jitterChart.paint(series.jitter);
    lossChart.paint(series.loss, { min: 0, max: 100 });
  }

  async function loadBufferbloat() {
    try {
      const to = new Date();
      const from = new Date(to.getTime() - 90 * 24 * 3600 * 1000);
      const r = await mgmt.nethealthBufferbloat({ from: from.toISOString(), to: to.toISOString() });
      bufferbloat = r.points || [];
      bufferbloatError = null;
    } catch (e) {
      bufferbloatError = e;
    }
    paintBufferbloat();
  }

  async function probeNow() {
    probing = true;
    paintStatus();
    try {
      await mgmt.nethealthProbeNow();
      await load();
    } catch (e) {
      notify('Could not run a probe: ' + e.message);
    } finally {
      probing = false;
      paintStatus();
    }
  }

  async function runBufferbloat() {
    runningBufferbloat = true;
    paintBufferbloat();
    try {
      await mgmt.nethealthBufferbloatRun();
      await loadBufferbloat();
      notify('Bufferbloat test finished');
    } catch (e) {
      notify('Could not run a bufferbloat test: ' + e.message);
    } finally {
      runningBufferbloat = false;
      paintBufferbloat();
    }
  }

  return {
    async show() {
      await load();
      clearInterval(timer);
      timer = setInterval(() => { if (!root.hidden) load(); }, 15000);
    },
    hide() { clearInterval(timer); },
  };
}
