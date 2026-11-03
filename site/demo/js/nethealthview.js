// The Network health screen: a top-level view (not a device-drawer panel —
// there is no "device" here, this is about the network as a whole). One
// header row carries the verdict (a status pill), the time-range picker and
// "Probe now"; four metric tiles each pair the current reading with its own
// area chart over the chosen range (latency, jitter, packet loss,
// reachability); below them sit the bufferbloat card and a short "how this
// is measured" card. All server text is placed with textContent; only the
// SVG chart coordinates (pure numbers from nethealth.js) are set as
// attributes.
import { el } from './dom.js?v=65858b99';
import { button, segmented, emptyState, unavailableCard } from './ui.js?v=c9bbb094';
import { unavailable } from './mgmt.js?v=8b3f5c53';
import { fmtDateTime } from './format.js?v=86b54455';
import {
  gradeClass, gradeLabel, fmtMS, fmtMSValue, fmtLoss, reachabilityText, statusHeadline, statusKind, statusPillLabel,
  areaPath, axisMax, seriesSpan, seriesToPoints, RANGE_PRESETS,
} from './nethealth.js?v=d5668974';

const NS = 'http://www.w3.org/2000/svg';
function svg(tag, attrs) {
  const e = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, String(v));
  return e;
}

const W = 600, H = 100, PAD = 4;

// fmtWhen is fmtDateTime without the seconds: on an axis or in a history
// list the seconds are noise, and the extra width crowds a narrow tile.
const fmtWhen = (ms) => fmtDateTime(ms).replace(/:\d\d$/, '');
let gradSeq = 0;

// metricTile builds one tile: label, big current value, a min–max subline
// for the range, and an area chart. `fmt` formats a value for the axis and
// subline; `fmtNow` formats the headline value (fmtMS's "0 means no
// reading" convention applies to the live number, not to the axis).
function metricTile(label, { fmt, fmtNow = fmt }) {
  const root = el('section', 'card nh-tile');
  const head = el('div', 'nh-tile-head');
  head.append(el('span', 'k', label));
  const range = el('span', 'nh-tile-range mono', '');
  head.append(range);
  const value = el('div', 'v', '—');
  const sub = el('div', 'sub nh-tile-sub', '');

  const wrap = el('div', 'nh-chart-wrap');
  const chart = svg('svg', { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: 'none', class: 'nh-svg', 'aria-hidden': 'true' });
  const gid = 'nh-grad-' + (++gradSeq);
  const defs = svg('defs', {});
  const grad = svg('linearGradient', { id: gid, x1: 0, y1: 0, x2: 0, y2: 1 });
  grad.append(svg('stop', { offset: '0%', 'stop-color': 'currentColor', 'stop-opacity': '.32' }), svg('stop', { offset: '100%', 'stop-color': 'currentColor', 'stop-opacity': '0' }));
  defs.append(grad);
  const grid = svg('g', { class: 'nh-grid' });
  for (const f of [0.25, 0.5, 0.75]) {
    const y = (PAD + (H - PAD * 2) * f).toFixed(1);
    grid.append(svg('line', { x1: 0, x2: W, y1: y, y2: y }));
  }
  const area = svg('path', { d: '', fill: `url(#${gid})`, stroke: 'none' });
  const line = svg('path', { d: '', fill: 'none', stroke: 'currentColor', 'stroke-width': '1.6', 'stroke-linejoin': 'round', 'vector-effect': 'non-scaling-stroke' });
  chart.append(defs, grid, area, line);
  const yMax = el('span', 'nh-ylab top mono', '');
  const yMin = el('span', 'nh-ylab bottom mono', '');
  const empty = el('p', 'muted small nh-chart-empty', 'Not enough data yet.');
  wrap.append(chart, yMax, yMin, empty);

  const times = el('div', 'nh-times muted');
  const tFrom = el('span', 'mono', '');
  const tTo = el('span', 'mono', '');
  times.append(tFrom, tTo);

  root.append(head, value, sub, wrap, times);
  return {
    root,
    setValue(text, subText, tone) {
      value.textContent = text;
      sub.textContent = subText || '';
      root.className = 'card nh-tile' + (tone ? ' ' + tone : '');
    },
    paint(points, opts) {
      const r = areaPath(points, { width: W, height: H, pad: PAD, ...opts });
      area.setAttribute('d', r.area);
      line.setAttribute('d', r.line);
      const has = points.length > 1;
      empty.hidden = has;
      chart.hidden = !has;
      yMax.hidden = yMin.hidden = !has;
      yMax.textContent = has ? fmt(r.max) : '';
      yMin.textContent = has ? fmt(r.min) : '';
      range.textContent = has ? fmt(Math.min(...points.map((p) => p.v))) + ' – ' + fmt(Math.max(...points.map((p) => p.v))) : '';
      const span = seriesSpan(points);
      tFrom.textContent = span ? fmtWhen(span.from) : '';
      tTo.textContent = span ? fmtWhen(span.to) : '';
    },
    // the chart's own current-value formatter, for callers that want it
    fmtNow,
  };
}

export function createNethealth({ root, mgmt, notify }) {
  let range = RANGE_PRESETS[0];
  let status = null;
  let statusError = null;
  let series = { latency: [], jitter: [], loss: [], reach: [] };
  let bufferbloat = [];
  let bufferbloatError = null;
  let timer = 0;
  let probing = false;
  let runningBufferbloat = false;

  root.replaceChildren();

  // ------------------------------------------------------------- header
  const head = el('div', 'pg-head nh-head');
  const title = el('h2', 'pg-title');
  title.append(el('span', '', 'Network health'));
  const pill = el('span', 'nh-pill none', 'No probe yet');
  title.append(pill);
  const rangeSeg = segmented(RANGE_PRESETS.map((p) => ({ id: p.id, label: p.label })), range.id, (id) => {
    range = RANGE_PRESETS.find((p) => p.id === id) || RANGE_PRESETS[0];
    loadSeries();
  }, 'Time range');
  const probeBtn = button('Probe now', 'ghost', () => probeNow());
  const sub = el('p', 'pg-sub muted', 'Latency, jitter, packet loss and reachability to the internet, probed every couple of minutes — not just "is it up now" but whether it has been reliable.');
  head.append(title, el('span', 'spacer'), rangeSeg.root, probeBtn, sub);
  root.append(head);

  const body = el('div', 'nh-body');
  root.append(body);

  // Error / unavailable state replaces the whole body.
  const errorBox = el('div', 'nh-error');
  errorBox.hidden = true;
  body.append(errorBox);

  // ------------------------------------------------------------- tiles
  const latencyTile = metricTile('Latency', { fmt: fmtMSValue, fmtNow: fmtMS });
  const jitterTile = metricTile('Jitter', { fmt: fmtMSValue, fmtNow: fmtMS });
  const lossTile = metricTile('Packet loss', { fmt: fmtLoss });
  const reachTile = metricTile('Reachability', { fmt: (v) => String(Math.round(v)) });
  const tiles = el('div', 'nh-tiles');
  tiles.append(latencyTile.root, jitterTile.root, lossTile.root, reachTile.root);
  body.append(tiles);

  // ------------------------------------------------------------- lower row
  const lower = el('div', 'nh-lower');
  body.append(lower);

  const bbCard = el('section', 'card nh-bufferbloat');
  const bbHead = el('div', 'card-h');
  bbHead.append(el('h3', 'card-t', 'Bufferbloat'));
  const bbBtn = button('Run test now', 'ghost', () => runBufferbloat());
  bbHead.append(bbBtn);
  const bbCurrent = el('div', 'nh-bb-current');
  const bbList = el('ul', 'list nh-bb-list');
  bbCard.append(bbHead, bbCurrent, bbList);
  lower.append(bbCard);

  const aboutCard = el('section', 'card nh-about');
  aboutCard.append(el('h3', 'card-t', 'How this is measured'));
  const aboutTargets = el('div', 'nh-targets');
  const aboutP1 = el('p', 'muted small', '');
  aboutCard.append(
    aboutP1,
    el('p', 'muted small', 'Latency is the mean round trip to each reachable target, jitter is how much those round trips vary within one cycle, and loss is the share of probes that got no answer. A sustained stretch of loss or high latency raises the network-degraded alarm.'),
    el('p', 'muted small', 'Bufferbloat compares idle latency with latency under a short download burst: A adds under 30 ms, B under 60, C under 200, D under 400, F more. It generates real load, so it is off unless enabled in [nethealth] or run by hand.'),
    el('div', 'k nh-targets-k', 'Targets'),
    aboutTargets,
  );
  lower.append(aboutCard);

  function paintStatus() {
    if (statusError) {
      errorBox.hidden = false;
      tiles.hidden = lower.hidden = true;
      errorBox.replaceChildren(unavailable(statusError) ? unavailableCard('Network health') : emptyState('Could not load network status', statusError.message, button('Try again', 'ghost', load)));
      probeBtn.disabled = true;
      pill.className = 'nh-pill none';
      pill.textContent = 'Unavailable';
      return;
    }
    errorBox.hidden = true;
    tiles.hidden = lower.hidden = false;
    const cur = status && status.current;
    const kind = statusKind(cur, !!(status && status.degraded));
    pill.className = 'nh-pill ' + kind;
    pill.textContent = statusPillLabel(kind);
    pill.title = statusHeadline(cur, !!(status && status.degraded));
    const tone = kind === 'bad' ? 'bad' : kind === 'warn' ? 'warn' : '';
    const checked = cur ? 'checked ' + fmtWhen(Date.parse(cur.time)) : 'no probe has run yet';
    latencyTile.setValue(cur ? fmtMS(cur.latency_ms) : '—', cur ? 'mean round trip · ' + checked : checked, tone);
    jitterTile.setValue(cur ? fmtMS(cur.jitter_ms) : '—', cur ? 'variation within a cycle' : '', tone);
    lossTile.setValue(cur ? fmtLoss(cur.loss_pct) : '—', cur ? 'of probes unanswered' : '', cur && cur.loss_pct > 0 ? (tone || 'warn') : tone);
    reachTile.setValue(cur ? `${cur.reachable_targets}/${cur.total_targets}` : '—', cur ? reachabilityText(cur.reachable_targets, cur.total_targets) : '', tone);

    const targets = (status && status.targets) || [];
    aboutTargets.replaceChildren();
    for (const t of targets) aboutTargets.append(el('span', 'nh-target mono', t));
    if (!targets.length) aboutTargets.append(el('span', 'muted small', 'No targets configured.'));
    aboutP1.textContent = (status && status.enabled
      ? 'Every two minutes Shepherd opens a few short connections to each target below and records the result.'
      : 'The scheduled probe is off; readings here come from manual probes only. Enable it in [nethealth].')
      + ' Targets are your configured DNS upstreams plus two public resolvers, so an upstream outage is distinguishable from the whole path to the internet being down.';
    probeBtn.disabled = probing || !(status && status.enabled !== undefined);
  }

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
      bbCurrent.append(el('p', 'muted small nh-bb-none', status && status.bufferbloat_enabled ? 'No check has run yet.' : 'Off by default — it generates real load against your own connection. Enable it in [nethealth] or run one manually.'));
    } else {
      const badge = el('span', gradeClass(latest.grade) + ' big');
      badge.textContent = latest.load_error ? '!' : (latest.grade || '—');
      badge.title = gradeLabel(latest.grade, latest.load_error);
      const stats = el('div', 'nh-bb-stats');
      const stat = (k, v) => { const d = el('div', 'nh-bb-stat'); d.append(el('span', 'k', k), el('span', 'nh-bb-v mono', v)); return d; };
      if (latest.load_error) {
        stats.append(el('p', 'muted small', latest.load_error));
      } else {
        stats.append(stat('Idle', fmtMSValue(latest.idle_ms)), stat('Loaded', fmtMSValue(latest.loaded_ms)), stat('Added', '+' + fmtMSValue(latest.increase_ms)));
      }
      const when = el('div', 'muted small nh-bb-when', gradeLabel(latest.grade, latest.load_error) + ' · ' + fmtWhen(Date.parse(latest.time)));
      const right = el('div', 'nh-bb-main');
      right.append(stats, when);
      bbCurrent.append(badge, right);
    }
    const prior = [...bufferbloat].reverse().slice(1, 11);
    for (const b of prior) {
      const li = el('li', '');
      const l1 = el('span', gradeClass(b.grade), b.load_error ? '!' : b.grade || '—');
      const l2 = el('span', 'grow small', fmtWhen(Date.parse(b.time)));
      const l3 = el('span', 'muted small mono', b.load_error ? 'could not run' : '+' + fmtMSValue(b.increase_ms));
      li.append(l1, l2, l3);
      bbList.append(li);
    }
    bbList.hidden = prior.length === 0;
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
    if (statusError) return;
    await Promise.all([loadSeries(), loadBufferbloat()]);
  }

  async function loadSeries() {
    const to = new Date();
    const from = new Date(to.getTime() - range.hours * 3600 * 1000);
    try {
      const params = { from: from.toISOString(), to: to.toISOString() };
      const res = await mgmt.nethealthSeries(params);
      const pts = res.points || [];
      // Every Point the server returns — raw or rolled up — uses the same
      // avg_latency_ms/avg_jitter_ms/avg_loss_pct fields (internal/nethealth
      // /store.go's Point: a raw sample's own min/avg/max are just that one
      // value, so there is no separate bare-named field for the raw case).
      series = {
        latency: seriesToPoints(pts, 'avg_latency_ms'),
        jitter: seriesToPoints(pts, 'avg_jitter_ms'),
        loss: seriesToPoints(pts, 'avg_loss_pct'),
        reach: seriesToPoints(pts, 'reachable_targets'),
      };
    } catch (e) {
      series = { latency: [], jitter: [], loss: [], reach: [] };
    }
    latencyTile.paint(series.latency, { min: 0 });
    jitterTile.paint(series.jitter, { min: 0 });
    lossTile.paint(series.loss, { min: 0, max: axisMax(series.loss, 5) });
    const total = status && status.current ? status.current.total_targets : 0;
    reachTile.paint(series.reach, { min: 0, max: Math.max(total, ...series.reach.map((p) => p.v), 1) });
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
