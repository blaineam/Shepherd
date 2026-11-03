// Pure nethealth-view helpers: formatting, bufferbloat grade presentation,
// and the line-chart math for the Network screen (nethealthview.js). No
// DOM, no network — kept separate so they are easy to unit test, the same
// reason internal/portal/web/js/alarms.js and vulnscan.js exist.

// GRADES mirrors internal/nethealth's own A-F bufferbloat scale
// (gradeBufferbloat in internal/nethealth/bufferbloat.go): best first.
export const GRADES = ['A', 'B', 'C', 'D', 'F'];

// gradeClass names the CSS class for a bufferbloat grade badge; an unknown
// or missing grade (a load burst that failed to run at all) gets a neutral
// "unknown" class rather than silently defaulting to a specific color.
export function gradeClass(grade) {
  return GRADES.includes(grade) ? 'nh-grade nh-grade-' + grade.toLowerCase() : 'nh-grade nh-grade-unknown';
}

export function gradeLabel(grade, loadError) {
  if (loadError) return 'Could not run';
  return GRADES.includes(grade) ? 'Grade ' + grade : 'No reading yet';
}

// fmtMS/fmtJitter format a latency-shaped number for display; 0 round
// trips (no samples at all, not "0ms") read as an em dash instead of a
// potentially misleading zero.
export function fmtMS(v) {
  return v > 0 ? Math.round(v) + ' ms' : '—';
}

// fmtMSValue is fmtMS without the "0 means no data" convention: for a
// value that is legitimately zero (a chart axis bound, a bufferbloat
// increase that rounded all the way down to no measurable bloat — a good
// result, not a missing one), printing "0 ms" is correct where fmtMS's
// em dash would misleadingly read as "no reading at all".
export function fmtMSValue(v) {
  return Math.round(Number(v) || 0) + ' ms';
}

export function fmtLoss(v) {
  return (Number(v) || 0).toFixed(v >= 10 ? 0 : 1) + '%';
}

// reachabilityText turns {reachable_targets, total_targets} into a short,
// honest summary, including the "nothing probed yet" and "total outage"
// edge cases a plain fraction would leave ambiguous.
export function reachabilityText(reachable, total) {
  if (!total) return 'no targets yet';
  if (reachable === 0) return `${reachable}/${total} — total outage`;
  if (reachable === total) return `${reachable}/${total} reachable`;
  return `${reachable}/${total} reachable`;
}

// statusHeadline summarizes one current Sample for the top status card.
export function statusHeadline(sample, degraded) {
  if (!sample) return 'No probe has run yet.';
  if (degraded) return 'Degraded: sustained loss or latency over the last few probe cycles.';
  if (sample.reachable_targets === 0) return 'Total outage: no target answered the last probe.';
  return 'Healthy.';
}

// chartPath computes an SVG path's "d" attribute for a simple line chart
// over `points` (each {time, v}), scaled into a width x height viewBox with
// `pad` pixels of margin on every side. Pure math, no DOM: a single point
// draws a flat line across the middle; an empty list draws nothing. min/max
// can be forced (e.g. to 0 for a percentage chart); otherwise they are
// taken from the data, widened slightly so a perfectly flat line is not
// drawn right on the chart's edge.
export function chartPath(points, { width = 600, height = 120, pad = 6, min, max } = {}) {
  const vals = (points || []).map((p) => Number(p.v) || 0);
  if (!vals.length) return { d: '', min: 0, max: 0 };
  let lo = min != null ? min : Math.min(...vals);
  let hi = max != null ? max : Math.max(...vals);
  if (hi - lo < 1e-9) { hi += 1; if (min == null) lo = Math.max(0, lo - 1); }
  const xw = width - pad * 2;
  const yh = height - pad * 2;
  const n = vals.length;
  const d = vals.map((v, i) => {
    const x = pad + (n === 1 ? xw / 2 : (i / (n - 1)) * xw);
    const y = pad + yh - ((v - lo) / (hi - lo)) * yh;
    return (i === 0 ? 'M' : 'L') + x.toFixed(1) + ',' + y.toFixed(1);
  }).join(' ');
  return { d, min: lo, max: hi };
}

// areaPath is chartPath plus the closed "fill under the line" path an area
// chart needs: the same line, continued down to the bottom edge at both
// ends. Same inputs and the same min/max widening rules as chartPath, so
// the two always agree on scale; an empty series gives two empty paths.
export function areaPath(points, opts = {}) {
  const { d, min, max } = chartPath(points, opts);
  if (!d) return { line: '', area: '', min, max };
  const { width = 600, height = 120, pad = 6 } = opts;
  const xs = [...d.matchAll(/[ML]([0-9.]+),/g)].map((m) => m[1]);
  const bottom = (height - pad).toFixed(1);
  const area = d + ' L' + xs[xs.length - 1] + ',' + bottom + ' L' + xs[0] + ',' + bottom + ' Z';
  return { line: d, area, min, max };
}

// axisMax picks the top of a chart's scale for a metric that should be read
// against a floor rather than its own maximum: packet loss is the case —
// a 0–100% axis hides a 1% blip entirely, while a pure auto-scale makes a
// 0.1% blip look like an outage. The data's own max wins once it is above
// the floor (with a little headroom so the peak is not drawn on the edge).
export function axisMax(points, floor) {
  const hi = Math.max(0, ...(points || []).map((p) => Number(p.v) || 0));
  return hi > floor ? hi * 1.15 : floor;
}

// statusKind classifies the current sample for the header pill: 'none'
// (no probe yet), 'bad' (total outage), 'warn' (degraded), 'good'.
export function statusKind(sample, degraded) {
  if (!sample) return 'none';
  if (sample.reachable_targets === 0) return 'bad';
  if (degraded) return 'warn';
  return 'good';
}

export function statusPillLabel(kind) {
  return { none: 'No probe yet', bad: 'Outage', warn: 'Degraded', good: 'Healthy' }[kind] || 'Unknown';
}

// seriesSpan returns the first and last timestamps (ms) of a point series,
// or null when there are fewer than two points to span.
export function seriesSpan(points) {
  if (!points || points.length < 2) return null;
  const a = Date.parse(points[0].time), b = Date.parse(points[points.length - 1].time);
  return Number.isFinite(a) && Number.isFinite(b) ? { from: a, to: b } : null;
}

// seriesToPoints maps the server's /api/nethealth/series points (each with
// an ISO time string and the metric fields) into {time, v} pairs for
// chartPath, picking one metric by key ('avg_latency_ms', 'avg_jitter_ms',
// 'avg_loss_pct', or 'latency_ms'/'jitter_ms'/'loss_pct' for a raw bucket).
export function seriesToPoints(points, key) {
  return (points || []).map((p) => ({ time: p.time, v: Number(p[key]) || 0 }));
}

// RANGE_PRESETS are the quick-pick spans the Network screen offers; `hours`
// is how far back `from` goes. The server picks a sensible bucket
// resolution for each span on its own (docs/NETHEALTH.md's defaultBucket),
// so the client never needs to duplicate that threshold logic.
export const RANGE_PRESETS = [
  { id: '24h', label: '24h', hours: 24 },
  { id: '7d', label: '7d', hours: 24 * 7 },
  { id: '30d', label: '30d', hours: 24 * 30 },
  { id: '90d', label: '90d', hours: 24 * 90 },
];
