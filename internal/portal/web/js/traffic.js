// The Bandwidth screen's pure logic: ranges, scopes, turning the server's
// per-bucket byte counts into chart paths and readable numbers. The server
// (internal/traffic, internal/portal/api_traffic.go) owns the numbers;
// nothing here estimates anything. Kept apart from trafficview.js so all
// of it is unit-tested (test/traffic.test.js) with no DOM.
import { fmtBytes } from './weight.js';
import { fmtBitsPerSecond } from './watch.js';

export { fmtBytes, fmtBitsPerSecond };

// Quick-pick spans. The server picks the bucket from the span (minutes up
// to a day, hours to two months, days beyond), matching its retention.
export const RANGE_PRESETS = [
  { id: '1h', label: '1h', hours: 1 },
  { id: '24h', label: '24h', hours: 24 },
  { id: '7d', label: '7d', hours: 24 * 7 },
  { id: '30d', label: '30d', hours: 24 * 30 },
  { id: '90d', label: '90d', hours: 24 * 90 },
];

export function rangeWindow(preset, now = Date.now()) {
  const p = RANGE_PRESETS.find((r) => r.id === (preset && preset.id ? preset.id : preset)) || RANGE_PRESETS[1];
  return { from: new Date(now - p.hours * 3600000).toISOString(), to: new Date(now).toISOString() };
}

export const BUCKET_SECONDS = { second: 1, minute: 60, hour: 3600, day: 86400 };

// The scope picker's options: the whole network, then every group, then
// every device, each as the server's scope string.
export function scopeOptions(groups, devices) {
  const out = [{ id: 'network', label: 'Whole network' }];
  for (const g of groups || []) out.push({ id: 'group:' + g.id, label: g.name || g.id, kind: 'group' });
  const devs = [...(devices || [])].sort((a, b) => String(a.name || '').localeCompare(String(b.name || '')));
  for (const d of devs) out.push({ id: 'device:' + d.id, label: d.name || d.id, kind: 'device' });
  return out;
}

export function scopeLabel(scope, groups, devices) {
  return (scopeOptions(groups, devices).find((o) => o.id === scope) || {}).label || 'Whole network';
}

// fillSeries lays the server's sparse points (one per bucket that had any
// traffic) onto every bucket in [from, to], so a quiet hour draws as a
// quiet hour rather than being skipped. Returns {time, up, down} per
// bucket, oldest first. Bucket boundaries are UTC, as the server's are.
export function fillSeries(points, from, to, bucket) {
  const step = (BUCKET_SECONDS[bucket] || 60) * 1000;
  const start = Math.floor(Date.parse(from) / step) * step;
  const end = Date.parse(to);
  if (!Number.isFinite(start) || !Number.isFinite(end) || end < start) return [];
  const byTime = new Map();
  for (const p of points || []) {
    const t = Date.parse(p.time);
    if (Number.isFinite(t)) byTime.set(Math.floor(t / step) * step, { up: Number(p.up) || 0, down: Number(p.down) || 0 });
  }
  const out = [];
  for (let t = start; t <= end; t += step) {
    const v = byTime.get(t) || { up: 0, down: 0 };
    out.push({ time: t, up: v.up, down: v.down });
  }
  return out;
}

// sumPoints totals a series.
export function sumPoints(points) {
  let up = 0;
  let down = 0;
  for (const p of points || []) { up += Number(p.up) || 0; down += Number(p.down) || 0; }
  return { up, down };
}

// A bucket's bytes as an average rate over the bucket, in bits per second,
// which is the unit people read bandwidth in.
export const bucketRate = (bytes, bucket) => (Number(bytes) || 0) * 8 / (BUCKET_SECONDS[bucket] || 60);

// areaPaths draws the filled series: two areas from the baseline, download
// and upload, over a width x height viewBox. Both share one scale so the
// eye compares them honestly; max is that scale's top in bits per second.
export function areaPaths(series, bucket, { width = 600, height = 140, pad = 6 } = {}) {
  const n = (series || []).length;
  if (!n) return { down: '', up: '', max: 0 };
  let max = 0;
  for (const p of series) max = Math.max(max, bucketRate(p.down, bucket), bucketRate(p.up, bucket));
  if (max <= 0) max = 1;
  const xw = width - pad * 2;
  const yh = height - pad * 2;
  const x = (i) => pad + (n === 1 ? xw / 2 : (i / (n - 1)) * xw);
  const y = (v) => pad + yh - (v / max) * yh;
  const base = (pad + yh).toFixed(1);
  const path = (key) => {
    let d = 'M' + x(0).toFixed(1) + ',' + base;
    for (let i = 0; i < n; i++) d += ' L' + x(i).toFixed(1) + ',' + y(bucketRate(series[i][key], bucket)).toFixed(1);
    return d + ' L' + x(n - 1).toFixed(1) + ',' + base + ' Z';
  };
  return { down: path('down'), up: path('up'), max };
}

// Three labels for the chart's left edge: top, middle, zero.
export function axisLabels(max) {
  return [fmtBitsPerSecond(max / 8), fmtBitsPerSecond(max / 16), '0'];
}

// Time labels along the bottom: first, middle, last, worded for the span.
export function timeLabels(series, bucket) {
  const n = (series || []).length;
  if (!n) return [];
  const pick = n === 1 ? [series[0]] : n === 2 ? [series[0], series[1]] : [series[0], series[Math.floor(n / 2)], series[n - 1]];
  const fmt = (t) => {
    const d = new Date(t);
    if (bucket === 'day') return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
    if (bucket === 'hour') return d.toLocaleDateString(undefined, { weekday: 'short' }) + ' ' + d.toLocaleTimeString(undefined, { hour: 'numeric' });
    return d.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });
  };
  return pick.map((p) => fmt(p.time));
}

// The share of one total in another, as a percentage string.
export function shareOf(part, total) {
  const p = Number(part) || 0;
  const t = Number(total) || 0;
  if (t <= 0 || p <= 0) return '0%';
  const pct = (p / t) * 100;
  return (pct < 1 ? '<1' : pct < 10 ? pct.toFixed(1) : Math.round(pct)) + '%';
}

// One line about what is being measured, with a tone for its colour.
export function statusHeadline(status) {
  const s = status || {};
  // The router reader, when it is working, is what the screen is showing,
  // whatever Watch mode is doing.
  if (!s.measuring && readingNow(s.router)) {
    const st = s.router.status || {};
    const live = s.live || {};
    return {
      tone: 'good',
      text: 'Reading ' + (st.matched || 0) + ' devices from your ' + (s.router.source || 'router') + ': '
        + fmtBitsPerSecond(live.down_bytes_per_second) + ' down, ' + fmtBitsPerSecond(live.up_bytes_per_second) + ' up at the last reading.',
    };
  }
  if (!s.enabled) return { tone: 'muted', text: 'Watch mode is off, so nothing is being measured. Connect your router below, or turn Watch mode on.' };
  if (!s.measuring) return { tone: 'warn', text: 'Watch mode is stopped, so nothing new is being measured. History up to now is still here.' };
  const live = s.live || {};
  const n = (s.devices || []).length;
  return { tone: 'good', text: 'Measuring ' + (n === 1 ? '1 device' : n + ' devices') + ': ' + fmtBitsPerSecond(live.down_bytes_per_second) + ' down, ' + fmtBitsPerSecond(live.up_bytes_per_second) + ' up right now.' };
}

// What the download number is and is not, in one sentence, used wherever
// it is shown so the caveat travels with the figure.
export const DOWNLOAD_CAVEAT = 'Download is an estimate read from each device’s own TCP acknowledgements: it never over-counts, but it cannot see QUIC, other UDP traffic or VPN tunnels, so video and some apps show lower than they really are. Upload is measured exactly.';

// Rows for the live table, busiest first (the server already sorts; this
// only guards against an unsorted fake).
export function liveRows(status) {
  return [...((status && status.devices) || [])].sort((a, b) => ((Number(b.down_bytes_per_second) || 0) + (Number(b.up_bytes_per_second) || 0)) - ((Number(a.down_bytes_per_second) || 0) + (Number(a.up_bytes_per_second) || 0)));
}

// ---------------------------------------------------------------- charts
// A "nice" ceiling for an axis: 1, 2, 2.5, 5 or 10 times a power of ten, so
// gridlines land on round numbers instead of the data's own maximum.
export function niceCeil(v) {
  const x = Number(v) || 0;
  if (x <= 0) return 1;
  const p = Math.pow(10, Math.floor(Math.log10(x)));
  for (const m of [1, 2, 2.5, 5, 10]) if (x <= m * p) return m * p;
  return 10 * p;
}

// Evenly spaced gridline values from zero to a nice ceiling, in bits/s.
export function yTicks(max, n = 4) {
  const top = niceCeil(max);
  return Array.from({ length: n + 1 }, (_, i) => (top * i) / n);
}

// A stroke-and-fill path pair for one series scaled to a shared ceiling.
// values are rates; the area closes along the baseline.
export function lineArea(values, top, { width = 600, height = 140, pad = 6 } = {}) {
  const n = (values || []).length;
  if (!n) return { line: '', area: '' };
  const t = top > 0 ? top : 1;
  const xw = width - pad * 2;
  const yh = height - pad * 2;
  const x = (i) => pad + (n === 1 ? xw / 2 : (i / (n - 1)) * xw);
  const y = (v) => pad + yh - Math.min(1, Math.max(0, v / t)) * yh;
  const pts = values.map((v, i) => x(i).toFixed(1) + ',' + y(Number(v) || 0).toFixed(1));
  const base = (pad + yh).toFixed(1);
  return {
    line: 'M' + pts.join(' L'),
    area: 'M' + x(0).toFixed(1) + ',' + base + ' L' + pts.join(' L') + ' L' + x(n - 1).toFixed(1) + ',' + base + ' Z',
  };
}

// The index of the sample nearest a pointer fraction (0..1) across a series.
export function nearestIndex(fraction, n) {
  if (n <= 1) return 0;
  return Math.min(n - 1, Math.max(0, Math.round(fraction * (n - 1))));
}

// A rolling window of live samples: append, keep the newest `max`.
export function pushSample(buf, sample, max = 90) {
  const out = [...(buf || []), sample];
  return out.length > max ? out.slice(out.length - max) : out;
}

// Donut slices from {value} items: the biggest `keep` stay, the rest fold
// into one "Other". Returns [{item, value, fraction}] summing to 1.
export function shareSlices(items, keep = 5) {
  const rows = [...(items || [])].map((it) => ({ item: it, value: Number(it.value) || 0 })).filter((r) => r.value > 0).sort((a, b) => b.value - a.value);
  const total = rows.reduce((s, r) => s + r.value, 0);
  if (!total) return [];
  let shown = rows.slice(0, keep);
  const rest = rows.slice(keep);
  if (rest.length) shown = [...shown, { item: { name: 'Other', other: true }, value: rest.reduce((s, r) => s + r.value, 0) }];
  return shown.map((r) => ({ item: r.item, value: r.value, fraction: r.value / total }));
}

// The SVG path of one donut ring segment between two fractions of a turn.
export function arcPath(cx, cy, rOuter, rInner, from, to) {
  const full = to - from >= 0.9999;
  const end = full ? from + 0.9999 : to;
  const a0 = from * Math.PI * 2 - Math.PI / 2;
  const a1 = end * Math.PI * 2 - Math.PI / 2;
  const p = (r, a) => (cx + r * Math.cos(a)).toFixed(2) + ',' + (cy + r * Math.sin(a)).toFixed(2);
  const large = end - from > 0.5 ? 1 : 0;
  return 'M' + p(rOuter, a0) + ' A' + rOuter + ',' + rOuter + ' 0 ' + large + ' 1 ' + p(rOuter, a1)
    + ' L' + p(rInner, a1) + ' A' + rInner + ',' + rInner + ' 0 ' + large + ' 0 ' + p(rInner, a0) + ' Z';
}

// Peak and average of a rate series, for the chart's caption.
export function rateStats(values) {
  const v = (values || []).map((x) => Number(x) || 0);
  if (!v.length) return { peak: 0, avg: 0 };
  return { peak: Math.max(...v), avg: v.reduce((s, x) => s + x, 0) / v.length };
}

// ------------------------------------------------- where the numbers come from
// Bandwidth can be measured two ways. Watch mode relays each device's
// traffic and counts the bytes, which is exact but needs a network that
// tolerates steering. Reading the owner's own router touches nothing, but
// a router that reports only its instantaneous rate (eero) gives figures
// that are integrated between polls, and must never be shown as measured.

// routerConnection describes the router side of GET /api/traffic in one
// line, with a tone, for the Bandwidth screen's source section.
export function routerConnection(router) {
  const r = router || {};
  if (!r.available) return { tone: 'muted', text: 'This build cannot read bandwidth from a router.' };
  if (!r.connected) return { tone: 'muted', text: 'No router is connected. Shepherd can read per-device bandwidth from your router without touching your traffic.' };
  const st = r.status || {};
  if (!r.enabled) return { tone: 'muted', text: 'Connected to ' + (r.source || 'your router') + ', but switched off.' };
  if (st.needs_sign_in) return { tone: 'bad', text: 'Your ' + (r.source || 'router') + ' sign-in has expired. Sign in again to carry on reading bandwidth.' };
  if (st.last_error) return { tone: 'warn', text: 'Could not read ' + (r.source || 'the router') + ': ' + st.last_error };
  if (!st.last_poll) return { tone: 'muted', text: 'Connected to ' + (r.source || 'your router') + '. Waiting for the first reading.' };
  return {
    tone: 'good',
    text: 'Reading ' + (st.matched || 0) + ' of ' + (st.devices_seen || 0) + ' devices from your ' + (r.source || 'router')
      + ' every ' + (st.interval_seconds || 0) + 's.',
  };
}

// readingNow reports whether the router reader is the thing currently
// producing numbers, which is true only when it is on and last succeeded.
export function readingNow(router) {
  const r = router || {};
  const st = r.status || {};
  return !!(r.available && r.connected && r.enabled && st.last_poll && !st.last_error);
}

// measurementNote is the one sentence under the live tiles saying how the
// figures were arrived at, so an estimate is never mistaken for a count.
export function measurementNote(status) {
  const s = status || {};
  if (s.measuring) return DOWNLOAD_CAVEAT;
  if (!readingNow(s.router)) return '';
  const est = (s.router.status || {}).estimated;
  const src = s.router.source || 'your router';
  return est
    ? 'These figures are read from ' + src + ', which reports only the rate at each moment. Shepherd samples that and fills in the time between, so they show which devices are busy rather than how much they moved: anything shorter than the gap between readings is largely missed, and a few hundred megabytes downloaded in under a minute can be counted as a fraction of that. Treat the totals as a floor, not a measurement.'
    : 'These figures are byte counts read from ' + src + '.';
}

// liveChartCaption says what the rolling chart is actually showing. The
// screen polls every pollMs, but when the numbers come from a router that
// is read every 30 seconds the line is a staircase, and saying "every two
// seconds" would overstate it.
export function liveChartCaption(status, samples, pollMs) {
  const mins = Math.max(0.1, Math.round((samples * pollMs) / 6000) / 10);
  const span = 'The last ' + mins + ' minutes';
  if (!readingNow((status || {}).router)) return span + ', one sample every ' + Math.round(pollMs / 1000) + ' seconds.';
  const every = ((status.router.status || {}).interval_seconds) || 0;
  return span + '. Your ' + (status.router.source || 'router') + ' is read every ' + every
    + ' seconds, so the line steps rather than curves.';
}
