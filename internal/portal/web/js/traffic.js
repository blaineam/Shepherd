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

export const BUCKET_SECONDS = { minute: 60, hour: 3600, day: 86400 };

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
  if (!s.enabled) return { tone: 'muted', text: 'Watch mode is off, so nothing is being measured. Turn it on to see bandwidth.' };
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
