import test from 'node:test';
import assert from 'node:assert/strict';
import {
  RANGE_PRESETS, rangeWindow, scopeOptions, scopeLabel, fillSeries, sumPoints, bucketRate, areaPaths, axisLabels,
  timeLabels, shareOf, statusHeadline, liveRows, DOWNLOAD_CAVEAT, fmtBytes, fmtBitsPerSecond,
} from '../js/traffic.js';

const T0 = Date.parse('2026-11-01T12:00:00Z');

test('range presets produce a window ending now, defaulting to 24h', () => {
  assert.equal(RANGE_PRESETS.length, 5);
  const w = rangeWindow('7d', T0);
  assert.equal(w.to, '2026-11-01T12:00:00.000Z');
  assert.equal(w.from, '2026-10-25T12:00:00.000Z');
  assert.equal(rangeWindow(RANGE_PRESETS[0], T0).from, '2026-11-01T11:00:00.000Z');
  assert.equal(rangeWindow('nope', T0).from, '2026-10-31T12:00:00.000Z');
});

test('scope options list the network, then groups, then devices by name', () => {
  const opts = scopeOptions([{ id: 'g1', name: 'Kids' }, { id: 'g2' }], [{ id: 'd2', name: 'TV' }, { id: 'd1', name: 'Phone' }, { id: 'd3' }]);
  assert.deepEqual(opts.map((o) => o.id), ['network', 'group:g1', 'group:g2', 'device:d3', 'device:d1', 'device:d2']);
  assert.equal(opts[2].label, 'g2');
  assert.equal(opts[3].label, 'd3');
  assert.equal(scopeLabel('device:d2', [], [{ id: 'd2', name: 'TV' }]), 'TV');
  assert.equal(scopeLabel('group:zzz', [], []), 'Whole network');
  assert.equal(scopeOptions(null, null).length, 1);
});

test('fillSeries lays sparse points onto every bucket and keeps zeros', () => {
  const pts = [{ time: '2026-11-01T12:02:00Z', up: 5, down: 50 }, { time: '2026-11-01T12:00:00Z', up: 1, down: 10 }];
  const s = fillSeries(pts, '2026-11-01T12:00:00Z', '2026-11-01T12:04:00Z', 'minute');
  assert.equal(s.length, 5);
  assert.deepEqual(s.map((p) => p.down), [10, 0, 50, 0, 0]);
  assert.equal(s[0].time, T0);
  // Hourly, with a point not on a boundary still landing in its bucket.
  const h = fillSeries([{ time: '2026-11-01T12:30:00Z', up: 1, down: 2 }], '2026-11-01T12:00:00Z', '2026-11-01T14:00:00Z', 'hour');
  assert.deepEqual(h.map((p) => p.down), [2, 0, 0]);
  assert.deepEqual(fillSeries([], 'bad', 'worse', 'day'), []);
  assert.deepEqual(fillSeries([], '2026-11-02T00:00:00Z', '2026-11-01T00:00:00Z', 'day'), []);
  assert.equal(fillSeries([{ time: 'nope', up: 1 }], '2026-11-01T12:00:00Z', '2026-11-01T12:00:00Z', 'weird').length, 1);
});

test('sums, rates and shares', () => {
  assert.deepEqual(sumPoints([{ up: 1, down: 2 }, { up: 3, down: 'x' }]), { up: 4, down: 2 });
  assert.deepEqual(sumPoints(null), { up: 0, down: 0 });
  assert.equal(bucketRate(600, 'minute'), 80);
  assert.equal(bucketRate(3600, 'hour'), 8);
  assert.equal(bucketRate(60, undefined), 8);
  assert.equal(shareOf(50, 200), '25%');
  assert.equal(shareOf(1, 200), '<1%');
  assert.equal(shareOf(5, 200), '2.5%');
  assert.equal(shareOf(0, 200), '0%');
  assert.equal(shareOf(5, 0), '0%');
});

test('areaPaths draws two closed areas on one shared scale', () => {
  const series = [{ time: T0, up: 60, down: 600 }, { time: T0 + 60000, up: 0, down: 0 }, { time: T0 + 120000, up: 120, down: 300 }];
  const p = areaPaths(series, 'minute', { width: 100, height: 50, pad: 0 });
  assert.equal(p.max, 80); // 600 bytes/min = 80 bit/s is the top
  assert.match(p.down, /^M0\.0,50\.0 L0\.0,0\.0 L50\.0,50\.0 L100\.0,25\.0 L100\.0,50\.0 Z$/);
  assert.match(p.up, /^M0\.0,50\.0 L0\.0,45\.0 L50\.0,50\.0 L100\.0,40\.0 L100\.0,50\.0 Z$/);
  assert.deepEqual(areaPaths([], 'minute'), { down: '', up: '', max: 0 });
  const flat = areaPaths([{ time: T0, up: 0, down: 0 }], 'hour', { width: 100, height: 50, pad: 0 });
  assert.equal(flat.max, 1);
  assert.match(flat.down, /^M50\.0,50\.0 L50\.0,50\.0 L50\.0,50\.0 Z$/);
});

test('axis and time labels', () => {
  assert.deepEqual(axisLabels(8000), ['8.00 kbit/s', '4.00 kbit/s', '0']);
  assert.deepEqual(timeLabels([], 'minute'), []);
  const one = timeLabels([{ time: T0 }], 'day');
  assert.equal(one.length, 1);
  const three = timeLabels([{ time: T0 }, { time: T0 + 3600000 }, { time: T0 + 7200000 }, { time: T0 + 10800000 }], 'hour');
  assert.equal(three.length, 3);
  assert.equal(timeLabels([{ time: T0 }, { time: T0 + 60000 }], 'minute').length, 2);
});

test('statusHeadline covers off, stopped and measuring', () => {
  assert.equal(statusHeadline(null).tone, 'muted');
  assert.equal(statusHeadline({ enabled: true, measuring: false }).tone, 'warn');
  const on = statusHeadline({ enabled: true, measuring: true, live: { down_bytes_per_second: 125000, up_bytes_per_second: 1250 }, devices: [{}] });
  assert.equal(on.tone, 'good');
  assert.match(on.text, /1 device: 1\.00 Mbit\/s down, 10\.0 kbit\/s up/);
  assert.match(statusHeadline({ enabled: true, measuring: true, devices: [{}, {}] }).text, /2 devices/);
});

test('liveRows sorts busiest first and the caveat names the blind spots', () => {
  const rows = liveRows({ devices: [{ name: 'a', down_bytes_per_second: 1 }, { name: 'b', down_bytes_per_second: 5, up_bytes_per_second: 5 }, { name: 'c' }] });
  assert.deepEqual(rows.map((r) => r.name), ['b', 'a', 'c']);
  assert.deepEqual(liveRows(null), []);
  assert.match(DOWNLOAD_CAVEAT, /QUIC/);
  assert.equal(fmtBytes(2048), '2.0 KB');
  assert.equal(fmtBitsPerSecond(125), '1.00 kbit/s');
});
