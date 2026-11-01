import test from 'node:test';
import assert from 'node:assert/strict';
import {
  gradeClass, gradeLabel, fmtMS, fmtMSValue, fmtLoss, reachabilityText, statusHeadline, chartPath, seriesToPoints, RANGE_PRESETS,
  areaPath, axisMax, statusKind, statusPillLabel, seriesSpan,
} from '../js/nethealth.js';

test('gradeClass/gradeLabel cover every grade plus the unknown/error cases', () => {
  assert.equal(gradeClass('A'), 'nh-grade nh-grade-a');
  assert.equal(gradeClass('F'), 'nh-grade nh-grade-f');
  assert.equal(gradeClass(''), 'nh-grade nh-grade-unknown');
  assert.equal(gradeClass('Z'), 'nh-grade nh-grade-unknown');

  assert.equal(gradeLabel('B'), 'Grade B');
  assert.equal(gradeLabel('', 'timed out'), 'Could not run');
  assert.equal(gradeLabel(''), 'No reading yet');
});

test('fmtMS and fmtLoss format sensibly, including the no-data case', () => {
  assert.equal(fmtMS(0), '—');
  assert.equal(fmtMS(12.6), '13 ms');
  assert.equal(fmtMS(123.4), '123 ms');
  assert.equal(fmtLoss(0), '0.0%');
  assert.equal(fmtLoss(5.26), '5.3%');
  assert.equal(fmtLoss(42.9), '43%');
});

test('fmtMSValue always shows a number, unlike fmtMS, for a legitimately-zero reading', () => {
  assert.equal(fmtMSValue(0), '0 ms');
  assert.equal(fmtMSValue(12.6), '13 ms');
  assert.equal(fmtMSValue(undefined), '0 ms');
});

test('reachabilityText covers no-targets, total-outage and partial/full reachability', () => {
  assert.equal(reachabilityText(0, 0), 'no targets yet');
  assert.equal(reachabilityText(0, 3), '0/3 — total outage');
  assert.equal(reachabilityText(2, 3), '2/3 reachable');
  assert.equal(reachabilityText(3, 3), '3/3 reachable');
});

test('statusHeadline reflects no-data, degraded, outage and healthy states', () => {
  assert.equal(statusHeadline(null, false), 'No probe has run yet.');
  assert.match(statusHeadline({ reachable_targets: 2, total_targets: 2 }, true), /Degraded/);
  assert.match(statusHeadline({ reachable_targets: 0, total_targets: 2 }, false), /Total outage/);
  assert.equal(statusHeadline({ reachable_targets: 2, total_targets: 2 }, false), 'Healthy.');
});

test('chartPath handles empty, single-point and multi-point series', () => {
  assert.deepEqual(chartPath([]), { d: '', min: 0, max: 0 });

  const one = chartPath([{ v: 10 }], { width: 100, height: 50, pad: 0 });
  assert.ok(one.d.startsWith('M50.0,25.0'));

  const many = chartPath([{ v: 0 }, { v: 10 }], { width: 100, height: 50, pad: 0 });
  assert.equal(many.d, 'M0.0,50.0 L100.0,0.0');
  assert.equal(many.min, 0);
  assert.equal(many.max, 10);
});

test('chartPath widens a perfectly flat series so the line is not drawn on the edge', () => {
  const flat = chartPath([{ v: 5 }, { v: 5 }, { v: 5 }], { width: 100, height: 50, pad: 0 });
  assert.ok(flat.max > flat.min);
  // every y coordinate should be identical for a flat series
  const ys = [...flat.d.matchAll(/,([0-9.]+)/g)].map((m) => m[1]);
  assert.equal(new Set(ys).size, 1);
});

test('chartPath respects a forced min/max (e.g. a 0-100 percentage axis)', () => {
  const p = chartPath([{ v: 50 }], { width: 100, height: 50, pad: 0, min: 0, max: 100 });
  assert.equal(p.min, 0);
  assert.equal(p.max, 100);
});

test('seriesToPoints extracts the named metric and tolerates missing values', () => {
  const pts = seriesToPoints([{ time: 't1', avg_latency_ms: 12 }, { time: 't2' }], 'avg_latency_ms');
  assert.deepEqual(pts, [{ time: 't1', v: 12 }, { time: 't2', v: 0 }]);
  assert.deepEqual(seriesToPoints(null, 'avg_latency_ms'), []);
});

test('RANGE_PRESETS are ordered shortest to longest and all distinct', () => {
  const hours = RANGE_PRESETS.map((p) => p.hours);
  assert.deepEqual(hours, [...hours].sort((a, b) => a - b));
  assert.equal(new Set(RANGE_PRESETS.map((p) => p.id)).size, RANGE_PRESETS.length);
});

test('areaPath closes the line down to the bottom edge and agrees with chartPath on scale', () => {
  assert.deepEqual(areaPath([]), { line: '', area: '', min: 0, max: 0 });
  const a = areaPath([{ v: 0 }, { v: 10 }], { width: 100, height: 50, pad: 0 });
  assert.equal(a.line, 'M0.0,50.0 L100.0,0.0');
  assert.equal(a.area, 'M0.0,50.0 L100.0,0.0 L100.0,50.0 L0.0,50.0 Z');
  assert.equal(a.min, 0);
  assert.equal(a.max, 10);
});

test('axisMax keeps a floor until the data rises above it', () => {
  assert.equal(axisMax([], 5), 5);
  assert.equal(axisMax([{ v: 0.4 }, { v: 1 }], 5), 5);
  assert.ok(Math.abs(axisMax([{ v: 40 }], 5) - 46) < 1e-9);
});

test('statusKind and its pill label cover none, outage, degraded and healthy', () => {
  assert.equal(statusKind(null, false), 'none');
  assert.equal(statusKind({ reachable_targets: 0, total_targets: 3 }, true), 'bad');
  assert.equal(statusKind({ reachable_targets: 3, total_targets: 3 }, true), 'warn');
  assert.equal(statusKind({ reachable_targets: 3, total_targets: 3 }, false), 'good');
  assert.equal(statusPillLabel('good'), 'Healthy');
  assert.equal(statusPillLabel('bad'), 'Outage');
  assert.equal(statusPillLabel('none'), 'No probe yet');
});

test('seriesSpan needs two parseable timestamps', () => {
  assert.equal(seriesSpan([]), null);
  assert.equal(seriesSpan([{ time: '2026-01-01T00:00:00Z' }]), null);
  assert.deepEqual(seriesSpan([{ time: '2026-01-01T00:00:00Z' }, { time: '2026-01-01T01:00:00Z' }]), { from: Date.parse('2026-01-01T00:00:00Z'), to: Date.parse('2026-01-01T01:00:00Z') });
});
