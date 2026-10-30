import test from 'node:test';
import assert from 'node:assert/strict';
import { RANGES, rangeFor, buildQuery, normalizeResponse, mergeOlder, nextCursor, sane, retainedSpan, fmtSpan, placeOf, toLocalInput } from '../js/history.js';

const NOW = Date.parse('2026-03-02T12:00:00Z');
const E = (id, t, extra = {}) => ({ id, time: new Date(t).toISOString(), client: '192.0.2.1', name: 'a.example.com', type: 'A', action: 'allowed', ...extra });

test('rangeFor presets and custom', () => {
  assert.deepEqual(rangeFor('1h', NOW), { from: NOW - 3600000, to: NOW });
  assert.deepEqual(rangeFor('24h', NOW), { from: NOW - 86400000, to: NOW });
  assert.deepEqual(rangeFor('7d', NOW), { from: NOW - 7 * 86400000, to: NOW });
  assert.deepEqual(rangeFor('bogus', NOW), { from: NOW - 86400000, to: NOW });
  const c = rangeFor('custom', NOW, { from: '2026-03-01T00:00', to: '2026-03-01T06:00' });
  assert.equal(c.to - c.from, 6 * 3600000);
  assert.deepEqual(rangeFor('custom', NOW, { from: '', to: 'x' }), { from: NOW - 86400000, to: NOW });
  assert.deepEqual(rangeFor('custom', NOW), { from: NOW - 86400000, to: NOW });
  assert.equal(RANGES.length, 4);
});

test('buildQuery includes only the filters that are set', () => {
  const q = buildQuery({ from: NOW - 1000, to: NOW, limit: 50 });
  assert.deepEqual(Object.keys(q).sort(), ['from', 'limit', 'to']);
  assert.equal(q.to, '2026-03-02T12:00:00.000Z');
  const f = buildQuery({ from: 0, to: NOW, client: '192.0.2.1', q: 'x', action: 'blocked' });
  assert.deepEqual([f.client, f.q, f.action, f.limit], ['192.0.2.1', 'x', 'blocked', 100]);
  assert.equal(buildQuery({ from: 0, to: NOW, action: 'all' }).action, undefined);
});

test('normalizeResponse sorts newest first and normalises untrusted fields', () => {
  const r = normalizeResponse({ entries: [E(1, NOW - 3000), E(2, NOW - 1000), E(3, NOW - 2000, { action: '<b>' }), null], source: 'encrypted', oldest: '2026-03-01T00:00:00Z', newest: '2026-03-02T12:00:00Z', skipped: 2 });
  assert.deepEqual(r.entries.map((e) => e.id), [2, 3, 1]);
  assert.equal(r.entries[1].action, 'error');
  assert.equal(r.source, 'encrypted'); assert.equal(r.skipped, 2); assert.equal(r.locked, false);
  const m = normalizeResponse({ entries: 'nope', source: 'weird' });
  assert.deepEqual([m.entries.length, m.source, m.skipped], [0, 'memory', 0]);
  assert.equal(normalizeResponse(null).entries.length, 0);
  assert.equal(normalizeResponse({ locked: true }).locked, true);
});

test('mergeOlder drops the repeated seam and nextCursor uses the oldest time', () => {
  const page1 = normalizeResponse({ entries: [E(5, NOW), E(4, NOW - 1000)] }).entries;
  const page2 = normalizeResponse({ entries: [E(4, NOW - 1000), E(3, NOW - 2000), E(2, NOW - 3000)] }).entries;
  const m = mergeOlder(page1, page2);
  assert.deepEqual(m.entries.map((e) => e.id), [5, 4, 3, 2]);
  assert.equal(m.added, 2);
  assert.equal(nextCursor(m.entries, 4, 4), NOW - 3000);
  assert.equal(nextCursor(m.entries, 100, 3), null);
  assert.equal(nextCursor([], 10, 10), null);
  const noId = normalizeResponse({ entries: [{ time: '2026-03-02T10:00:00Z', client: 'c', name: 'n', type: 'A', action: 'allowed' }] }).entries;
  assert.equal(mergeOlder(noId, noId).added, 0);
});

test('sane and retainedSpan guard against the zero time', () => {
  assert.ok(sane(NOW) && !sane(NaN) && !sane(Date.parse('0001-01-01T00:00:00Z')));
  assert.equal(retainedSpan({ oldest: Date.parse('0001-01-01T00:00:00Z'), newest: NOW }), null);
  assert.equal(retainedSpan({ oldest: NOW, newest: NOW - 1 }), null);
  assert.equal(retainedSpan(null), null);
  assert.deepEqual(retainedSpan({ oldest: NOW - 5000, newest: NOW }), { oldest: NOW - 5000, newest: NOW, ms: 5000 });
});

test('fmtSpan', () => {
  assert.equal(fmtSpan(30 * 60000), '30 min');
  assert.equal(fmtSpan(5 * 3600000), '5 hours');
  assert.equal(fmtSpan(7 * 86400000), '7 days');
});

test('placeOf and toLocalInput', () => {
  assert.equal(placeOf({ dests: [{ city: 'Port Almer', country: 'US' }] }), 'Port Almer, US');
  assert.equal(placeOf({ dests: [{ country: 'US' }] }), 'US');
  assert.equal(placeOf({ dests: [{}] }), '');
  assert.equal(placeOf({ action: 'blocked' }), 'Blocked at home');
  assert.equal(placeOf({ action: 'allowed' }), '');
  assert.match(toLocalInput(NOW), /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/);
});
