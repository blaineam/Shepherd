import test from 'node:test';
import assert from 'node:assert/strict';
import { Model } from '../js/model.js';
import { normalizeEntry } from '../js/entry.js';

let n = 0;
const E = (o = {}) => normalizeEntry({
  id: ++n, time: '2026-01-01T00:00:00Z', client: '192.0.2.10', name: 'a.example.com', action: 'allowed',
  dests: [{ lat: 10, lon: 20, city: 'X', country: 'US' }], ...o,
});

test('counters and lane routing', () => {
  const m = new Model();
  assert.equal(m.ingest(E()), 'lane');
  assert.equal(m.ingest(E({ action: 'cached' })), 'lane');
  assert.equal(m.ingest(E({ action: 'blocked', dests: undefined })), 'blocked');
  assert.equal(m.ingest(E({ action: 'error', dests: undefined })), 'nodest');
  assert.deepEqual(m.counters, { total: 4, blocked: 1, cached: 1, errors: 1, allowed: 2 });
  assert.ok(Math.abs(m.blockedPct - 25) < 1e-9);
  assert.equal(m.clients.get('192.0.2.10'), 4);
  assert.equal(m.touched.length, 0);
});

test('mapUnavailable only after several entries with no dests', () => {
  const m = new Model();
  for (let i = 0; i < 4; i++) m.ingest(E({ dests: undefined }));
  assert.equal(m.mapUnavailable, false);
  m.ingest(E({ dests: undefined }));
  assert.equal(m.mapUnavailable, true);
  m.ingest(E());
  assert.equal(m.mapUnavailable, false);
});

test('filters by device, action and domain search', () => {
  const m = new Model();
  m.setFilters({ device: '192.0.2.99' });
  assert.equal(m.ingest(E()), 'filtered');
  m.setFilters({ device: '', q: 'GAME' });
  assert.equal(m.ingest(E({ name: 'x.example.com' })), 'filtered');
  assert.equal(m.ingest(E({ name: 'game.example.net' })), 'lane');
  m.setFilters({ q: '' });
  m.filters.actions.delete('cached');
  assert.equal(m.ingest(E({ action: 'cached' })), 'filtered');
  // filtered events still count toward totals
  assert.equal(m.counters.total, 4);
});

test('laneVisible follows the same filters', () => {
  const m = new Model();
  m.ingest(E({ name: 'video.example.com' }));
  const lane = [...m.lanes.byKey.values()][0];
  assert.ok(m.laneVisible(lane));
  m.setFilters({ device: '192.0.2.77' });
  assert.ok(!m.laneVisible(lane));
  m.setFilters({ device: '', q: 'video' });
  assert.ok(m.laneVisible(lane));
  m.setFilters({ q: 'nomatch' });
  assert.ok(!m.laneVisible(lane));
  m.setFilters({ q: '' });
  m.filters.actions.delete('allowed');
  assert.ok(!m.laneVisible(lane));
});

test('bytes entries switch the lanes to bytes mode', () => {
  const m = new Model();
  m.ingest(E());
  assert.equal(m.mode, 'lookups');
  m.ingest(E({ bytes_down: 5000 }));
  assert.equal(m.mode, 'bytes');
  const lane = [...m.lanes.byKey.values()][0];
  assert.equal(lane.w, 5000);
});

test('recent ring keeps the newest entries first and stays bounded', () => {
  const m = new Model({ recentCap: 5 });
  for (let i = 0; i < 40; i++) m.ingest(E({ name: `n${i}.example.com` }));
  assert.ok(m.recent.length <= 10);
  const r = m.recentNewestFirst(3);
  assert.deepEqual(r.map((e) => e.name), ['n39.example.com', 'n38.example.com', 'n37.example.com']);
});

test('reset clears state', () => {
  const m = new Model();
  m.ingest(E());
  m.reset();
  assert.equal(m.counters.total, 0);
  assert.equal(m.lanes.size, 0);
  assert.equal(m.clients.size, 0);
  assert.equal(m.blockedPct, 0);
});

test('a blocked connection that has a place is drawn there; a blocked lookup pulses at home', () => {
  const m = new Model();
  // A lookup the filter refused: nowhere to draw to.
  assert.equal(m.ingest(E({ action: 'blocked', dests: undefined })), 'blocked');
  // A connection the firewall turned away, with the far end known.
  const dest = [{ lat: 52, lon: 5, city: 'Amsterdam', country: 'NL' }];
  assert.equal(m.ingest(E({ action: 'blocked', type: 'FLOW', inbound: true, dests: dest })), 'lane');
  assert.equal(m.touched.length, 1);
  assert.equal(m.touched[0].action, 'blocked');
  assert.equal(m.counters.blocked, 2);

  // Allowed traffic to the same place keeps its own lane, so the two
  // colours do not fight over one arc.
  assert.equal(m.ingest(E({ type: 'FLOW', bytes_down: 50000, dests: dest })), 'lane');
  const allowed = m.touched[0];
  assert.equal(allowed.action, 'allowed');
  assert.equal(m.lanes.byKey.size, 2);
  m.ingest(E({ action: 'blocked', type: 'FLOW', dests: dest }));
  assert.equal(m.touched[0].action, 'blocked');
  assert.equal(allowed.action, 'allowed');
  assert.equal(m.lanes.byKey.size, 2);
  assert.equal(m.lanes.mode, 'bytes');
});
