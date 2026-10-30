import test from 'node:test';
import assert from 'node:assert/strict';
import { LaneTable } from '../js/lanes.js';
import { normalizeEntry } from '../js/entry.js';
import { weightScale } from '../js/weight.js';

const T0 = Date.parse('2026-01-01T00:00:00Z');
let n = 0;
function entry(over = {}) {
  return normalizeEntry({
    id: ++n, time: new Date(T0 + (over.dt || 0)).toISOString(), client: '192.0.2.10', name: 'a.example.com', action: 'allowed',
    dests: [{ lat: 35.68, lon: 139.69, city: 'Kuro Bay', country: 'JP', ip: '203.0.113.5' }], ...over,
  });
}
const home = { lat: 39.1, lon: -94.6 };

test('repeated events for one device and place merge into one lane', () => {
  const t = new LaneTable();
  t.setHome(home);
  for (let i = 0; i < 5; i++) t.add(entry({ dt: i * 100 }));
  assert.equal(t.size, 1);
  const lane = [...t.byKey.values()][0];
  assert.equal(lane.count, 5);
  assert.ok(lane.w > 4.5 && lane.w <= 5);
  assert.ok(lane.angle > 0 && lane.lift > 0);
  assert.equal(lane.from.length, 3);
});

test('different devices or places get different lanes', () => {
  const t = new LaneTable();
  t.add(entry());
  t.add(entry({ client: '192.0.2.11' }));
  t.add(entry({ dests: [{ lat: 51.5, lon: -0.1, city: 'Westerhall', country: 'GB' }] }));
  assert.equal(t.size, 3);
});

test('places within the same 0.1 degree cell merge, others do not', () => {
  const t = new LaneTable();
  t.add(entry({ dests: [{ lat: 35.681, lon: 139.691 }] }));
  t.add(entry({ dests: [{ lat: 35.684, lon: 139.694 }] }));
  assert.equal(t.size, 1);
  t.add(entry({ dests: [{ lat: 35.9, lon: 139.7 }] }));
  assert.equal(t.size, 2);
});

test('weight decays with the configured half life', () => {
  const t = new LaneTable({ halfLifeMs: 10000 });
  t.add(entry({ dt: 0 }));
  const lane = [...t.byKey.values()][0];
  assert.equal(t.valueAt(lane, T0), 1);
  assert.ok(Math.abs(t.valueAt(lane, T0 + 10000) - 0.5) < 1e-9);
  assert.ok(Math.abs(t.valueAt(lane, T0 + 20000) - 0.25) < 1e-9);
  assert.equal(t.valueAt(lane, T0 - 5000), 1); // never grows into the past
});

test('heavy flows end up thicker than one-off lookups', () => {
  const t = new LaneTable();
  t.add(entry({ client: '192.0.2.50' }));
  for (let i = 0; i < 80; i++) t.add(entry({ client: '192.0.2.51', dt: i * 50 }));
  const light = t.byKey.get([...t.byKey.keys()].find((k) => k.startsWith('192.0.2.50')));
  const heavy = t.byKey.get([...t.byKey.keys()].find((k) => k.startsWith('192.0.2.51')));
  const now = T0 + 4000;
  assert.ok(weightScale(t.valueAt(heavy, now)) > weightScale(t.valueAt(light, now)) + 0.3);
});

test('decay is applied before new weight accumulates', () => {
  const t = new LaneTable({ halfLifeMs: 1000 });
  t.add(entry({ dt: 0 }));
  t.add(entry({ dt: 1000 }));
  const lane = [...t.byKey.values()][0];
  assert.ok(Math.abs(lane.w - 1.5) < 1e-9);
});

test('prune removes lanes below the floor and frees their slots', () => {
  const t = new LaneTable({ halfLifeMs: 1000 });
  t.add(entry());
  const slot = [...t.byKey.values()][0].slot;
  assert.equal(t.prune(T0 + 500).length, 0);
  const removed = t.prune(T0 + 60000);
  assert.equal(removed.length, 1);
  assert.equal(t.size, 0);
  assert.equal(t.slots[slot], null);
  t.add(entry({ dt: 61000 }));
  assert.equal([...t.byKey.values()][0].slot, slot);
});

test('cap evicts the oldest lane', () => {
  const t = new LaneTable({ cap: 3 });
  for (let i = 0; i < 3; i++) t.add(entry({ client: '192.0.2.' + (20 + i), dt: i * 1000 }));
  assert.equal(t.size, 3);
  t.add(entry({ client: '192.0.2.99', dt: 10000 }));
  assert.equal(t.size, 3);
  assert.ok(![...t.byKey.keys()].some((k) => k.startsWith('192.0.2.20|')), 'oldest was evicted');
  assert.ok([...t.byKey.keys()].some((k) => k.startsWith('192.0.2.99|')));
  const used = new Set([...t.byKey.values()].map((l) => l.slot));
  assert.equal(used.size, 3);
});

test('entries without dests create no lanes', () => {
  const t = new LaneTable();
  const out = t.add(entry({ dests: undefined }));
  assert.equal(out.length, 0);
  assert.equal(t.size, 0);
});

test('multiple dests split the weight and are capped', () => {
  const t = new LaneTable({ maxDests: 2 });
  const dests = [1, 2, 3].map((i) => ({ lat: i * 10, lon: i * 10 }));
  const out = t.add(entry({ dests }));
  assert.equal(out.length, 2);
  assert.ok(Math.abs(out[0].w - 0.5) < 1e-9);
  assert.equal(t.size, 2);
});

test('bytes mode weighs by bytes and mode changes clear lanes', () => {
  const t = new LaneTable({ mode: 'bytes' });
  t.add(entry({ bytes_up: 100, bytes_down: 9900 }));
  const lane = [...t.byKey.values()][0];
  assert.equal(lane.w, 10000);
  assert.equal(lane.bytes, 10000);
  t.setMode('lookups');
  assert.equal(t.size, 0);
  assert.equal(t.mode, 'lookups');
  t.setMode('lookups'); // no-op
});

test('home changes recompute geometry; unset home disables arcs', () => {
  const t = new LaneTable();
  t.add(entry());
  const lane = [...t.byKey.values()][0];
  assert.equal(lane.from, null);
  assert.equal(lane.angle, 0);
  t.setHome(home);
  const a1 = lane.angle;
  assert.ok(a1 > 0);
  t.setHome({ lat: 35.7, lon: 139.7 });
  assert.ok(lane.angle < a1);
  t.setHome(null);
  assert.equal(t.home, null);
  t.setHome({ lat: NaN, lon: 1 });
  assert.equal(t.home, null);
});

test('domains are tracked per lane, capped, and ranked', () => {
  const t = new LaneTable();
  for (let i = 0; i < 12; i++) t.add(entry({ name: `d${i}.example.com`, dt: i }));
  for (let i = 0; i < 5; i++) t.add(entry({ name: 'popular.example.com', dt: 100 + i }));
  const lane = [...t.byKey.values()][0];
  assert.ok(lane.domains.size <= 8);
  const top = t.topDomains(lane, 3);
  assert.equal(top[0].name, 'popular.example.com');
  assert.equal(top[0].n, 5);
  assert.equal(lane.lastName, 'popular.example.com');
  t.add(entry({ name: '' }));
  assert.ok(!lane.domains.has(''));
});

test('clear empties everything and restores slots', () => {
  const t = new LaneTable({ cap: 4 });
  t.add(entry());
  t.clear();
  assert.equal(t.size, 0);
  assert.equal(t.free.length, 4);
  assert.equal(t.floor(), 0.2);
});
