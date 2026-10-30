import test from 'node:test';
import assert from 'node:assert/strict';
import { ReplaySource } from '../js/replay.js';

const mk = (t, id) => ({ id, t, name: 'x' });

function fakeLoader(all, { limitHit = false } = {}) {
  const calls = [];
  const load = async (from, to, limit) => {
    calls.push([from, to, limit]);
    return { entries: all.filter((e) => e.t >= from && e.t < to).slice(0, limit) };
  };
  return { load, calls };
}
const tick = () => new Promise((r) => setImmediate(r));

test('seek loads a chunk and drain hands out entries as the clock passes them', async () => {
  const all = [mk(1000, 1), mk(2000, 2), mk(3000, 3), mk(500000, 4)];
  const { load, calls } = fakeLoader(all);
  const rs = new ReplaySource({ load, chunkMs: 60000, bound: () => 1e9 });
  await rs.seek(0);
  assert.equal(rs.loading, false);
  assert.equal(calls[0][0], 0);
  assert.equal(calls[0][1], 60000);
  const out = [];
  rs.drain(1500, out);
  assert.deepEqual(out.map((e) => e.id), [1]);
  rs.drain(3500, out);
  assert.deepEqual(out.map((e) => e.id), [1, 2, 3]);
  rs.drain(3500, out);
  assert.equal(out.length, 3, 'no duplicates');
});

test('prefetches the next chunk near the end of the loaded window', async () => {
  const all = [mk(10, 1), mk(70000, 2), mk(130000, 3)];
  const { load, calls } = fakeLoader(all);
  const rs = new ReplaySource({ load, chunkMs: 60000, prefetch: 0.5, bound: () => 1e9 });
  await rs.seek(0);
  const out = [];
  rs.drain(10, out);
  assert.equal(calls.length, 1);
  rs.drain(40000, out); // within 50% of the end of [0, 60000)
  await tick();
  assert.equal(calls.length, 2);
  assert.equal(calls[1][0], 60000);
  rs.drain(75000, out);
  assert.deepEqual(out.map((e) => e.id), [1, 2]);
});

test('ceiling stalls the clock until data arrives', async () => {
  let release;
  const load = () => new Promise((r) => { release = () => r({ entries: [] }); });
  const rs = new ReplaySource({ load, chunkMs: 1000, bound: () => 1e9 });
  const p = rs.seek(5000);
  assert.equal(rs.loading, true);
  assert.equal(rs.ceiling, 5000);
  release();
  await p;
  assert.equal(rs.loading, false);
  assert.equal(rs.ceiling, 6000);
});

test('hitting the limit only trusts data up to the last entry', async () => {
  const all = [mk(1, 1), mk(2, 2), mk(3, 3), mk(4, 4)];
  const { load } = fakeLoader(all);
  const rs = new ReplaySource({ load, chunkMs: 60000, limit: 3, bound: () => 1e9 });
  await rs.seek(0);
  assert.equal(rs.loadedUntil, 3);
  const out = [];
  rs.drain(10, out);
  assert.deepEqual(out.map((e) => e.id), [1, 2, 3]);
  await tick();
  assert.ok(rs.buf.some((e) => e.id === 4) || out.length >= 3);
});

test('stale responses from before a new seek are dropped', async () => {
  const resolvers = [];
  const load = (from) => new Promise((r) => resolvers.push(() => r({ entries: [mk(from + 1, from)] })));
  const rs = new ReplaySource({ load, chunkMs: 1000, bound: () => 1e9 });
  const first = rs.seek(0);
  const second = rs.seek(100000);
  resolvers[0]();
  resolvers[1]();
  await Promise.all([first, second]);
  const out = [];
  rs.drain(200000, out);
  assert.deepEqual(out.map((e) => e.id), [100000]);
});

test('errors do not stall forever and are reported', async () => {
  let changed = 0;
  const rs = new ReplaySource({ load: async () => { throw new Error('boom'); }, chunkMs: 1000, bound: () => 1e9 });
  rs.onChange = () => { changed++; };
  await rs.seek(0);
  assert.equal(rs.error.message, 'boom');
  assert.equal(rs.loading, false);
  assert.equal(rs.loadedUntil, 1000);
  assert.ok(changed >= 1);
});

test('seeking at or beyond the live edge loads nothing', async () => {
  const { load, calls } = fakeLoader([]);
  const rs = new ReplaySource({ load, chunkMs: 1000, bound: () => 5000 });
  await rs.seek(9000);
  assert.equal(calls.length, 0);
  assert.equal(rs.loadedUntil, 5000);
  assert.equal(rs.ceiling, Infinity);
});

test('stop clears buffered data and setChunk enforces a minimum', async () => {
  const { load } = fakeLoader([mk(1, 1)]);
  const rs = new ReplaySource({ load, chunkMs: 60000, bound: () => 1e9 });
  await rs.seek(0);
  rs.stop();
  const out = [];
  rs.drain(100, out);
  assert.equal(out.length, 0);
  rs.setChunk(1);
  assert.equal(rs.chunkMs, 60000);
  rs.setChunk(900000);
  assert.equal(rs.chunkMs, 900000);
});

test('entries are returned sorted even if the loader is not', async () => {
  const load = async () => ({ entries: [mk(30, 3), mk(10, 1), mk(20, 2)] });
  const rs = new ReplaySource({ load, chunkMs: 1000, bound: () => 1e9 });
  await rs.seek(0);
  const out = [];
  rs.drain(100, out);
  assert.deepEqual(out.map((e) => e.id), [1, 2, 3]);
});

test('does not refetch in a loop once loaded up to the live edge', async () => {
  let edge = 100000;
  const { load, calls } = fakeLoader([mk(10, 1)]);
  const rs = new ReplaySource({ load, chunkMs: 60000, edgeGapMs: 2000, bound: () => edge });
  await rs.seek(50000);
  assert.equal(calls.length, 1);
  assert.equal(rs.loadedUntil, 100000);
  const out = [];
  for (let i = 0; i < 20; i++) { edge += 16; rs.drain(edge - 100, out); await tick(); }
  assert.equal(calls.length, 1, 'no refetch within the edge gap');
  assert.equal(rs.ceiling, Infinity);
  edge += 5000;
  rs.drain(edge - 100, out);
  await tick();
  assert.equal(calls.length, 2, 'fetches again once the edge has moved on');
});
