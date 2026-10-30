import test from 'node:test';
import assert from 'node:assert/strict';
import { createDeviceList } from '../js/devlist.js';

const tick = () => new Promise((r) => setImmediate(r));
const all = Array.from({ length: 25 }, (_, i) => ({ id: 'd' + i, name: 'n' + i }));
function server({ fail = false } = {}) {
  const calls = [];
  const fetchPage = async (p) => {
    calls.push(p);
    if (fail) throw Object.assign(new Error('boom'), { status: 500 });
    const rows = p.q ? all.filter((d) => d.name.includes(p.q)) : all;
    return { devices: rows.slice(p.offset, p.offset + p.limit), total: rows.length };
  };
  return { fetchPage, calls };
}

test('reset loads the first page lazily and ensure loads more', async () => {
  const s = server();
  let changes = 0;
  const l = createDeviceList({ fetchPage: s.fetchPage, pageSize: 10, onChange: () => { changes++; } });
  await l.reset('', 'recent');
  assert.equal(l.total, 25);
  assert.ok(l.ready);
  assert.equal(l.get(0).id, 'd0');
  assert.equal(l.get(10), null);
  l.ensure(8, 22);
  await tick(); await tick();
  assert.equal(l.get(10).id, 'd10');
  assert.equal(l.get(24).id, 'd24');
  assert.deepEqual(s.calls.map((c) => c.offset), [0, 10, 20]);
  assert.ok(changes >= 3);
  l.ensure(0, 24);
  await tick();
  assert.equal(s.calls.length, 3, 'loaded pages are not refetched');
});

test('orderedIds, loaded, patch and remove', async () => {
  const l = createDeviceList({ fetchPage: server().fetchPage, pageSize: 10 });
  await l.reset();
  const ids = l.orderedIds();
  assert.equal(ids.length, 25);
  assert.equal(ids[0], 'd0');
  assert.equal(ids[15], undefined);
  assert.equal(l.loaded().length, 10);
  assert.equal(l.patch('d1', (d) => ({ ...d, name: 'renamed' })).name, 'renamed');
  assert.equal(l.get(1).name, 'renamed');
  assert.equal(l.patch('nope', (d) => d), null);
  l.remove(['d0', 'd1']);
  assert.equal(l.total, 23);
  assert.equal(l.get(0).id, 'd2');
});

test('a new reset discards stale responses', async () => {
  let release;
  const slow = new Promise((r) => { release = r; });
  const fetchPage = async (p) => { if (p.q === 'slow') await slow; return { devices: [{ id: p.q }], total: 1 }; };
  const l = createDeviceList({ fetchPage, pageSize: 10 });
  const a = l.reset('slow');
  await l.reset('fast');
  release();
  await a;
  assert.equal(l.get(0).id, 'fast');
  assert.equal(l.query, 'fast');
});

test('errors are surfaced and a later reset recovers', async () => {
  let fail = true;
  const l = createDeviceList({ fetchPage: async () => { if (fail) throw new Error('x'); return { devices: [], total: 0 }; } });
  await l.reset();
  assert.equal(l.error.message, 'x');
  assert.ok(!l.ready);
  fail = false;
  await l.reset();
  assert.equal(l.error, null);
  assert.ok(l.ready);
  assert.equal(l.total, 0);
  l.ensure(0, 10);
});

test('refresh re-fetches held pages and keeps count in sync', async () => {
  const data = all.slice();
  const l = createDeviceList({ fetchPage: async (p) => ({ devices: data.slice(p.offset, p.offset + p.limit), total: data.length }), pageSize: 10 });
  await l.reset();
  l.ensure(10, 19);
  await tick(); await tick();
  data.splice(0, 3);
  await l.refresh();
  assert.equal(l.total, 22);
  assert.equal(l.get(0).id, 'd3');
  assert.equal(l.get(19).id, 'd22');
});

test('refresh reports errors without losing data', async () => {
  let fail = false;
  const l = createDeviceList({ fetchPage: async () => { if (fail) throw new Error('later'); return { devices: all.slice(0, 5), total: 5 }; }, pageSize: 10 });
  await l.reset();
  fail = true;
  await l.refresh();
  assert.equal(l.error.message, 'later');
  assert.equal(l.get(0).id, 'd0');
});

test('fetchAll pages through every match', async () => {
  const l = createDeviceList({ fetchPage: server().fetchPage, pageSize: 10 });
  await l.reset('n1');
  const rows = await l.fetchAll(4);
  assert.equal(rows.length, l.total);
  assert.ok(rows.every((d) => d.name.includes('n1')));
  assert.equal((await createDeviceList({ fetchPage: async () => ({ devices: [], total: 0 }) }).fetchAll()).length, 0);
});

test('missing total falls back to what was seen', async () => {
  const l = createDeviceList({ fetchPage: async () => ({ devices: [{ id: 'a' }, { id: 'b' }] }), pageSize: 10 });
  await l.reset();
  assert.equal(l.total, 2);
  const bad = createDeviceList({ fetchPage: async () => ({ devices: 'nope' }), pageSize: 10 });
  await bad.reset();
  assert.equal(bad.total, 0);
});
