import test from 'node:test';
import assert from 'node:assert/strict';
import {
  DemoGenerator, mulberry32, hash2, DEVICES, SERVICES, TRACKERS, PLACES, DEMO_HOME, diurnal,
} from '../js/demo.js';
import { validDest } from '../js/entry.js';
import { createDemoApi } from '../js/demoapi.js';

const T = Date.parse('2026-03-02T12:00:00Z');
const MIN = 60000;

test('prng is deterministic and in range', () => {
  const a = mulberry32(5), b = mulberry32(5), c = mulberry32(6);
  const xs = Array.from({ length: 5 }, () => a());
  assert.deepEqual(xs, Array.from({ length: 5 }, () => b()));
  assert.notDeepEqual(xs, Array.from({ length: 5 }, () => c()));
  assert.ok(xs.every((x) => x >= 0 && x < 1));
  assert.notEqual(hash2(1, 2), hash2(2, 1));
  assert.equal(hash2(1, 2), hash2(1, 2));
});

test('same window yields the same entries (replay matches live)', () => {
  const g1 = new DemoGenerator({ seed: 3 }), g2 = new DemoGenerator({ seed: 3 });
  const a = g1.range(T, T + 5 * MIN), b = g2.range(T, T + 5 * MIN);
  assert.ok(a.length > 50);
  assert.deepEqual(a, b);
  const sub = g1.range(T + MIN, T + 2 * MIN);
  assert.deepEqual(sub, a.filter((e) => e.t >= T + MIN && e.t < T + 2 * MIN));
});

test('range returns fresh objects and respects limit and bounds', () => {
  const g = new DemoGenerator();
  const a = g.range(T, T + MIN);
  const b = g.range(T, T + MIN);
  assert.notEqual(a[0], b[0]);
  assert.notEqual(a.find((e) => e.dests).dests, b.find((e) => e.dests).dests);
  assert.ok(a.every((e) => e.t >= T && e.t < T + MIN));
  assert.equal(g.range(T, T + 10 * MIN, 7).length, 7);
  assert.equal(g.range(T, T).length, 0);
});

test('entries are sorted with unique, increasing ids', () => {
  const g = new DemoGenerator();
  const es = g.range(T, T + 3 * MIN);
  for (let i = 1; i < es.length; i++) { assert.ok(es[i].t >= es[i - 1].t); assert.ok(es[i].id > es[i - 1].id); }
  assert.equal(new Set(es.map((e) => e.id)).size, es.length);
});

test('uses only synthetic identifiers', () => {
  const g = new DemoGenerator({ bytes: true });
  const es = g.range(T, T + 10 * MIN);
  const clientOK = /^(192\.0\.2|198\.51\.100)\.\d+$/;
  for (const e of es) {
    assert.match(e.client, clientOK);
    assert.match(e.name, /\.example\.(com|net|org)$/);
    assert.ok(e.upstream === '' || e.upstream.startsWith('203.0.113.'));
    for (const d of e.dests || []) { assert.match(d.ip, /^203\.0\.113\.\d+$/); assert.ok(validDest(d)); }
  }
  assert.ok(DEVICES.every((d) => clientOK.test(d)));
  assert.ok(SERVICES.every((s) => /\.example\.(com|net|org)$/.test(s[0])));
  assert.ok(TRACKERS.every((s) => /\.example\.(com|net|org)$/.test(s)));
  assert.ok(PLACES.every((p) => Math.abs(p[2]) <= 90 && Math.abs(p[3]) <= 180));
  assert.ok(validDest(DEMO_HOME));
});

test('action mix has blocked entries without destinations', () => {
  const g = new DemoGenerator();
  const es = g.range(T, T + 20 * MIN);
  const by = (a) => es.filter((e) => e.action === a);
  assert.ok(by('blocked').length > 0 && by('cached').length > 0 && by('error').length > 0);
  assert.ok(by('blocked').every((e) => !e.dests && TRACKERS.includes(e.name)));
  assert.ok(by('error').every((e) => !e.dests));
  assert.ok(by('allowed').every((e) => e.dests && e.dests.length >= 1));
});

test('traffic is heavy tailed: a few device->service pairs dominate', () => {
  const g = new DemoGenerator();
  const es = g.range(T, T + 30 * MIN).filter((e) => e.dests);
  const counts = new Map();
  for (const e of es) counts.set(e.client + '|' + e.name, (counts.get(e.client + '|' + e.name) || 0) + 1);
  const sorted = [...counts.values()].sort((a, b) => b - a);
  const total = sorted.reduce((a, b) => a + b, 0);
  const top10 = sorted.slice(0, Math.ceil(sorted.length * 0.1)).reduce((a, b) => a + b, 0);
  assert.ok(top10 / total > 0.3, `top decile share ${top10 / total}`);
  assert.ok(sorted[0] > 10 * sorted[Math.floor(sorted.length / 2)] / 2);
});

test('bytes mode adds heavy-tailed byte counts only to entries with destinations', () => {
  const g = new DemoGenerator({ bytes: true });
  const es = g.range(T, T + 10 * MIN);
  const withDests = es.filter((e) => e.dests);
  assert.ok(withDests.every((e) => e.bytes_down > 0 && e.bytes_up > 0));
  assert.ok(es.filter((e) => !e.dests).every((e) => e.bytes_down === undefined));
  const b = withDests.map((e) => e.bytes_down).sort((x, y) => x - y);
  assert.ok(b[b.length - 1] / b[Math.floor(b.length / 2)] > 20);
  const plain = new DemoGenerator().range(T, T + MIN);
  assert.ok(plain.every((e) => e.bytes_down === undefined));
});

test('rate scales the event count', () => {
  const lo = new DemoGenerator({ rate: 2 }).range(T, T + 5 * MIN).length;
  const hi = new DemoGenerator({ rate: 20 }).range(T, T + 5 * MIN).length;
  assert.ok(hi > lo * 1.5);
});

test('diurnal factor stays within bounds', () => {
  for (let h = 0; h < 24; h++) { const d = diurnal(new Date(2026, 0, 1, h).getTime()); assert.ok(d >= 0.09 && d <= 1.01); }
});

test('source interface: drain emits live entries once, load feeds replay', async () => {
  const g = new DemoGenerator({ rate: 20 });
  g.start(T);
  const out = [];
  g.drain(T + 30000, out);
  assert.ok(out.length > 0);
  assert.ok(out.every((e) => e.live === true && e.t >= T && e.t < T + 30000));
  const n = out.length;
  g.drain(T + 30000, out);
  assert.equal(out.length, n, 'nothing new at the same instant');
  g.drain(T + 60000, out);
  assert.ok(out.length > n);
  const r = await g.load(T, T + MIN, 5);
  assert.equal(r.entries.length, 5);
  assert.deepEqual(g.history(T), { oldest: T - 24 * 3600 * 1000, newest: T });
  g.stop();
  const fresh = new DemoGenerator();
  const o2 = [];
  fresh.drain(T, o2); // first drain just anchors the cursor
  assert.equal(o2.length, 0);
});

test('demo api serves synthetic status and keeps rules in memory', async () => {
  const api = createDemoApi({ getCounters: () => ({ total: 100, blocked: 5, cached: 20, errors: 1 }), topClients: () => [{ key: '192.0.2.11', n: 3 }], home: DEMO_HOME });
  const st = await api('/api/status');
  assert.equal(st.version, 'demo');
  assert.equal(st.stats.total, 100);
  assert.ok(st.upstreams.every((u) => u.addr.startsWith('203.0.113.')));
  let r = await api('/api/rules', { method: 'POST', body: JSON.stringify({ kind: 'block', domain: 'Ads.Example.net' }) });
  assert.deepEqual(r.block, ['ads.example.net']);
  r = await api('/api/rules', { method: 'POST', body: JSON.stringify({ kind: 'allow', domain: 'ads.example.net' }) });
  assert.deepEqual(r.block, []);
  assert.deepEqual(r.allow, ['ads.example.net']);
  r = await api('/api/rules?kind=allow&domain=ads.example.net', { method: 'DELETE' });
  assert.deepEqual(r.allow, []);
  await assert.rejects(api('/api/rules', { method: 'POST', body: JSON.stringify({ kind: 'block', domain: ' ' }) }), /domain required/);
  r = await api('/api/policies', { method: 'POST', body: JSON.stringify({ name: 'apple-private-relay', enabled: false }) });
  assert.equal(r.policies['apple-private-relay'], false);
  assert.equal(await api('/api/lists/refresh', { method: 'POST' }), null);
  const s = await api('/api/settings');
  assert.equal(s.home.lat, DEMO_HOME.lat);
  const s2 = await api('/api/settings/home', { method: 'POST', body: JSON.stringify({ lat: 1, lon: 2 }) });
  assert.equal(s2.home.lon, 2);
  await assert.rejects(api('/api/history'), (e) => e.status === 404);
});
