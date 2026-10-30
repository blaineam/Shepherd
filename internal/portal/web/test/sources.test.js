import test from 'node:test';
import assert from 'node:assert/strict';
import { LiveSource } from '../js/sources.js';

class FakeES {
  constructor(url) { this.url = url; this.listeners = {}; this.readyState = 0; this.closed = false; FakeES.last = this; FakeES.all.push(this); }
  addEventListener(n, f) { (this.listeners[n] ||= []).push(f); }
  close() { this.closed = true; this.readyState = 2; }
  emit(n, data) { for (const f of this.listeners[n] || []) f({ data: typeof data === 'string' ? data : JSON.stringify(data) }); }
}
FakeES.all = [];

function fakeTimers() {
  const t = { ivs: [], tos: [], now: 0 };
  t.setInterval = (f, ms) => { const h = { f, ms, on: true }; t.ivs.push(h); return h; };
  t.clearInterval = (h) => { if (h) h.on = false; };
  t.setTimeout = (f, ms) => { const h = { f, ms, on: true }; t.tos.push(h); return h; };
  t.clearTimeout = (h) => { if (h) h.on = false; };
  t.fireIntervals = () => t.ivs.filter((h) => h.on).forEach((h) => h.f());
  t.fireTimeouts = () => t.tos.filter((h) => h.on).forEach((h) => { h.on = false; h.f(); });
  return t;
}

const entry = (id, over = {}) => ({ id, time: '2026-01-01T00:00:00Z', client: '192.0.2.1', name: 'a.example.com', action: 'allowed', ...over });
function mk(over = {}) {
  FakeES.all = [];
  const timers = fakeTimers();
  const states = [];
  const calls = [];
  const src = new LiveSource({
    esFactory: (u) => new FakeES(u), timers, onState: (s) => states.push(s),
    fetchJson: async (p) => { calls.push(p); return { entries: [entry(10), entry(11)], last: 11 }; },
    ...over,
  });
  return { src, timers, states, calls };
}

test('consumes SSE query events and drains them once', () => {
  const { src, states } = mk();
  src.start();
  assert.equal(FakeES.last.url, '/api/stream');
  FakeES.last.emit('open', {});
  FakeES.last.emit('query', entry(1));
  FakeES.last.emit('query', entry(2, { dests: [{ lat: 1, lon: 2 }] }));
  const out = [];
  src.drain(Date.now(), out);
  assert.equal(out.length, 2);
  assert.ok(out.every((e) => e.live === true && Number.isFinite(e.t)));
  assert.deepEqual(out[1].dests, [{ lat: 1, lon: 2 }]);
  src.drain(Date.now(), out);
  assert.equal(out.length, 2);
  assert.deepEqual(states, ['connecting', 'live']);
  assert.equal(src.lastId, 2);
});

test('duplicates, old ids and malformed messages are ignored', () => {
  const { src } = mk();
  src.start();
  const es = FakeES.last;
  es.emit('query', entry(5));
  es.emit('query', entry(5));
  es.emit('query', entry(4));
  es.emit('query', 'not json');
  es.emit('query', 'null');
  const out = [];
  src.drain(0, out);
  assert.equal(out.length, 1);
  src.seed(100);
  es.emit('query', entry(50));
  src.drain(0, out);
  assert.equal(out.length, 1);
  src.seed(Number.NaN);
  assert.equal(src.lastId, 100);
});

test('transient errors stay on SSE, repeated or closed errors fall back to polling', async () => {
  const { src, timers, states, calls } = mk({ maxErrors: 3 });
  src.start();
  const es = FakeES.last;
  es.onerror();
  es.onerror();
  assert.equal(src.state, 'connecting');
  es.emit('query', entry(1)); // resets the error counter
  es.onerror(); es.onerror();
  assert.equal(src.state, 'connecting');
  es.onerror();
  assert.equal(src.state, 'poll');
  assert.ok(es.closed);
  await Promise.resolve(); await Promise.resolve();
  assert.ok(calls.length >= 1);
  assert.match(calls[0], /^\/api\/queries\?limit=200&after=/);
  assert.ok(states.includes('poll'));
  // closed readyState falls back immediately
  const b = mk();
  b.src.start();
  FakeES.last.readyState = 2;
  FakeES.last.onerror();
  assert.equal(b.src.state, 'poll');
});

test('polling dedupes by id, advances the cursor and keeps going on a timer', async () => {
  const { src, timers, calls } = mk();
  src.fetchJson = async (p) => { calls.push(p); return { entries: [entry(10), entry(11)], last: 11 }; };
  src.start();
  FakeES.last.readyState = 2;
  FakeES.last.onerror();
  await new Promise((r) => setImmediate(r));
  const out = [];
  src.drain(0, out);
  assert.deepEqual(out.map((e) => e.id), [10, 11]);
  assert.equal(src.lastId, 11);
  timers.fireIntervals();
  await new Promise((r) => setImmediate(r));
  assert.match(calls[calls.length - 1], /after=11$/);
  src.drain(0, out);
  assert.equal(out.length, 2, 'already-seen entries are not repeated');
});

test('polling retries SSE after a while', async () => {
  const { src, timers } = mk();
  src.start();
  FakeES.last.readyState = 2;
  FakeES.last.onerror();
  const before = FakeES.all.length;
  timers.fireTimeouts();
  assert.equal(FakeES.all.length, before + 1);
  assert.equal(timers.ivs.filter((h) => h.on).length, 0, 'polling stopped');
});

test('a throwing EventSource constructor falls back to polling', async () => {
  const { src } = mk({ esFactory: () => { throw new Error('nope'); } });
  src.start();
  assert.equal(src.state, 'poll');
});

test('poll failures show offline, unauthorized stops quietly', async () => {
  const a = mk({ fetchJson: async () => { throw new Error('boom'); } });
  a.src.start();
  FakeES.last.readyState = 2; FakeES.last.onerror();
  await new Promise((r) => setImmediate(r));
  assert.equal(a.src.state, 'offline');

  const b = mk({ fetchJson: async () => { throw new Error('unauthorized'); } });
  b.src.start();
  FakeES.last.readyState = 2; FakeES.last.onerror();
  await new Promise((r) => setImmediate(r));
  assert.equal(b.src.state, 'idle');
  assert.equal(b.timers.ivs.filter((h) => h.on).length, 0);
});

test('stop closes everything and bounds the buffer', () => {
  const { src } = mk({ maxBuffer: 3 });
  src.start();
  const es = FakeES.last;
  for (let i = 1; i <= 10; i++) es.emit('query', entry(i));
  assert.equal(src.buf.length, 3);
  src.stop();
  assert.ok(es.closed);
  assert.equal(src.state, 'idle');
  src.es = null;
  src.stop(); // idempotent
});

test('an overlapping poll is skipped', async () => {
  let resolve;
  const { src } = mk({ fetchJson: () => new Promise((r) => { resolve = r; }) });
  src.stopped = false;
  const p1 = src.poll();
  const p2 = src.poll();
  resolve({ entries: [], last: 0 });
  await Promise.all([p1, p2]);
  assert.equal(src.polling, false);
});

test('default timers work when called as methods (no Illegal invocation)', async () => {
  const src = new LiveSource({ esFactory: (u) => new FakeES(u), fetchJson: async () => ({ entries: [], last: 0 }), pollMs: 5, retrySseMs: 1000000 });
  FakeES.all = [];
  src.start();
  FakeES.last.readyState = 2;
  FakeES.last.onerror();
  assert.equal(src.state, 'poll');
  await new Promise((r) => setTimeout(r, 30));
  src.stop();
  assert.equal(src.pollTimer, null);
});

test('a restarted server (ids reset, times newer) is not mistaken for duplicates', () => {
  const { src } = mk();
  src.start();
  const es = FakeES.last;
  es.emit('query', entry(500, { time: '2026-01-01T00:00:00Z' }));
  es.emit('query', entry(1, { time: '2026-01-01T00:05:00Z' }));
  es.emit('query', entry(2, { time: '2026-01-01T00:05:01Z' }));
  const out = [];
  src.drain(0, out);
  assert.deepEqual(out.map((e) => e.id), [500, 1, 2]);
  assert.equal(src.lastId, 2);
});

test('polling follows a server whose cursor went backwards', async () => {
  const calls = [];
  const { src } = mk({ fetchJson: async (p) => { calls.push(p); return { entries: [], last: 3 }; } });
  src.stopped = false;
  src.lastId = 900;
  await src.poll();
  assert.equal(src.lastId, 3);
  await src.poll();
  assert.match(calls[1], /after=3$/);
});
