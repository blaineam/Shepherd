import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeEntry, validDest, destKey, placeName, toStr, ACTIONS } from '../js/entry.js';

test('normalizeEntry adds a timestamp and keeps valid fields', () => {
  const e = normalizeEntry({ id: 1, time: '2026-01-01T00:00:00Z', client: '192.0.2.1', name: 'a.example.com', action: 'allowed' });
  assert.equal(e.t, Date.parse('2026-01-01T00:00:00Z'));
  assert.equal(e.dests, null);
  assert.equal(e.action, 'allowed');
});

test('normalizeEntry coerces untrusted values', () => {
  const e = normalizeEntry({ time: 'nonsense', client: 42, name: { toString() { return 'x'; } }, action: '<script>' });
  assert.ok(Number.isFinite(e.t));
  assert.equal(e.client, '42');
  assert.equal(typeof e.name, 'string');
  assert.equal(e.action, 'error');
  assert.equal(normalizeEntry(null), null);
  assert.equal(normalizeEntry('x'), null);
  assert.equal(toStr('x'.repeat(500)).length, 256);
  assert.equal(toStr(undefined), '');
});

test('normalizeEntry keeps and caps the block reason', () => {
  const e = normalizeEntry({ time: '2026-01-01T00:00:00Z', action: 'blocked', reason: 'ads-main' });
  assert.equal(e.reason, 'ads-main');
  const capped = normalizeEntry({ time: '2026-01-01T00:00:00Z', action: 'blocked', reason: 'x'.repeat(500) });
  assert.equal(capped.reason.length, 160);
  const none = normalizeEntry({ time: '2026-01-01T00:00:00Z', action: 'allowed' });
  assert.equal(none.reason, '');
});

test('dests are filtered down to valid coordinates', () => {
  const e = normalizeEntry({ time: '2026-01-01T00:00:00Z', action: 'allowed', dests: [
    { lat: 10, lon: 20, city: 'A', country: 'US' }, { lat: 'x', lon: 1 }, { lat: 95, lon: 0 }, null,
  ] });
  assert.equal(e.dests.length, 1);
  const none = normalizeEntry({ time: '2026-01-01T00:00:00Z', action: 'allowed', dests: [{ lat: 999, lon: 0 }] });
  assert.equal(none.dests, null);
  assert.equal(normalizeEntry({ action: 'allowed', dests: 'nope' }).dests, null);
});

test('helpers', () => {
  assert.ok(validDest({ lat: 0, lon: 0 }));
  assert.ok(!validDest(null));
  assert.equal(destKey({ lat: 12.34, lon: -56.78 }), '12.3,-56.8');
  assert.equal(placeName({ city: 'Port Almer', country: 'US' }), 'Port Almer, US');
  assert.equal(placeName({ country: 'US' }), 'US');
  assert.equal(placeName({ city: 'X' }), 'X');
  assert.equal(placeName({}), 'Unknown place');
  assert.deepEqual(ACTIONS, ['allowed', 'cached', 'blocked', 'error']);
});
