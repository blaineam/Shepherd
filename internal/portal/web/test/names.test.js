import test from 'node:test';
import assert from 'node:assert/strict';
import { createNameBook } from '../js/names.js';
import { normalizeEntry, deviceLabel } from '../js/entry.js';
import { createApi, ApiError } from '../js/api.js';

test('name book remembers friendly names per address', () => {
  const b = createNameBook();
  b.note({ client: '192.0.2.1', device: 'Kids Tablet' });
  b.note({ client: '192.0.2.2', device: '192.0.2.2' });
  b.note({ client: '192.0.2.3' });
  b.note(null);
  assert.equal(b.label('192.0.2.1'), 'Kids Tablet');
  assert.equal(b.label('192.0.2.2'), '192.0.2.2');
  assert.ok(b.has('192.0.2.1') && !b.has('192.0.2.3'));
  assert.equal(b.size, 1);
});

test('entries carry the device name and fall back to the client', () => {
  const e = normalizeEntry({ time: '2026-03-02T00:00:00Z', client: '192.0.2.1', device: 'Kids Tablet', device_id: 'd1', action: 'allowed' });
  assert.equal(deviceLabel(e), 'Kids Tablet');
  assert.equal(e.device_id, 'd1');
  const bare = normalizeEntry({ time: '2026-03-02T00:00:00Z', client: '192.0.2.1', action: 'allowed' });
  assert.equal(bare.device, '');
  assert.equal(deviceLabel(bare), '192.0.2.1');
  assert.equal(deviceLabel(null), '');
  assert.equal(normalizeEntry({ device: 'x'.repeat(500) }).device.length, 128);
});

test('keep401 surfaces the server message without signing the user out', async () => {
  let out = 0;
  const res = (status, text) => ({ status, ok: false, statusText: 'U', text: async () => text });
  const api = createApi({ fetchFn: async () => res(401, 'wrong passphrase\n'), onUnauthorized: () => { out++; } });
  await assert.rejects(api('/api/history/unlock', { method: 'POST', keep401: true }), (e) => e instanceof ApiError && e.status === 401 && e.message === 'wrong passphrase');
  assert.equal(out, 0);
  await assert.rejects(api('/api/x'), (e) => e.message === 'unauthorized');
  assert.equal(out, 1);
  const empty = createApi({ fetchFn: async () => res(401, '') });
  await assert.rejects(empty('/x', { keep401: true }), (e) => e.message === 'unauthorized');
});

import { typeLabel, typeIcon, TYPES, normType } from '../js/devtypes.js';
test('device types map real server strings to labels and icons with safe fallbacks', () => {
  assert.equal(typeLabel('tv'), 'TV');
  assert.equal(typeLabel('game console'), 'Game console');
  assert.equal(typeLabel('router/infrastructure'), 'Router/infrastructure');
  assert.equal(typeLabel(''), 'Device');
  assert.equal(typeIcon('camera'), 'camera');
  assert.equal(typeIcon('router/infrastructure'), 'router');
  assert.equal(typeIcon('smart-home hub'), 'iot');
  assert.equal(typeIcon('game console'), 'console');
  assert.equal(typeIcon('Phone'), 'phone');
  assert.equal(typeIcon('desktop'), 'desktop');
  assert.equal(typeIcon('nonsense'), 'unknown');
  assert.equal(typeIcon(null), 'unknown');
  for (const t of ['tablet', 'laptop', 'tv', 'speaker', 'printer', 'watch']) assert.equal(typeIcon(t), t);
  assert.ok(TYPES.every((t) => typeIcon(t) !== 'unknown' || t === 'unknown'));
  assert.equal(normType('Smart-home hub'), 'smarthomehub');
});
