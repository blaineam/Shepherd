import test from 'node:test';
import assert from 'node:assert/strict';
import { pushSupport, permissionLine, urlBase64ToUint8Array, subscribeBody, defaultDeviceName, deviceLine, isThisBrowser } from '../js/push.js';

const ok = { secureContext: true, hasServiceWorker: true, hasPushManager: true, hasNotification: true };

test('pushSupport names the one reason that blocks subscribing', () => {
  assert.deepEqual(pushSupport(ok), { ok: true, reason: '' });
  assert.match(pushSupport({ ...ok, secureContext: false }).reason, /HTTPS/);
  assert.match(pushSupport({ ...ok, ios: true, standalone: false }).reason, /Home Screen/);
  assert.equal(pushSupport({ ...ok, ios: true, standalone: true }).ok, true);
  assert.match(pushSupport({ ...ok, hasPushManager: false }).reason, /support/);
  assert.equal(pushSupport(null).ok, false);
});

test('permissionLine covers granted, denied and default', () => {
  assert.equal(permissionLine('granted').tone, 'good');
  assert.equal(permissionLine('denied').tone, 'bad');
  assert.equal(permissionLine('default').tone, 'muted');
  assert.equal(permissionLine(undefined).tone, 'muted');
});

test('urlBase64ToUint8Array decodes base64url with or without padding', () => {
  assert.deepEqual([...urlBase64ToUint8Array('AQID')], [1, 2, 3]);
  assert.deepEqual([...urlBase64ToUint8Array('AQI')], [1, 2]);
  assert.deepEqual([...urlBase64ToUint8Array('-_8')], [251, 255]);
  assert.equal(urlBase64ToUint8Array('').length, 0);
});

test('subscribeBody keeps exactly the subscription fields and a bounded name', () => {
  const b = subscribeBody({ endpoint: 'https://push.example/abc', expirationTime: null, keys: { p256dh: 'P', auth: 'A' } }, '  Phone  ');
  assert.deepEqual(b, { subscription: { endpoint: 'https://push.example/abc', keys: { p256dh: 'P', auth: 'A' } }, name: 'Phone' });
  assert.equal(subscribeBody(null, 'x'.repeat(100)).name.length, 60);
  assert.equal(subscribeBody({}, '').subscription.endpoint, '');
});

test('defaultDeviceName guesses from the user agent', () => {
  assert.equal(defaultDeviceName('Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)'), 'iPhone');
  assert.equal(defaultDeviceName('Mozilla/5.0 (iPad; CPU OS 17_0)'), 'iPad');
  assert.equal(defaultDeviceName('Mozilla/5.0 (Linux; Android 14)'), 'Android phone');
  assert.equal(defaultDeviceName('Mozilla/5.0 (Macintosh; Intel Mac OS X)'), 'Mac');
  assert.equal(defaultDeviceName('Mozilla/5.0 (Windows NT 10.0)'), 'Windows PC');
  assert.equal(defaultDeviceName('Mozilla/5.0 (X11; Linux x86_64)'), 'Linux PC');
  assert.equal(defaultDeviceName(''), 'This browser');
});

test('deviceLine words each subscription state', () => {
  const now = Date.parse('2026-11-01T12:00:00Z');
  assert.equal(deviceLine({ id: 'a', name: 'Phone' }).tone, 'muted');
  const fresh = deviceLine({ name: 'Phone', last_ok: '2026-11-01T11:59:40Z', service: 'push.example' }, now);
  assert.equal(fresh.tone, 'good');
  assert.match(fresh.text, /just now via push.example/);
  assert.match(deviceLine({ name: 'Phone', last_ok: '2026-11-01T11:30:00Z' }, now).text, /30 min ago/);
  assert.match(deviceLine({ name: 'Phone', last_ok: '2026-11-01T09:00:00Z' }, now).text, /3 h ago/);
  assert.match(deviceLine({ name: 'Phone', last_ok: '2026-10-29T12:00:00Z' }, now).text, /3 d ago/);
  const bad = deviceLine({ name: 'Phone', last_ok: '2026-11-01T11:00:00Z', last_error: '410 gone', failures: 3 }, now);
  assert.equal(bad.tone, 'warn');
  assert.match(bad.text, /410 gone \(3 in a row\)/);
  assert.equal(deviceLine({ user_agent: 'UA' }).name, 'UA');
  assert.equal(deviceLine(null).name, 'A browser');
  assert.equal(isThisBrowser({ id: 'x' }, 'x'), true);
  assert.equal(isThisBrowser({ id: 'x' }, ''), false);
});
