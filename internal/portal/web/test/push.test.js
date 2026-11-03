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

import { suggestTopic, ntfyStatusLine, ntfyFields, ntfySaveBody, NTFY_STEPS, NTFY_DEFAULT_SERVER } from '../js/push.js';

test('suggestTopic ends in random letters from bytes and falls back safely', () => {
  assert.equal(suggestTopic([0, 1, 31, 32]), 'shepherd-ab9a');
  assert.equal(suggestTopic([]), 'shepherd-alarms');
  assert.equal(suggestTopic(null), 'shepherd-alarms');
  assert.match(suggestTopic([200, 7, 99, 3, 250, 18, 5, 77]), /^shepherd-[a-z2-9]{8}$/);
});

test('ntfyStatusLine distinguishes not set up, set up but off, and delivering', () => {
  assert.equal(ntfyStatusLine(null).tone, 'muted');
  assert.match(ntfyStatusLine(null).text, /not set up/);
  const off = ntfyStatusLine({ configured: true, enabled: false, server: 'https://ntfy.example.com', topic: 'x' });
  assert.equal(off.tone, 'warn');
  assert.match(off.text, /switched off/);
  const on = ntfyStatusLine({ configured: true, enabled: true, server: 'https://ntfy.example.com', topic: 'x' });
  assert.equal(on.tone, 'good');
  assert.match(on.text, /ntfy\.example\.com \/ x/);
});

test('ntfyFields prefills the form and says when a credential is already stored', () => {
  const empty = ntfyFields(null, 'shepherd-abc');
  assert.equal(empty.server, NTFY_DEFAULT_SERVER);
  assert.equal(empty.topic, 'shepherd-abc');
  assert.equal(empty.enabled, true);
  assert.match(empty.tokenPlaceholder, /only for a server that needs a login/);
  assert.equal(empty.passwordPlaceholder, '');
  const stored = ntfyFields({ configured: true, enabled: false, server: 'https://ntfy.example.com', topic: 't', username: 'u', has_token: true, has_password: true });
  assert.equal(stored.server, 'https://ntfy.example.com');
  assert.equal(stored.topic, 't');
  assert.equal(stored.username, 'u');
  assert.equal(stored.enabled, false);
  assert.match(stored.tokenPlaceholder, /leave blank to keep it/);
  assert.match(stored.passwordPlaceholder, /leave blank to keep it/);
  // The fields never carry the secret itself; the API does not send it.
  assert.equal(JSON.stringify(stored).includes('token"'), false);
});

test('ntfySaveBody trims, keeps a stored credential by leaving it out, and clears on request', () => {
  const body = ntfySaveBody({ server: ' https://ntfy.example.com ', topic: ' t ', username: ' u ', token: ' tk ', enabled: true }, null);
  assert.deepEqual(body, { server: 'https://ntfy.example.com', topic: 't', username: 'u', enabled: true, token: 'tk' });
  // Blank with one stored: nothing is sent, so the server keeps it.
  const keep = ntfySaveBody({ server: 'https://ntfy.example.com', topic: 't', enabled: false }, { has_token: true, has_password: true });
  assert.deepEqual(keep, { server: 'https://ntfy.example.com', topic: 't', username: '', enabled: false });
  const cleared = ntfySaveBody({ server: 'https://ntfy.example.com', topic: 't', clearToken: true, clearPassword: true }, { has_token: true, has_password: true });
  assert.equal(cleared.clear_token, true);
  assert.equal(cleared.clear_password, true);
});

test('the ntfy steps are what happens on the phone, with no file to edit', () => {
  assert.equal(NTFY_STEPS.length, 3);
  for (const step of NTFY_STEPS) assert.equal(/shepherd\.toml/.test(step), false);
});
