import test from 'node:test';
import assert from 'node:assert/strict';
import { lockedURL, unlockedURL, isLockedDemo, pinIssue, idleChoices, IDLE_STOPS, signInOrder, autoTryPasskey, methodLabel } from '../js/locking.js';

test('lockedURL sets demo and locked, keeping other params', () => {
  const u = lockedURL('http://x.invalid/?foo=bar');
  const p = new URL(u).searchParams;
  assert.equal(p.get('demo'), '1');
  assert.equal(p.get('locked'), '1');
  assert.equal(p.get('foo'), 'bar');
});

test('unlockedURL strips every demo/locked marker', () => {
  const u = unlockedURL('http://x.invalid/?demo=1&locked=1&rate=9&bytes=1&setup_pin=1&keep=yes');
  const p = new URL(u).searchParams;
  for (const k of ['demo', 'locked', 'rate', 'bytes', 'setup_pin']) assert.equal(p.has(k), false, k);
  assert.equal(p.get('keep'), 'yes');
});

test('isLockedDemo', () => {
  assert.equal(isLockedDemo('http://x.invalid/?demo=1&locked=1'), true);
  assert.equal(isLockedDemo('http://x.invalid/?demo=1'), false);
  assert.equal(isLockedDemo('http://x.invalid/'), false);
});

test('pinIssue: length', () => {
  assert.match(pinIssue('12345'), /6 to 12/);
  assert.match(pinIssue('1234567890123'), /6 to 12/);
  assert.equal(pinIssue('123abc'), '');
});

test('pinIssue: character set', () => {
  assert.match(pinIssue('has space'), /letters and digits/);
  assert.match(pinIssue('ünïcode1'), /letters and digits/);
});

test('pinIssue: weak PINs rejected', () => {
  assert.notEqual(pinIssue('111111'), '');
  assert.notEqual(pinIssue('123456'), '');
  assert.notEqual(pinIssue('654321'), '');
  assert.notEqual(pinIssue('aaaaaa'), '');
});

test('pinIssue: accepts a reasonable PIN', () => {
  assert.equal(pinIssue('a1b2c3'), '');
  assert.equal(pinIssue('correct9'), '');
});

test('idleChoices includes the fixed stops and preserves a custom value', () => {
  const normal = idleChoices(10);
  assert.deepEqual(normal.map((c) => c.value), IDLE_STOPS);
  const custom = idleChoices(45);
  assert.ok(custom.some((c) => c.value === 45));
  assert.deepEqual([...custom.map((c) => c.value)].sort((a, b) => a - b), custom.map((c) => c.value));
});

test('idleChoices labels 0 as Never', () => {
  const choices = idleChoices(0);
  assert.equal(choices[0].label, 'Never');
});

test('signInOrder leads with the best way in this browser actually has', () => {
  // Everything available: the passkey is the one with nothing to type.
  assert.deepEqual(signInOrder({ passkey: true, pin: true }, { hasWebAuthn: true, secureContext: true }),
    ['passkey', 'pin', 'token']);
  // A registered passkey is no use without WebAuthn or a secure context,
  // whatever the server says.
  assert.deepEqual(signInOrder({ passkey: true, pin: true }, { hasWebAuthn: false, secureContext: true }),
    ['pin', 'token']);
  assert.deepEqual(signInOrder({ passkey: true, pin: true }, { hasWebAuthn: true, secureContext: false }),
    ['pin', 'token']);
  // A browser that is not trusted has no PIN to offer.
  assert.deepEqual(signInOrder({ passkey: false, pin: false }, {}), ['token']);
  // The token is always there: it is the way back in when the rest is gone.
  assert.ok(signInOrder({}, {}).includes('token'));
  assert.ok(signInOrder(null, {}).includes('token'));
});

test('autoTryPasskey only when the passkey leads, the page is looked at, and once', () => {
  const order = ['passkey', 'pin', 'token'];
  assert.equal(autoTryPasskey({ order, visible: true, tried: false }), true);
  // Not on a background tab: an unasked-for prompt on a tab nobody is
  // looking at is an interruption.
  assert.equal(autoTryPasskey({ order, visible: false, tried: false }), false);
  // Not twice: a cancelled attempt must leave the button, not loop.
  assert.equal(autoTryPasskey({ order, visible: true, tried: true }), false);
  // Not when the passkey is only an alternative.
  assert.equal(autoTryPasskey({ order: ['pin', 'token'], visible: true, tried: false }), false);
  assert.equal(autoTryPasskey({}), false);
});

test('methodLabel names the alternatives the way they would be looked for', () => {
  assert.match(methodLabel('passkey'), /passkey/i);
  assert.match(methodLabel('pin'), /PIN/);
  assert.match(methodLabel('token'), /token/i);
});
