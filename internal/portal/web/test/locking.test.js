import test from 'node:test';
import assert from 'node:assert/strict';
import { lockedURL, unlockedURL, isLockedDemo, pinIssue, idleChoices, IDLE_STOPS } from '../js/locking.js';

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
