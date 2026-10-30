import test from 'node:test';
import assert from 'node:assert/strict';
import { ReplayClock, SPEEDS } from '../js/clock.js';

test('advances by dt times speed', () => {
  const c = new ReplayClock(1000, 1);
  c.tick(100);
  assert.equal(c.time, 1100);
  c.setSpeed(60);
  c.tick(100);
  assert.equal(c.time, 1100 + 6000);
});

test('only the offered speeds are accepted', () => {
  const c = new ReplayClock(0, 1);
  assert.deepEqual(SPEEDS, [1, 10, 60, 300]);
  c.setSpeed(300);
  assert.equal(c.speed, 300);
  c.setSpeed(7);
  assert.equal(c.speed, 300);
});

test('pause, play and toggle', () => {
  const c = new ReplayClock(0, 10);
  c.pause();
  assert.equal(c.tick(1000), false);
  assert.equal(c.time, 0);
  assert.equal(c.toggle(), true);
  c.tick(1000);
  assert.equal(c.time, 10000);
  assert.equal(c.toggle(), false);
  c.play();
  assert.equal(c.playing, true);
});

test('seek jumps and the ceiling stops the clock', () => {
  const c = new ReplayClock(0, 60);
  c.seek(5000);
  assert.equal(c.time, 5000);
  assert.equal(c.tick(1000, 20000), true);
  assert.equal(c.time, 20000);
  assert.equal(c.tick(1000, 20000), true);
  assert.equal(c.time, 20000);
  // a ceiling behind the clock never moves it backwards
  c.seek(30000);
  c.tick(10, 20000);
  assert.equal(c.time, 30000);
});
