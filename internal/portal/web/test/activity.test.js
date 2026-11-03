import { test } from 'node:test';
import assert from 'node:assert/strict';
import { startActivityReports } from '../js/activity.js';

function fakeTarget() {
  const h = {};
  return {
    addEventListener: (ev, fn) => { (h[ev] ||= []).push(fn); },
    removeEventListener: (ev, fn) => { h[ev] = (h[ev] || []).filter((f) => f !== fn); },
    fire: (ev) => (h[ev] || []).forEach((f) => f()),
  };
}

test('input is reported at most once per interval', () => {
  const target = fakeTarget();
  let t = 0;
  let sent = 0;
  startActivityReports({ target, send: () => { sent++; }, now: () => t, interval: 1000 });
  target.fire('pointermove');
  target.fire('keydown');
  assert.equal(sent, 1);
  t = 999; target.fire('wheel');
  assert.equal(sent, 1);
  t = 1000; target.fire('wheel');
  assert.equal(sent, 2);
});

test('a failing report never throws and the stop function detaches', async () => {
  const target = fakeTarget();
  let sent = 0;
  const stop = startActivityReports({ target, send: () => { sent++; return Promise.reject(new Error('x')); }, now: () => 0 });
  target.fire('pointerdown');
  await new Promise((r) => setImmediate(r));
  assert.equal(sent, 1);
  stop();
  target.fire('pointerdown');
  assert.equal(sent, 1);
});
