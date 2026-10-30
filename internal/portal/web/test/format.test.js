import test from 'node:test';
import assert from 'node:assert/strict';
import { fmtNum, fmtUptime, fmtClock, fmtAgo, fmtPct, fmtDateTime } from '../js/format.js';

test('number and percentage formatting', () => {
  assert.equal(fmtNum(0), '0');
  assert.equal(fmtNum(undefined), '0');
  assert.equal(fmtNum(1234567), (1234567).toLocaleString());
  assert.equal(fmtPct(2.34), '2.3%');
  assert.equal(fmtPct(12.6), '13%');
  assert.equal(fmtPct(0), '0.0%');
});

test('uptime', () => {
  assert.equal(fmtUptime(90), '1m up');
  assert.equal(fmtUptime(3 * 3600 + 5 * 60), '3h 5m up');
  assert.equal(fmtUptime(2 * 86400 + 60), '2d 0h 1m up');
});

test('clock and ago', () => {
  const d = new Date(2026, 0, 5, 7, 8, 9).getTime();
  assert.equal(fmtClock(d), '07:08:09');
  assert.match(fmtDateTime(d), /07:08:09$/);
  assert.equal(fmtAgo(-5), '0s ago');
  assert.equal(fmtAgo(12000), '12s ago');
  assert.equal(fmtAgo(5 * 60000), '5m ago');
  assert.equal(fmtAgo(3 * 3600000), '3h ago');
});
