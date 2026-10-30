import test from 'node:test';
import assert from 'node:assert/strict';
import {
  weightScale, weightFromScale, hasBytes, detectMode, entryWeight, widthPx, baseAlpha, legendText,
  fmtBytes, fmtWeight, MIN_WIDTH, MAX_WIDTH, MODES,
} from '../js/weight.js';

test('weightScale is monotonic, log shaped and clamped', () => {
  assert.equal(weightScale(0), 0);
  assert.equal(weightScale(-3), 0);
  assert.equal(weightScale(NaN), 0);
  let prev = 0;
  for (const w of [1, 2, 5, 10, 50, 100, 150]) { const s = weightScale(w); assert.ok(s > prev); prev = s; }
  assert.equal(weightScale(150), 1);
  assert.equal(weightScale(1e9), 1);
  // log: the same absolute increase counts for less at the top than at the bottom
  assert.ok(weightScale(11) - weightScale(1) > weightScale(111) - weightScale(101));
});

test('bytes mode uses its own range', () => {
  assert.equal(weightScale(0, 'bytes'), 0);
  assert.ok(weightScale(1024, 'bytes') < weightScale(1024 * 1024, 'bytes'));
  assert.equal(weightScale(2 ** 30, 'bytes'), 1);
  assert.ok(weightScale(5000, 'bytes') < weightScale(5000, 'lookups'));
  assert.equal(weightScale(10, 'nonsense'), weightScale(10, 'lookups'));
});

test('weightFromScale inverts weightScale', () => {
  for (const mode of ['lookups', 'bytes']) {
    for (const s of [0.1, 0.4, 0.8]) {
      const w = weightFromScale(s, mode);
      assert.ok(Math.abs(weightScale(w, mode) - s) < 1e-9);
    }
  }
  assert.equal(weightFromScale(-1, 'lookups'), 0);
  assert.ok(weightFromScale(2, 'lookups') <= weightFromScale(1, 'lookups') + 1e-9);
});

test('mode detection and entry weight', () => {
  assert.equal(hasBytes({}), false);
  assert.equal(hasBytes({ bytes_down: 10 }), true);
  assert.equal(hasBytes({ bytes_up: 0 }), true);
  assert.equal(detectMode({ name: 'x' }), 'lookups');
  assert.equal(detectMode({ bytes_up: 1 }), 'bytes');
  assert.equal(entryWeight({}, 'lookups'), 1);
  assert.equal(entryWeight({ bytes_up: 5, bytes_down: 7 }, 'bytes'), 12);
  assert.equal(entryWeight({}, 'bytes'), 0);
  assert.equal(entryWeight({ bytes_up: -5 }, 'bytes'), 0);
});

test('thickness and brightness grow with weight', () => {
  assert.equal(widthPx(0), MIN_WIDTH);
  assert.equal(widthPx(1), MAX_WIDTH);
  assert.ok(widthPx(0.7) > widthPx(0.2));
  assert.equal(baseAlpha(0), 0);
  assert.ok(baseAlpha(0.9) > baseAlpha(0.1));
  assert.ok(baseAlpha(1) <= 1);
});

test('legend is honest about the unit', () => {
  assert.match(legendText('lookups'), /lookups/i);
  assert.match(legendText('bytes'), /bytes/i);
  assert.ok(MODES.lookups.unit === 'lookups' && MODES.bytes.unit === 'bytes');
});

test('byte and weight formatting', () => {
  assert.equal(fmtBytes(0), '0 B');
  assert.equal(fmtBytes(512), '512 B');
  assert.equal(fmtBytes(2048), '2.0 KB');
  assert.equal(fmtBytes(5 * 1024 * 1024), '5.0 MB');
  assert.equal(fmtBytes(300 * 1024 * 1024), '300 MB');
  assert.equal(fmtBytes(-1), '0 B');
  assert.equal(fmtBytes(NaN), '0 B');
  assert.equal(fmtWeight(0.4, 'lookups'), '1');
  assert.equal(fmtWeight(49.6, 'lookups'), '50');
  assert.equal(fmtWeight(2048, 'bytes'), '2.0 KB');
});
