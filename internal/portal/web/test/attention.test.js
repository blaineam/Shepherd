import test from 'node:test';
import assert from 'node:assert/strict';
import { mergeAttention, attentionReasonLabel } from '../js/attention.js';

const dA = { id: 'a', name: 'Unknown-1', last_seen: '2026-10-30T12:00:00Z' };
const dB = { id: 'b', name: 'Guest Phone', last_seen: '2026-10-30T10:00:00Z' };
const dC = { id: 'c', name: 'Old Router', last_seen: '2026-10-29T00:00:00Z' };

test('mergeAttention dedupes a device matching more than one reason', () => {
  const merged = mergeAttention([
    { reason: 'wandering', devices: [dB] },
    { reason: 'quarantine', devices: [dA, dB] },
    { reason: 'excluded', devices: [dC] },
  ]);
  assert.equal(merged.length, 3);
  const b = merged.find((m) => m.device.id === 'b');
  assert.deepEqual(b.reasons.sort(), ['quarantine', 'wandering'].sort());
});

test('mergeAttention sorts quarantine first, then wandering, then excluded', () => {
  const merged = mergeAttention([
    { reason: 'excluded', devices: [dC] },
    { reason: 'wandering', devices: [dB] },
    { reason: 'quarantine', devices: [dA] },
  ]);
  assert.deepEqual(merged.map((m) => m.device.id), ['a', 'b', 'c']);
});

test('mergeAttention breaks ties within a reason by most recently seen', () => {
  const older = { id: 'd', name: 'Older wanderer', last_seen: '2026-10-30T08:00:00Z' };
  const merged = mergeAttention([{ reason: 'wandering', devices: [older, dB] }]);
  assert.deepEqual(merged.map((m) => m.device.id), ['b', 'd']);
});

test('mergeAttention tolerates missing/empty input', () => {
  assert.deepEqual(mergeAttention(undefined), []);
  assert.deepEqual(mergeAttention([]), []);
  assert.deepEqual(mergeAttention([{ reason: 'wandering', devices: undefined }]), []);
  assert.deepEqual(mergeAttention([{ reason: 'wandering', devices: [null, {}] }]), []);
});

test('attentionReasonLabel', () => {
  assert.equal(attentionReasonLabel('quarantine'), 'New / quarantined');
  assert.equal(attentionReasonLabel('wandering'), 'Wandering');
  assert.equal(attentionReasonLabel('excluded'), 'Excluded');
  assert.equal(attentionReasonLabel('bogus'), 'bogus');
  assert.equal(attentionReasonLabel(), '');
});
