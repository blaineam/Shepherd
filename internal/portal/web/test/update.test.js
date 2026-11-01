import test from 'node:test';
import assert from 'node:assert/strict';
import { updateLine, rollbackLine, dataDirLine, overBudget } from '../js/update.js';

test('updateLine covers off, unchecked, failed, current, available, applying and applied', () => {
  assert.equal(updateLine(null).tone, 'muted');
  assert.equal(updateLine({ enabled: false }).tone, 'muted');
  assert.match(updateLine({ enabled: true, status: {} }).text, /Not checked/);
  assert.match(updateLine({ enabled: true, status: { last_error: 'HTTP 503' } }).text, /HTTP 503/);
  assert.equal(updateLine({ enabled: true, status: { current: '1.0.0', latest_version: '1.0.0', available: false } }).tone, 'good');
  const avail = updateLine({ enabled: true, status: { current: '1.0.0', latest_version: '1.1.0', available: true } });
  assert.equal(avail.tone, 'warn');
  assert.match(avail.text, /1\.1\.0 is available/);
  assert.match(updateLine({ enabled: true, status: { applying: true, latest_version: '1.1.0' } }).text, /Installing 1\.1\.0/);
  assert.match(updateLine({ enabled: true, status: { applied: '1.1.0' } }).text, /restarting/);
});

test('rollbackLine and dataDirLine', () => {
  assert.equal(rollbackLine(null), '');
  assert.match(rollbackLine({ status: { state: { rolled_back: 'asked' } } }), /rolled back: asked/);
  assert.match(rollbackLine({ status: { state: { applied: '1.1.0' } } }), /still being confirmed/);
  assert.equal(rollbackLine({ status: { state: { applied: '1.1.0', confirmed: true } } }), '');
  assert.equal(dataDirLine(null), '');
  assert.match(dataDirLine({ status: { data_dir_bytes: 3 * 1048576, data_dir_parts: { history: 2 * 1048576, lists: 1048576, tiny: 10 } } }), /Data on disk: 3\.0 MB \(history 2\.0 MB, lists 1\.0 MB, tiny 10 B\)/);
});

test('dataDirLine and overBudget against a retention budget', () => {
  const under = { status: { data_dir_bytes: 3 * 1048576, budget_bytes: 512 * 1048576, data_dir_parts: { history: 3 * 1048576 } } };
  assert.match(dataDirLine(under), /Data on disk: 3\.0 MB of a 512 MB budget \(history 3\.0 MB\)\./);
  assert.equal(overBudget(under), false);
  const over = { status: { data_dir_bytes: 600 * 1048576, budget_bytes: 512 * 1048576 } };
  assert.match(dataDirLine(over), /600 MB, over the 512 MB budget\./);
  assert.equal(overBudget(over), true);
  assert.equal(overBudget(null), false);
});
