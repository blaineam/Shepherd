import test from 'node:test';
import assert from 'node:assert/strict';
import { validLogin, validCode, reportRows, reportTitle } from '../js/import.js';

test('validLogin accepts a trimmed, reasonable email or phone number', () => {
  assert.ok(validLogin('owner@example.net'));
  assert.ok(validLogin('  +15550100123  '));
  assert.ok(!validLogin(''));
  assert.ok(!validLogin('   '));
  assert.ok(!validLogin('a'.repeat(257)));
  assert.ok(!validLogin('bad\x07login'));
});

test('validCode accepts a short, printable code', () => {
  assert.ok(validCode('123456'));
  assert.ok(!validCode(''));
  assert.ok(!validCode('a'.repeat(33)));
  assert.ok(!validCode('12\x0034'));
});

test('reportRows lists only the non-zero counts, in order', () => {
  const rows = reportRows({ created: 2, matched_by_mac: 0, groups_created: 1, unchanged: 0 });
  assert.deepEqual(rows, [{ label: 'Devices to create', count: 2 }, { label: 'Groups to create', count: 1 }]);
  assert.deepEqual(reportRows(null), []);
  assert.deepEqual(reportRows({}), []);
});

test('reportTitle describes dry-run vs. applied, changed vs. not', () => {
  assert.equal(reportTitle(null), '');
  assert.equal(reportTitle({ changed: false, dry_run: true }), 'Nothing would change.');
  assert.equal(reportTitle({ changed: false, dry_run: false }), 'Nothing changed.');
  assert.equal(reportTitle({ changed: true, dry_run: true }), 'Here is what would change:');
  assert.equal(reportTitle({ changed: true, dry_run: false }), 'Done. Here is what changed:');
});
