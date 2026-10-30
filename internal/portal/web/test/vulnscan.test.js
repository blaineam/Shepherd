import test from 'node:test';
import assert from 'node:assert/strict';
import { severityRank, sortFindings, activeFindings, resolvedFindings, findingTooltip } from '../js/vulnscan.js';

test('severityRank orders the five severities and handles unknowns', () => {
  assert.ok(severityRank('critical') > severityRank('high'));
  assert.ok(severityRank('high') > severityRank('medium'));
  assert.ok(severityRank('medium') > severityRank('low'));
  assert.ok(severityRank('low') > severityRank('info'));
  assert.equal(severityRank('bogus'), -1);
});

test('sortFindings puts the worst severity first, then port, then name', () => {
  const findings = [
    { signature_id: 'a', name: 'B', severity: 'low', port: 80 },
    { signature_id: 'b', name: 'A', severity: 'critical', port: 445 },
    { signature_id: 'c', name: 'C', severity: 'critical', port: 22 },
    { signature_id: 'd', name: 'A', severity: 'high', port: 21 },
  ];
  const got = sortFindings(findings).map((f) => f.signature_id);
  assert.deepEqual(got, ['c', 'b', 'd', 'a']);
});

test('sortFindings tolerates missing input', () => {
  assert.deepEqual(sortFindings(undefined), []);
  assert.deepEqual(sortFindings(null), []);
  assert.deepEqual(sortFindings([]), []);
});

test('sortFindings never mutates its input', () => {
  const findings = [{ signature_id: 'a', severity: 'low', port: 2 }, { signature_id: 'b', severity: 'critical', port: 1 }];
  const copy = findings.map((f) => ({ ...f }));
  sortFindings(findings);
  assert.deepEqual(findings, copy);
});

test('activeFindings and resolvedFindings split by the active flag', () => {
  const findings = [
    { signature_id: 'a', severity: 'high', port: 23, active: true },
    { signature_id: 'b', severity: 'critical', port: 445, active: false },
    { signature_id: 'c', severity: 'medium', port: 21, active: true },
  ];
  assert.deepEqual(activeFindings(findings).map((f) => f.signature_id), ['a', 'c']);
  assert.deepEqual(resolvedFindings(findings).map((f) => f.signature_id), ['b']);
});

test('findingTooltip combines evidence and resolution time', () => {
  assert.equal(findingTooltip(null), '');
  assert.equal(findingTooltip({ evidence: 'SSH-1.5-1.2.27' }), 'SSH-1.5-1.2.27');
  const t = findingTooltip({ active: false, resolved_at: '2026-01-02T03:04:05Z', evidence: 'x' });
  assert.ok(t.startsWith('x — Resolved '));
  assert.equal(findingTooltip({ active: true, resolved_at: '2026-01-02T03:04:05Z' }), '');
});
