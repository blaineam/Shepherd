import test from 'node:test';
import assert from 'node:assert/strict';
import { severityRank, sortFindings, activeFindings, resolvedFindings, findingTooltip, flattenFindings, matchRow, scanSummary } from '../js/vulnscan.js';

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

const devA = { device_id: 'd1', name: 'Garage Camera', ip: '192.0.2.31', last_scanned: '2026-10-30T12:00:00Z', findings: [
  { signature_id: 'telnet-exposed', name: 'Telnet exposed', description: 'plain text logins', severity: 'high', port: 23, active: true },
  { signature_id: 'smb1-enabled', name: 'SMBv1 enabled', description: 'EternalBlue-era protocol', severity: 'critical', port: 445, active: true },
] };
const devB = { device_id: 'd2', name: 'NAS', ip: '192.0.2.40', last_scanned: '2026-10-30T11:00:00Z', findings: [
  { signature_id: 'apache-outdated', name: 'Outdated Apache', description: 'missing fixes', severity: 'low', port: 80, active: false, resolved_at: '2026-10-29T00:00:00Z' },
] };

test('flattenFindings orders worst severity first across devices, then by device name', () => {
  const rows = flattenFindings([devA, devB]);
  assert.deepEqual(rows.map((r) => r.finding.signature_id), ['smb1-enabled', 'telnet-exposed', 'apache-outdated']);
  assert.equal(rows[0].deviceName, 'Garage Camera');
  assert.equal(rows[0].ip, '192.0.2.31');
});

test('flattenFindings tolerates missing input', () => {
  assert.deepEqual(flattenFindings(undefined), []);
  assert.deepEqual(flattenFindings([{ device_id: 'd1', name: 'X' }]), []);
});

test('matchRow filters by minimum severity, active/resolved state and free text', () => {
  const rows = flattenFindings([devA, devB]);
  const [smb, telnet, apache] = rows;
  assert.deepEqual(rows.filter((r) => matchRow(r, { severity: 'critical' })), [smb]);
  assert.deepEqual(rows.filter((r) => matchRow(r, { state: 'resolved' })), [apache]);
  assert.deepEqual(rows.filter((r) => matchRow(r, { state: 'active' })), [smb, telnet]);
  assert.deepEqual(rows.filter((r) => matchRow(r, { text: 'garage' })), [smb, telnet]);
  assert.deepEqual(rows.filter((r) => matchRow(r, { text: 'eternalblue' })), [smb]);
  assert.equal(rows.filter((r) => matchRow(r, {})).length, 3);
});

test('scanSummary counts devices scanned and active findings', () => {
  assert.equal(scanSummary({ devices: [devA, devB] }), 'Scanned 2 devices — 2 active findings');
  assert.equal(scanSummary({ devices: [devB] }), 'Scanned 1 device — 0 active findings');
  assert.equal(scanSummary(null), 'Scanned 0 devices — 0 active findings');
});
