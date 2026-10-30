import test from 'node:test';
import assert from 'node:assert/strict';
import {
  SEVERITIES, STATES, severityLabel, severityBadgeClass, stateLabel,
  MUTE_PRESETS, MUTE_SCOPES, alarmQuery, bulkSummary, ruleMatchSummary,
} from '../js/alarms.js';

test('severity and state presentation', () => {
  assert.deepEqual(SEVERITIES, ['info', 'low', 'medium', 'high', 'critical']);
  assert.deepEqual(STATES, ['new', 'acknowledged', 'muted', 'resolved']);
  assert.equal(severityLabel('critical'), 'Critical');
  assert.equal(severityLabel(''), '');
  assert.equal(severityBadgeClass('critical'), 'badge bad');
  assert.equal(severityBadgeClass('high'), 'badge bad');
  assert.equal(severityBadgeClass('medium'), 'badge warn');
  assert.equal(severityBadgeClass('low'), 'badge inh');
  assert.equal(severityBadgeClass('info'), 'badge');
  assert.equal(severityBadgeClass('bogus'), 'badge');
  for (const s of STATES) assert.ok(stateLabel(s).length > 0);
  assert.equal(stateLabel('bogus'), 'bogus');
  assert.equal(stateLabel(''), '');
});

test('mute presets and scopes are well-formed', () => {
  for (const p of MUTE_PRESETS) {
    assert.ok(p.id && p.label && p.spec && p.spec.preset);
  }
  for (const s of MUTE_SCOPES) {
    assert.ok(s.id && s.label);
  }
});

test('alarmQuery only sets fields that were given', () => {
  assert.deepEqual(alarmQuery(), { offset: 0, limit: 50 });
  assert.deepEqual(alarmQuery({ severity: 'high', state: 'new', text: 'x', types: 'new-device', offset: 10, limit: 20 }),
    { offset: 10, limit: 20, min_severity: 'high', states: 'new', text: 'x', types: 'new-device' });
});

test('bulkSummary describes a BatchResult', () => {
  assert.equal(bulkSummary('Acknowledged', { changed: 1 }), 'Acknowledged 1 alarm');
  assert.equal(bulkSummary('Resolved', { changed: 3 }), 'Resolved 3 alarms');
  assert.equal(bulkSummary('Muted', { changed: 2, skipped: 1 }), 'Muted 2 alarms (1 skipped)');
  assert.equal(bulkSummary('Deleted', {}), 'Deleted 0 alarms');
});

test('ruleMatchSummary lists every non-empty field', () => {
  assert.equal(ruleMatchSummary(null), '');
  assert.equal(ruleMatchSummary({}), '');
  assert.equal(ruleMatchSummary({ types: ['new-device'], device_ids: ['d1', 'd2'] }), 'type: new-device; device: d1, d2');
  assert.equal(ruleMatchSummary({ domains: ['ads.example'], key_prefixes: ['k|'] }), 'domain: ads.example; key: k|');
  assert.equal(ruleMatchSummary({ group_ids: ['g1'] }), 'group: g1');
});
