import test from 'node:test';
import assert from 'node:assert/strict';
import {
  SEVERITIES, STATES, severityLabel, severityBadgeClass, stateLabel,
  MUTE_PRESETS, MUTE_SCOPES, alarmQuery, bulkSummary, ruleMatchSummary,
  feedLine, matchLine,
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

test('feedLine words a feed that is fresh, stale, failed or missing', () => {
  const now = Date.parse('2026-11-01T12:00:00Z');
  assert.equal(feedLine({}).tone, 'muted');
  assert.match(feedLine({ count: 1200, updated: '2026-11-01T11:50:00Z' }, now).text, /1,200 entries, updated under an hour ago/);
  assert.match(feedLine({ count: 5, updated: '2026-11-01T06:00:00Z' }, now).text, /6 h ago/);
  const bad = feedLine({ count: 5, error: 'HTTP 503' });
  assert.equal(bad.tone, 'warn');
  assert.match(bad.text, /keeping 5 entries/);
  assert.equal(feedLine(null).tone, 'muted');
});

test('matchLine says who reached for what', () => {
  assert.match(matchLine({ device: 'Laptop', name: 'x.bad.example.com', indicator: 'bad.example.com', feed_id: 'urlhaus', action: 'blocked' }).text,
    /Laptop was blocked looking up x\.bad\.example\.com \(under bad\.example\.com\), on the urlhaus feed\./);
  assert.match(matchLine({ client: '192.0.2.5', name: 'cdn.example.org', indicator: '192.0.2.0/24', kind: 'ip', feed_id: 'feodo', action: 'allowed' }).text,
    /10\.0\.0\.5 looked up cdn\.example\.org which resolved into 192\.0\.2\.0\/24/);
  assert.equal(matchLine(null).who, 'A device');
});
