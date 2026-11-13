import test from 'node:test';
import assert from 'node:assert/strict';
import {
  SEVERITIES, STATES, severityLabel, severityBadgeClass, stateLabel,
  MUTE_PRESETS, MUTE_SCOPES, alarmQuery, bulkSummary, ruleMatchSummary,
  feedLine, matchLine, hoursOf, deliveryLine, digestFromForm,
  FINDING_KINDS, detectIntro, findingLine, decoyLine, touchLine,
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
    /192\.0\.2\.5 looked up cdn\.example\.org which resolved into 192\.0\.2\.0\/24/);
  assert.equal(matchLine(null).who, 'A device');
});

test('hoursOf reads Go durations and seconds', () => {
  assert.equal(hoursOf('6h0m0s'), 6);
  assert.equal(hoursOf('90m'), 1.5);
  assert.equal(hoursOf(7200), 2);
  assert.equal(hoursOf(''), 0);
  assert.equal(hoursOf('junk'), 0);
});

test('deliveryLine words the immediate threshold and the digest', () => {
  assert.match(deliveryLine({ immediate_min: 'high', digest: { enabled: true, every: '6h0m0s' } }), /High and above are sent at once; lower alarms are gathered into one digest every 6 hours\./);
  assert.match(deliveryLine({ immediate_min: 'medium', digest: { enabled: true, every: '90m', at: '08:30' } }), /Medium and above.*at 08:30 each day/);
  assert.match(deliveryLine({ immediate_min: 'low', digest: { enabled: true, every: '90m' } }), /every 1\.5 hours/);
  assert.match(deliveryLine({ immediate_min: 'critical', digest: { enabled: false } }), /digest is off/);
  assert.match(deliveryLine(null), /could not be read/);
});

test('digestFromForm validates the interval and the time', () => {
  assert.deepEqual(digestFromForm({ enabled: false }), { digest: { enabled: false, every: '6h' } });
  assert.deepEqual(digestFromForm({ enabled: true, mode: 'every', hours: '6' }), { digest: { enabled: true, every: '21600s' } });
  assert.deepEqual(digestFromForm({ enabled: true, mode: 'every', hours: '0.5' }), { digest: { enabled: true, every: '1800s' } });
  assert.match(digestFromForm({ enabled: true, mode: 'every', hours: '0' }).error, /at least one minute/);
  assert.match(digestFromForm({ enabled: true, mode: 'every', hours: 'x' }).error, /at least one minute/);
  assert.deepEqual(digestFromForm({ enabled: true, mode: 'at', at: '08:00' }), { digest: { enabled: true, every: '6h', at: '08:00' } });
  assert.match(digestFromForm({ enabled: true, mode: 'at', at: '8am' }).error, /HH:MM/);
});

test('detectIntro says whether the checks are still learning and what is switched off', () => {
  const now = Date.parse('2026-11-01T12:00:00Z');
  const learning = detectIntro({ status: { learning: true, learning_until: '2026-11-04T06:00:00Z', traffic: true } }, now);
  assert.match(learning, /about 3 more days/);
  assert.doesNotMatch(learning, /bandwidth/);
  assert.match(detectIntro({ status: { learning: true, learning_until: '2026-11-01T13:00:00Z', traffic: true } }, now), /about 1 more day:/);
  const steady = detectIntro({ status: { learning: false, devices: 82, domains: 12345, traffic: false } }, now);
  assert.match(steady, /Watching 82 devices against 12,345 domains/);
  assert.match(steady, /off until bandwidth is being recorded/);
  assert.match(detectIntro(null), /Watching 0 devices/);
});

test('findingLine names the device and the kind of finding', () => {
  assert.deepEqual(findingLine({ kind: 'dns-beacon', device: 'Camera', summary: 'Camera checks in.' }), { who: 'Camera', kind: 'Regular check-in', text: 'Camera checks in.' });
  assert.deepEqual(findingLine({ kind: 'future-kind', client: '192.0.2.9' }), { who: '192.0.2.9', kind: 'future-kind', text: '' });
  assert.deepEqual(findingLine(null), { who: 'A device', kind: 'Finding', text: '' });
  assert.equal(Object.keys(FINDING_KINDS).length, 7);
});

test('decoyLine words open, skipped, failed and disabled decoy ports', () => {
  assert.equal(decoyLine(null).tone, 'muted');
  assert.equal(decoyLine({ enabled: false, ports: [] }).tone, 'muted');
  const all = decoyLine({ enabled: true, ports: [{ port: 23, listening: true }, { port: 3389, listening: true }] });
  assert.equal(all.tone, 'good');
  assert.match(all.text, /Listening on 23, 3389 and serving nothing/);
  assert.doesNotMatch(all.text, /Skipped/);
  assert.match(decoyLine({ enabled: true, ports: [{ port: 23, listening: true }, { port: 5900, listening: false, error: 'in use' }] }).text, /Skipped 5900/);
  const none = decoyLine({ enabled: true, ports: [{ port: 23, listening: false }] });
  assert.equal(none.tone, 'warn');
  assert.match(none.text, /No decoy port could be opened \(23\)/);
});

test('touchLine words a connection to a decoy port', () => {
  assert.equal(touchLine({ source: '192.0.2.7', port: 23, count: 1 }), '192.0.2.7 connected to port 23.');
  assert.equal(touchLine({ source: '192.0.2.7', port: 23, count: 4 }), '192.0.2.7 connected to port 23 (4 times so far).');
  assert.equal(touchLine(null), '? connected to port ?.');
});
