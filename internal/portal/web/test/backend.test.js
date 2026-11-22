import { test } from 'node:test';
import assert from 'node:assert/strict';
import { can, statusLine, targetOf, blockSpecFromFlow, ruleSummary, requestLine, auditLine } from '../js/backend.js';

test('a capability is only present when the server lists it', () => {
  assert.equal(can({ capabilities: ['devices', 'rules'] }, 'rules'), true);
  assert.equal(can({ capabilities: ['devices'] }, 'rules:write'), false);
  assert.equal(can(null, 'rules'), false);
  assert.equal(can({}, 'rules'), false);
});

test('the status line says what is wrong in order of what to fix first', () => {
  assert.equal(statusLine(null).tone, 'muted');
  assert.match(statusLine({ available: false }).text, /no router dashboard/);
  assert.match(statusLine({ available: true, connected: false }).text, /under Connections/);
  assert.match(statusLine({ available: true, connected: true, enabled: false, address: 'https://a.firewalla.net' }).text, /switched off/);
  assert.deepEqual(statusLine({ available: true, connected: true, enabled: true, error: 'bad address' }), { tone: 'bad', text: 'bad address' });
  assert.equal(statusLine({ available: true, connected: true, enabled: true, running: false }).text, 'Starting.');
  assert.equal(statusLine({ available: true, connected: true, enabled: true, running: true, status: { needs_token: true } }).tone, 'bad');
  const warn = statusLine({ available: true, connected: true, enabled: true, running: true, status: { errors: { flows: 'HTTP 500' } } });
  assert.equal(warn.tone, 'warn');
  assert.match(warn.text, /flows: HTTP 500/);
  assert.match(statusLine({ available: true, connected: true, enabled: true, running: true, status: {} }).text, /Waiting for the first/);
  const ok = statusLine({ available: true, connected: true, enabled: true, running: true, read_only: true, address: 'https://a.firewalla.net', status: { last_poll: 'x' } });
  assert.equal(ok.tone, 'good');
  assert.match(ok.text, /read only/);
  assert.match(statusLine({ available: true, connected: true, enabled: true, running: true, read_only: false, status: { last_poll: 'x' } }).text, /changes allowed/);
});

test('a request is about its name when it has one and its address otherwise', () => {
  assert.deepEqual(targetOf({ Domain: 'ads.example', RemoteIP: '198.51.100.7' }), { type: 'domain', value: 'ads.example' });
  assert.deepEqual(targetOf({ RemoteIP: '198.51.100.7' }), { type: 'ip', value: '198.51.100.7' });
  assert.equal(targetOf({}), null);
  assert.equal(targetOf(null), null);
});

test('Block on a request is a DNS-only block of that target for that device', () => {
  const spec = blockSpecFromFlow({ Domain: 'ads.example', DeviceMAC: '02005e000001' });
  assert.deepEqual(spec, {
    action: 'block', target_type: 'domain', target: 'ads.example', block_connections: false,
    scope_type: 'device', scope: '02005e000001', notes: 'Blocked from Shepherd',
  });
  const anon = blockSpecFromFlow({ RemoteIP: '198.51.100.7' });
  assert.equal(anon.scope_type, '');
  assert.equal(anon.target_type, 'ip');
  assert.equal(blockSpecFromFlow({}), null);
});

test('a rule reads as a sentence naming the device when it can', () => {
  const devices = [{ MAC: '02005e000001', Name: 'Living room TV' }, { MAC: '02005e000002', Name: '' }];
  assert.equal(ruleSummary({ Action: 'block', TargetType: 'domain', Target: 'ads.example', DNSOnly: true, ScopeType: 'device', Scope: '02005e000001' }, devices),
    'Block domain ads.example for Living room TV, name lookups only');
  assert.equal(ruleSummary({ Action: 'allow', TargetType: 'ip', Target: '198.51.100.1' }), 'Allow ip 198.51.100.1 for every device');
  assert.equal(ruleSummary({ Action: 'block', TargetType: 'category', Target: 'gamble', ScopeType: 'group', Scope: 'kids' }), 'Block category gamble for the group kids');
  assert.equal(ruleSummary({ Action: 'block', TargetType: 'domain', Target: 'x', ScopeType: 'device', Scope: 'zz' }, devices), 'Block domain x for one device');
  assert.equal(ruleSummary({ Action: 'timelimit', TargetType: 'app', Target: 'youtube', ScopeType: 'user' }), 'Time limit app youtube for the user');
  assert.equal(ruleSummary(null), 'Rule target  for every device');
});

test('a request row names what, who and the outcome', () => {
  assert.deepEqual(requestLine({ Domain: 'a.example', Device: 'TV', Blocked: true }), { what: 'a.example', who: 'TV', blocked: true, outbound: true });
  assert.deepEqual(requestLine({ RemoteIP: '198.51.100.7', DeviceIP: '192.0.2.5', Outbound: false }), { what: '198.51.100.7', who: '192.0.2.5', blocked: false, outbound: false });
  assert.equal(requestLine(null).what, 'unknown');
});

test('the change log marks failures', () => {
  assert.equal(auditLine({ action: 'delete rule', target: 'r1' }), 'delete rule r1');
  assert.equal(auditLine({ action: 'delete rule', target: 'r1', Error: 'read-only' }), 'Failed: delete rule r1 (read-only)');
});

import { daysText, scheduleText, scheduleFor, scheduleBody, scheduleProblem } from '../js/backend.js';

test('weekdays read the way a person says them', () => {
  assert.equal(daysText([0, 1, 2, 3, 4, 5, 6]), 'every day');
  assert.equal(daysText([5, 4, 3, 2, 1]), 'weekdays');
  assert.equal(daysText([6, 0]), 'weekends');
  assert.equal(daysText([0, 1, 2, 3, 4]), 'Sun–Thu');
  assert.equal(daysText([1, 3]), 'Mon, Wed');
  assert.equal(daysText([2]), 'Tue');
  assert.equal(daysText(null), '');
});

test('a schedule says when the rule is enforced and when it spills past midnight', () => {
  assert.equal(scheduleText({ days: [0, 1, 2, 3, 4], start: '21:00', end: '07:00', tz: 'America/New_York' }),
    'Enforced Sun–Thu 21:00–07:00 (into the next day) (America/New_York)');
  assert.equal(scheduleText({ days: [1, 2, 3, 4, 5], start: '15:00', end: '18:00', tz: 'UTC' }), 'Enforced weekdays 15:00–18:00 (UTC)');
});

test('the schedule that governs a rule is found by its rule id', () => {
  const list = [{ id: 'a', rule_id: 'r1' }, { id: 'b', rule_id: 'r2' }];
  assert.equal(scheduleFor(list, 'r2').id, 'b');
  assert.equal(scheduleFor(list, 'r9'), null);
  assert.equal(scheduleFor(null, 'r1'), null);
});

test('the schedule form is checked before it is sent and sends sorted days', () => {
  assert.equal(scheduleProblem(new Set(), '21:00', '07:00'), 'Choose at least one day.');
  assert.equal(scheduleProblem(new Set([1]), '', '07:00'), 'Set both times.');
  assert.equal(scheduleProblem(new Set([1]), '21:00', '21:00'), 'The start and end must differ.');
  assert.equal(scheduleProblem(new Set([1]), '21:00', '07:00'), '');
  assert.deepEqual(scheduleBody('r1', new Set([3, 1]), '21:00', '07:00', 'UTC'), { rule_id: 'r1', days: [1, 3], start: '21:00', end: '07:00', tz: 'UTC' });
});

test('a time-limit rule shows how much of its allowance is used', () => {
  assert.equal(ruleSummary({ Action: 'timelimit', TargetType: 'app', Target: 'youtube', ScopeType: 'group', Scope: 'kids', QuotaMinutes: 60, UsedMinutes: 45 }),
    'Time limit app youtube for the group kids, 45 of 60 min used today');
});

import { productName } from '../js/backend.js';

test('the product is named the way its owner knows it', () => {
  assert.equal(productName({ name: 'unifi' }), 'UniFi');
  assert.equal(productName({ name: 'firewalla' }), 'Firewalla');
  assert.equal(productName({}), 'Router');
  assert.equal(productName(null), 'Router');
});

test('a UniFi firewall policy is shown by name, since its filters cannot be described here', () => {
  assert.equal(ruleSummary({ Action: 'block', TargetType: 'policy', Name: 'Block IoT to LAN', Target: 'Block IoT to LAN' }), 'Block policy "Block IoT to LAN"');
  assert.equal(ruleSummary({ Action: 'allow', TargetType: 'policy', ID: 'p9' }), 'Allow policy "p9"');
});

test('what is connected is named in the status line', () => {
  const line = statusLine({ available: true, connected: true, enabled: true, running: true, name: 'unifi', read_only: true, address: '', status: { last_poll: 'x' } });
  assert.match(line.text, /UniFi/);
  assert.match(statusLine({ available: true, connected: true, enabled: true, running: true, name: 'unifi', status: { needs_token: true } }).text, /UniFi refused the credential/);
});
