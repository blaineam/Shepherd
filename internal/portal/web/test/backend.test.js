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
  assert.match(statusLine({ available: true, connected: false }).text, /Bandwidth screen/);
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
