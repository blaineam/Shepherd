import test from 'node:test';
import assert from 'node:assert/strict';
import { createMgmt, unavailable } from '../js/mgmt.js';
import { ApiError } from '../js/api.js';

function rig() {
  const calls = [];
  const api = async (p, o = {}) => { calls.push([p, o]); return { ok: true }; };
  return { calls, m: createMgmt(api) };
}

test('unavailable recognises missing endpoints', () => {
  assert.ok(unavailable(new ApiError('x', 404)) && unavailable({ status: 405 }) && unavailable({ status: 501 }));
  assert.ok(!unavailable(new ApiError('x', 500)) && !unavailable(null));
});

test('device endpoints build the documented requests', async () => {
  const { calls, m } = rig();
  await m.devices({ q: 'group:kids tv', sort: 'name', offset: 100, limit: 50 });
  assert.equal(calls[0][0], '/api/devices?q=group%3Akids+tv&sort=name&offset=100&limit=50');
  await m.devices({ q: '', sort: 'recent', offset: 0, limit: 10 });
  assert.equal(calls[1][0], '/api/devices?sort=recent&offset=0&limit=10');
  await m.device('dev/1');
  assert.equal(calls[2][0], '/api/devices/dev%2F1');
  await m.patchDevice('d1', { alias: 'TV' });
  assert.deepEqual([calls[3][1].method, calls[3][1].body], ['PATCH', '{"alias":"TV"}']);
  await m.deleteDevice('d1');
  assert.equal(calls[4][1].method, 'DELETE');
  await m.bulk({ ids: ['a'], op: 'delete' });
  assert.deepEqual([calls[5][0], calls[5][1].method], ['/api/devices/bulk', 'POST']);
});

test('group endpoints', async () => {
  const { calls, m } = rig();
  await m.groups();
  await m.createGroup('Kids', '#fff');
  assert.equal(calls[1][1].body, '{"name":"Kids","color":"#fff"}');
  await m.patchGroup('g 1', { name: 'K' });
  assert.equal(calls[2][0], '/api/groups/g%201');
  await m.deleteGroup('g1');
  assert.equal(calls[3][1].method, 'DELETE');
});

test('policy endpoints', async () => {
  const { calls, m } = rig();
  const scope = { kind: 'group', id: 'g1' };
  await m.catalog(); await m.policy();
  await m.setItem(scope, 'ig', null);
  assert.equal(calls[2][1].body, '{"scope":{"kind":"group","id":"g1"},"item":"ig","enabled":null}');
  await m.addRule(scope, 'block', 'a.example.com');
  await m.delRule(scope, 'allow', 'a.example.com');
  assert.equal(calls[4][0], '/api/policy/rules?scope_kind=group&scope_id=g1&kind=allow&domain=a.example.com');
  await m.delRule({ kind: 'network', id: '' }, 'block', 'x.example.com');
  assert.equal(calls[5][0], '/api/policy/rules?scope_kind=network&kind=block&domain=x.example.com');
  await m.setSwitch(scope, 'relay', true);
  await m.addCustomList({ name: 'n', url: 'https://example.com/l.txt' });
  await m.delCustomList('cl-1');
  assert.equal(calls[8][1].method, 'DELETE');
  await m.refreshLists();
  assert.equal(calls[9][1].body, '{}');
  await m.refreshLists('ads');
  assert.equal(calls[10][1].body, '{"item":"ads"}');
  await m.setMode(scope, 'allow');
  assert.equal(calls[11][1].body, '{"scope":{"kind":"group","id":"g1"},"mode":"allow"}');
  await m.setMode(scope, null);
  assert.equal(calls[12][1].body, '{"scope":{"kind":"group","id":"g1"},"mode":null}');
  const sched = { days: [1, 2, 3, 4, 5], start_min: 540, end_min: 1020 };
  await m.addRule(scope, 'block', 'games.example.com', sched);
  assert.equal(calls[13][1].body, '{"scope":{"kind":"group","id":"g1"},"kind":"block","domain":"games.example.com","schedule":{"days":[1,2,3,4,5],"start_min":540,"end_min":1020}}');
});

test('accountability endpoints', async () => {
  const { calls, m } = rig();
  await m.contacts();
  assert.equal(calls[0][0], '/api/accountability/contacts');
  await m.addContact('Jordan', 'jordan@example.net');
  assert.deepEqual([calls[1][0], calls[1][1].method, calls[1][1].body], ['/api/accountability/contacts', 'POST', '{"name":"Jordan","email":"jordan@example.net"}']);
  await m.deleteContact('c 1');
  assert.deepEqual([calls[2][0], calls[2][1].method], ['/api/accountability/contacts/c%201', 'DELETE']);
  await m.subscriptions();
  assert.equal(calls[3][0], '/api/accountability/subscriptions');
  await m.subscriptions('c1');
  assert.equal(calls[4][0], '/api/accountability/subscriptions?contact_id=c1');
  const body = { contact_id: 'c1', scope: { kind: 'device', id: 'd1' }, items: ['ads'] };
  await m.addSubscription(body);
  assert.deepEqual([calls[5][0], calls[5][1].method, calls[5][1].body], ['/api/accountability/subscriptions', 'POST', JSON.stringify(body)]);
  await m.deleteSubscription('s1');
  assert.deepEqual([calls[6][0], calls[6][1].method], ['/api/accountability/subscriptions/s1', 'DELETE']);
});

test('upstream, history and unlock endpoints', async () => {
  const { calls, m } = rig();
  await m.upstreams();
  await m.testUpstream('tls://dns.example.net');
  await m.addUpstream('9.9.9.10');
  await m.removeUpstream('tls://dns.example.net');
  assert.equal(calls[3][0], '/api/upstreams?addr=tls%3A%2F%2Fdns.example.net');
  await m.setUpstreams(['a', 'b']);
  assert.deepEqual([calls[4][1].method, calls[4][1].body], ['PUT', '{"addrs":["a","b"]}']);
  await m.setBootstrap(['9.9.9.9']);
  assert.equal(calls[5][0], '/api/upstreams/bootstrap');
  await m.history({ from: 'a', to: 'b', limit: 100, q: '' });
  assert.equal(calls[6][0], '/api/history?from=a&to=b&limit=100');
  await m.unlock('pw');
  assert.equal(calls[7][1].keep401, true);
  await m.settings();
  assert.equal(calls[8][0], '/api/settings');
});

test('import endpoints build the documented requests', async () => {
  const { calls, m } = rig();
  await m.importEeroStart('owner@example.net');
  assert.deepEqual([calls[0][0], calls[0][1].body], ['/api/import/eero/start', '{"login":"owner@example.net"}']);
  await m.importEeroVerify('sess-1', '123456');
  assert.equal(calls[1][1].body, '{"session_id":"sess-1","code":"123456"}');
  await m.importEeroPreview('sess-1', '3001', true);
  assert.equal(calls[2][1].body, '{"session_id":"sess-1","network_id":"3001","overwrite_names":true}');
  await m.importEeroApply('sess-1');
  assert.deepEqual([calls[3][0], calls[3][1].body], ['/api/import/eero/apply', '{"session_id":"sess-1"}']);
  await m.importEeroCancel('sess-1');
  assert.equal(calls[4][1].body, '{"session_id":"sess-1"}');
  await m.importCSVPreview('mac,name\n', false);
  assert.equal(calls[5][1].body, '{"csv":"mac,name\\n","overwrite_names":false}');
  await m.importCSVApply('mac,name\n', true);
  assert.deepEqual([calls[6][0], calls[6][1].method], ['/api/import/csv/apply', 'POST']);
});

test('alarm endpoints build the documented requests', async () => {
  const { calls, m } = rig();
  await m.alarms({ types: 'new-device', offset: 0, limit: 50 });
  assert.equal(calls[0][0], '/api/alarms?types=new-device&offset=0&limit=50');
  await m.alarm('a1');
  assert.equal(calls[1][0], '/api/alarms/a1');
  await m.patchAlarm('a1', 'acknowledged');
  assert.deepEqual([calls[2][0], calls[2][1].method, calls[2][1].body], ['/api/alarms/a1', 'PATCH', '{"state":"acknowledged"}']);
  await m.deleteAlarm('a1');
  assert.equal(calls[3][1].method, 'DELETE');
  await m.muteAlarm('a1', { preset: '1h' });
  assert.deepEqual([calls[4][0], calls[4][1].method, calls[4][1].body], ['/api/alarms/a1/mute', 'POST', '{"preset":"1h"}']);
  await m.alarmsBulk({ all: true, op: 'acknowledge' });
  assert.deepEqual([calls[5][0], calls[5][1].body], ['/api/alarms/bulk', '{"all":true,"op":"acknowledge"}']);
  await m.undoAlarms('u1');
  assert.equal(calls[6][1].body, '{"handle":"u1"}');
  await m.alarmsSummary();
  assert.equal(calls[7][0], '/api/alarms/summary');
  await m.alarmTypes();
  assert.equal(calls[8][0], '/api/alarms/types');
  await m.alarmRules();
  assert.equal(calls[9][0], '/api/alarms/rules');
  await m.alarmRules(true);
  assert.equal(calls[10][0], '/api/alarms/rules?all=1');
  await m.createAlarmRule({ name: 'x' });
  assert.equal(calls[11][1].body, '{"name":"x"}');
  await m.deleteAlarmRule('r 1');
  assert.deepEqual([calls[12][0], calls[12][1].method], ['/api/alarms/rules/r%201', 'DELETE']);
});

test('portscan endpoints', async () => {
  const { calls, m } = rig();
  await m.portscanStatus();
  assert.equal(calls[0][0], '/api/portscan');
  await m.portscanDevices();
  assert.equal(calls[1][0], '/api/portscan/devices');
  await m.portscanDevice('d 1');
  assert.equal(calls[2][0], '/api/portscan/devices/d%201');
  await m.scanPorts();
  assert.deepEqual([calls[3][0], calls[3][1].method, calls[3][1].body], ['/api/portscan/scan', 'POST', '{}']);
  await m.scanPorts('d1');
  assert.equal(calls[4][1].body, '{"device_id":"d1"}');
});

test('locking endpoints', async () => {
  const { calls, m } = rig();
  await m.setLockingSettings(30);
  assert.deepEqual([calls[0][0], calls[0][1].method, calls[0][1].body], ['/api/settings/locking', 'POST', '{"idle_lock_minutes":30}']);
  await m.setPIN('a1b2c3');
  assert.deepEqual([calls[1][0], calls[1][1].method, calls[1][1].body], ['/api/pin', 'POST', '{"pin":"a1b2c3"}']);
  await m.clearPIN();
  assert.deepEqual([calls[2][0], calls[2][1].method], ['/api/pin', 'DELETE']);
  await m.trustedDevices();
  assert.equal(calls[3][0], '/api/trusted-devices');
  await m.revokeTrustedDevice('abc 123');
  assert.deepEqual([calls[4][0], calls[4][1].method], ['/api/trusted-devices/abc%20123', 'DELETE']);
  await m.lock();
  assert.deepEqual([calls[5][0], calls[5][1].method], ['/api/lock', 'POST']);
});
