import test from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeMAC, isMAC, parseIPv4, inRange, inSubnet, validateReservation,
  modeLabel, stateSummary, consequences, sortLeases, filterLeases, leaseBody, originLabel,
} from '../js/dhcp.js';

test('normalizeMAC accepts the spellings people paste and refuses the rest', () => {
  for (const input of ['02:00:5E:01:02:03', '02-00-5e-01-02-03', '02005e010203', ' 02:00:5e:01:02:03 ']) {
    assert.equal(normalizeMAC(input), '02:00:5e:01:02:03', input);
  }
  for (const bad of ['', '02:00:5e:01:02', '02:00:5e:01:02:03:04', 'not a mac', null, undefined]) {
    assert.equal(normalizeMAC(bad), '', JSON.stringify(bad));
  }
  assert.equal(isMAC('02:00:5e:01:02:03'), true);
  assert.equal(isMAC('02005e010203'), false, 'isMAC checks the canonical form, not any spelling');
});

test('parseIPv4 is strict about leading zeros, because they change the address in some resolvers', () => {
  assert.deepEqual(parseIPv4('192.0.2.10'), [192, 0, 2, 10]);
  assert.deepEqual(parseIPv4(' 203.0.113.255 '), [203, 0, 113, 255]);
  for (const bad of ['192.0.2.010', '192.0.2.256', '192.0.2', '192.0.2.1.1', '192.0.2.a', '', 'x']) {
    assert.equal(parseIPv4(bad), null, bad);
  }
});

test('inRange and inSubnet answer the two questions a reservation has to pass', () => {
  assert.equal(inRange('192.0.2.150', '192.0.2.100', '192.0.2.200'), true);
  assert.equal(inRange('192.0.2.100', '192.0.2.100', '192.0.2.200'), true, 'the range is inclusive');
  assert.equal(inRange('192.0.2.200', '192.0.2.100', '192.0.2.200'), true);
  assert.equal(inRange('192.0.2.50', '192.0.2.100', '192.0.2.200'), false);
  assert.equal(inRange('nope', '192.0.2.100', '192.0.2.200'), false);

  assert.equal(inSubnet('192.0.2.10', '192.0.2.0/24'), true);
  assert.equal(inSubnet('198.51.100.10', '192.0.2.0/24'), false);
  assert.equal(inSubnet('192.0.2.10', '0.0.0.0/0'), true);
  assert.equal(inSubnet('192.0.2.10', 'not a prefix'), false);
  assert.equal(inSubnet('192.0.2.10', '192.0.2.0/33'), false);
});

const settings = { subnet: '192.0.2.0/24', server_ip: '192.0.2.20', gateway: '192.0.2.1', pool_start: '192.0.2.100', pool_end: '192.0.2.200', lease_seconds: 600 };

test('validateReservation accepts a name-only reservation and a static address outside the pool', () => {
  const named = validateReservation({ mac: '02-00-5E-01-02-03', hostname: 'printer' }, settings);
  assert.deepEqual(named, { ok: true, value: { mac: '02:00:5e:01:02:03', ip: '', hostname: 'printer', note: '' } });

  const fixed = validateReservation({ mac: '02:00:5e:01:02:04', ip: '192.0.2.50', hostname: 'nas', note: 'the printer by the door' }, settings);
  assert.equal(fixed.ok, true);
  assert.equal(fixed.value.ip, '192.0.2.50');
});

// This is the rule that matters most: an address inside the pool can be
// handed out twice, once because it is reserved and once because the pool
// walked onto it.
test('validateReservation refuses an address inside the dynamic pool, and says why', () => {
  const r = validateReservation({ mac: '02:00:5e:01:02:03', ip: '192.0.2.150' }, settings);
  assert.equal(r.ok, false);
  assert.equal(r.field, 'ip');
  assert.match(r.error, /pool/i);
  assert.match(r.error, /two devices/i);
});

test('validateReservation refuses the other ways to break addressing', () => {
  const cases = [
    [{ mac: '' }, 'mac', /MAC/i],
    [{ mac: 'nope' }, 'mac', /MAC/i],
    [{ mac: '02:00:5e:01:02:03', ip: 'nope' }, 'ip', /IPv4/i],
    [{ mac: '02:00:5e:01:02:03', ip: '198.51.100.5' }, 'ip', /not inside the LAN/i],
    [{ mac: '02:00:5e:01:02:03', ip: '192.0.2.20' }, 'ip', /Shepherd's own/i],
    [{ mac: '02:00:5e:01:02:03', ip: '192.0.2.1' }, 'ip', /router's own/i],
    [{ mac: '02:00:5e:01:02:03', hostname: '-bad' }, 'hostname', /hyphen/i],
    [{ mac: '02:00:5e:01:02:03', hostname: 'a'.repeat(64) }, 'hostname', /63/],
    [{ mac: '02:00:5e:01:02:03', note: 'x'.repeat(201) }, 'note', /200/],
  ];
  for (const [input, field, re] of cases) {
    const r = validateReservation(input, settings);
    assert.equal(r.ok, false, JSON.stringify(input));
    assert.equal(r.field, field, JSON.stringify(input));
    assert.match(r.error, re, JSON.stringify(input));
  }
});

test('validateReservation checks only what the settings supply', () => {
  // With no addressing known yet -- the mode has never been turned on -- a
  // reservation is still worth saving, so only the MAC is required.
  const r = validateReservation({ mac: '02:00:5e:01:02:03', ip: '198.51.100.5' }, {});
  assert.equal(r.ok, true);
});

test('modeLabel names the three positions', () => {
  assert.equal(modeLabel('off'), 'Off');
  assert.equal(modeLabel('observe'), 'Watching');
  assert.equal(modeLabel('serve'), 'Serving');
  assert.equal(modeLabel(undefined), 'Off');
});

// The screen must never read "on" while something is stopping it: the live
// install's own lesson from Watch mode's "steered and healthy".
test('stateSummary never claims to be doing something it is not', () => {
  assert.match(stateSummary({ available: false }).text, /not configured/i);
  assert.match(stateSummary({ available: true, status: { mode: 'off' } }).text, /^Off\./);

  const watching = stateSummary({ available: true, status: { mode: 'observe' } });
  assert.match(watching.text, /cannot answer/i);
  assert.equal(watching.tone, 'good');

  const blocked = stateSummary({ available: true, status: { mode: 'serve', serving: false, blocked: 'another DHCP server is answering from 192.0.2.1' } });
  assert.equal(blocked.tone, 'warn');
  assert.match(blocked.text, /another DHCP server/);

  const leasingOnly = stateSummary({ available: true, status: { mode: 'serve', serving: true, routing: false } });
  assert.match(leasingOnly.text, /router's own address/);
  assert.match(leasingOnly.text, /Nothing is on Shepherd's data path/);

  const routeBlocked = stateSummary({ available: true, status: { mode: 'serve', serving: true, routing: false, routing_blocked: 'the kill switch is pulled' } });
  assert.equal(routeBlocked.tone, 'warn');
  assert.match(routeBlocked.text, /kill switch/);

  const routing = stateSummary({ available: true, status: { mode: 'serve', serving: true, routing: true, routed_count: 1 } });
  assert.match(routing.text, /routing 1 device through/);
  assert.match(stateSummary({ available: true, status: { mode: 'serve', serving: true, routing: true, routed_count: 4 } }).text, /4 devices/);
});

test('consequences names every cost, in the owner\'s own terms', () => {
  const list = consequences({ gateway: '192.0.2.1', lease_seconds: 600 });
  const all = list.map((c) => c.title + ' ' + c.body).join('\n');
  for (const re of [/router's DHCP must be off/i, /two NATs/i, /NAT type/i, /load-bearing/i, /IPv6/i, /10 minutes/]) {
    assert.match(all, re);
  }
  assert.ok(list.every((c) => c.title && c.body), 'every consequence has a title and a body');
  // It must read sensibly before the mode has ever been configured.
  assert.match(consequences({}).map((c) => c.body).join(' '), /your router/);
});

test('sortLeases puts routed first, then active, then by address, with expired last', () => {
  const rows = [
    { ip: '192.0.2.120', mac: 'a', expired: true, routed: true },
    { ip: '192.0.2.110', mac: 'b', expired: false, routed: false },
    { ip: '192.0.2.105', mac: 'c', expired: false, routed: true },
    { ip: '192.0.2.101', mac: 'd', expired: false, routed: false },
  ];
  assert.deepEqual(sortLeases(rows).map((r) => r.mac), ['c', 'd', 'b', 'a']);
  assert.deepEqual(sortLeases([]), []);
  assert.deepEqual(sortLeases(undefined), []);
});

test('filterLeases matches anything on the row', () => {
  const rows = [
    { mac: '02:00:5e:01:02:03', ip: '192.0.2.101', hostname: 'printer', vendor_class: 'MSFT 5.0' },
    { mac: '02:00:5e:01:02:04', ip: '192.0.2.102', hostname: 'tv', reason: 'game consoles are left on the gateway' },
  ];
  assert.equal(filterLeases(rows, 'printer').length, 1);
  assert.equal(filterLeases(rows, '192.0.2.102')[0].hostname, 'tv');
  assert.equal(filterLeases(rows, 'MSFT').length, 1);
  assert.equal(filterLeases(rows, 'console').length, 1);
  assert.equal(filterLeases(rows, '').length, 2);
  assert.equal(filterLeases(rows, 'nothing').length, 0);
});

test('leaseBody pre-fills a reservation from what the device already holds', () => {
  assert.deepEqual(leaseBody({ mac: '02-00-5E-01-02-03', ip: '192.0.2.50', hostname: 'nas' }),
    { mac: '02:00:5e:01:02:03', ip: '192.0.2.50', hostname: 'nas', note: '' });
  assert.deepEqual(leaseBody(null), { mac: '', ip: '', hostname: '', note: '' });
});

test('originLabel distinguishes a lease Shepherd gave from one it only watched', () => {
  assert.equal(originLabel('observed'), 'from your router');
  assert.equal(originLabel('shepherd'), 'from Shepherd');
  assert.equal(originLabel(''), 'from Shepherd');
});
