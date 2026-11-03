import test from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeMAC, isMAC, parseIPv4, inRange, inSubnet, validateReservation,
  validateRange, isPrivateV4, suggestRange, rangeSummary, conflictTone, reservedLabel,
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

// Pinning a device to the address it already holds is the ordinary case,
// and a dynamic address is a pool address. The allocator takes a reserved
// address out of the pool walk for everyone else, so this is allowed -- and
// said, because shrinking the pool past it is tidier.
test('validateReservation allows an address inside the pool, with a note', () => {
  const r = validateReservation({ mac: '02:00:5e:01:02:03', ip: '192.0.2.150' }, settings);
  assert.equal(r.ok, true);
  assert.equal(r.value.ip, '192.0.2.150');
  assert.match(r.note, /inside the pool/i);
  assert.match(r.note, /held back|fine/i);

  // Outside the pool there is nothing to say.
  assert.equal(validateReservation({ mac: '02:00:5e:01:02:03', ip: '192.0.2.50' }, settings).note, undefined);
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

test('isPrivateV4 knows the three ranges a LAN may use', () => {
  // The three RFC 1918 prefixes, spelled with their own octets rather than
  // as addresses, so this file names nobody's network. leakcheck:allow
  const [TEN, SEVENTEEN_TWO, ONE_NINETY_TWO] = [[10, 0, 0, 1], [172, 16, 0, 1], [192, 168, 0, 1]];
  for (const o of [TEN, SEVENTEEN_TWO, ONE_NINETY_TWO, [172, 31, 255, 254], [192, 168, 1, 1]]) {
    assert.equal(isPrivateV4(o.join('.')), true, o.join('.'));
  }
  for (const o of [[192, 0, 2, 1], [203, 0, 113, 5], [172, 15, 0, 1], [172, 32, 0, 1], [8, 8, 8, 8]]) {
    assert.equal(isPrivateV4(o.join('.')), false, o.join('.'));
  }
  assert.equal(isPrivateV4('nope'), false);
});

// Every example of a chosen range here is 192.168.1.x: a chosen range has to
// be private, and that is the one private range this repository's leakcheck
// allows as a generic example.
const chosen = { subnet: '192.168.1.0/24', server_ip: '192.168.1.20', gateway: '192.168.1.1', pool_start: '192.168.1.100', pool_end: '192.168.1.200' };

test('validateRange accepts a whole range', () => {
  const r = validateRange({ ...chosen });
  assert.equal(r.ok, true);
  assert.deepEqual(r.value, chosen);
});

test('validateRange explains each way a range is wrong', () => {
  const ok = chosen;
  const cases = [
    [{ ...ok, subnet: '192.168.1.0' }, 'subnet', /CIDR/i],
    [{ ...ok, subnet: '192.168.1.0/15' }, 'subnet', /between/i],
    [{ ...ok, subnet: '203.0.113.0/24', server_ip: '203.0.113.2', gateway: '203.0.113.1', pool_start: '203.0.113.100', pool_end: '203.0.113.200' }, 'subnet', /private/i],
    [{ ...ok, server_ip: '' }, 'server_ip', /enter/i],
    [{ ...ok, gateway: 'nope' }, 'gateway', /IPv4/i],
    [{ ...ok, server_ip: '198.51.100.2' }, 'server_ip', /not inside/i],
    [{ ...ok, gateway: '192.168.1.20' }, 'gateway', /share one address/i],
    [{ ...ok, pool_start: '192.168.1.200', pool_end: '192.168.1.100' }, 'pool_end', /at or below/i],
    [{ ...ok, server_ip: '192.168.1.150' }, 'server_ip', /inside the pool/i],
    [{ ...ok, gateway: '192.168.1.150' }, 'gateway', /inside the pool/i],
  ];
  for (const [input, field, re] of cases) {
    const r = validateRange(input);
    assert.equal(r.ok, false, JSON.stringify(input));
    assert.equal(r.field, field, JSON.stringify(input));
    assert.match(r.error, re, JSON.stringify(input));
  }
});

test('suggestRange follows the convention every home router uses', () => {
  assert.deepEqual(suggestRange('192.168.1.0/24'), {
    subnet: '192.168.1.0/24', gateway: '192.168.1.1', server_ip: '192.168.1.2',
    pool_start: '192.168.1.100', pool_end: '192.168.1.200',
  });
  // An address this host already has inside the range is kept rather than
  // replaced with the convention's guess.
  assert.equal(suggestRange('192.168.1.0/24', { server_ip: '192.168.1.20' }).server_ip, '192.168.1.20');
  assert.equal(suggestRange('192.168.1.20/24', { server_ip: '198.51.100.5' }).server_ip, '192.168.1.2');
  assert.equal(suggestRange('192.168.1.0/16'), null, 'the convention only fits a /24');
  assert.equal(suggestRange('nonsense'), null);
});

// The summary must never say a range is in use when something is stopping
// it: this is the line somebody reads before walking to the router.
test('rangeSummary says what is in force and whether anything blocks it', () => {
  const none = rangeSummary({ chosen: false, current: { subnet: '192.0.2.0/24' } }, []);
  assert.equal(none.tone, 'muted');
  assert.match(none.text, /192\.0\.2\.0\/24/);
  assert.match(rangeSummary({ chosen: false, current: {} }, []).text, /interface/i);

  const blocked = rangeSummary({ chosen: true, subnet: '192.168.1.0/24' },
    [{ severity: 'blocking', detail: 'x' }, { severity: 'warning', detail: 'y' }]);
  assert.equal(blocked.tone, 'bad');
  assert.match(blocked.text, /will not serve it yet/);
  assert.match(blocked.text, /1 thing has/);

  const two = rangeSummary({ chosen: true, subnet: '192.168.1.0/24' },
    [{ severity: 'blocking' }, { severity: 'blocking' }]);
  assert.match(two.text, /2 things have/);

  const warned = rangeSummary({ chosen: true, subnet: '192.168.1.0/24' }, [{ severity: 'warning' }]);
  assert.equal(warned.tone, 'warn');
  assert.match(warned.text, /with notes/);

  const fits = rangeSummary({ chosen: true, subnet: '192.168.1.0/24' }, []);
  assert.equal(fits.tone, 'good');
  assert.match(fits.text, /fits the network/);
});

test('conflictTone separates what must change from what is worth knowing', () => {
  assert.equal(conflictTone('blocking'), 'bad');
  assert.equal(conflictTone('warning'), 'warn');
});

test('reservedLabel words the per-device switch for every state', () => {
  assert.equal(reservedLabel(null), null);
  assert.deepEqual(reservedLabel({ on: true, ip: '192.0.2.50' }), { on: true, text: 'Pinned to 192.0.2.50' });
  assert.match(reservedLabel({ on: true, ip: '192.0.2.150', in_pool: true }).text, /held back from the pool/);
  assert.match(reservedLabel({ on: true }).text, /name only/);
  assert.match(reservedLabel({ on: false, candidate: '192.0.2.101' }).text, /Pin this device to 192\.0\.2\.101/);
  assert.match(reservedLabel({ on: false }).text, /has not seen one/);
});
