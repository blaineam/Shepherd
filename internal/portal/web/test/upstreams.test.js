import test from 'node:test';
import assert from 'node:assert/strict';
import { isIPv4, isIPv6, isIP, classifyAddr, move, presetVariants, parseBootstrap, healthLabel, isEncrypted, KIND_LABEL } from '../js/upstreams.js';

test('IP detection', () => {
  assert.ok(isIPv4('9.9.9.10') && isIPv4('255.255.255.255'));
  assert.ok(!isIPv4('256.1.1.1') && !isIPv4('1.2.3') && !isIPv4('a.b.c.d'));
  for (const ok of ['2001:db8::1', '::1', '::', 'fe80::1', '2001:db8:0:0:0:0:0:1', '::ffff:192.0.2.1']) assert.ok(isIPv6(ok), ok); // leakcheck:allow syntax fixtures, not real addresses
  for (const bad of ['', '1.2.3.4', '2001:db8::1::2', 'gggg::1', '1:2:3:4:5:6:7', '1:2:3:4:5:6:7:8:9', '::ffff:999.1.1.1']) assert.ok(!isIPv6(bad), bad); // leakcheck:allow syntax fixtures, not real addresses
  assert.ok(isIP('1.1.1.1') && isIP('::1') && !isIP('example.com'));
});

test('classifyAddr: plain forms', () => {
  assert.equal(classifyAddr('9.9.9.10').kind, 'udp');
  assert.ok(classifyAddr('9.9.9.10:5353').hint.includes('5353'));
  assert.ok(classifyAddr('[2001:db8::1]:53').ok);
  assert.ok(classifyAddr('[2001:db8::1]').ok);
  const bare = classifyAddr('2001:db8::1');
  assert.ok(bare.ok === false && /brackets/.test(bare.error));
  assert.ok(!classifyAddr('9.9.9.10:99999').ok);
  assert.ok(!classifyAddr('999.1.1.1').ok);
  assert.ok(!classifyAddr('dns.example.net').ok);
  assert.match(classifyAddr('dns.example.net').error, /tls:\/\/dns\.example\.net/);
  assert.ok(!classifyAddr('[nope]:53').ok);
});

test('classifyAddr: schemes', () => {
  assert.equal(classifyAddr('tcp://9.9.9.10').kind, 'tcp');
  assert.ok(!classifyAddr('tcp://dns.example.net').ok);
  assert.equal(classifyAddr('tls://dns.example.net').kind, 'dot');
  assert.ok(classifyAddr('tls://dns.example.net:853').hint.includes('853'));
  assert.ok(classifyAddr('tls://192.0.2.1').ok);
  assert.ok(!classifyAddr('tls://').ok);
  assert.equal(classifyAddr('https://dns.example.net/dns-query').kind, 'doh');
  assert.ok(classifyAddr('https://dns.example.net').hint.includes('/dns-query'));
  assert.ok(classifyAddr('https://192.0.2.1/dns-query').ok);
  assert.ok(!classifyAddr('https:///x').ok);
  assert.match(classifyAddr('ftp://x').error, /Unsupported/);
  assert.ok(!classifyAddr('').ok && classifyAddr('').hint);
  assert.match(classifyAddr('a b').error, /spaces/);
  assert.equal(classifyAddr('  TLS://dns.example.net ').kind, 'dot');
});

test('labels and encryption flags', () => {
  assert.ok(isEncrypted('dot') && isEncrypted('doh') && !isEncrypted('udp') && !isEncrypted('tcp'));
  assert.equal(KIND_LABEL.dot, 'DoT');
});

test('move reorders immutably and ignores bad indexes', () => {
  const a = ['a', 'b', 'c'];
  assert.deepEqual(move(a, 0, 2), ['b', 'c', 'a']);
  assert.deepEqual(move(a, 2, 0), ['c', 'a', 'b']);
  assert.equal(move(a, 1, 1), a);
  assert.equal(move(a, -1, 1), a);
  assert.equal(move(a, 0, 3), a);
  assert.deepEqual(a, ['a', 'b', 'c']);
});

test('presetVariants offers plain, DoH and DoT', () => {
  const v = presetVariants({ plain: ['203.0.113.1', '203.0.113.2', '203.0.113.3'], doh: 'https://x.example.net/dns-query', dot: 'x.example.net' });
  assert.deepEqual(v.map((x) => [x.kind, x.addr]), [['udp', '203.0.113.1'], ['udp', '203.0.113.2'], ['doh', 'https://x.example.net/dns-query'], ['dot', 'tls://x.example.net']]);
  assert.equal(presetVariants({ dot: 'tls://y.example.net' })[0].addr, 'tls://y.example.net');
  assert.deepEqual(presetVariants({}), []);
});

test('parseBootstrap separates good and bad entries', () => {
  assert.deepEqual(parseBootstrap('9.9.9.9, 1.1.1.1  [2001:db8::1]'), { servers: ['9.9.9.9', '1.1.1.1', '[2001:db8::1]'], bad: [] });
  assert.deepEqual(parseBootstrap('9.9.9.9 dns.example.net').bad, ['dns.example.net']);
  assert.deepEqual(parseBootstrap(''), { servers: [], bad: [] });
});

test('healthLabel', () => {
  assert.equal(healthLabel({ healthy: true, rtt_ms: 14.6 }), '15 ms');
  assert.equal(healthLabel({ healthy: true }), 'ok');
  assert.equal(healthLabel({ healthy: false, consecutive_failures: 3 }), 'failing (3)');
  assert.equal(healthLabel({ healthy: false }), 'down');
});
