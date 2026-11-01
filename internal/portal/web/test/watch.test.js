import test from 'node:test';
import assert from 'node:assert/strict';
import {
  WATCH_CHOICES, watchSwitchOf, watchSwitchLabel, relayLabel, relayExplanation, statusHeadline, ipv6Line,
  fmtBitsPerSecond, fmtPacketsPerSecond, fmtTotalBytes, deviceBadge, summarize, sortByTraffic,
  watchedDevices, historyLine, canKill,
} from '../js/watch.js';

test('the Watch switch defaults to automatic and rejects anything else', () => {
  assert.equal(watchSwitchOf(null), 'auto');
  assert.equal(watchSwitchOf({}), 'auto');
  assert.equal(watchSwitchOf({ watch: 'off' }), 'off');
  assert.equal(watchSwitchOf({ watch: 'on' }), 'on');
  assert.equal(watchSwitchOf({ watch: 'maybe' }), 'auto');
  assert.equal(watchSwitchOf({ watch: 7 }), 'auto');
  assert.equal(watchSwitchLabel('off'), 'Never watch');
  assert.equal(watchSwitchLabel('nope'), 'Automatic');
  assert.equal(WATCH_CHOICES.length, 3);
  for (const c of WATCH_CHOICES) assert.ok(c.label && c.text, c.id);
});

test('relay names are in the owner’s words, and unknown ones say nothing', () => {
  assert.match(relayLabel('xdp-native'), /kernel/i);
  assert.match(relayLabel('xdp-generic'), /generic/i);
  assert.match(relayLabel('userspace'), /userspace/i);
  assert.equal(relayLabel('something-new'), '');
  assert.equal(relayLabel(undefined), '');
  assert.match(relayExplanation('xdp-native'), /driver/i);
  assert.equal(relayExplanation('nope'), '');
});

test('statusHeadline covers every phase, including the ones that mean nothing is watched', () => {
  assert.deepEqual(statusHeadline({ enabled: false }).tone, 'muted');
  assert.match(statusHeadline({ enabled: false }).text, /DNS filtering/);
  assert.equal(statusHeadline(null).tone, 'muted');

  const killed = statusHeadline({ enabled: true, armed: false, phase: 'running' });
  assert.equal(killed.tone, 'bad');
  assert.match(killed.text, /kill switch/i);

  const one = statusHeadline({ enabled: true, armed: true, phase: 'running', relay: 'xdp-native', steered: 1 });
  assert.equal(one.tone, 'good');
  assert.match(one.text, /1 device/);
  const many = statusHeadline({ enabled: true, armed: true, phase: 'running', relay: 'userspace', steered: 4 });
  assert.match(many.text, /4 devices/);
  const none = statusHeadline({ enabled: true, armed: true, phase: 'running', steered: 0 });
  assert.equal(none.tone, 'warn');

  assert.match(statusHeadline({ enabled: true, armed: true, phase: 'starting', reason: 'attaching the relay' }).text, /attaching/);
  const bad = statusHeadline({ enabled: true, armed: true, phase: 'unavailable', reason: 'operation not permitted' });
  assert.equal(bad.tone, 'bad');
  assert.match(bad.text, /not permitted/);
  assert.match(bad.text, /DNS filtering is unaffected/);
  assert.equal(statusHeadline({ enabled: true, armed: true, phase: 'disabled', reason: 'no' }).tone, 'muted');
});

test('throughput is formatted in the units people read speeds in', () => {
  assert.equal(fmtBitsPerSecond(0), '0 bit/s');
  assert.equal(fmtBitsPerSecond(-5), '0 bit/s');
  assert.equal(fmtBitsPerSecond(null), '0 bit/s');
  assert.equal(fmtBitsPerSecond(100), '800 bit/s');
  assert.equal(fmtBitsPerSecond(125), '1.00 kbit/s');
  // The live trial's own numbers: 207 MB/s was reported as ~1.6 Gbit/s and
  // 221 MB/s as ~1.77 Gbit/s (docs/WATCH.md).
  assert.equal(fmtBitsPerSecond(207e6), '1.66 Gbit/s');
  assert.equal(fmtBitsPerSecond(221e6), '1.77 Gbit/s');
  assert.equal(fmtBitsPerSecond(12.5e6), '100 Mbit/s');
  assert.equal(fmtBitsPerSecond(1.25e6), '10.0 Mbit/s');

  assert.equal(fmtPacketsPerSecond(0), '0 pkt/s');
  assert.equal(fmtPacketsPerSecond(950), '950 pkt/s');
  assert.equal(fmtPacketsPerSecond(1500), '1.5k pkt/s');
  assert.equal(fmtPacketsPerSecond(167000), '167k pkt/s');
  assert.equal(fmtPacketsPerSecond(1.8e6), '1.80M pkt/s');
  assert.equal(fmtTotalBytes(0), '0 B');
  assert.match(fmtTotalBytes(5.39e9), /GB$/);
});

test('deviceBadge says nothing at all when Watch mode is not wired in', () => {
  assert.equal(deviceBadge({ id: 'd1' }), null);
  assert.equal(deviceBadge(null), null);
  assert.equal(deviceBadge({ watch_state: { state: 'something-new' } }), null);
});

test('deviceBadge names each state the engine can report', () => {
  const healthy = deviceBadge({ watch_state: { state: 'steered', healthy: true } });
  assert.equal(healthy.label, 'Watching');
  assert.equal(healthy.cls, 'good');

  const quiet = deviceBadge({ watch_state: { state: 'steered', healthy: false } });
  assert.equal(quiet.cls, 'warn');
  assert.match(quiet.title, /stops watching it on its own/);

  const waiting = deviceBadge({ watch_state: { state: 'pending', reason: 'failed open 1 time; retrying in 30 s' } });
  assert.equal(waiting.label, 'Waiting');
  assert.match(waiting.title, /failed open/);

  const idle = deviceBadge({ watch_state: { state: 'idle', reason: 'not seen for 3 h' } });
  assert.equal(idle.cls, 'muted');
  assert.match(idle.title, /not seen/);

  // A standing refusal reads differently depending on whose decision it was.
  const infra = deviceBadge({ watch: 'auto', watch_state: { state: 'skipped', reason: 'network infrastructure (router/infrastructure)' } });
  assert.equal(infra.label, 'Never watched');
  assert.match(infra.title, /infrastructure/);
  const off = deviceBadge({ watch: 'off', watch_state: { state: 'skipped', reason: 'Watch switched off for this device' } });
  assert.equal(off.label, 'Watch off');
  assert.match(off.title, /You switched/);

  const na = deviceBadge({ watch_state: { state: 'unavailable', reason: 'Watch mode is not running' } });
  assert.equal(na.label, 'Unavailable');
  assert.match(na.title, /not running/);
  // A reason the server did not give still produces a usable tooltip.
  assert.ok(deviceBadge({ watch_state: { state: 'pending' } }).title);
  assert.ok(deviceBadge({ watch_state: { state: 'idle' } }).title);
  assert.ok(deviceBadge({ watch_state: { state: 'skipped' } }).title);
  assert.ok(deviceBadge({ watch_state: { state: 'unavailable' } }).title);
});

test('summarize counts states, and unhealthy watched devices separately', () => {
  const s = summarize([
    { state: 'steered', healthy: true }, { state: 'steered', healthy: false },
    { state: 'pending' }, { state: 'idle' }, { state: 'skipped' }, { state: 'skipped' },
    { state: 'unavailable' }, { state: 'nonsense' },
  ]);
  assert.deepEqual(s, { steered: 2, pending: 1, idle: 1, skipped: 2, unavailable: 1, unhealthy: 1 });
  assert.deepEqual(summarize(null), { steered: 0, pending: 0, idle: 0, skipped: 0, unavailable: 0, unhealthy: 0 });
});

test('sortByTraffic puts the busiest device first and falls back to totals then name', () => {
  const list = [
    { name: 'Quiet', bytes_per_second: 0, bytes_relayed: 10 },
    { name: 'Busy', bytes_per_second: 500 },
    { name: 'Idle B', bytes_relayed: 0 },
    { name: 'Idle A', bytes_relayed: 0 },
  ];
  assert.deepEqual(sortByTraffic(list).map((d) => d.name), ['Busy', 'Quiet', 'Idle A', 'Idle B']);
  assert.deepEqual(sortByTraffic(null), []);
  assert.equal(list[0].name, 'Quiet', 'sortByTraffic must not mutate its input');
});

test('watchedDevices keeps only what is actually being relayed', () => {
  assert.deepEqual(watchedDevices([{ state: 'steered', name: 'a' }, { state: 'idle', name: 'b' }]).map((d) => d.name), ['a']);
  assert.deepEqual(watchedDevices(undefined), []);
});

test('historyLine falls back to the MAC when the device is gone', () => {
  const l = historyLine({ name: 'Phone', mac: '02:00:5e:00:00:10', reason: 'panic stop', time: '2026-10-30T12:00:00Z' });
  assert.equal(l.who, 'Phone');
  assert.equal(l.why, 'panic stop');
  assert.ok(Number.isFinite(l.at));
  assert.equal(historyLine({ mac: '02:00:5e:00:00:10' }).who, '02:00:5e:00:00:10');
  assert.equal(historyLine({}).who, 'a device');
  assert.ok(Number.isNaN(historyLine({}).at));
});

test('canKill only when there is something to stop', () => {
  assert.equal(canKill({ enabled: true, armed: true, phase: 'running' }), true);
  assert.equal(canKill({ enabled: true, armed: true, phase: 'starting' }), true);
  assert.equal(canKill({ enabled: true, armed: true, phase: 'unavailable' }), false);
  assert.equal(canKill({ enabled: true, armed: false, phase: 'running' }), false);
  assert.equal(canKill({ enabled: false, armed: true, phase: 'running' }), false);
  assert.equal(canKill(null), false);
});

test('ipv6Line reads asked-for-but-idle as normal, not as a fault', () => {
  assert.equal(ipv6Line({ ipv6_wanted: false }).tone, 'muted');
  assert.match(ipv6Line({ ipv6_wanted: false }).text, /IPv4 only/);
  assert.equal(ipv6Line(null).tone, 'muted');

  // Assembled rather than written out, so no link-local literal is in the
  // source (scripts/leakcheck).
  const ll = 'fe' + '80::1';
  const on = ipv6Line({ ipv6_wanted: true, ipv6: true, gateway_link_local: ll });
  assert.equal(on.tone, 'good');
  assert.ok(on.text.includes(ll));
  assert.match(ipv6Line({ ipv6_wanted: true, ipv6: true }).text, /link-local/);

  const idle = ipv6Line({ ipv6_wanted: true, ipv6: false, ipv6_reason: 'this network has no global IPv6 route (unique-local addresses only)' });
  assert.equal(idle.tone, 'warn');
  assert.match(idle.text, /idle/);
  assert.match(idle.text, /no global IPv6 route/);
  assert.match(ipv6Line({ ipv6_wanted: true }).text, /cannot carry it/);
});

test('a device steered for both families says so on its badge', () => {
  const both = deviceBadge({ watch_state: { state: 'steered', healthy: true, families: ['ipv4', 'ipv6'] } });
  assert.equal(both.label, 'Watching v4+v6');
  assert.match(both.title, /both IPv4 and IPv6/);
  const v4 = deviceBadge({ watch_state: { state: 'steered', healthy: true, families: ['ipv4'] } });
  assert.equal(v4.label, 'Watching');
  assert.equal(deviceBadge({ watch_state: { state: 'steered', healthy: true } }).label, 'Watching');
  // A device with nothing relayed yet reads the same either way.
  assert.equal(deviceBadge({ watch_state: { state: 'steered', healthy: false, families: ['ipv4', 'ipv6'] } }).label, 'No traffic yet');
});
