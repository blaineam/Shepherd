import { test } from 'node:test';
import assert from 'node:assert/strict';
import { KINDS, connectionState, bandwidthNote, toggleLabel } from '../js/connections.js';

const poll = '2026-11-21T12:00:00Z';

test('every kind of connection is listed once, Firewalla first', () => {
  assert.deepEqual(KINDS.map((k) => k.id), ['firewalla', 'unifi_api', 'eero', 'unifi']);
  for (const k of KINDS) assert.ok(k.title && k.what);
});

test('a connection that is not stored says so', () => {
  assert.deepEqual(connectionState('firewalla', null), { tone: 'muted', text: 'Not connected.' });
  assert.equal(connectionState('eero', { eero: { connected: false } }).text, 'Not connected.');
});

test('a dashboard connection reports what the hub is doing with it', () => {
  const fw = { connected: true, enabled: true, address: 'https://a.firewalla.net' };
  assert.match(connectionState('firewalla', { firewalla: { ...fw, enabled: false } }).text, /switched off/);
  assert.equal(connectionState('firewalla', { firewalla: fw }).text, 'Connected. Starting.');
  assert.deepEqual(connectionState('firewalla', { firewalla: fw, dashboard_error: 'bad address' }), { tone: 'bad', text: 'bad address' });

  const dash = (status, read_only = true) => ({ firewalla: fw, dashboard: { name: 'firewalla', status, read_only } });
  assert.match(connectionState('firewalla', dash({})).text, /Waiting for the first reading/);
  assert.equal(connectionState('firewalla', dash({ needs_token: true })).tone, 'bad');
  const warn = connectionState('firewalla', dash({ last_poll: poll, errors: { flows: 'HTTP 500' } }));
  assert.equal(warn.tone, 'warn');
  assert.match(warn.text, /Could not read flows: HTTP 500/);
  assert.match(connectionState('firewalla', dash({ last_poll: poll })).text, /Reading https:\/\/a\.firewalla\.net \(read only\)/);
  assert.match(connectionState('firewalla', dash({ last_poll: poll }, false)).text, /changes allowed/);
});

test('only one dashboard runs, and the other connection says which', () => {
  const conns = {
    unifi_api: { connected: true, enabled: true, address: 'https://192.0.2.1' },
    dashboard: { name: 'firewalla', status: { last_poll: poll } },
  };
  const st = connectionState('unifi_api', conns);
  assert.equal(st.tone, 'muted');
  assert.match(st.text, /Firewalla is the one in use/);
  const other = connectionState('firewalla', { firewalla: { connected: true, enabled: true }, dashboard: { name: 'unifi', status: {} } });
  assert.match(other.text, /UniFi console is the one in use/);
  assert.match(connectionState('unifi_api', { unifi_api: { connected: true, enabled: true }, dashboard: { name: 'unifi', status: { last_poll: poll } } }).text, /Reading UniFi console/);
});

test('eero stays useful for names when something more exact supplies bandwidth', () => {
  const eero = { connected: true, enabled: true, network: 'n1' };
  assert.match(connectionState('eero', { eero: { connected: true, enabled: true, network: '' } }).text, /no network is chosen/);
  const beside = connectionState('eero', { eero, bandwidth: { source: 'firewalla', last_poll: poll } });
  assert.equal(beside.tone, 'good');
  assert.match(beside.text, /device names\. Bandwidth comes from your firewalla/);
  assert.equal(connectionState('eero', { eero }).text, 'Connected for device names.');
  assert.match(connectionState('eero', { eero: { ...eero, enabled: false } }).text, /Bandwidth reading is switched off/);

  const bw = (extra) => ({ eero, bandwidth: { source: 'eero', ...extra } });
  assert.match(connectionState('eero', bw({ last_poll: poll, matched: 9, devices_seen: 12 })).text, /Reading bandwidth for 9 of 12 devices/);
  assert.match(connectionState('eero', bw({})).text, /Waiting for the first reading/);
  assert.equal(connectionState('eero', bw({ needs_sign_in: true })).tone, 'bad');
  assert.match(connectionState('eero', bw({ last_error: 'timeout' })).text, /Could not read it: timeout/);
});

test('the UniFi controller sign-in is read for bandwidth only', () => {
  const unifi = { connected: true, enabled: true, address: 'https://192.0.2.1:8443' };
  assert.match(connectionState('unifi', { unifi, bandwidth: { source: 'unifi', last_poll: poll, matched: 3, devices_seen: 4 } }).text, /3 of 4 devices/);
  assert.match(connectionState('unifi', { unifi: { ...unifi, enabled: false } }).text, /https:\/\/192\.0\.2\.1:8443, but switched off/);
  assert.match(connectionState('unifi', { unifi: { connected: true, enabled: false } }).text, /the controller, but switched off/);
  assert.equal(connectionState('unifi', { unifi }).text, 'Connected. Starting.');
});

test('the bandwidth note warns that a Firewalla is minutes behind', () => {
  assert.equal(bandwidthNote(null), '');
  assert.equal(bandwidthNote({ bandwidth: {} }), '');
  assert.match(bandwidthNote({ bandwidth: { source: 'firewalla' } }), /several minutes behind/);
  assert.match(bandwidthNote({ bandwidth: { source: 'eero', estimated: true } }), /your eero, as estimates/);
  assert.match(bandwidthNote({ bandwidth: { source: 'unifi' } }), /exact byte counts/);
});

test('the switch is worded for what it turns off', () => {
  assert.equal(toggleLabel('eero', null), '');
  assert.equal(toggleLabel('eero', { connected: false }), '');
  assert.equal(toggleLabel('eero', { connected: true, enabled: true }), 'Stop reading bandwidth');
  assert.equal(toggleLabel('eero', { connected: true, enabled: false }), 'Read bandwidth');
  assert.equal(toggleLabel('firewalla', { connected: true, enabled: true }), 'Switch off');
  assert.equal(toggleLabel('firewalla', { connected: true, enabled: false }), 'Switch on');
});
