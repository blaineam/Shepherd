// Watch mode's pure logic: how the engine's status and each device's
// Watch state are worded, and how relayed throughput is formatted. The
// server (internal/watch) decides everything; nothing here guesses a
// state, it only names what came back. Kept separate from watchview.js so
// all of it is unit-tested (test/watch.test.js) with no DOM.
import { fmtBytes } from './weight.js';

// The three positions of a device's own Watch switch, matching
// devices.WatchMode in Go.
export const WATCH_CHOICES = [
  { id: 'auto', label: 'Automatic', text: 'Watched unless Shepherd has a reason not to: never infrastructure, never an excluded device.' },
  { id: 'on', label: 'Always watch', text: 'Watched even if it looks like infrastructure. An excluded device is still never watched.' },
  { id: 'off', label: 'Never watch', text: 'Left out of Watch mode. Its traffic is never steered through Shepherd.' },
];

export const watchSwitchOf = (d) => {
  const v = d && typeof d.watch === 'string' ? d.watch : 'auto';
  return WATCH_CHOICES.some((c) => c.id === v) ? v : 'auto';
};

export const watchSwitchLabel = (id) => (WATCH_CHOICES.find((c) => c.id === id) || WATCH_CHOICES[0]).label;

// The relay actually carrying the traffic, in the owner's words rather
// than the engine's identifiers.
const RELAYS = {
  'xdp-native': { short: 'In-kernel (XDP)', long: 'In the network card’s own driver, before the packet reaches the kernel’s network stack. The fastest path.' },
  'xdp-generic': { short: 'In-kernel (XDP, generic)', long: 'In the kernel, just after the packet arrives. Slower than the driver path because the driver does not support XDP, but it still never reaches Shepherd’s own process.' },
  userspace: { short: 'Userspace relay', long: 'Shepherd copies each packet out and back in itself, across several parallel workers. Used when the in-kernel relay cannot load.' },
};

export function relayLabel(relay) {
  return (RELAYS[relay] || {}).short || '';
}

export function relayExplanation(relay) {
  return (RELAYS[relay] || {}).long || '';
}

// One line about the engine, with a tone for its colour. This is what the
// panel leads with, so it has to be true for every phase including the
// ones that mean "nothing is being watched".
export function statusHeadline(status) {
  const s = status || {};
  if (!s.enabled) return { tone: 'muted', text: 'Watch mode is turned off. Only DNS filtering is protecting this network.' };
  if (!s.armed) return { tone: 'bad', text: 'Stopped by the kill switch. Nothing is being watched until you re-arm it.' };
  switch (s.phase) {
    case 'running': {
      const n = Number(s.steered) || 0;
      const what = n === 1 ? '1 device' : n + ' devices';
      return { tone: n ? 'good' : 'warn', text: n ? 'Watching ' + what + ' through the ' + (relayLabel(s.relay) || 'relay').toLowerCase() + '.' : 'Running, but nothing is being watched yet.' };
    }
    case 'starting':
      return { tone: 'warn', text: 'Starting: ' + (s.reason || 'finding the interface and the gateway') + '.' };
    case 'unavailable':
      return { tone: 'bad', text: 'Not running: ' + (s.reason || 'reason unknown') + '. DNS filtering is unaffected.' };
    default:
      return { tone: 'muted', text: s.reason || 'Watch mode is not available in this build.' };
  }
}

// One line about IPv6 steering, for the status card. IPv6 is opt-in and,
// even when asked for, only engages on a network that has a global IPv6
// route to steer anything to — so "asked for but idle" is a normal,
// expected state that has to read as such rather than as a fault.
export function ipv6Line(status) {
  const s = status || {};
  if (!s.ipv6_wanted) return { tone: 'muted', text: 'Off. Watch mode is steering IPv4 only.' };
  if (s.ipv6) return { tone: 'good', text: 'On, through the router at ' + (s.gateway_link_local || 'its link-local address') + '.' };
  return { tone: 'warn', text: 'Asked for, but idle: ' + (s.ipv6_reason || 'this network cannot carry it') + '.' };
}

// Throughput, in the units people read speeds in. The relay only ever
// sees a device's outbound traffic, so every number here is one-directional
// by construction; the panel says so in words.
export function fmtBitsPerSecond(bytesPerSecond) {
  const bits = (Number(bytesPerSecond) || 0) * 8;
  if (bits <= 0) return '0 bit/s';
  const units = ['bit/s', 'kbit/s', 'Mbit/s', 'Gbit/s', 'Tbit/s'];
  let i = 0;
  let v = bits;
  while (v >= 1000 && i < units.length - 1) { v /= 1000; i++; }
  return (v < 10 && i > 0 ? v.toFixed(2) : v < 100 && i > 0 ? v.toFixed(1) : Math.round(v)) + ' ' + units[i];
}

export function fmtPacketsPerSecond(pps) {
  const n = Number(pps) || 0;
  if (n <= 0) return '0 pkt/s';
  if (n < 1000) return Math.round(n) + ' pkt/s';
  if (n < 1e6) return (n / 1000 < 10 ? (n / 1000).toFixed(1) : Math.round(n / 1000)) + 'k pkt/s';
  return (n / 1e6).toFixed(2) + 'M pkt/s';
}

export const fmtTotalBytes = (n) => fmtBytes(Number(n) || 0);

// The badge for one device, from the engine's own state for it. null means
// Watch mode is not wired in at all, so the column stays empty rather than
// inventing a state.
export function deviceBadge(d) {
  const st = d && d.watch_state;
  if (!st) return null;
  const sw = watchSwitchOf(d);
  const reason = typeof st.reason === 'string' ? st.reason : '';
  switch (st.state) {
    case 'steered': {
      const both = (st.families || []).includes('ipv6');
      return st.healthy
        ? { label: both ? 'Watching v4+v6' : 'Watching', cls: 'good', title: both
          ? 'Traffic from this device is being relayed through Shepherd right now, both IPv4 and IPv6.'
          : 'Traffic from this device is being relayed through Shepherd right now.' }
        : { label: 'No traffic yet', cls: 'warn', title: 'Steered, but nothing has been relayed yet. Shepherd stops watching it on its own if that does not change.' };
    }
    case 'pending':
      return { label: 'Waiting', cls: 'warn', title: reason || 'Waiting to be watched.' };
    case 'idle':
      return { label: 'Not on the network', cls: 'muted', title: reason || 'Not seen recently enough to watch.' };
    case 'skipped':
      return sw === 'off'
        ? { label: 'Watch off', cls: 'muted', title: 'You switched Watch mode off for this device.' }
        : { label: 'Never watched', cls: 'muted', title: reason || 'Shepherd never watches this device.' };
    case 'unavailable':
      return { label: 'Unavailable', cls: 'muted', title: reason || 'Watch mode is not running.' };
    default:
      return null;
  }
}

// How many devices are in each state, for the panel's summary line.
export function summarize(devices) {
  const out = { steered: 0, pending: 0, idle: 0, skipped: 0, unavailable: 0, unhealthy: 0 };
  for (const d of devices || []) {
    if (Object.prototype.hasOwnProperty.call(out, d.state)) out[d.state]++;
    if (d.state === 'steered' && !d.healthy) out.unhealthy++;
  }
  return out;
}

// The devices worth showing in the panel, busiest first: the server
// already sorts by state then name, so this only re-orders the watched
// ones by how much they are actually moving.
export function sortByTraffic(devices) {
  return [...(devices || [])].sort((a, b) => (Number(b.bytes_per_second) || 0) - (Number(a.bytes_per_second) || 0)
    || (Number(b.bytes_relayed) || 0) - (Number(a.bytes_relayed) || 0)
    || String(a.name || '').localeCompare(String(b.name || '')));
}

export const watchedDevices = (devices) => (devices || []).filter((d) => d.state === 'steered');

// One history line: what stopped being watched, and why. The reasons come
// from the engine and the interception library; they are shown as given.
export function historyLine(rec) {
  const r = rec || {};
  return {
    who: r.name || r.mac || 'a device',
    mac: r.mac || '',
    why: r.reason || '',
    at: r.time ? Date.parse(r.time) : NaN,
  };
}

// True when the status means a kill switch would do something.
export const canKill = (s) => !!(s && s.enabled && s.armed && (s.phase === 'running' || s.phase === 'starting'));
