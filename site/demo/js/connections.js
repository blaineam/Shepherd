// Pure helpers for the Connections card on the Router screen
// (connectionsview.js): which routers and firewalls Shepherd can read, what
// each is for, and what each is doing. Nothing here touches the DOM.

// KINDS is every connection Shepherd knows how to make, in the order the
// screen lists them. More than one can be connected at once: a Firewalla
// supplies the dashboard and exact bandwidth while an eero account still
// supplies the names a household typed into its app.
export const KINDS = [
  { id: 'firewalla', title: 'Firewalla', what: 'Requests, alarms, rules, exact bandwidth and device names, read on the box itself or through your MSP account.' },
  { id: 'unifi_api', title: 'UniFi console', what: 'Clients, firewall policies and client blocking, through an Integration API key.' },
  { id: 'eero', title: 'eero', what: 'Device names, and estimated bandwidth when nothing more exact is connected.' },
  { id: 'unifi', title: 'UniFi controller sign-in', what: 'Exact per-device bandwidth from a controller account. A read-only account is enough.' },
];

const title = (id) => (KINDS.find((k) => k.id === id) || { title: id }).title;

// where names what a connection reads: a Firewalla read on the box itself
// has a loopback address, which says nothing to a person.
const where = (id, c) => (c.local ? 'this Firewalla box' : (c.address || title(id)));

// connectionState is one connection in a sentence, with a tone.
export function connectionState(id, conns) {
  const all = conns || {};
  const c = all[id] || {};
  if (!c.connected) return { tone: 'muted', text: 'Not connected.' };
  if (id === 'eero' && !c.network) return { tone: 'warn', text: 'Signed in, but no network is chosen. Disconnect and sign in again.' };
  const dash = all.dashboard || null;
  const bw = all.bandwidth || {};
  if (id === 'firewalla' || id === 'unifi_api') {
    const name = id === 'firewalla' ? 'firewalla' : 'unifi';
    if (!c.enabled) return { tone: 'muted', text: 'Connected to ' + where(id, c) + ', but switched off.' };
    if (dash && dash.name === name) {
      const st = dash.status || {};
      if (st.needs_token) return { tone: 'bad', text: 'The credential was refused. Disconnect and connect again with a new one.' };
      const errs = Object.entries(st.errors || {});
      if (errs.length) return { tone: 'warn', text: 'Could not read ' + errs.map(([k]) => k).join(', ') + ': ' + errs[0][1] };
      if (!st.last_poll) return { tone: 'muted', text: 'Connected to ' + where(id, c) + '. Waiting for the first reading.' };
      return { tone: 'good', text: 'Reading ' + where(id, c) + (c.local ? ' directly' : '') + (dash.read_only ? ' (read only).' : ' (changes allowed).') };
    }
    if (all.dashboard_error) return { tone: 'bad', text: all.dashboard_error };
    if (dash) return { tone: 'muted', text: 'Connected, but the ' + title(dash.name === 'firewalla' ? 'firewalla' : 'unifi_api') + ' is the one in use: one dashboard runs at a time.' };
    return { tone: 'muted', text: 'Connected. Starting.' };
  }
  // eero and the UniFi controller sign-in are read for bandwidth.
  const source = id === 'eero' ? 'eero' : 'unifi';
  if (bw.source === source) {
    if (bw.needs_sign_in) return { tone: 'bad', text: 'The sign-in has expired. Disconnect and sign in again.' };
    if (bw.last_error) return { tone: 'warn', text: 'Could not read it: ' + bw.last_error };
    if (!bw.last_poll) return { tone: 'muted', text: 'Connected. Waiting for the first reading.' };
    return { tone: 'good', text: 'Reading bandwidth for ' + (bw.matched || 0) + ' of ' + (bw.devices_seen || 0) + ' devices.' };
  }
  if (id === 'eero') {
    return { tone: 'good', text: bw.source ? 'Connected for device names. Bandwidth comes from your ' + bw.source + ', which is more exact.' : 'Connected for device names.' + (c.enabled ? '' : ' Bandwidth reading is switched off.') };
  }
  if (!c.enabled) return { tone: 'muted', text: 'Connected to ' + (c.address || 'the controller') + ', but switched off.' };
  return { tone: 'muted', text: 'Connected. Starting.' };
}

// bandwidthNote says where the Bandwidth screen's numbers come from, and
// warns about a Firewalla's delay, which otherwise reads as a fault.
export function bandwidthNote(conns) {
  const bw = (conns || {}).bandwidth || {};
  if (!bw.source) return '';
  if (bw.source === 'firewalla' && ((conns || {}).firewalla || {}).local) {
    return 'Bandwidth comes from this Firewalla box, as exact byte counts, as the traffic happens.';
  }
  if (bw.source === 'firewalla') {
    return 'Bandwidth comes from your Firewalla. Its cloud reports traffic in batches several minutes behind, so new figures arrive every few minutes rather than live.';
  }
  return 'Bandwidth comes from your ' + bw.source + (bw.estimated ? ', as estimates from sampled rates.' : ', as exact byte counts.');
}

// canToggle reports whether a connection has an on/off switch worth
// showing, and what flipping it does.
export function toggleLabel(id, c) {
  if (!c || !c.connected) return '';
  if (id === 'eero') return c.enabled ? 'Stop reading bandwidth' : 'Read bandwidth';
  return c.enabled ? 'Switch off' : 'Switch on';
}
