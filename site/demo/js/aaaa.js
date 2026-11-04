// AAAA filtering: the wording and the state summary. Pure: no DOM, no network.
//
// Shepherd can answer AAAA queries with nothing, for a network whose devices
// have no IPv6 route to the internet. It is set here rather than only in
// shepherd.toml, and per device as well as network-wide, because the device
// that needs an exception is found by watching the query log: one that does
// not cache an empty answer asks for the same name again without end instead
// of falling back to IPv4. See docs/IPV6.md.

export const AAAA_CHOICES = [
  {
    id: 'auto',
    label: 'Automatic',
    text: 'Withhold AAAA answers only while this network has no IPv6 route to the internet. Checked every minute.',
  },
  {
    id: 'on',
    label: 'Always withhold',
    text: 'Never hand out an IPv6 address, even if IPv6 works here.',
  },
  {
    id: 'off',
    label: 'Never withhold',
    text: 'Answer every AAAA query in full, as an ordinary resolver does.',
  },
];

export const DEVICE_AAAA_CHOICES = [
  {
    id: 'auto',
    label: "Follow the network",
    text: "Whatever the network's IPv6 setting says.",
  },
  {
    id: 'on',
    label: 'Withhold',
    text: 'Withhold AAAA answers from this device even where the network hands them out.',
  },
  {
    id: 'off',
    label: 'Answer in full',
    text: 'Always answer this device in full. Use it for a device that asks for the same filtered name without end instead of falling back to IPv4.',
  },
];

const choiceOf = (choices, id) => choices.find((c) => c.id === id) || choices[0];

export const aaaaChoice = (id) => choiceOf(AAAA_CHOICES, id);
export const deviceAAAAChoice = (id) => choiceOf(DEVICE_AAAA_CHOICES, id);

// aaaaSwitchOf reads a device's switch, treating anything unknown as "auto".
export function aaaaSwitchOf(d) {
  const v = d && typeof d.aaaa === 'string' ? d.aaaa : 'auto';
  return DEVICE_AAAA_CHOICES.some((c) => c.id === v) ? v : 'auto';
}

export function aaaaMode(doc) {
  const v = doc && typeof doc.mode === 'string' ? doc.mode : 'auto';
  return AAAA_CHOICES.some((c) => c.id === v) ? v : 'auto';
}

// aaaaSummary turns GET /api/dns/aaaa into the one line the card leads with:
// what is happening right now, and why.
//
// state is 'filtering', 'answering' or 'unknown' (the server did not say,
// which happens only where AAAA filtering is not wired in at all).
export function aaaaSummary(doc) {
  const mode = aaaaMode(doc);
  if (!doc || typeof doc.filtering !== 'boolean') {
    return { mode, state: 'unknown', headline: 'Shepherd is not reporting what it does with AAAA answers.', detail: '' };
  }
  const filtering = doc.filtering;
  const state = filtering ? 'filtering' : 'answering';
  const headline = filtering
    ? 'AAAA answers are being withheld.'
    : 'AAAA answers are being given out in full.';
  // Only "automatic" needs saying why; for the other two the headline and the
  // switch's own help line already say everything, and repeating it here put
  // the same sentence on the card twice.
  let detail = '';
  if (mode === 'auto') {
    const usable = doc.ipv6_usable;
    if (usable === true) detail = 'Automatic, and outbound IPv6 is reachable from here.';
    else if (usable === false) detail = 'Automatic, and outbound IPv6 is not reachable from here.';
    else detail = 'Automatic: it follows whether outbound IPv6 is reachable.';
  }
  if (doc.from_config) {
    detail = (detail ? detail + ' ' : '') + 'Set in shepherd.toml (dns.filter_aaaa); choosing here saves it in the portal instead.';
  }
  return { mode, state, headline, detail };
}

// aaaaExceptions lists the devices with a switch of their own, the withheld
// ones first (they are the surprising kind), then by name.
export function aaaaExceptions(doc) {
  const list = (doc && Array.isArray(doc.exceptions) ? doc.exceptions : []).filter((e) => e && e.id);
  const rank = (e) => (e.aaaa === 'on' ? 0 : 1);
  return list.slice().sort((a, b) => rank(a) - rank(b) || String(a.name || '').localeCompare(String(b.name || '')));
}

// exceptionNote is what one exception row says it does.
export function exceptionNote(e) {
  return e && e.aaaa === 'on' ? 'AAAA withheld from this device' : 'answered in full';
}
