// Pure alarm-view helpers: severity and state presentation, mute presets and
// scopes, and small request/response shaping. No DOM, no network — kept
// separate so they are easy to unit test (see docs/ALARMS.md for the server
// model these mirror).

export const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'];
export const STATES = ['new', 'acknowledged', 'muted', 'resolved'];

export function severityLabel(s) {
  return s ? s[0].toUpperCase() + s.slice(1) : '';
}

// severityBadgeClass reuses the portal's existing badge palette (bad/warn/inh)
// instead of introducing new colors, so an alarm's severity reads the same
// way a device page already uses those classes.
export function severityBadgeClass(s) {
  switch (s) {
    case 'critical':
    case 'high':
      return 'badge bad';
    case 'medium':
      return 'badge warn';
    case 'low':
      return 'badge inh';
    default:
      return 'badge';
  }
}

export function stateLabel(s) {
  switch (s) {
    case 'new':
      return 'New';
    case 'acknowledged':
      return 'Acknowledged';
    case 'muted':
      return 'Muted';
    case 'resolved':
      return 'Resolved';
    default:
      return s || '';
  }
}

// MUTE_PRESETS are alarms.MuteSpec values the mute menu offers.
export const MUTE_PRESETS = [
  { id: 'hour', label: '1 hour', spec: { preset: '1h' } },
  { id: 'tomorrow', label: 'Until tomorrow', spec: { preset: 'tomorrow' } },
  { id: 'week', label: '7 days', spec: { preset: 'days', days: 7 } },
  { id: 'forever', label: 'Forever', spec: { preset: 'forever' } },
];

// MUTE_SCOPES are alarms.MuteBy values the bulk mute menu offers.
export const MUTE_SCOPES = [
  { id: 'alarm', label: 'Just these alarms' },
  { id: 'type', label: 'This alarm type' },
  { id: 'device', label: 'This device' },
  { id: 'type+device', label: 'This type on this device' },
  { id: 'domain', label: 'This domain' },
  { id: 'key', label: 'Exactly this' },
];

// alarmQuery turns the view's filter state into the query-param object
// mgmt.alarms() sends to GET /api/alarms.
export function alarmQuery({ severity, state, text, types, offset = 0, limit = 50 } = {}) {
  const q = { offset, limit };
  if (severity) q.min_severity = severity;
  if (state) q.states = state;
  if (text) q.text = text;
  if (types) q.types = types;
  return q;
}

// bulkSummary describes a BatchResult for a toast.
export function bulkSummary(verb, res) {
  const n = res && typeof res.changed === 'number' ? res.changed : 0;
  const skipped = res && res.skipped ? res.skipped : 0;
  let s = verb + ' ' + n + ' alarm' + (n === 1 ? '' : 's');
  if (skipped) s += ' (' + skipped + ' skipped)';
  return s;
}

// ruleMatchSummary describes a mute rule's RuleMatch for display.
export function ruleMatchSummary(match) {
  if (!match) return '';
  const parts = [];
  const add = (label, list) => { if (Array.isArray(list) && list.length) parts.push(label + ': ' + list.join(', ')); };
  add('type', match.types);
  add('device', match.device_ids);
  add('group', match.group_ids);
  add('domain', match.domains);
  add('key', match.key_prefixes);
  return parts.join('; ');
}

// ---- Threat feeds (docs/THREATS.md)

// feedLine words one feed's state for the Threats tab.
export function feedLine(f, now = Date.now()) {
  const feed = f || {};
  if (feed.error) return { tone: 'warn', text: 'Could not update: ' + feed.error + (feed.count ? ' (keeping ' + feed.count.toLocaleString() + ' entries from before)' : '') };
  if (!feed.updated || !feed.count) return { tone: 'muted', text: 'Not downloaded yet' };
  const age = Math.max(0, now - Date.parse(feed.updated));
  const h = Math.round(age / 3600000);
  return { tone: 'good', text: feed.count.toLocaleString() + ' entries, updated ' + (h < 1 ? 'under an hour ago' : h + ' h ago') };
}

// matchLine words one match: who, what, and what the engine did about it.
export function matchLine(m) {
  const x = m || {};
  const who = x.device || x.client || 'A device';
  const did = x.action === 'blocked' ? 'was blocked looking up' : 'looked up';
  const via = x.kind === 'ip' ? ' which resolved into ' + x.indicator : (x.indicator && x.indicator !== x.name ? ' (under ' + x.indicator + ')' : '');
  return { who, text: who + ' ' + did + ' ' + (x.name || x.indicator || '?') + via + ', on the ' + (x.feed_id || '?') + ' feed.' };
}

// ---- Detections (docs/DETECT.md)

// What each kind of finding is called on the Detections tab.
export const FINDING_KINDS = {
  'encrypted-dns': 'Encrypted-DNS resolver',
  'dns-silent': 'Not using Shepherd for DNS',
  'dns-random-names': 'Machine-made names',
  'dns-tunnel': 'Data in DNS',
  'dns-beacon': 'Regular check-in',
  'new-country': 'New country',
  'upload-spike': 'Large upload',
};

// detectIntro says what the checks are doing right now: still learning, and
// whether the ones that need byte counts have any.
export function detectIntro(d, now = Date.now()) {
  const st = (d && d.status) || {};
  const parts = [];
  if (st.learning && st.learning_until) {
    const days = Math.max(1, Math.ceil((Date.parse(st.learning_until) - now) / 86400000));
    parts.push('Still learning what is normal here, for about ' + days + ' more day' + (days === 1 ? '' : 's') + ': the beacon and new-country checks only watch until then.');
  } else {
    parts.push('Watching ' + Number(st.devices || 0).toLocaleString() + ' devices against ' + Number(st.domains || 0).toLocaleString() + ' domains this network has looked up.');
  }
  if (!st.traffic) parts.push('The silent-device and large-upload checks are off until bandwidth is being recorded.');
  return parts.join(' ');
}

// findingLine words one finding for the list.
export function findingLine(f) {
  const x = f || {};
  return { who: x.device || x.client || 'A device', kind: FINDING_KINDS[x.kind] || x.kind || 'Finding', text: x.summary || '' };
}

// decoyLine says which decoy ports are open and which could not be.
export function decoyLine(dc) {
  const ports = (dc && dc.ports) || [];
  if (!dc || !dc.enabled || !ports.length) return { tone: 'muted', text: 'Decoy ports are off (detect.decoy_ports is empty in shepherd.toml).' };
  const open = ports.filter((p) => p.listening).map((p) => p.port);
  const shut = ports.filter((p) => !p.listening).map((p) => p.port);
  if (!open.length) return { tone: 'warn', text: 'No decoy port could be opened (' + shut.join(', ') + '). They are in use on this host, or Shepherd may not bind them.' };
  return {
    tone: 'good',
    text: 'Listening on ' + open.join(', ') + ' and serving nothing: any connection is an alarm.' + (shut.length ? ' Skipped ' + shut.join(', ') + ' (in use, or not permitted).' : ''),
  };
}

// touchLine words one connection to a decoy port.
export function touchLine(t) {
  const x = t || {};
  return (x.source || '?') + ' connected to port ' + (x.port || '?') + (x.count > 1 ? ' (' + x.count + ' times so far)' : '') + '.';
}

// Delivery preferences (docs/ALARMS.md "When"): the part of the alarm
// preferences the Notifications tab edits. Pure, so the tests need no DOM.

// hoursOf turns a Go duration string ("6h0m0s", "90m") or seconds into hours.
export function hoursOf(d) {
  if (typeof d === 'number') return d / 3600;
  const m = /^(?:(\d+)h)?(?:(\d+)m)?(?:([\d.]+)s)?$/.exec(String(d || ''));
  if (!m || !String(d)) return 0;
  return (Number(m[1] || 0)) + (Number(m[2] || 0)) / 60 + (Number(m[3] || 0)) / 3600;
}

// deliveryLine says, in one sentence, what is sent when.
export function deliveryLine(p) {
  if (!p) return 'Delivery settings could not be read.';
  const min = severityLabel(p.immediate_min || 'high');
  const d = p.digest || {};
  if (!d.enabled) return min + ' and above are sent at once; everything else is sent at once too, since the digest is off.';
  const when = d.at ? 'at ' + d.at + ' each day' : 'every ' + trimHours(hoursOf(d.every)) + ' hours';
  return min + ' and above are sent at once; lower alarms are gathered into one digest ' + when + '.';
}

function trimHours(h) {
  return Number.isInteger(h) ? String(h) : h.toFixed(1).replace(/\.0$/, '');
}

// digestFromForm turns the form's fields into the digest preference, or an
// error message. mode is 'every' or 'at'.
export function digestFromForm({ enabled, mode, hours, at }) {
  if (!enabled) return { digest: { enabled: false, every: '6h' } };
  if (mode === 'at') {
    if (!/^([01]\d|2[0-3]):[0-5]\d$/.test(String(at || ''))) return { error: 'Give the digest time as HH:MM, for example 08:00.' };
    return { digest: { enabled: true, every: '6h', at } };
  }
  const h = Number(hours);
  if (!(h >= 1 / 60) || !Number.isFinite(h)) return { error: 'The digest interval must be at least one minute.' };
  return { digest: { enabled: true, every: Math.round(h * 3600) + 's' } };
}
