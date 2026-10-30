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
