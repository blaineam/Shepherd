// Pure helpers for the router dashboard screen (backendview.js): what to
// show for a connection, how a request becomes a rule, how a rule reads.
// Nothing here touches the DOM, so it is all unit-testable.

// can reports whether the connected backend offers a capability right now.
// Write capabilities are absent while writes are switched off.
export function can(data, cap) {
  return !!(data && Array.isArray(data.capabilities) && data.capabilities.includes(cap));
}

// productName is how the connected product is written on the screen.
export function productName(data) {
  const n = (data && data.name) || '';
  if (n === 'unifi') return 'UniFi';
  if (n === 'firewalla') return 'Firewalla';
  return 'Router';
}

// statusLine is the one sentence under the title, with a tone.
export function statusLine(data) {
  const d = data || {};
  if (!d.available) return { tone: 'muted', text: 'This build has no router dashboard.' };
  if (!d.connected) {
    return { tone: 'muted', text: 'Nothing is connected. Connect a Firewalla or a UniFi console under Connections.' };
  }
  const where = d.local ? 'this Firewalla box' : (d.address || productName(d));
  if (!d.enabled) return { tone: 'muted', text: 'Connected to ' + where + ', but switched off.' };
  if (d.error) return { tone: 'bad', text: d.error };
  if (!d.running) return { tone: 'muted', text: 'Starting.' };
  const st = d.status || {};
  if (st.needs_token) return { tone: 'bad', text: productName(d) + ' refused the credential. Connect again with a new one.' };
  const errs = Object.entries(st.errors || {});
  if (errs.length) return { tone: 'warn', text: 'Could not read ' + errs.map(([k]) => k).join(', ') + ': ' + errs[0][1] };
  if (!st.last_poll) return { tone: 'muted', text: 'Connected. Waiting for the first reading.' };
  return { tone: 'good', text: 'Reading ' + where + (d.read_only ? ' (read only).' : ' (changes allowed).') };
}

// targetOf picks what a flow is about: the name when there is one,
// otherwise the address. It says which, because a rule needs to know.
export function targetOf(flow) {
  if (flow && flow.Domain) return { type: 'domain', value: flow.Domain };
  if (flow && flow.RemoteIP) return { type: 'ip', value: flow.RemoteIP };
  return null;
}

// blockSpecFromFlow is the rule "block this for that device" a person
// means when they press Block on a request. It is DNS-only for a domain,
// which is what Firewalla does by default and the gentlest block.
export function blockSpecFromFlow(flow) {
  const t = targetOf(flow);
  if (!t) return null;
  const spec = { action: 'block', target_type: t.type, target: t.value, block_connections: false, scope_type: '', scope: '', notes: 'Blocked from Shepherd' };
  if (flow.DeviceMAC) { spec.scope_type = 'device'; spec.scope = flow.DeviceMAC; }
  return spec;
}

const ACTION = { block: 'Block', allow: 'Allow', timelimit: 'Time limit' };

// ruleSummary reads a rule as a sentence.
export function ruleSummary(rule, devices = []) {
  const r = rule || {};
  const verb = ACTION[r.Action] || r.Action || 'Rule';
  // A UniFi firewall policy is shown by its name; its zones and filters
  // are not something this screen can describe.
  if (r.TargetType === 'policy') return verb + ' policy "' + (r.Name || r.Target || r.ID) + '"';
  let where = 'every device';
  if (r.ScopeType === 'device') {
    const d = devices.find((x) => x.MAC === r.Scope);
    where = d && d.Name ? d.Name : 'one device';
  } else if (r.ScopeType) {
    where = 'the ' + r.ScopeType + (r.Scope ? ' ' + r.Scope : '');
  }
  const how = r.DNSOnly ? ', name lookups only' : '';
  let usage = '';
  if (r.QuotaMinutes) usage = ', ' + r.UsedMinutes + ' of ' + r.QuotaMinutes + ' min used today';
  return verb + ' ' + (r.TargetType || 'target') + ' ' + (r.Target || '') + ' for ' + where + how + usage;
}

// requestLine is one request as a row: what, for whom, and the outcome.
export function requestLine(flow) {
  const f = flow || {};
  const what = f.Domain || f.RemoteIP || 'unknown';
  const who = f.Device || f.DeviceIP || 'unknown device';
  return { what, who, blocked: !!f.Blocked, outbound: f.Outbound !== false };
}

// auditLine is one entry of the change log.
export function auditLine(a) {
  const e = a || {};
  return (e.Error ? 'Failed: ' : '') + e.action + ' ' + e.target + (e.Error ? ' (' + e.Error + ')' : '');
}

export const DAY_NAMES = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

// daysText writes a set of weekdays the way a person would: "every day",
// "weekdays", "weekends", a run like "Sun–Thu", or a list.
export function daysText(days) {
  const d = [...new Set(days || [])].sort((a, b) => a - b);
  if (d.length === 7) return 'every day';
  const key = d.join(',');
  if (key === '1,2,3,4,5') return 'weekdays';
  if (key === '0,6') return 'weekends';
  const run = d.length > 2 && d.every((v, i) => i === 0 || v === d[i - 1] + 1);
  if (run) return DAY_NAMES[d[0]] + '–' + DAY_NAMES[d[d.length - 1]];
  return d.map((v) => DAY_NAMES[v]).join(', ');
}

// scheduleText reads a schedule: the rule enforces inside the window.
export function scheduleText(s) {
  const x = s || {};
  const over = x.end <= x.start ? ' (into the next day)' : '';
  return 'Enforced ' + daysText(x.days) + ' ' + x.start + '–' + x.end + over + ' (' + x.tz + ')';
}

// scheduleFor finds the schedule that governs a rule, if any.
export function scheduleFor(schedules, ruleId) {
  return (schedules || []).find((s) => s.rule_id === ruleId) || null;
}

// scheduleBody builds the request from the form's pieces. days is a set of
// weekday numbers; tz comes from the browser.
export function scheduleBody(ruleId, days, start, end, tz) {
  return { rule_id: ruleId, days: [...days].sort((a, b) => a - b), start, end, tz };
}

// scheduleProblem says what is wrong with a form before it is sent, or ''.
export function scheduleProblem(days, start, end) {
  if (!days || !days.size) return 'Choose at least one day.';
  if (!/^\d\d:\d\d$/.test(start || '') || !/^\d\d:\d\d$/.test(end || '')) return 'Set both times.';
  if (start === end) return 'The start and end must differ.';
  return '';
}
