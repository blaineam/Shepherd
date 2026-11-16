// Pure helpers for the router dashboard screen (backendview.js): what to
// show for a connection, how a request becomes a rule, how a rule reads.
// Nothing here touches the DOM, so it is all unit-testable.

// can reports whether the connected backend offers a capability right now.
// Write capabilities are absent while writes are switched off.
export function can(data, cap) {
  return !!(data && Array.isArray(data.capabilities) && data.capabilities.includes(cap));
}

// statusLine is the one sentence under the title, with a tone.
export function statusLine(data) {
  const d = data || {};
  if (!d.available) return { tone: 'muted', text: 'This build has no router dashboard.' };
  if (!d.connected) {
    return { tone: 'muted', text: 'No Firewalla is connected. Connect one under "Read from your router" on the Bandwidth screen.' };
  }
  if (!d.enabled) return { tone: 'muted', text: 'Connected to ' + (d.address || 'Firewalla') + ', but switched off.' };
  if (d.error) return { tone: 'bad', text: d.error };
  if (!d.running) return { tone: 'muted', text: 'Starting.' };
  const st = d.status || {};
  if (st.needs_token) return { tone: 'bad', text: 'Firewalla refused the token. Connect again with a new one.' };
  const errs = Object.entries(st.errors || {});
  if (errs.length) return { tone: 'warn', text: 'Could not read ' + errs.map(([k]) => k).join(', ') + ': ' + errs[0][1] };
  if (!st.last_poll) return { tone: 'muted', text: 'Connected. Waiting for the first reading.' };
  return { tone: 'good', text: 'Reading ' + (d.address || 'Firewalla') + (d.read_only ? ' (read only).' : ' (changes allowed).') };
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
  let where = 'every device';
  if (r.ScopeType === 'device') {
    const d = devices.find((x) => x.MAC === r.Scope);
    where = d && d.Name ? d.Name : 'one device';
  } else if (r.ScopeType) {
    where = 'the ' + r.ScopeType + (r.Scope ? ' ' + r.Scope : '');
  }
  const how = r.DNSOnly ? ', name lookups only' : '';
  return verb + ' ' + (r.TargetType || 'target') + ' ' + (r.Target || '') + ' for ' + where + how;
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
