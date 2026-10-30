// Blocking scopes: Network, a group, or a device. Blocks union across the
// scopes that apply to a device; an allow rule at a more specific scope beats
// a block from a broader one. Everything here is pure and immutable.

export const NETWORK = { kind: 'network', id: '' };

export const scopeKey = (s) => s.kind + ':' + (s.id || '');
export const sameScope = (a, b) => !!a && !!b && scopeKey(a) === scopeKey(b);
const ORDER = { network: 0, group: 1, device: 2 };

// Broad to specific. `groupIds` are the groups a device belongs to.
export function chainFor(scope, groupIds = []) {
  if (scope.kind === 'network') return [NETWORK];
  if (scope.kind === 'group') return [NETWORK, scope];
  return [NETWORK, ...groupIds.map((id) => ({ kind: 'group', id })), scope];
}

export function dataFor(policy, scope) {
  const hit = ((policy && policy.scopes) || []).find((s) => s.scope && sameScope(s.scope, scope));
  return {
    items: (hit && hit.items) || {},
    rules: { allow: (hit && hit.rules && hit.rules.allow) || [], block: (hit && hit.rules && hit.rules.block) || [] },
    switches: (hit && hit.switches) || {},
  };
}

export function scopeLabel(scope, { groups = [], devices = {} } = {}) {
  if (scope.kind === 'network') return 'Network';
  if (scope.kind === 'group') { const g = groups.find((x) => x.id === scope.id); return g ? g.name : 'Group'; }
  return devices[scope.id] || 'Device';
}

// Entries that bundle other items (categories, apps with includes).
export function bundlesContaining(catalog, id) {
  const out = [];
  for (const e of (catalog && catalog.entries) || []) if (Array.isArray(e.includes) && e.includes.includes(id)) out.push(e);
  return out;
}

// How is `id` blocked at `scope`? Mirrors the server: a switch directly on the
// item beats the switch of a category or umbrella that contains it (so
// items[id] === false carves one app out of an enabled category), an "off"
// container beats an "on" container, and blocks union across scopes.
//   here: set to on directly   off: explicitly off here   via: enabled bundles here
//   inherited: broader scopes that block it (directly or via a bundle)
export function itemStatus(policy, catalog, scope, groupIds, id) {
  const chain = chainFor(scope, groupIds);
  const bundles = bundlesContaining(catalog, id);
  const here = dataFor(policy, scope).items;
  const bundleOff = bundles.some((b) => here[b.id] === false);
  const covered = bundleOff ? [] : bundles.filter((b) => here[b.id] === true);
  const status = {
    here: here[id] === true, off: here[id] === false,
    covered: covered.length > 0, via: here[id] === false ? [] : covered,
    inherited: [], effective: false,
  };
  for (const s of chain) {
    if (sameScope(s, scope)) continue;
    const items = dataFor(policy, s).items;
    if (items[id] === true) status.inherited.push({ scope: s, via: null });
    else if (items[id] !== false && !bundles.some((b) => items[b.id] === false)) {
      const b = bundles.find((x) => items[x.id] === true);
      if (b) status.inherited.push({ scope: s, via: b });
    }
  }
  status.effective = status.here || status.via.length > 0 || status.inherited.length > 0;
  return status;
}

// The value to store when the user flips an item's switch at this scope:
// true, false (carve one item out of an enabled bundle) or null (remove it).
export function nextItemValue(status, wantOn) {
  if (wantOn) return status.covered ? null : true;
  return status.covered ? false : null;
}

// Rules visible at a scope: those set here plus those inherited, tagged with their origin.
export function rulesView(policy, scope, groupIds = []) {
  const out = [];
  for (const s of chainFor(scope, groupIds)) {
    const d = dataFor(policy, s).rules;
    for (const kind of ['block', 'allow']) for (const domain of d[kind]) out.push({ kind, domain, scope: s, here: sameScope(s, scope) });
  }
  out.sort((a, b) => (b.here - a.here) || a.domain.localeCompare(b.domain));
  return out;
}

export function switchView(policy, scope, groupIds, name) {
  let here = null; const inherited = [];
  for (const s of chainFor(scope, groupIds)) {
    const v = dataFor(policy, s).switches[name];
    if (sameScope(s, scope)) here = typeof v === 'boolean' ? v : null;
    else if (v === true) inherited.push(s);
  }
  return { here, inherited, effective: here === true || inherited.length > 0 };
}

export function effectiveSummary(policy, catalog, scope, groupIds = []) {
  const entries = (catalog && catalog.entries) || [];
  const byId = new Map(entries.map((e) => [e.id, e]));
  const custom = new Map(((policy && policy.custom_lists) || []).map((c) => [c.id, c]));
  const counts = { apps: 0, lists: 0, categories: 0, custom: 0, here: 0, inherited: 0, blockRules: 0, allowRules: 0, switches: [] };
  const seen = new Set();
  const chain = chainFor(scope, groupIds);
  for (const s of chain) {
    const here = sameScope(s, scope);
    for (const [id, on] of Object.entries(dataFor(policy, s).items)) {
      if (!on) continue;
      const e = byId.get(id);
      const kind = e ? e.kind : custom.has(id) ? 'custom' : null;
      if (!kind) continue;
      const key = scopeKey(s) + '|' + id;
      if (seen.has(key)) continue;
      seen.add(key);
      if (kind === 'app') counts.apps++; else if (kind === 'list') counts.lists++; else if (kind === 'category') counts.categories++; else counts.custom++;
      if (here) counts.here++; else counts.inherited++;
    }
    const r = dataFor(policy, s).rules;
    counts.blockRules += r.block.length; counts.allowRules += r.allow.length;
  }
  for (const sw of (policy && policy.switches) || []) if (switchView(policy, scope, groupIds, sw.name).effective) counts.switches.push(sw.title || sw.name);
  return counts;
}

// ---- immutable updates, used for optimistic edits and rollback ----
function withScope(policy, scope, fn) {
  const scopes = [...((policy && policy.scopes) || [])];
  let i = scopes.findIndex((s) => s.scope && sameScope(s.scope, scope));
  const cur = i >= 0 ? scopes[i] : { scope: { kind: scope.kind, id: scope.id || '' }, items: {}, rules: { allow: [], block: [] }, switches: {} };
  const next = fn({
    scope: cur.scope, items: { ...(cur.items || {}) },
    rules: { allow: [...((cur.rules && cur.rules.allow) || [])], block: [...((cur.rules && cur.rules.block) || [])] },
    switches: { ...(cur.switches || {}) },
  });
  if (i >= 0) scopes[i] = next; else scopes.push(next);
  scopes.sort((a, b) => (ORDER[a.scope.kind] - ORDER[b.scope.kind]) || String(a.scope.id).localeCompare(String(b.scope.id)));
  return { ...policy, scopes };
}

export function setItem(policy, scope, id, enabled) {
  return withScope(policy, scope, (s) => { if (enabled === null || enabled === undefined) delete s.items[id]; else s.items[id] = !!enabled; return s; });
}
export function setSwitch(policy, scope, name, enabled) {
  return withScope(policy, scope, (s) => { if (enabled === null || enabled === undefined) delete s.switches[name]; else s.switches[name] = !!enabled; return s; });
}
export function addRule(policy, scope, kind, domain) {
  const other = kind === 'block' ? 'allow' : 'block';
  return withScope(policy, scope, (s) => {
    s.rules[other] = s.rules[other].filter((d) => d !== domain);
    if (!s.rules[kind].includes(domain)) s.rules[kind].push(domain);
    return s;
  });
}
export function delRule(policy, scope, kind, domain) {
  return withScope(policy, scope, (s) => { s.rules[kind] = s.rules[kind].filter((d) => d !== domain); return s; });
}

// Normalises what a person types into a domain: strips scheme, path, port, www-less, lowercases.
export function normalizeDomain(input) {
  let d = String(input || '').trim().toLowerCase();
  d = d.replace(/^[a-z]+:\/\//, '').replace(/^\*\./, '').replace(/[/?#].*$/, '').replace(/:\d+$/, '').replace(/\.$/, '');
  if (!d || d.length > 253) return '';
  if (!/^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*$/.test(d)) return '';
  return d;
}

// Enabled item counts at each ancestor scope, for "inheriting from ..." text.
export function inheritedSources(policy, scope, groupIds = []) {
  const out = [];
  for (const s of chainFor(scope, groupIds)) {
    if (sameScope(s, scope)) continue;
    const d = dataFor(policy, s);
    const items = Object.values(d.items).filter(Boolean).length;
    const rules = d.rules.block.length + d.rules.allow.length;
    if (items || rules) out.push({ scope: s, items, rules });
  }
  return out;
}
