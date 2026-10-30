// Shared catalog and policy state for the Blocking screen and the device
// drawer. Edits are optimistic: the UI changes at once and a failed request
// rolls just that edit back (and the caller shows the error).
import { normalizeCatalog } from './catalog.js';
import { dataFor, setItem, setSwitch, setMode, addRule, delRule } from './scope.js';

export function normalizePolicy(p) {
  const q = p && typeof p === 'object' ? p : {};
  return {
    scopes: Array.isArray(q.scopes) ? q.scopes.filter((s) => s && s.scope && typeof s.scope.kind === 'string') : [],
    custom_lists: Array.isArray(q.custom_lists) ? q.custom_lists : [],
    lists: Array.isArray(q.lists) ? q.lists : [],
    switches: Array.isArray(q.switches) ? q.switches : [],
  };
}

export function createPolicyStore({ mgmt, onChange = () => {} }) {
  let catalog = null, policy = null, inflight = null;
  const subs = new Set();
  const emit = () => { onChange(); for (const f of subs) f(); };

  async function load(force = false) {
    if (!force && catalog && policy) return;
    if (inflight) return inflight;
    inflight = (async () => {
      try {
        const [c, p] = await Promise.all([mgmt.catalog(), mgmt.policy()]);
        catalog = normalizeCatalog(c);
        policy = normalizePolicy(p);
        emit();
      } finally { inflight = null; }
    })();
    return inflight;
  }

  async function mutate(apply, undo, call) {
    policy = apply(policy);
    emit();
    try {
      const r = await call();
      if (r && Array.isArray(r.scopes)) { policy = normalizePolicy(r); emit(); }
    } catch (e) {
      policy = undo(policy);
      emit();
      throw e;
    }
  }

  return {
    get catalog() { return catalog; },
    get policy() { return policy; },
    get ready() { return !!(catalog && policy); },
    load,
    invalidate() { catalog = null; policy = null; },
    subscribe(f) { subs.add(f); return () => subs.delete(f); },

    setItem(scope, id, enabled) {
      const was = dataFor(policy, scope).items[id];
      const prev = typeof was === 'boolean' ? was : null;
      return mutate((p) => setItem(p, scope, id, enabled), (p) => setItem(p, scope, id, prev), () => mgmt.setItem(scope, id, enabled));
    },
    setSwitch(scope, name, enabled) {
      const was = dataFor(policy, scope).switches[name];
      const prev = typeof was === 'boolean' ? was : null;
      return mutate((p) => setSwitch(p, scope, name, enabled), (p) => setSwitch(p, scope, name, prev), () => mgmt.setSwitch(scope, name, enabled));
    },
    setMode(scope, mode) {
      const prev = dataFor(policy, scope).mode || null;
      return mutate((p) => setMode(p, scope, mode), (p) => setMode(p, scope, prev), () => mgmt.setMode(scope, mode));
    },
    addRule(scope, kind, domain, schedule = null) {
      const d = dataFor(policy, scope);
      const other = kind === 'block' ? 'allow' : 'block';
      const flipped = d.rules[other].includes(domain);
      const had = d.rules[kind].includes(domain);
      const prevSchedule = d.rule_schedules[kind][domain] || null;
      return mutate((p) => addRule(p, scope, kind, domain, schedule), (p) => {
        let n = had ? addRule(p, scope, kind, domain, prevSchedule) : delRule(p, scope, kind, domain);
        if (flipped) n = addRule(n, scope, other, domain);
        return n;
      }, () => mgmt.addRule(scope, kind, domain, schedule || undefined));
    },
    delRule(scope, kind, domain) {
      return mutate((p) => delRule(p, scope, kind, domain), (p) => addRule(p, scope, kind, domain), () => mgmt.delRule(scope, kind, domain));
    },
    async addCustom(body) {
      const c = await mgmt.addCustomList(body);
      if (c && c.id) {
        policy = { ...policy, custom_lists: [...policy.custom_lists, c], lists: [...policy.lists, { id: c.id, name: c.name, count: c.count || 0, size_bytes: 0, updated: new Date().toISOString() }] };
        emit();
      }
      return c;
    },
    async delCustom(id) {
      const prev = policy;
      policy = {
        ...policy,
        custom_lists: policy.custom_lists.filter((c) => c.id !== id),
        scopes: policy.scopes.map((s) => { const items = { ...s.items }; delete items[id]; return { ...s, items }; }),
      };
      emit();
      try { await mgmt.delCustomList(id); } catch (e) { policy = prev; emit(); throw e; }
    },
    async refreshLists(item) {
      await mgmt.refreshLists(item);
      setTimeout(() => { load(true).catch(() => {}); }, 1500);
    },
  };
}
