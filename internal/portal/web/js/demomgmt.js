// In-browser fake of the management endpoints (devices, groups, catalog and
// policy, upstreams, history). Used only in demo mode so every screen works
// with no backend. All data is synthetic; state lives in memory.
import { ApiError } from './api.js';
import { parseQuery, matchDevice, sortDevices } from './search.js';
import { applyBulkLocal, normTag } from './bulk.js';
import { applyModeLocal } from './wander.js';
import { buildDevices, fallbackName, DEMO_GROUPS, DEMO_CATALOG, DEMO_SWITCHES, DEMO_PRESETS } from './demodata.js';
import { GROUP_COLORS } from './devtypes.js';
import { classifyAddr, isIP } from './upstreams.js';
import { normalizeDomain, scopeKey } from './scope.js';
import { hostBody, formatTarget, sortHosts } from './reverseproxy.js';

const err = (status, msg) => new ApiError(msg, status);
const delay = (ms) => new Promise((r) => setTimeout(r, ms));

function initialPolicy() {
  const sc = (kind, id, items, rules = {}, switches = {}, mode = null) => ({
    scope: { kind, id }, items, rules: { allow: rules.allow || [], block: rules.block || [] },
    rule_schedules: { allow: {}, block: {} }, switches, mode,
  });
  return [
    sc('network', '', { 'core-ads': true, 'malware-domains': true, 'phishing-watch': true }, { block: ['ads.example.net'], allow: [] }, { 'apple-private-relay': true }),
    sc('group', 'grp-kids', { instagram: true, tiktok: true, snapchat: true, discord: true, 'adult-core': true, 'gambling-core': true }, {}, { 'safe-search': true }),
    sc('group', 'grp-guests', { 'tv-telemetry': true }),
    sc('group', 'grp-work', {}, { allow: ['tools.example.com'] }),
    sc('device', 'dev-0002', { youtube: true }, { block: ['video.example.com'] }),
  ];
}

const LIST_STATUS = {
  'core-ads': { count: 111958, size_bytes: 2310400, ago: 3 }, 'tracker-shield': { count: 64803, size_bytes: 1405000, ago: 3 },
  'tv-telemetry': { count: 2297, size_bytes: 51200, ago: 20 }, 'malware-domains': { count: 92411, size_bytes: 1983000, ago: 1 },
  'phishing-watch': { count: 31204, size_bytes: 700300, ago: 1 }, 'scam-sites': { count: 0, size_bytes: 0, ago: 30, error: 'download failed: timeout after 20s' },
  cryptojacking: { count: 1790, size_bytes: 39000, ago: 26 }, 'adult-core': { count: 411980, size_bytes: 9100000, ago: 6 }, 'gambling-core': { count: 18188, size_bytes: 402000, ago: 6 },
};

export function createDemoMgmt({ count = 38, gen = null, history = 'encrypted', now = () => Date.now() } = {}) {
  let devices = buildDevices(count, now());
  let groups = DEMO_GROUPS.map((g) => ({ ...g }));
  let scopes = initialPolicy();
  let custom = [{ id: 'cl-1', name: 'Family blocklist', category: 'Ads & Trackers', url: 'https://example.com/family-list.txt', inline: false, count: 412 }];
  let nextId = 2;
  let upstreams = [
    { config: 'tls://dns1.example.net', kind: 'dot', healthy: true, rtt_ms: 14.2, consecutive_failures: 0, last_error: '', queries: 18432, errors: 3 },
    { config: 'https://dns2.example.org/dns-query', kind: 'doh', healthy: true, rtt_ms: 23.6, consecutive_failures: 0, last_error: '', queries: 9120, errors: 11 },
    { config: '203.0.113.53', kind: 'udp', healthy: false, rtt_ms: 0, consecutive_failures: 4, last_error: 'read udp: i/o timeout', queries: 412, errors: 380 },
  ];
  let bootstrap = ['198.51.100.2', '198.51.100.3'];
  let proxyHosts = [
    { id: 'rp-1', domain: 'media.example.com', target_scheme: 'http', target_host: '192.0.2.20', target_port: 8096, skip_tls_verify: false, enabled: true },
    { id: 'rp-2', domain: 'photos.example.com', target_scheme: 'http', target_host: '192.0.2.21', target_port: 2283, skip_tls_verify: false, enabled: true },
    { id: 'rp-3', domain: 'nas.example.com', target_scheme: 'https', target_host: '192.0.2.22', target_port: 5001, skip_tls_verify: true, enabled: true },
    { id: 'rp-4', domain: 'old.wiki.example.com', target_scheme: 'http', target_host: '192.0.2.23', target_port: 3000, skip_tls_verify: false, enabled: false },
  ];
  let nextProxyId = 5;
  const hist = { mode: history === 'memory' ? 'memory' : 'encrypted', locked: history === 'locked' || history === 'fresh', initialized: history !== 'fresh' };
  let lastBulk = 0;

  const gname = (id) => (groups.find((g) => g.id === id) || {}).name || id;
  const withCount = (g) => ({ ...g, count: devices.filter((d) => d.groups.includes(g.id)).length });
  const dev = (id) => { const d = devices.find((x) => x.id === id); if (!d) throw err(404, 'device not found'); return d; };
  const setDev = (id, fn) => { const i = devices.findIndex((x) => x.id === id); if (i < 0) throw err(404, 'device not found'); devices[i] = fn(devices[i]); return devices[i]; };

  function policyDoc() {
    return {
      scopes: scopes.map((s) => JSON.parse(JSON.stringify(s))),
      custom_lists: custom.map((c) => ({ ...c })),
      lists: [
        ...DEMO_CATALOG.entries.filter((e) => e.kind === 'list').map((e) => {
          const st = LIST_STATUS[e.id] || { count: e.approx_entries, size_bytes: 0, ago: 5 };
          const o = { id: e.id, name: e.name, count: st.count, size_bytes: st.size_bytes, updated: new Date(now() - st.ago * 3600000).toISOString() };
          if (st.error) o.error = st.error;
          return o;
        }),
        ...custom.map((c) => ({ id: c.id, name: c.name, count: c.count, size_bytes: c.count * 22, updated: new Date(now() - 2 * 3600000).toISOString() })),
      ],
      switches: DEMO_SWITCHES.map((s) => ({ ...s })),
    };
  }

  function scopeRef(sc) {
    if (!sc || !['network', 'group', 'device'].includes(sc.kind)) throw err(400, 'invalid scope');
    const ref = { kind: sc.kind, id: sc.kind === 'network' ? '' : String(sc.id || '') };
    if (ref.kind !== 'network' && !ref.id) throw err(400, 'scope id required');
    let s = scopes.find((x) => scopeKey(x.scope) === scopeKey(ref));
    if (!s) { s = { scope: ref, items: {}, rules: { allow: [], block: [] }, rule_schedules: { allow: {}, block: {} }, switches: {}, mode: null }; scopes.push(s); }
    if (!s.rule_schedules) s.rule_schedules = { allow: {}, block: {} };
    return s;
  }

  function upstreamDoc() {
    return { upstreams: upstreams.map((u) => ({ ...u })), presets: DEMO_PRESETS.map((p) => ({ ...p })), bootstrap: [...bootstrap] };
  }

  async function probe(addr) {
    const c = classifyAddr(addr);
    await delay(350);
    if (!c.ok) return { ok: false, rtt_ms: 0, rcode: '', error: c.error };
    if (/bad|fail|198\.51\.100\.99/.test(addr)) return { ok: false, rtt_ms: 0, rcode: '', error: 'handshake failed: connection timed out (some networks block encrypted DNS)' };
    let h = 0; for (const ch of addr) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
    return { ok: true, rtt_ms: 9 + (h % 340) / 10, rcode: 'NOERROR', error: '' };
  }

  function historyEntries(q) {
    const to = Date.parse(q.get('to')) || now(), from = Date.parse(q.get('from')) || to - 86400000;
    const limit = Math.min(5000, Math.max(1, Number(q.get('limit')) || 500));
    const client = q.get('client') || '', text = (q.get('q') || '').toLowerCase(), action = q.get('action') || '';
    const out = [];
    let skipped = 0;
    if (!gen) return { entries: out, skipped };
    const last = Math.floor((to - 1) / 60000), first = Math.floor(from / 60000);
    let scanned = 0;
    for (let m = last; m >= first && out.length < limit; m--) {
      if (++scanned > 2200) { skipped = 1; break; }
      const list = gen._minute(m);
      for (let i = list.length - 1; i >= 0 && out.length < limit; i--) {
        const e = list[i];
        if (e.t < from || e.t >= to) continue;
        if (client && e.client !== client) continue;
        if (action && e.action !== action) continue;
        if (text && !(e.name.toLowerCase().includes(text) || (e.device || '').toLowerCase().includes(text))) continue;
        out.push({ ...e, dests: e.dests ? e.dests.map((d) => ({ ...d })) : undefined });
      }
    }
    out.reverse();
    return { entries: out, skipped };
  }

  // Like the server, clear timers that have run out.
  function expire() {
    const t = now();
    devices = devices.map((d) => (d.wandering && d.wandering_until && Date.parse(d.wandering_until) <= t ? (({ wandering_until, ...rest }) => ({ ...rest, wandering: false }))(d) : d));
  }

  async function handle(method, path, url, body) {
    expire();
    const q = url.searchParams;
    let m;
    // ---- devices
    if (path === '/api/devices' && method === 'GET') {
      const gnames = (id) => gname(id);
      const parsed = parseQuery(q.get('q') || '');
      const t = now();
      const all = sortDevices(devices.filter((d) => matchDevice(d, parsed, { now: t, groupName: gnames })), q.get('sort') === 'name' ? 'name' : 'recent');
      const offset = Math.max(0, Number(q.get('offset')) || 0), limit = Math.min(500, Math.max(1, Number(q.get('limit')) || 100));
      return { devices: all.slice(offset, offset + limit), total: all.length, offset, limit };
    }
    if (path === '/api/devices/bulk' && method === 'POST') {
      const ids = Array.isArray(body.ids) ? body.ids : [];
      if (!ids.length) throw err(400, 'ids required');
      if (body.op === 'assign_group' && !groups.some((g) => g.id === body.group_id)) throw err(404, 'group not found');
      if (!['assign_group', 'remove_group', 'set_excluded', 'set_wandering', 'set_tags', 'delete'].includes(body.op)) throw err(400, 'unknown op');
      const set = new Set(ids);
      const have = new Set(devices.map((d) => d.id));
      const missing = ids.filter((id) => !have.has(id));
      let changed = 0;
      if (body.op === 'delete') { const before = devices.length; devices = devices.filter((d) => !set.has(d.id)); changed = before - devices.length; scopes = scopes.filter((s) => !(s.scope.kind === 'device' && set.has(s.scope.id))); }
      else devices = devices.map((d) => { if (!set.has(d.id)) return d; changed++; return body.op === 'set_wandering' ? applyModeLocal(d, { wandering: !!body.wandering, wandering_minutes: body.wandering_minutes }, now()) : applyBulkLocal(d, body); });
      lastBulk = changed;
      return { changed, missing };
    }
    if (path === '/api/devices/merge' && method === 'POST') {
      const target = dev(body.target);
      for (const sid of body.sources || []) {
        const s = dev(sid);
        setDev(target.id, (d) => ({ ...d, ips: [...new Set([...d.ips, ...s.ips])], macs: [...new Set([...d.macs, ...s.macs])], groups: [...new Set([...d.groups, ...s.groups])] }));
        devices = devices.filter((d) => d.id !== sid);
      }
      return dev(target.id);
    }
    if ((m = /^\/api\/devices\/([^/]+)$/.exec(path))) {
      const id = decodeURIComponent(m[1]);
      if (method === 'GET') return dev(id);
      if (method === 'DELETE') { dev(id); devices = devices.filter((d) => d.id !== id); return { ok: true }; }
      if (method === 'PATCH') {
        return setDev(id, (d) => {
          const n = { ...d };
          if (typeof body.alias === 'string') n.alias = body.alias.trim().slice(0, 64);
          if (typeof body.notes === 'string') n.notes = body.notes.slice(0, 1000);
          if (typeof body.type === 'string') n.type = body.type;
          if (typeof body.excluded === 'boolean') n.excluded = body.excluded;
          if (typeof body.wandering === 'boolean') { const m = applyModeLocal(n, body, now()); n.wandering = m.wandering; n.excluded = m.excluded; if (m.wandering_until) n.wandering_until = m.wandering_until; else delete n.wandering_until; }
          if (Array.isArray(body.tags)) n.tags = [...new Set(body.tags.map(normTag).filter(Boolean))];
          n.name = fallbackName(n);
          return n;
        });
      }
    }
    // ---- groups
    if (path === '/api/groups') {
      if (method === 'GET') return { groups: groups.map(withCount) };
      if (method === 'POST') {
        const name = String(body.name || '').trim();
        if (!name) throw err(400, 'name required');
        if (groups.some((g) => g.name.toLowerCase() === name.toLowerCase())) throw err(409, 'a group with that name exists');
        const g = { id: 'grp-' + (nextId++) + '-' + name.toLowerCase().replace(/[^a-z0-9]+/g, '').slice(0, 8), name: name.slice(0, 40), color: body.color || GROUP_COLORS[groups.length % GROUP_COLORS.length] };
        groups.push(g);
        return withCount(g);
      }
    }
    if ((m = /^\/api\/groups\/([^/]+)$/.exec(path))) {
      const id = decodeURIComponent(m[1]);
      const g = groups.find((x) => x.id === id);
      if (!g) throw err(404, 'group not found');
      if (method === 'PATCH') {
        if (typeof body.name === 'string' && body.name.trim()) {
          if (groups.some((x) => x.id !== id && x.name.toLowerCase() === body.name.trim().toLowerCase())) throw err(409, 'a group with that name exists');
          g.name = body.name.trim().slice(0, 40);
        }
        if (typeof body.color === 'string') g.color = body.color;
        return withCount(g);
      }
      if (method === 'DELETE') {
        groups = groups.filter((x) => x.id !== id);
        devices = devices.map((d) => (d.groups.includes(id) ? { ...d, groups: d.groups.filter((x) => x !== id) } : d));
        scopes = scopes.filter((s) => !(s.scope.kind === 'group' && s.scope.id === id));
        return { ok: true };
      }
    }
    // ---- catalog and policy
    if (path === '/api/catalog' && method === 'GET') return JSON.parse(JSON.stringify(DEMO_CATALOG));
    if (path === '/api/policy' && method === 'GET') return policyDoc();
    if (path === '/api/policy/items' && method === 'POST') {
      const s = scopeRef(body.scope);
      const known = DEMO_CATALOG.entries.some((e) => e.id === body.item) || custom.some((c) => c.id === body.item);
      if (!known) throw err(404, 'unknown item');
      if (body.enabled === null || body.enabled === undefined) delete s.items[body.item]; else s.items[body.item] = !!body.enabled;
      return policyDoc();
    }
    if (path === '/api/policy/rules') {
      if (method === 'POST') {
        const s = scopeRef(body.scope);
        const d = normalizeDomain(body.domain);
        if (!d) throw err(400, 'not a valid domain');
        if (body.kind !== 'allow' && body.kind !== 'block') throw err(400, 'kind must be allow or block');
        const other = body.kind === 'block' ? 'allow' : 'block';
        s.rules[other] = s.rules[other].filter((x) => x !== d);
        delete s.rule_schedules[other][d];
        if (!s.rules[body.kind].includes(d)) s.rules[body.kind].push(d);
        if (body.schedule) s.rule_schedules[body.kind][d] = body.schedule; else delete s.rule_schedules[body.kind][d];
        return policyDoc();
      }
      if (method === 'DELETE') {
        const s = scopeRef({ kind: q.get('scope_kind'), id: q.get('scope_id') || '' });
        const k = q.get('kind');
        if (s.rules[k]) s.rules[k] = s.rules[k].filter((x) => x !== q.get('domain'));
        if (s.rule_schedules[k]) delete s.rule_schedules[k][q.get('domain')];
        return policyDoc();
      }
    }
    if (path === '/api/policy/switches' && method === 'POST') {
      const s = scopeRef(body.scope);
      if (!DEMO_SWITCHES.some((x) => x.name === body.name)) throw err(404, 'unknown switch');
      if (body.enabled === null || body.enabled === undefined) delete s.switches[body.name]; else s.switches[body.name] = !!body.enabled;
      return policyDoc();
    }
    if (path === '/api/policy/mode' && method === 'POST') {
      const s = scopeRef(body.scope);
      if (body.mode !== null && body.mode !== 'block' && body.mode !== 'allow') throw err(400, 'mode must be block or allow');
      s.mode = body.mode;
      return policyDoc();
    }
    if (path === '/api/policy/custom-lists' && method === 'POST') {
      const name = String(body.name || '').trim();
      if (!name) throw err(400, 'name required');
      if (!!body.url === !!body.inline) throw err(400, 'give exactly one of url or inline');
      if (body.url && !/^https?:\/\//i.test(body.url)) throw err(400, 'url must be http or https');
      const lines = body.inline ? String(body.inline).split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#')) : [];
      if (body.inline && !lines.length) throw err(400, 'no domains found in the pasted text');
      const c = { id: 'cl-' + nextId++, name: name.slice(0, 60), category: body.category || 'Other', count: body.inline ? lines.length : 250 + ((name.length * 37) % 900) };
      if (body.url) c.url = body.url; else c.inline = true;
      custom.push(c);
      return c;
    }
    if ((m = /^\/api\/policy\/custom-lists\/([^/]+)$/.exec(path)) && method === 'DELETE') {
      const id = decodeURIComponent(m[1]);
      if (!custom.some((c) => c.id === id)) throw err(404, 'list not found');
      custom = custom.filter((c) => c.id !== id);
      for (const s of scopes) delete s.items[id];
      return { ok: true };
    }
    if (path === '/api/policy/refresh' && method === 'POST') { await delay(250); return null; }
    // ---- upstreams
    if (path === '/api/upstreams') {
      if (method === 'GET') return upstreamDoc();
      if (method === 'POST') {
        const addr = String(body.addr || '').trim();
        const c = classifyAddr(addr);
        if (!c.ok) throw err(400, c.error);
        if (upstreams.some((u) => u.config === addr)) throw err(409, 'already added');
        upstreams.push({ config: addr, kind: c.kind, healthy: true, rtt_ms: 12 + (addr.length % 20), consecutive_failures: 0, last_error: '', queries: 0, errors: 0 });
        return upstreamDoc();
      }
      if (method === 'DELETE') {
        const addr = q.get('addr');
        if (upstreams.length <= 1) throw err(409, 'cannot remove the last upstream');
        if (!upstreams.some((u) => u.config === addr)) throw err(404, 'upstream not found');
        upstreams = upstreams.filter((u) => u.config !== addr);
        return upstreamDoc();
      }
      if (method === 'PUT') {
        const order = body.addrs || [];
        const by = new Map(upstreams.map((u) => [u.config, u]));
        const next = order.map((a) => by.get(a) || (() => { const c = classifyAddr(a); if (!c.ok) throw err(400, c.error); return { config: a, kind: c.kind, healthy: true, rtt_ms: 15, consecutive_failures: 0, last_error: '', queries: 0, errors: 0 }; })());
        if (!next.length) throw err(400, 'at least one upstream is required');
        upstreams = next;
        return upstreamDoc();
      }
    }
    if (path === '/api/upstreams/test' && method === 'POST') return probe(String(body.addr || '').trim());
    if (path === '/api/upstreams/bootstrap' && method === 'PUT') {
      const bad = (body.servers || []).filter((s) => !isIP(String(s).replace(/^\[|\]$/g, '')));
      if (bad.length) throw err(400, 'not an IP address: ' + bad[0]);
      bootstrap = [...body.servers];
      return upstreamDoc();
    }
    // ---- reverse proxy
    if (path === '/api/reverseproxy' && method === 'GET') {
      return { enabled: true, listen: ':443', wildcard: '*.example.com', certificate: { names: ['*.example.com'], not_after: new Date(now() + 54 * 86400000).toISOString() } };
    }
    if (path === '/api/reverseproxy/hosts' && method === 'GET') return { hosts: sortHosts(proxyHosts) };
    if (path.startsWith('/api/reverseproxy/hosts')) {
      const id = decodeURIComponent(path.slice('/api/reverseproxy/hosts/'.length));
      const i = proxyHosts.findIndex((h) => h.id === id);
      if (method === 'DELETE') {
        if (i < 0) throw err(404, 'no such proxy host');
        proxyHosts.splice(i, 1);
        return { ok: true };
      }
      if (method === 'PUT' && i < 0) throw err(404, 'no such proxy host');
      const target = body.target_host ? formatTarget(body) : '';
      const r = hostBody({ domain: body.domain, target, skipVerify: body.skip_tls_verify, enabled: body.enabled });
      if (!r.ok) throw err(400, r.error);
      if (proxyHosts.some((h, j) => h.domain === r.body.domain && j !== i)) throw err(409, 'another proxy host already uses that domain');
      if (method === 'POST') {
        const h = { id: 'rp-' + nextProxyId++, enabled: true, ...r.body };
        proxyHosts.push(h);
        return h;
      }
      if (method === 'PUT') {
        proxyHosts[i] = { id, enabled: proxyHosts[i].enabled, ...r.body };
        return proxyHosts[i];
      }
    }
    // ---- history
    if (path === '/api/history' && method === 'GET') {
      if (hist.mode === 'encrypted' && hist.locked) {
        const e = err(423, JSON.stringify({ locked: true, source: 'encrypted', entries: [] }));
        throw e;
      }
      const r = historyEntries(q);
      const n = now();
      return { entries: r.entries, source: hist.mode, locked: false, oldest: new Date(n - (hist.mode === 'encrypted' ? 7 * 86400000 : 3 * 3600000)).toISOString(), newest: new Date(n).toISOString(), skipped: r.skipped };
    }
    if (path === '/api/history/unlock' && method === 'POST') {
      if (hist.mode !== 'encrypted') throw err(400, 'history is not encrypted, so there is nothing to unlock');
      const pass = String(body.passphrase || '');
      await delay(300);
      if (!hist.initialized) {
        if (pass.length < 8) throw err(400, 'choose a passphrase of at least 8 characters');
        hist.initialized = true; hist.locked = false;
        return { ok: true, locked: false };
      }
      if (!pass || pass === 'wrong') throw err(401, 'wrong passphrase');
      hist.locked = false;
      return { ok: true, locked: false };
    }
    if (path === '/api/demo/history-lock' && method === 'POST') { hist.locked = !!body.locked; return { ...hist }; }
    return undefined;
  }

  return {
    handle,
    historyState: () => ({ ...hist }),
    // For the traffic generator: current name, id and wandering state of an address.
    deviceOf(ip) { expire(); const d = devices.find((x) => x.ips.includes(ip)); return d ? { id: d.id, name: d.name, wandering: !!d.wandering } : null; },
    get bulkChanged() { return lastBulk; },
  };
}
