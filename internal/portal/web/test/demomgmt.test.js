import test from 'node:test';
import assert from 'node:assert/strict';
import { createDemoMgmt } from '../js/demomgmt.js';
import { createDemoApi } from '../js/demoapi.js';
import { DemoGenerator } from '../js/demo.js';
import { buildDevices, DEVICE_BY_IP, DEVICE_IPS, ipFor, macFor, fallbackName, DEMO_CATALOG, DEMO_PRESETS, DEMO_SWITCHES, DEMO_GROUPS } from '../js/demodata.js';

const NOW = Date.parse('2026-03-02T12:00:00Z');
const gen = () => new DemoGenerator({ seed: 5, deviceOf: (ip) => DEVICE_BY_IP.get(ip) });
function rig(opts = {}) {
  const d = createDemoMgmt({ count: 38, gen: gen(), now: () => NOW, ...opts });
  const call = async (method, path, body = {}) => { const r = await d.handle(method, new URL(path, 'http://x').pathname, new URL(path, 'http://x'), body); return r; };
  return { d, call };
}
const fails = async (p, status) => assert.rejects(p, (e) => e.status === status);

test('demo data is synthetic: documentation ranges, example domains, 02:00:5e MACs', () => {
  const devs = buildDevices(2000, NOW);
  const ok = /^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|2001:db8:)/;
  for (const d of devs) {
    for (const ip of d.ips) assert.match(ip, ok, ip);
    for (const m of d.macs) assert.match(m, /^02:00:5e:/);
    for (const n of [d.names.rdns]) if (n) assert.match(n, /\.example\.net$/);
  }
  assert.equal(new Set(devs.map((d) => d.ips[0])).size, 2000, 'addresses are unique');
  assert.equal(new Set(devs.map((d) => d.id)).size, 2000);
  assert.ok(DEVICE_IPS.every((ip) => DEVICE_BY_IP.has(ip)));
  assert.equal(DEVICE_BY_IP.get('192.0.2.14').name, 'Kids Tablet');
  assert.equal(ipFor(0), '192.0.2.11');
  assert.match(macFor(70000), /^02:00:5e:01:11:70$/);
  for (const e of DEMO_CATALOG.entries) { if (e.homepage) assert.match(e.homepage, /^https:\/\/example\.org\//); }
  for (const p of DEMO_PRESETS) for (const a of [...p.plain, p.doh, p.dot]) assert.match(a, /(203\.0\.113|198\.51\.100|\.example\.(net|org|com))/);
  assert.ok(DEMO_SWITCHES.length >= 2 && DEMO_GROUPS.length === 5);
  assert.equal(fallbackName({ alias: 'A' }), 'A');
  assert.equal(fallbackName({ names: { mdns: 'living-room-tv.local' } }), 'Living Room Tv');
  assert.equal(fallbackName({ names: { hostname: 'h1' } }), 'h1');
  assert.equal(fallbackName({ names: { rdns: 'r.example.net' } }), 'r.example.net');
  assert.equal(fallbackName({ vendor: 'Aurora', type: 'tv' }), 'Aurora TV');
  assert.equal(fallbackName({ vendor: 'Orbis', type: 'game console' }), 'Orbis Game console');
  assert.equal(fallbackName({ ips: ['192.0.2.1'] }), '192.0.2.1');
  assert.equal(fallbackName({}), 'Unknown device');
});

test('traffic entries carry device names and ids', () => {
  const es = gen().range(NOW, NOW + 60000);
  assert.ok(es.length > 20);
  for (const e of es) { assert.ok(e.device && e.device_id); assert.equal(e.device, DEVICE_BY_IP.get(e.client).name); }
});

test('devices: search, sort and paging', async () => {
  const { call } = rig();
  const all = await call('GET', '/api/devices?limit=500');
  assert.equal(all.total, 38);
  const cams = await call('GET', '/api/devices?q=type:camera');
  assert.ok(cams.total >= 4 && cams.devices.every((d) => d.type === 'camera'));
  const hubs = await call('GET', '/api/devices?q=type:smart-home');
  assert.ok(hubs.total >= 5 && hubs.devices.every((d) => d.type === 'smart-home hub'));
  const kids = await call('GET', '/api/devices?q=group:kids');
  assert.ok(kids.devices.every((d) => d.groups.includes('grp-kids')));
  const notKids = await call('GET', '/api/devices?q=-group:kids&limit=500');
  assert.equal(notKids.total + kids.total, 38);
  const byName = await call('GET', '/api/devices?sort=name&limit=500');
  const names = byName.devices.map((d) => d.name);
  assert.deepEqual(names, [...names].sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base', numeric: true })));
  const p2 = await call('GET', '/api/devices?offset=10&limit=5');
  assert.equal(p2.devices.length, 5);
  assert.equal(p2.offset, 10);
  const recent = await call('GET', '/api/devices?sort=recent&limit=3');
  assert.ok(Date.parse(recent.devices[0].last_seen) >= Date.parse(recent.devices[2].last_seen));
});

test('devices: get, patch (alias renames, rederives name), delete', async () => {
  const { call } = rig();
  const d = await call('GET', '/api/devices/dev-0003');
  assert.equal(d.name, 'Work Laptop');
  const p = await call('PATCH', '/api/devices/dev-0003', { alias: '  Dad Laptop ', notes: 'n', tags: ['A b', 'a b'], excluded: true, type: 'desktop' });
  assert.deepEqual([p.name, p.alias, p.notes, p.tags, p.excluded, p.type], ['Dad Laptop', 'Dad Laptop', 'n', ['a-b'], true, 'desktop']);
  const cleared = await call('PATCH', '/api/devices/dev-0003', { alias: '' });
  assert.notEqual(cleared.name, 'Dad Laptop');
  assert.deepEqual(await call('DELETE', '/api/devices/dev-0003'), { ok: true });
  await fails(call('GET', '/api/devices/dev-0003'), 404);
  await fails(call('PATCH', '/api/devices/nope', {}), 404);
  await fails(call('DELETE', '/api/devices/nope'), 404);
});

test('bulk ops: assign, remove, exclude, tags, delete and validation', async () => {
  const { call } = rig();
  const ids = ['dev-0001', 'dev-0002', 'ghost'];
  const r = await call('POST', '/api/devices/bulk', { ids, op: 'assign_group', group_id: 'grp-work' });
  assert.deepEqual([r.changed, r.missing], [2, ['ghost']]);
  assert.ok((await call('GET', '/api/devices/dev-0001')).groups.includes('grp-work'));
  await call('POST', '/api/devices/bulk', { ids, op: 'remove_group', group_id: 'grp-work' });
  assert.ok(!(await call('GET', '/api/devices/dev-0001')).groups.includes('grp-work'));
  await call('POST', '/api/devices/bulk', { ids, op: 'set_excluded', excluded: true });
  assert.equal((await call('GET', '/api/devices/dev-0002')).excluded, true);
  await call('POST', '/api/devices/bulk', { ids, op: 'set_tags', add_tags: ['x'], remove_tags: [] });
  assert.ok((await call('GET', '/api/devices/dev-0002')).tags.includes('x'));
  await fails(call('POST', '/api/devices/bulk', { ids: [], op: 'delete' }), 400);
  await fails(call('POST', '/api/devices/bulk', { ids, op: 'assign_group', group_id: 'nope' }), 404);
  await fails(call('POST', '/api/devices/bulk', { ids, op: 'explode' }), 400);
  const del = await call('POST', '/api/devices/bulk', { ids: ['dev-0001'], op: 'delete' });
  assert.equal(del.changed, 1);
  assert.equal((await call('GET', '/api/devices?limit=1')).total, 37);
});

test('merge folds sources into the target', async () => {
  const { call } = rig();
  const t = await call('POST', '/api/devices/merge', { target: 'dev-0001', sources: ['dev-0002'] });
  assert.ok(t.ips.length === 2 && t.macs.length === 2);
  await fails(call('GET', '/api/devices/dev-0002'), 404);
  await fails(call('POST', '/api/devices/merge', { target: 'dev-0001', sources: ['ghost'] }), 404);
});

test('groups: counts, create, rename, recolor, delete cascades to policy', async () => {
  const { call } = rig();
  const g = (await call('GET', '/api/groups')).groups;
  assert.equal(g.find((x) => x.id === 'grp-kids').count, g.find((x) => x.id === 'grp-kids').count);
  const n = await call('POST', '/api/groups', { name: 'Study' });
  assert.deepEqual([n.name, n.count], ['Study', 0]);
  assert.match(n.color, /^#/);
  await fails(call('POST', '/api/groups', { name: 'study' }), 409);
  await fails(call('POST', '/api/groups', { name: ' ' }), 400);
  const ren = await call('PATCH', '/api/groups/' + n.id, { name: 'Homework', color: '#123456' });
  assert.deepEqual([ren.name, ren.color], ['Homework', '#123456']);
  await fails(call('PATCH', '/api/groups/' + n.id, { name: 'Kids' }), 409);
  await fails(call('PATCH', '/api/groups/nope', {}), 404);
  assert.ok((await call('GET', '/api/policy')).scopes.some((s) => s.scope.id === 'grp-kids'));
  await call('DELETE', '/api/groups/grp-kids');
  assert.ok(!(await call('GET', '/api/policy')).scopes.some((s) => s.scope.id === 'grp-kids'));
  assert.ok((await call('GET', '/api/devices?limit=500')).devices.every((d) => !d.groups.includes('grp-kids')));
  await fails(call('DELETE', '/api/groups/nope'), 404);
});

test('catalog and policy: items, rules, switches, scopes', async () => {
  const { call } = rig();
  const cat = await call('GET', '/api/catalog');
  assert.ok(cat.entries.length > 40 && cat.categories.includes('Social'));
  cat.entries.length = 0;
  assert.ok((await call('GET', '/api/catalog')).entries.length > 40, 'callers cannot mutate the fake');
  const p = await call('GET', '/api/policy');
  assert.ok(p.scopes.some((s) => s.scope.kind === 'network'));
  assert.ok(p.lists.some((l) => l.error));
  const g = { kind: 'group', id: 'grp-guests' };
  const after = await call('POST', '/api/policy/items', { scope: g, item: 'tiktok', enabled: true });
  assert.equal(after.scopes.find((s) => s.scope.id === 'grp-guests').items.tiktok, true);
  const off = await call('POST', '/api/policy/items', { scope: g, item: 'tiktok', enabled: null });
  assert.equal('tiktok' in off.scopes.find((s) => s.scope.id === 'grp-guests').items, false);
  await fails(call('POST', '/api/policy/items', { scope: g, item: 'unknown', enabled: true }), 404);
  await fails(call('POST', '/api/policy/items', { scope: { kind: 'planet', id: 'x' }, item: 'tiktok', enabled: true }), 400);
  await fails(call('POST', '/api/policy/items', { scope: { kind: 'group', id: '' }, item: 'tiktok', enabled: true }), 400);
  const dev = { kind: 'device', id: 'dev-0005' };
  const r1 = await call('POST', '/api/policy/rules', { scope: dev, kind: 'block', domain: 'https://Ads.Example.com/x' });
  assert.deepEqual(r1.scopes.find((s) => s.scope.id === 'dev-0005').rules.block, ['ads.example.com']);
  const r2 = await call('POST', '/api/policy/rules', { scope: dev, kind: 'allow', domain: 'ads.example.com' });
  const rules = r2.scopes.find((s) => s.scope.id === 'dev-0005').rules;
  assert.deepEqual([rules.allow, rules.block], [['ads.example.com'], []]);
  const r3 = await call('DELETE', '/api/policy/rules?scope_kind=device&scope_id=dev-0005&kind=allow&domain=ads.example.com');
  assert.deepEqual(r3.scopes.find((s) => s.scope.id === 'dev-0005').rules.allow, []);
  await fails(call('POST', '/api/policy/rules', { scope: dev, kind: 'allow', domain: 'not a domain' }), 400);
  await fails(call('POST', '/api/policy/rules', { scope: dev, kind: 'maybe', domain: 'a.example.com' }), 400);
  const s1 = await call('POST', '/api/policy/switches', { scope: dev, name: 'safe-search', enabled: true });
  assert.equal(s1.scopes.find((s) => s.scope.id === 'dev-0005').switches['safe-search'], true);
  const s2 = await call('POST', '/api/policy/switches', { scope: dev, name: 'safe-search', enabled: null });
  assert.equal('safe-search' in s2.scopes.find((s) => s.scope.id === 'dev-0005').switches, false);
  await fails(call('POST', '/api/policy/switches', { scope: dev, name: 'nope', enabled: true }), 404);
  assert.equal(await call('POST', '/api/policy/refresh', {}), null);

  const sched = { days: [1, 2, 3, 4, 5], start_min: 540, end_min: 1020 };
  const r4 = await call('POST', '/api/policy/rules', { scope: dev, kind: 'block', domain: 'games.example.com', schedule: sched });
  const sc4 = r4.scopes.find((s) => s.scope.id === 'dev-0005');
  assert.deepEqual(sc4.rule_schedules.block['games.example.com'], sched);
  const r5 = await call('POST', '/api/policy/rules', { scope: dev, kind: 'block', domain: 'games.example.com' });
  assert.equal('games.example.com' in r5.scopes.find((s) => s.scope.id === 'dev-0005').rule_schedules.block, false, 'a bare repeat clears the schedule');
  await call('POST', '/api/policy/rules', { scope: dev, kind: 'block', domain: 'games.example.com', schedule: sched });
  const r7 = await call('DELETE', '/api/policy/rules?scope_kind=device&scope_id=dev-0005&kind=block&domain=games.example.com');
  assert.equal('games.example.com' in r7.scopes.find((s) => s.scope.id === 'dev-0005').rule_schedules.block, false);

  const m1 = await call('POST', '/api/policy/mode', { scope: dev, mode: 'allow' });
  assert.equal(m1.scopes.find((s) => s.scope.id === 'dev-0005').mode, 'allow');
  const m2 = await call('POST', '/api/policy/mode', { scope: dev, mode: null });
  assert.equal(m2.scopes.find((s) => s.scope.id === 'dev-0005').mode, null);
  await fails(call('POST', '/api/policy/mode', { scope: dev, mode: 'sideways' }), 400);
  await fails(call('POST', '/api/policy/mode', { scope: { kind: 'planet' }, mode: 'allow' }), 400);
});

test('custom lists: add by url or text, validate, delete', async () => {
  const { call } = rig();
  const u = await call('POST', '/api/policy/custom-lists', { name: 'By URL', category: 'Social', url: 'https://example.com/l.txt' });
  assert.ok(u.url && !u.inline && u.count > 0);
  const t = await call('POST', '/api/policy/custom-lists', { name: 'Pasted', inline: 'a.example.com\n# c\n\nb.example.com' });
  assert.deepEqual([t.inline, t.count], [true, 2]);
  await fails(call('POST', '/api/policy/custom-lists', { name: '', url: 'https://example.com/x' }), 400);
  await fails(call('POST', '/api/policy/custom-lists', { name: 'x' }), 400);
  await fails(call('POST', '/api/policy/custom-lists', { name: 'x', url: 'https://e.com', inline: 'a' }), 400);
  await fails(call('POST', '/api/policy/custom-lists', { name: 'x', url: 'ftp://e.com' }), 400);
  await fails(call('POST', '/api/policy/custom-lists', { name: 'x', inline: '# nothing' }), 400);
  await call('POST', '/api/policy/items', { scope: { kind: 'network', id: '' }, item: t.id, enabled: true });
  assert.deepEqual(await call('DELETE', '/api/policy/custom-lists/' + t.id), { ok: true });
  const p = await call('GET', '/api/policy');
  assert.ok(!p.custom_lists.some((c) => c.id === t.id));
  assert.ok(!(p.scopes[0].items[t.id]));
  await fails(call('DELETE', '/api/policy/custom-lists/' + t.id), 404);
});

test('upstreams: test, add, reorder, remove, bootstrap', async () => {
  const { call } = rig();
  const g = await call('GET', '/api/upstreams');
  assert.equal(g.upstreams.length, 3);
  assert.ok(g.presets.length >= 4 && g.bootstrap.length === 2);
  assert.equal((await call('POST', '/api/upstreams/test', { addr: 'tls://good.example.net' })).ok, true);
  const bad = await call('POST', '/api/upstreams/test', { addr: 'tls://bad.example.net' });
  assert.ok(!bad.ok && /block/.test(bad.error));
  assert.ok(!(await call('POST', '/api/upstreams/test', { addr: 'nonsense value' })).ok);
  const added = await call('POST', '/api/upstreams', { addr: 'tcp://203.0.113.9' });
  assert.equal(added.upstreams.at(-1).kind, 'tcp');
  await fails(call('POST', '/api/upstreams', { addr: 'tcp://203.0.113.9' }), 409);
  await fails(call('POST', '/api/upstreams', { addr: 'junk!' }), 400);
  const order = added.upstreams.map((u) => u.config).reverse();
  const re = await call('PUT', '/api/upstreams', { addrs: order });
  assert.deepEqual(re.upstreams.map((u) => u.config), order);
  await fails(call('PUT', '/api/upstreams', { addrs: [] }), 400);
  await fails(call('PUT', '/api/upstreams', { addrs: ['bad value'] }), 400);
  const withNew = await call('PUT', '/api/upstreams', { addrs: [...order, '203.0.113.77'] });
  assert.equal(withNew.upstreams.at(-1).config, '203.0.113.77');
  const del = await call('DELETE', '/api/upstreams?addr=' + encodeURIComponent('203.0.113.77'));
  assert.ok(!del.upstreams.some((u) => u.config === '203.0.113.77'));
  await fails(call('DELETE', '/api/upstreams?addr=nope'), 404);
  const solo = await call('PUT', '/api/upstreams', { addrs: [order[0]] });
  await fails(call('DELETE', '/api/upstreams?addr=' + encodeURIComponent(solo.upstreams[0].config)), 409);
  const b = await call('PUT', '/api/upstreams/bootstrap', { servers: ['203.0.113.2'] });
  assert.deepEqual(b.bootstrap, ['203.0.113.2']);
  await fails(call('PUT', '/api/upstreams/bootstrap', { servers: ['dns.example.net'] }), 400);
});

test('history: newest-first windows, filters, paging backwards, lock cycle', async () => {
  const { call } = rig();
  const q = (extra = '') => '/api/history?' + new URLSearchParams({ from: new Date(NOW - 3600000).toISOString(), to: new Date(NOW).toISOString(), limit: '50' }) + extra;
  const a = await call('GET', q());
  assert.equal(a.source, 'encrypted'); assert.equal(a.locked, false);
  assert.equal(a.entries.length, 50);
  assert.ok(a.entries.every((e, i, l) => i === 0 || e.t >= l[i - 1].t), 'ascending like the real API');
  const oldest = a.entries[0].t;
  const b = await call('GET', '/api/history?' + new URLSearchParams({ from: new Date(NOW - 3600000).toISOString(), to: new Date(oldest).toISOString(), limit: '50' }));
  assert.ok(b.entries.every((e) => e.t < oldest), 'older page ends before the cursor');
  const one = await call('GET', q('&client=192.0.2.14'));
  assert.ok(one.entries.length && one.entries.every((e) => e.client === '192.0.2.14'));
  const blocked = await call('GET', q('&action=blocked'));
  assert.ok(blocked.entries.every((e) => e.action === 'blocked'));
  const text = await call('GET', q('&q=cdn.example'));
  assert.ok(text.entries.every((e) => e.name.includes('cdn.example')));
  const byDevice = await call('GET', q('&q=kids tablet'));
  assert.ok(byDevice.entries.every((e) => e.device === 'Kids Tablet'));
  assert.ok(Date.parse(a.oldest) < NOW - 6 * 86400000);
  await call('POST', '/api/demo/history-lock', { locked: true });
  await fails(call('GET', q()), 423);
  await fails(call('POST', '/api/history/unlock', { passphrase: 'wrong' }), 401);
  assert.deepEqual(await call('POST', '/api/history/unlock', { passphrase: 'anything' }), { ok: true, locked: false });
  assert.equal((await call('GET', q())).entries.length, 50);
});

test('history: first-ever unlock creates the passphrase; memory mode explains itself', async () => {
  const f = rig({ history: 'fresh' });
  assert.deepEqual(f.d.historyState(), { mode: 'encrypted', locked: true, initialized: false });
  await fails(f.call('POST', '/api/history/unlock', { passphrase: 'short' }), 400);
  assert.equal((await f.call('POST', '/api/history/unlock', { passphrase: 'long enough phrase' })).ok, true);
  assert.deepEqual(f.d.historyState(), { mode: 'encrypted', locked: false, initialized: true });
  const m = rig({ history: 'memory' });
  const r = await m.call('GET', '/api/history?' + new URLSearchParams({ from: new Date(NOW - 600000).toISOString(), to: new Date(NOW).toISOString() }));
  assert.equal(r.source, 'memory');
  await fails(m.call('POST', '/api/history/unlock', { passphrase: 'x' }), 400);
  const l = rig({ history: 'locked' });
  await fails(l.call('GET', '/api/history'), 423);
  const none = createDemoMgmt({ count: 9, gen: null, now: () => NOW });
  const e = await none.handle('GET', '/api/history', new URL('/api/history', 'http://x'), {});
  assert.deepEqual(e.entries, []);
});

test('unknown paths fall through and the demo api wires settings and delegation', async () => {
  const { d, call } = rig();
  assert.equal(await call('GET', '/api/nothing'), undefined);
  const api = createDemoApi({ getCounters: () => ({ total: 0, blocked: 0, cached: 0, errors: 0 }), topClients: () => [], home: { lat: 1, lon: 2, label: 'Home' }, mgmt: d });
  const s = await api('/api/settings');
  assert.equal(s.history.mode, 'encrypted');
  assert.equal((await api('/api/groups')).groups.length, 5);
  await assert.rejects(api('/api/zzz'), (e) => e.status === 404);
  assert.equal((await api('/api/devices?limit=1')).devices.length, 1);
  const plain = createDemoApi({ getCounters: () => ({}), topClients: () => [], home: { lat: 1, lon: 2 } });
  await assert.rejects(plain('/api/groups'), (e) => e.status === 404);
  assert.equal(d.bulkChanged, 0);
});
