import test from 'node:test';
import assert from 'node:assert/strict';
import * as S from '../js/scope.js';

const catalog = { entries: [
  { id: 'fb', kind: 'app', name: 'Facebook', category: 'Social' },
  { id: 'ig', kind: 'app', name: 'Instagram', category: 'Social' },
  { id: 'meta', kind: 'app', name: 'Meta', category: 'Social', includes: ['fb', 'ig'] },
  { id: 'cat-social', kind: 'category', name: 'All Social', category: 'Social', includes: ['fb', 'ig'] },
  { id: 'ads', kind: 'list', name: 'Ads', category: 'Ads' },
] };
const kids = { kind: 'group', id: 'g1' };
const tv = { kind: 'device', id: 'd1' };
const policy = {
  scopes: [
    { scope: S.NETWORK, items: { ads: true }, rules: { block: ['bad.example.com'], allow: [] }, switches: { relay: true } },
    { scope: kids, items: { meta: true, ig: false }, rules: { allow: ['ok.example.com'], block: [] }, switches: {} },
    { scope: tv, items: { 'cat-social': true }, rules: { allow: [], block: [] }, switches: { relay: false } },
  ],
  custom_lists: [{ id: 'cl-1', name: 'Mine' }],
  switches: [{ name: 'relay', title: 'Relay' }],
};

test('scope keys and equality', () => {
  assert.equal(S.scopeKey(kids), 'group:g1');
  assert.equal(S.scopeKey(S.NETWORK), 'network:');
  assert.ok(S.sameScope(kids, { kind: 'group', id: 'g1' }));
  assert.ok(!S.sameScope(kids, tv));
  assert.ok(!S.sameScope(null, kids));
});

test('chainFor orders broad to specific', () => {
  assert.deepEqual(S.chainFor(S.NETWORK), [S.NETWORK]);
  assert.deepEqual(S.chainFor(kids), [S.NETWORK, kids]);
  assert.deepEqual(S.chainFor(tv, ['g1', 'g2']).map(S.scopeKey), ['network:', 'group:g1', 'group:g2', 'device:d1']);
});

test('dataFor defaults for unlisted scopes and tolerates junk', () => {
  assert.deepEqual(S.dataFor(policy, { kind: 'group', id: 'zz' }), { items: {}, rules: { allow: [], block: [] }, switches: {} });
  assert.deepEqual(S.dataFor(null, S.NETWORK).items, {});
  assert.deepEqual(S.dataFor({ scopes: [{ scope: S.NETWORK }] }, S.NETWORK).rules, { allow: [], block: [] });
});

test('scopeLabel', () => {
  const ctx = { groups: [{ id: 'g1', name: 'Kids' }], devices: { d1: 'TV' } };
  assert.equal(S.scopeLabel(S.NETWORK, ctx), 'Network');
  assert.equal(S.scopeLabel(kids, ctx), 'Kids');
  assert.equal(S.scopeLabel({ kind: 'group', id: 'x' }, ctx), 'Group');
  assert.equal(S.scopeLabel(tv, ctx), 'TV');
  assert.equal(S.scopeLabel({ kind: 'device', id: 'x' }), 'Device');
});

test('itemStatus: direct, bundle and inherited states', () => {
  const net = S.itemStatus(policy, catalog, S.NETWORK, [], 'ads');
  assert.ok(net.here && net.effective && !net.inherited.length);
  const g = S.itemStatus(policy, catalog, kids, [], 'ads');
  assert.ok(!g.here && g.effective);
  assert.equal(g.inherited[0].scope, S.NETWORK);
  const fb = S.itemStatus(policy, catalog, kids, [], 'fb');
  assert.ok(!fb.here && fb.via.map((b) => b.id).join() === 'meta' && fb.effective);
  const ig = S.itemStatus(policy, catalog, kids, [], 'ig');
  assert.ok(!ig.here && ig.off, 'explicit false means off here');
  assert.ok(ig.via.length === 0 && !ig.effective && ig.covered, 'a leaf off carves it out of the Meta bundle');
  const d = S.itemStatus(policy, catalog, tv, ['g1'], 'fb');
  assert.ok(d.effective);
  assert.deepEqual(d.inherited.map((x) => [S.scopeKey(x.scope), x.via && x.via.id]), [['group:g1', 'meta']]);
  assert.ok(d.via.map((b) => b.id).includes('cat-social'));
  const none = S.itemStatus(policy, catalog, S.NETWORK, [], 'fb');
  assert.ok(!none.effective);
});

test('nextItemValue picks true, false or null', () => {
  assert.equal(S.nextItemValue({ covered: false }, true), true);
  assert.equal(S.nextItemValue({ covered: false }, false), null);
  assert.equal(S.nextItemValue({ covered: true }, true), null);
  assert.equal(S.nextItemValue({ covered: true }, false), false);
});

test('an off container beats an on container, and inheritance respects carve-outs', () => {
  const p = { scopes: [
    { scope: S.NETWORK, items: { meta: true, 'cat-social': false } },
    { scope: kids, items: { fb: false } },
  ] };
  assert.ok(!S.itemStatus(p, catalog, S.NETWORK, [], 'fb').effective);
  const k = S.itemStatus({ scopes: [{ scope: S.NETWORK, items: { meta: true } }, { scope: kids, items: { fb: false } }] }, catalog, kids, [], 'fb');
  assert.equal(k.inherited.length, 1, 'broader scopes still block: blocks union across scopes');
  const none = S.itemStatus({ scopes: [{ scope: S.NETWORK, items: { fb: false, meta: true } }] }, catalog, kids, [], 'fb');
  assert.equal(none.inherited.length, 0);
});

test('bundlesContaining', () => {
  assert.deepEqual(S.bundlesContaining(catalog, 'fb').map((b) => b.id), ['meta', 'cat-social']);
  assert.deepEqual(S.bundlesContaining(null, 'fb'), []);
});

test('rulesView marks origin and sorts local rules first', () => {
  const r = S.rulesView(policy, kids);
  assert.deepEqual(r.map((x) => [x.kind, x.domain, x.here]), [['allow', 'ok.example.com', true], ['block', 'bad.example.com', false]]);
  assert.equal(S.rulesView(policy, S.NETWORK).length, 1);
});

test('switchView', () => {
  assert.deepEqual(S.switchView(policy, S.NETWORK, [], 'relay'), { here: true, inherited: [], effective: true });
  const g = S.switchView(policy, kids, [], 'relay');
  assert.ok(g.effective && g.here === null && g.inherited.length === 1);
  const d = S.switchView(policy, tv, ['g1'], 'relay');
  assert.equal(d.here, false);
  assert.ok(d.effective, 'inherited on beats a local off');
  assert.ok(!S.switchView(policy, kids, [], 'nope').effective);
});

test('effectiveSummary counts what applies and where it comes from', () => {
  const n = S.effectiveSummary(policy, catalog, S.NETWORK);
  assert.equal(n.lists, 1); assert.equal(n.here, 1); assert.equal(n.blockRules, 1);
  assert.deepEqual(n.switches, ['Relay']);
  const g = S.effectiveSummary(policy, catalog, kids);
  assert.equal(g.apps, 1); assert.equal(g.lists, 1); assert.equal(g.inherited, 1); assert.equal(g.here, 1);
  assert.equal(g.allowRules, 1); assert.equal(g.blockRules, 1);
  const d = S.effectiveSummary(policy, catalog, tv, ['g1']);
  assert.equal(d.categories, 1);
  const c = S.effectiveSummary({ scopes: [{ scope: S.NETWORK, items: { 'cl-1': true, ghost: true } }], custom_lists: policy.custom_lists }, catalog, S.NETWORK);
  assert.equal(c.custom, 1);
  assert.equal(S.effectiveSummary(null, null, S.NETWORK).apps, 0);
});

test('immutable updates for items, switches and rules', () => {
  const p1 = S.setItem(policy, kids, 'tiktok', true);
  assert.equal(S.dataFor(p1, kids).items.tiktok, true);
  assert.equal(S.dataFor(policy, kids).items.tiktok, undefined);
  assert.equal('tiktok' in S.dataFor(S.setItem(p1, kids, 'tiktok', null), kids).items, false);
  const fresh = S.setItem({ scopes: [] }, { kind: 'device', id: 'x' }, 'a', true);
  assert.equal(fresh.scopes[0].scope.id, 'x');
  assert.equal(S.dataFor(S.setSwitch(policy, kids, 'relay', true), kids).switches.relay, true);
  assert.equal('relay' in S.dataFor(S.setSwitch(policy, tv, 'relay', null), tv).switches, false);
  const r = S.addRule(policy, kids, 'block', 'ok.example.com');
  assert.deepEqual(S.dataFor(r, kids).rules, { allow: [], block: ['ok.example.com'] }, 'adding a block removes the allow');
  assert.deepEqual(S.dataFor(S.addRule(r, kids, 'block', 'ok.example.com'), kids).rules.block, ['ok.example.com']);
  assert.deepEqual(S.dataFor(S.delRule(r, kids, 'block', 'ok.example.com'), kids).rules.block, []);
  const order = S.setItem(S.setItem({ scopes: [] }, tv, 'a', true), S.NETWORK, 'b', true);
  assert.deepEqual(order.scopes.map((s) => s.scope.kind), ['network', 'device']);
});

test('inheritedSources lists ancestors that set something', () => {
  const src = S.inheritedSources(policy, tv, ['g1']);
  assert.deepEqual(src.map((s) => [S.scopeKey(s.scope), s.items, s.rules]), [['network:', 1, 1], ['group:g1', 1, 1]]);
  assert.deepEqual(S.inheritedSources(policy, S.NETWORK), []);
  assert.deepEqual(S.inheritedSources(policy, { kind: 'group', id: 'none' }).map((s) => s.scope.kind), ['network']);
});

test('normalizeDomain accepts domains and strips decoration', () => {
  assert.equal(S.normalizeDomain('Example.COM'), 'example.com');
  assert.equal(S.normalizeDomain('https://www.example.com:8443/a/b?x=1'), 'www.example.com');
  assert.equal(S.normalizeDomain('*.example.org.'), 'example.org');
  assert.equal(S.normalizeDomain('localhost'), 'localhost');
  assert.equal(S.normalizeDomain('has space.com'), '');
  assert.equal(S.normalizeDomain('-bad.com'), '');
  assert.equal(S.normalizeDomain(''), '');
  assert.equal(S.normalizeDomain('a'.repeat(300) + '.com'), '');
});
