import test from 'node:test';
import assert from 'node:assert/strict';
import { createPolicyStore, normalizePolicy } from '../js/policystore.js';
import { dataFor, NETWORK } from '../js/scope.js';

const kids = { kind: 'group', id: 'g1' };
function fakeMgmt(over = {}) {
  const calls = [];
  const rec = (name, ret) => async (...a) => { calls.push([name, ...a]); if (over[name]) return over[name](...a); return ret; };
  return {
    calls,
    catalog: rec('catalog', { entries: [{ id: 'ads', kind: 'list', name: 'Ads', category: 'Ads' }], categories: ['Ads'] }),
    policy: rec('policy', { scopes: [{ scope: NETWORK, items: { ads: true }, rules: { allow: [], block: [] }, switches: {} }], custom_lists: [], lists: [], switches: [] }),
    setItem: rec('setItem', null), setSwitch: rec('setSwitch', null), addRule: rec('addRule', null), delRule: rec('delRule', null),
    addCustomList: rec('addCustomList', { id: 'cl-9', name: 'Mine', category: 'Other', count: 3 }), delCustomList: rec('delCustomList', { ok: true }),
    refreshLists: rec('refreshLists', null),
  };
}

test('normalizePolicy tolerates junk', () => {
  assert.deepEqual(normalizePolicy(null), { scopes: [], custom_lists: [], lists: [], switches: [] });
  assert.equal(normalizePolicy({ scopes: [null, { scope: { kind: 'network' } }, { nope: 1 }] }).scopes.length, 1);
  assert.deepEqual(normalizePolicy({ lists: 'x' }).lists, []);
});

test('load fetches once, can be forced, and dedupes concurrent calls', async () => {
  const m = fakeMgmt();
  const s = createPolicyStore({ mgmt: m });
  assert.ok(!s.ready);
  await Promise.all([s.load(), s.load()]);
  assert.ok(s.ready);
  assert.equal(m.calls.filter((c) => c[0] === 'policy').length, 1);
  await s.load();
  assert.equal(m.calls.filter((c) => c[0] === 'policy').length, 1);
  await s.load(true);
  assert.equal(m.calls.filter((c) => c[0] === 'policy').length, 2);
  s.invalidate();
  assert.ok(!s.ready);
});

test('load errors propagate and a retry works', async () => {
  let fail = true;
  const s = createPolicyStore({ mgmt: fakeMgmt({ catalog: async () => { if (fail) throw new Error('down'); return { entries: [], categories: [] }; } }) });
  await assert.rejects(s.load(), /down/);
  fail = false;
  await s.load();
  assert.ok(s.ready);
});

test('setItem is optimistic and rolls back on failure', async () => {
  const seen = [];
  let fail = false;
  const m = fakeMgmt({ setItem: async () => { if (fail) throw new Error('nope'); return null; } });
  const s = createPolicyStore({ mgmt: m });
  await s.load();
  s.subscribe(() => seen.push(dataFor(s.policy, kids).items.tiktok));
  const p = s.setItem(kids, 'tiktok', true);
  assert.equal(dataFor(s.policy, kids).items.tiktok, true, 'applied before the request resolves');
  await p;
  fail = true;
  await assert.rejects(s.setItem(kids, 'tiktok', null), /nope/);
  assert.equal(dataFor(s.policy, kids).items.tiktok, true, 'restored after failure');
  fail = false;
  await s.setItem(kids, 'tiktok', null);
  assert.equal('tiktok' in dataFor(s.policy, kids).items, false);
});

test('a server response containing a full policy replaces local state', async () => {
  const full = { scopes: [{ scope: NETWORK, items: { ads: true, extra: true }, rules: {}, switches: {} }], custom_lists: [], lists: [], switches: [] };
  const s = createPolicyStore({ mgmt: fakeMgmt({ setItem: async () => full }) });
  await s.load();
  await s.setItem(NETWORK, 'x', true);
  assert.equal(dataFor(s.policy, NETWORK).items.extra, true);
});

test('rules and switches: optimistic with rollback, including allow/block flips', async () => {
  let fail = false;
  const m = fakeMgmt({ addRule: async () => { if (fail) throw new Error('x'); }, delRule: async () => { if (fail) throw new Error('x'); }, setSwitch: async () => { if (fail) throw new Error('x'); } });
  const s = createPolicyStore({ mgmt: m });
  await s.load();
  await s.addRule(kids, 'allow', 'a.example.com');
  assert.deepEqual(dataFor(s.policy, kids).rules.allow, ['a.example.com']);
  fail = true;
  await assert.rejects(s.addRule(kids, 'block', 'a.example.com'));
  assert.deepEqual(dataFor(s.policy, kids).rules, { allow: ['a.example.com'], block: [] }, 'flip rolled back');
  await assert.rejects(s.addRule(kids, 'block', 'new.example.com'));
  assert.deepEqual(dataFor(s.policy, kids).rules.block, []);
  await assert.rejects(s.delRule(kids, 'allow', 'a.example.com'));
  assert.deepEqual(dataFor(s.policy, kids).rules.allow, ['a.example.com']);
  fail = false;
  await s.delRule(kids, 'allow', 'a.example.com');
  assert.deepEqual(dataFor(s.policy, kids).rules.allow, []);
  await s.setSwitch(kids, 'relay', true);
  assert.equal(dataFor(s.policy, kids).switches.relay, true);
  fail = true;
  await assert.rejects(s.setSwitch(kids, 'relay', null));
  assert.equal(dataFor(s.policy, kids).switches.relay, true);
  fail = false;
  await s.addRule(kids, 'block', 'z.example.com');
  fail = true;
  await assert.rejects(s.addRule(kids, 'block', 'z.example.com'));
  assert.deepEqual(dataFor(s.policy, kids).rules.block, ['z.example.com'], 'an existing rule is kept when a repeat fails');
});

test('custom lists: add appends, delete is optimistic and restores on failure', async () => {
  let fail = false;
  const s = createPolicyStore({ mgmt: fakeMgmt({ delCustomList: async () => { if (fail) throw new Error('x'); } }) });
  await s.load();
  const c = await s.addCustom({ name: 'Mine', inline: 'a.example.com' });
  assert.equal(c.id, 'cl-9');
  assert.equal(s.policy.custom_lists.length, 1);
  assert.equal(s.policy.lists.at(-1).id, 'cl-9');
  await s.setItem(NETWORK, 'cl-9', true);
  fail = true;
  await assert.rejects(s.delCustom('cl-9'));
  assert.equal(s.policy.custom_lists.length, 1);
  assert.equal(dataFor(s.policy, NETWORK).items['cl-9'], true);
  fail = false;
  await s.delCustom('cl-9');
  assert.equal(s.policy.custom_lists.length, 0);
  assert.equal('cl-9' in dataFor(s.policy, NETWORK).items, false);
});

test('refreshLists calls the server and reloads later', async () => {
  const m = fakeMgmt();
  const s = createPolicyStore({ mgmt: m });
  await s.load();
  await s.refreshLists('ads');
  assert.deepEqual(m.calls.find((c) => c[0] === 'refreshLists'), ['refreshLists', 'ads']);
});
