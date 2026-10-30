import test from 'node:test';
import assert from 'node:assert/strict';
import { Selection } from '../js/selection.js';

const ids = ['a', 'b', 'c', 'd', 'e', 'f'];

test('toggle selects and deselects and tracks the anchor', () => {
  const s = new Selection();
  assert.ok(s.empty);
  assert.equal(s.toggle('a', 0), true);
  assert.equal(s.toggle('b', 1), true);
  assert.equal(s.count(), 2);
  assert.equal(s.toggle('a', 0), false);
  assert.equal(s.count(), 1);
  assert.ok(s.has('b') && !s.has('a'));
});

test('range selects between the anchor and the clicked row in either direction', () => {
  const s = new Selection();
  s.toggle('b', 1);
  s.range(ids, 4);
  assert.deepEqual([...s.ids].sort(), ['b', 'c', 'd', 'e']);
  const t = new Selection();
  t.toggle('e', 4);
  t.range(ids, 1);
  assert.deepEqual([...t.ids].sort(), ['b', 'c', 'd', 'e']);
});

test('range without a usable anchor behaves like a toggle; unloaded ids are skipped', () => {
  const s = new Selection();
  s.range(ids, 2);
  assert.deepEqual([...s.ids], ['c']);
  const t = new Selection();
  t.toggle('a', 0);
  t.range(['a', undefined, 'c'], 2);
  assert.deepEqual([...t.ids].sort(), ['a', 'c']);
  const u = new Selection();
  u.anchor = 99;
  u.range(ids, 1);
  assert.deepEqual([...u.ids], ['b']);
});

test('selectPage and pageState', () => {
  const s = new Selection();
  assert.equal(s.pageState([]), 'none');
  assert.equal(s.pageState(ids), 'none');
  s.toggle('a', 0);
  assert.equal(s.pageState(ids), 'some');
  s.selectPage(ids);
  assert.equal(s.pageState(ids), 'all');
  assert.equal(s.count(), 6);
});

test('all-matches mode counts the total minus exceptions', () => {
  const s = new Selection();
  s.selectAllMatches(5000);
  assert.equal(s.count(), 5000);
  assert.ok(s.has('anything'));
  s.toggle('x', 3);
  s.toggle('y', 4);
  assert.equal(s.count(), 4998);
  assert.ok(!s.has('x'));
  s.toggle('x', 3);
  assert.equal(s.count(), 4999);
  s.setTotal(10);
  assert.equal(s.count(), 9);
  assert.equal(s.pageState(['x', 'y', 'z']), 'some');
  s.selectPage(['q']);
  assert.ok(!s.allMatches);
});

test('resolve returns ids or fetches all minus exceptions', async () => {
  const s = new Selection();
  s.selectPage(['a', 'b']);
  assert.deepEqual(await s.resolve(async () => { throw new Error('no'); }), ['a', 'b']);
  const t = new Selection();
  t.selectAllMatches(3);
  t.toggle('b', 1);
  assert.deepEqual(await t.resolve(async () => ['a', 'b', 'c']), ['a', 'c']);
});

test('forget and clear', () => {
  const s = new Selection();
  s.selectPage(ids);
  s.forget(['a', 'b']);
  assert.equal(s.count(), 4);
  s.selectAllMatches(4);
  s.toggle('c', 2);
  s.forget(['c']);
  assert.equal(s.excluded.size, 0);
  s.clear();
  assert.ok(s.empty && !s.allMatches);
});
