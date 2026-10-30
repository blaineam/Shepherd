import test from 'node:test';
import assert from 'node:assert/strict';
import { fmtCount, normalizeCatalog, matchesQuery, groupCatalog, listStatus, sources, safeHref, bundleProgress } from '../js/catalog.js';

const raw = { categories: ['Social', 'Ads'], entries: [
  { id: 'fb', kind: 'app', name: 'Facebook', category: 'Social', description: 'Feed and groups' },
  { id: 'ig', kind: 'app', name: 'Instagram', category: 'Social', description: 'Photos', recommended: true },
  { id: 'cat-social', kind: 'category', name: 'All Social', category: 'Social', includes: ['fb', 'ig'] },
  { id: 'ads', kind: 'list', name: 'Core Ads', category: 'Ads', description: 'Ad hosts', license: 'CC0', homepage: 'https://example.org/ads', approx_entries: 1200 },
  { id: 'misc', kind: 'weird', name: 'Misc', category: 'Zeta', description: 'Odd' },
  { id: 'adult', kind: 'list', name: 'Adult', category: 'Adult', description: 'x' },
  null, { name: 'no id' },
] };

test('fmtCount', () => {
  assert.equal(fmtCount(0), '0');
  assert.equal(fmtCount(950), '950');
  assert.equal(fmtCount(1500), '1.5k');
  assert.equal(fmtCount(112000), '112k');
  assert.equal(fmtCount(2300000), '2.3M');
  assert.equal(fmtCount(25000000), '25M');
  assert.equal(fmtCount('x'), '0');
});

test('normalizeCatalog is defensive and extends categories', () => {
  const c = normalizeCatalog(raw);
  assert.equal(c.entries.length, 6);
  assert.equal(c.entries.find((e) => e.id === 'misc').kind, 'list', 'unknown kinds become lists');
  assert.deepEqual(c.categories, ['Social', 'Ads', 'Zeta', 'Adult']);
  assert.deepEqual(normalizeCatalog(null), { entries: [], categories: [] });
  assert.equal(normalizeCatalog({ entries: [{ id: 1, name: 5, includes: [1, 2] }] }).entries[0].includes[0], '1');
});

test('matchesQuery matches every word across fields', () => {
  const e = normalizeCatalog(raw).entries[0];
  assert.ok(matchesQuery(e, ''));
  assert.ok(matchesQuery(e, 'face feed'));
  assert.ok(matchesQuery(e, 'SOCIAL'));
  assert.ok(!matchesQuery(e, 'face nope'));
});

test('groupCatalog sorts categories, recommended first, attaches bundles', () => {
  const c = normalizeCatalog(raw);
  const g = groupCatalog(c, '');
  assert.deepEqual(g.apps.map((s) => s.category), ['Social']);
  assert.deepEqual(g.apps[0].entries.map((e) => e.id), ['ig', 'fb']);
  assert.equal(g.apps[0].bundle.id, 'cat-social');
  assert.deepEqual(g.lists.map((s) => s.category), ['Ads', 'Zeta', 'Adult']);
  assert.equal(g.appCount, 2); assert.equal(g.listCount, 3);
  const q = groupCatalog(c, 'insta');
  assert.equal(q.appCount, 1); assert.equal(q.listCount, 0);
  assert.equal(groupCatalog(c, 'zzzz').appCount, 0);
});

test('listStatus reads lists and custom lists', () => {
  const p = { lists: [{ id: 'ads', count: 5, size_bytes: 10, updated: '2026-03-01T00:00:00Z', error: 'bad' }], custom_lists: [{ id: 'cl', count: 9 }] };
  const s = listStatus(p, 'ads');
  assert.equal(s.count, 5); assert.equal(s.error, 'bad'); assert.equal(s.updated, Date.parse('2026-03-01T00:00:00Z'));
  assert.equal(listStatus(p, 'cl').count, 9);
  assert.ok(Number.isNaN(listStatus(p, 'cl').updated));
  assert.equal(listStatus(p, 'none'), null);
  assert.equal(listStatus(null, 'x'), null);
});

test('sources are unique and sorted', () => {
  const c = normalizeCatalog({ entries: [
    { id: 'a', kind: 'list', name: 'Zed', homepage: 'https://e.org/z', license: 'MIT' },
    { id: 'b', kind: 'list', name: 'Alpha', homepage: 'https://e.org/a' },
    { id: 'c', kind: 'list', name: 'Alpha again', homepage: 'https://e.org/a' },
    { id: 'd', kind: 'list', name: 'NoLink' },
    { id: 'e', kind: 'app', name: 'App' },
  ] });
  assert.deepEqual(sources(c).map((s) => s.name), ['Alpha', 'NoLink', 'Zed']);
});

test('safeHref only allows web links', () => {
  assert.equal(safeHref('https://example.org/x'), 'https://example.org/x');
  assert.equal(safeHref('http://example.org'), 'http://example.org/');
  assert.equal(safeHref('javascript:alert(1)'), '');
  assert.equal(safeHref('data:text/html,x'), '');
  assert.equal(safeHref('not a url'), '');
  assert.equal(safeHref(''), '');
});

test('bundleProgress counts blocked members', () => {
  const blocked = new Set(['fb']);
  assert.deepEqual(bundleProgress({ includes: ['fb', 'ig'] }, [], (id) => blocked.has(id)), { on: 1, total: 2 });
  assert.deepEqual(bundleProgress(null, [{ id: 'fb' }, { id: 'x' }], (id) => blocked.has(id)), { on: 1, total: 2 });
});
