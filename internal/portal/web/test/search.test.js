import test from 'node:test';
import assert from 'node:assert/strict';
import { tokenize, parseQuery, formatFilter, stringifyQuery, addFilter, removeFilter, setText, hasGroupFilter, parseDuration, matchDevice, sortDevices, FILTER_KEYS, FILTER_HELP } from '../js/search.js';

const NOW = Date.parse('2026-03-02T12:00:00Z');
const dev = (o) => ({ id: 'd1', name: 'Kids Tablet', alias: 'Kids Tablet', names: { mdns: 'kids.local' }, vendor: 'Brightwave', type: 'tablet', ips: ['192.0.2.14'], macs: ['02:00:5e:00:00:02'], groups: ['g1'], tags: ['guest'], excluded: false, notes: 'upstairs', last_seen: '2026-03-02T11:30:00Z', ...o });

test('tokenize honours quotes and whitespace', () => {
  assert.deepEqual(tokenize('  a  b '), ['a', 'b']);
  assert.deepEqual(tokenize('group:"Living room" tv'), ['group:Living room', 'tv']);
  assert.deepEqual(tokenize('"two words" x'), ['two words', 'x']);
  assert.deepEqual(tokenize(''), []);
  assert.deepEqual(tokenize(null), []);
});

test('parseQuery splits free text from known filters and negation', () => {
  const q = parseQuery('living tv group:kids -vendor:acme foo:bar seen:1h');
  assert.equal(q.text, 'living tv foo:bar');
  assert.deepEqual(q.filters.map((f) => [f.key, f.value, f.neg]), [['group', 'kids', false], ['vendor', 'acme', true], ['seen', '1h', false]]);
  assert.deepEqual(parseQuery('GROUP:Kids').filters[0], { key: 'group', value: 'Kids', neg: false });
  assert.equal(parseQuery('group:').text, 'group:');
  assert.ok(FILTER_KEYS.every((k) => FILTER_HELP.some((h) => h.key === k)));
});

test('format and stringify round-trip, quoting spaces', () => {
  assert.equal(formatFilter({ key: 'group', value: 'Living room', neg: false }), 'group:"Living room"');
  assert.equal(formatFilter({ key: 'tag', value: 'x', neg: true }), '-tag:x');
  const q = parseQuery('tv group:"Living room" -type:camera');
  assert.equal(stringifyQuery(q), 'tv group:"Living room" -type:camera');
  assert.deepEqual(parseQuery(stringifyQuery(q)), q);
});

test('addFilter dedupes, removeFilter and setText are immutable', () => {
  const q = { text: '', filters: [] };
  const a = addFilter(q, 'group', 'Kids');
  assert.equal(a.filters.length, 1);
  assert.equal(addFilter(a, 'group', 'kids'), a);
  assert.equal(addFilter(a, 'group', 'kids', true).filters.length, 2);
  assert.equal(q.filters.length, 0);
  assert.equal(removeFilter(a, 0).filters.length, 0);
  assert.equal(setText(a, 'x').text, 'x');
  assert.equal(hasGroupFilter(a, 'KIDS'), 0);
  assert.equal(hasGroupFilter(a, 'other'), -1);
});

test('parseDuration', () => {
  assert.equal(parseDuration('30m'), 1800000);
  assert.equal(parseDuration('1h'), 3600000);
  assert.equal(parseDuration('2d'), 172800000);
  assert.equal(parseDuration('1w'), 604800000);
  assert.equal(parseDuration('1.5h'), 5400000);
  assert.equal(parseDuration('abc'), null);
  assert.equal(parseDuration(''), null);
});

test('matchDevice: free text across fields', () => {
  const d = dev();
  const m = (s, o) => matchDevice(d, parseQuery(s), { now: NOW, ...o });
  assert.ok(m('kids'));
  assert.ok(m('KIDS tablet'));
  assert.ok(m('bright'));
  assert.ok(m('192.0.2'));
  assert.ok(m('02:00:5e'));
  assert.ok(m('upstairs'));
  assert.ok(m('guest'));
  assert.ok(m('kids.local'));
  assert.ok(!m('missing'));
  assert.ok(!m('kids missing'));
});

test('matchDevice: filters', () => {
  const d = dev();
  const gn = (id) => ({ g1: 'Kids', g2: 'Work' }[id]);
  const m = (s) => matchDevice(d, parseQuery(s), { now: NOW, groupName: gn });
  assert.ok(m('group:kids'));
  assert.ok(m('group:g1'));
  assert.ok(!m('group:work'));
  assert.ok(m('-group:work'));
  assert.ok(!m('-group:kids'));
  assert.ok(m('vendor:bright'));
  assert.ok(m('type:tablet'));
  assert.ok(m('type:tab'), 'type matches loosely');
  assert.ok(!m('type:camera'));
  assert.ok(matchDevice(dev({ type: 'router/infrastructure' }), parseQuery('type:router'), { now: NOW }));
  assert.ok(matchDevice(dev({ type: 'game console' }), parseQuery('type:game_console'), { now: NOW }));
  assert.ok(m('ip:192.0.2.'));
  assert.ok(!m('ip:10.'));
  assert.ok(m('seen:1h'));
  assert.ok(!m('seen:10m'));
  assert.ok(!m('seen:bogus'));
  assert.ok(m('excluded:false'));
  assert.ok(!m('excluded:true'));
  assert.ok(m('unnamed:false'));
  assert.ok(m('tag:GUEST'));
  assert.ok(!m('tag:other'));
  assert.ok(matchDevice(dev({ alias: '', names: {} }), parseQuery('unnamed:true'), { now: NOW }));
  assert.ok(matchDevice(dev({ excluded: true }), parseQuery('excluded:yes'), { now: NOW }));
  assert.ok(matchDevice({ id: 'x' }, parseQuery(''), { now: NOW }));
});

test('sortDevices by recent and name does not mutate', () => {
  const a = dev({ id: 'a', name: 'b2', last_seen: '2026-03-02T10:00:00Z' });
  const b = dev({ id: 'b', name: 'B10', last_seen: '2026-03-02T11:00:00Z' });
  const c = dev({ id: 'c', name: 'a', last_seen: '2026-03-02T09:00:00Z' });
  const src = [a, b, c];
  assert.deepEqual(sortDevices(src, 'recent').map((x) => x.id), ['b', 'a', 'c']);
  assert.deepEqual(sortDevices(src, 'name').map((x) => x.id), ['c', 'a', 'b']);
  assert.deepEqual(src.map((x) => x.id), ['a', 'b', 'c']);
});
