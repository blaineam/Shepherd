import test from 'node:test';
import assert from 'node:assert/strict';
import { normTag, parseTags, applyBulkLocal, planUndo, describeBulk } from '../js/bulk.js';

const d = (id, o = {}) => ({ id, groups: [], tags: [], excluded: false, ...o });

test('tags are normalised and de-duplicated', () => {
  assert.equal(normTag('  Guest Room '), 'guest-room');
  assert.equal(normTag(null), '');
  assert.deepEqual(parseTags('a, B ,a\nc,,'), ['a', 'b', 'c']);
  assert.deepEqual(parseTags(''), []);
});

test('applyBulkLocal mirrors the server for each op', () => {
  const x = d('1', { groups: ['g1'], tags: ['a', 'b'] });
  assert.deepEqual(applyBulkLocal(x, { op: 'assign_group', group_id: 'g2' }).groups, ['g1', 'g2']);
  assert.equal(applyBulkLocal(x, { op: 'assign_group', group_id: 'g1' }).groups, x.groups);
  assert.deepEqual(applyBulkLocal(x, { op: 'remove_group', group_id: 'g1' }).groups, []);
  assert.equal(applyBulkLocal(x, { op: 'set_excluded', excluded: true }).excluded, true);
  assert.deepEqual(applyBulkLocal(x, { op: 'set_tags', add_tags: ['C d', 'a'], remove_tags: ['b'] }).tags, ['a', 'c-d']);
  assert.deepEqual(applyBulkLocal(d('2'), { op: 'assign_group', group_id: 'g' }).groups, ['g']);
  assert.equal(applyBulkLocal(x, { op: 'delete' }).id, '1');
  assert.deepEqual(x.groups, ['g1']);
});

test('planUndo restores only what changed', () => {
  const before = [d('1', { groups: ['g'] }), d('2')];
  assert.deepEqual(planUndo({ op: 'assign_group', group_id: 'g' }, before), [{ op: 'remove_group', group_id: 'g', ids: ['2'] }]);
  assert.deepEqual(planUndo({ op: 'remove_group', group_id: 'g' }, before), [{ op: 'assign_group', group_id: 'g', ids: ['1'] }]);
  const ex = [d('1', { excluded: true }), d('2')];
  assert.deepEqual(planUndo({ op: 'set_excluded', excluded: true }, ex), [{ op: 'set_excluded', excluded: false, ids: ['2'] }]);
  assert.deepEqual(planUndo({ op: 'set_excluded', excluded: false }, ex), [{ op: 'set_excluded', excluded: true, ids: ['1'] }]);
  const tg = [d('1', { tags: ['a'] }), d('2', { tags: ['z'] })];
  assert.deepEqual(planUndo({ op: 'set_tags', add_tags: ['a'], remove_tags: ['z'] }, tg), [
    { op: 'set_tags', remove_tags: ['a'], ids: ['2'] },
    { op: 'set_tags', add_tags: ['z'], ids: ['2'] },
  ]);
  assert.deepEqual(planUndo({ op: 'assign_group', group_id: 'g' }, [d('1', { groups: ['g'] })]), []);
  assert.equal(planUndo({ op: 'delete' }, before), null);
});

test('describeBulk words each op and pluralises', () => {
  const gn = (id) => ({ g: 'Kids' }[id] || id);
  assert.equal(describeBulk({ op: 'assign_group', group_id: 'g' }, 1, gn), 'Added 1 device to Kids');
  assert.equal(describeBulk({ op: 'remove_group', group_id: 'g' }, 3, gn), 'Removed 3 devices from Kids');
  assert.equal(describeBulk({ op: 'set_excluded', excluded: true }, 2), 'Excluded 2 devices');
  assert.equal(describeBulk({ op: 'set_excluded', excluded: false }, 2), 'Included 2 devices');
  assert.equal(describeBulk({ op: 'set_tags' }, 2), 'Updated tags on 2 devices');
  assert.equal(describeBulk({ op: 'delete' }, 1500), 'Deleted 1,500 devices');
  assert.equal(describeBulk({ op: 'zzz' }, 1), 'Done');
});
