import test from 'node:test';
import assert from 'node:assert/strict';
import { TIMER_CHOICES, MODES, isWandering, deviceMode, modeLabel, countdown, countdownShort, modePatch, applyModeLocal, shadowNote } from '../js/wander.js';
import { applyBulkLocal, planUndo, describeBulk } from '../js/bulk.js';
import { parseQuery, matchDevice, FILTER_KEYS } from '../js/search.js';
import { normalizeEntry } from '../js/entry.js';
import { createNameBook } from '../js/names.js';
import { LaneTable } from '../js/lanes.js';
import { Model } from '../js/model.js';
import { createDemoMgmt } from '../js/demomgmt.js';
import { DemoGenerator } from '../js/demo.js';

const NOW = Date.parse('2026-03-02T12:00:00Z');
const iso = (ms) => new Date(ms).toISOString();

test('timer choices cover 15 min to untimed, modes are the three documented', () => {
  assert.deepEqual(TIMER_CHOICES.map((t) => t.minutes), [15, 60, 240, 1440, 0]);
  assert.deepEqual(MODES.map((m) => m.id), ['protected', 'wandering', 'excluded']);
  assert.equal(modeLabel('wandering'), 'Wandering');
  assert.equal(modeLabel('zzz'), 'Protected');
});

test('isWandering honours expired timers; deviceMode prefers wandering over excluded', () => {
  assert.ok(isWandering({ wandering: true }, NOW));
  assert.ok(isWandering({ wandering: true, wandering_until: iso(NOW + 1000) }, NOW));
  assert.ok(!isWandering({ wandering: true, wandering_until: iso(NOW - 1000) }, NOW));
  assert.ok(!isWandering({ wandering: false }, NOW) && !isWandering(null));
  assert.equal(deviceMode({ wandering: true, excluded: true }, NOW), 'wandering');
  assert.equal(deviceMode({ excluded: true }, NOW), 'excluded');
  assert.equal(deviceMode({}, NOW), 'protected');
  assert.equal(deviceMode({ wandering: true, wandering_until: iso(NOW - 1) }, NOW), 'protected');
});

test('countdown wording', () => {
  const w = (ms) => ({ wandering: true, wandering_until: iso(NOW + ms) });
  assert.equal(countdown({}, NOW), '');
  assert.equal(countdown({ wandering: true }, NOW), 'until turned off');
  assert.equal(countdown(w(20000), NOW), 'under a minute left');
  assert.equal(countdown(w(42 * 60000), NOW), '42 min left');
  assert.equal(countdown(w(3 * 3600000 + 10 * 60000), NOW), '3 h 10 min left');
  assert.equal(countdown(w(2 * 3600000), NOW), '2 h left');
  assert.equal(countdown(w(3 * 86400000), NOW), '3 d left');
  assert.equal(countdownShort({}, NOW), '');
  assert.equal(countdownShort({ wandering: true }, NOW), '');
  assert.equal(countdownShort(w(30000), NOW), '<1m');
  assert.equal(countdownShort(w(42 * 60000), NOW), '42m');
  assert.equal(countdownShort(w(3 * 3600000), NOW), '3h');
  assert.equal(countdownShort(w(4 * 86400000), NOW), '4d');
});

test('modePatch and applyModeLocal', () => {
  assert.deepEqual(modePatch('protected'), { excluded: false, wandering: false });
  assert.deepEqual(modePatch('excluded'), { excluded: true, wandering: false });
  assert.deepEqual(modePatch('wandering'), { wandering: true, excluded: false });
  assert.deepEqual(modePatch('wandering', 60), { wandering: true, excluded: false, wandering_minutes: 60 });
  const t = applyModeLocal({ excluded: true }, modePatch('wandering', 15), NOW);
  assert.deepEqual([t.wandering, t.excluded, t.wandering_until], [true, false, iso(NOW + 900000)]);
  const u = applyModeLocal({ wandering: true, wandering_until: iso(NOW) }, modePatch('wandering'), NOW);
  assert.equal(u.wandering_until, undefined);
  const off = applyModeLocal({ wandering: true, wandering_until: iso(NOW) }, modePatch('protected'), NOW);
  assert.deepEqual([off.wandering, off.wandering_until], [false, undefined]);
  assert.equal(applyModeLocal({ id: 'x' }, { alias: 'a' }).id, 'x');
});

test('shadowNote', () => {
  assert.equal(shadowNote({ shadow: 'core-ads' }), 'would have blocked: core-ads');
  assert.equal(shadowNote({ shadow: '' }), '');
  assert.equal(shadowNote(null), '');
});

test('bulk set_wandering applies, describes and can be undone', () => {
  const a = { id: 'a', wandering: false }, b = { id: 'b', wandering: true, excluded: false }, c = { id: 'c', excluded: true };
  const req = { op: 'set_wandering', wandering: true, wandering_minutes: 60 };
  assert.equal(applyBulkLocal(a, req).wandering, true);
  assert.ok(applyBulkLocal(a, req).wandering_until);
  assert.equal(applyBulkLocal(c, { op: 'set_excluded', excluded: true }).wandering, false);
  assert.equal(applyBulkLocal(b, { op: 'set_excluded', excluded: true }).wandering, false);
  assert.deepEqual(planUndo(req, [a, b, c]), [
    { op: 'set_wandering', wandering: false, ids: ['a', 'c'] },
    { op: 'set_excluded', excluded: true, ids: ['c'] },
  ]);
  assert.deepEqual(planUndo({ op: 'set_wandering', wandering: false }, [a, b]), [{ op: 'set_wandering', wandering: true, ids: ['b'] }]);
  assert.equal(describeBulk(req, 2), '2 devices set to wandering for 1 h');
  assert.equal(describeBulk({ op: 'set_wandering', wandering: true, wandering_minutes: 15 }, 1), '1 device set to wandering for 15 min');
  assert.equal(describeBulk({ op: 'set_wandering', wandering: true }, 1), '1 device set to wandering');
  assert.equal(describeBulk({ op: 'set_wandering', wandering: false }, 3), '3 devices back to protected');
});

test('search: wandering filter respects timers', () => {
  assert.ok(FILTER_KEYS.includes('wandering'));
  const m = (d, s) => matchDevice(d, parseQuery(s), { now: NOW });
  assert.ok(m({ wandering: true }, 'wandering:true'));
  assert.ok(!m({ wandering: false }, 'wandering:true'));
  assert.ok(m({}, 'wandering:false'));
  assert.ok(!m({ wandering: true, wandering_until: iso(NOW - 1) }, 'wandering:true'));
  assert.ok(m({ wandering: true }, '-wandering:false'));
});

test('entries, name book, lanes and model carry wandering and shadow', () => {
  const e = normalizeEntry({ time: iso(NOW), client: '192.0.2.1', name: 'a.example.com', action: 'allowed', wandering: true, shadow: 'core-ads', dests: [{ lat: 1, lon: 2 }] });
  assert.equal(e.wandering, true); assert.equal(e.shadow, 'core-ads');
  const plain = normalizeEntry({ time: iso(NOW), client: 'c', action: 'allowed', wandering: 'yes' });
  assert.equal(plain.wandering, false); assert.equal(plain.shadow, '');
  const nb = createNameBook();
  nb.note(e);
  assert.ok(nb.isWandering('192.0.2.1'));
  nb.note({ client: '192.0.2.1', wandering: false });
  assert.ok(!nb.isWandering('192.0.2.1'));
  const lt = new LaneTable();
  const lane = lt.add(e)[0];
  assert.ok(lane.wandering && lane.shadow);
  lt.add({ ...e, wandering: false, shadow: '', t: e.t + 1 });
  assert.ok(!lane.wandering && !lane.shadow);
  const model = new Model();
  model.setFilters({ wandering: true });
  assert.equal(model.ingest({ ...e }), 'lane');
  assert.equal(model.ingest({ ...e, wandering: false }), 'filtered');
  const wl = { client: 'x', action: 'allowed', domains: new Map(), wandering: true, shadow: true };
  assert.ok(model.laneVisible(wl));
  assert.ok(!model.laneVisible({ ...wl, wandering: false }));
  model.setFilters({ wandering: false, shadow: true });
  assert.ok(model.matches({ ...e }) && !model.matches({ ...e, shadow: '' }));
  assert.ok(model.laneVisible(wl) && !model.laneVisible({ ...wl, shadow: false }));
});

test('demo: timed wandering device, patching, bulk, expiry and traffic', async () => {
  let t = NOW;
  const gen = new DemoGenerator({ seed: 5 });
  const d = createDemoMgmt({ count: 38, gen, now: () => t });
  gen.deviceOf = (ip) => d.deviceOf(ip);
  const call = (m, p, b = {}) => d.handle(m, new URL(p, 'http://x').pathname, new URL(p, 'http://x'), b);
  const w = await call('GET', '/api/devices?q=wandering:true&limit=50');
  assert.equal(w.total, 3);
  const timed = w.devices.find((x) => x.wandering_until);
  assert.equal(timed.name, 'Game Console');
  const p = await call('PATCH', '/api/devices/dev-0001', { wandering: true, wandering_minutes: 15 });
  assert.equal(p.wandering, true);
  assert.equal(p.wandering_until, iso(NOW + 900000));
  const off = await call('PATCH', '/api/devices/dev-0001', { wandering: false });
  assert.equal(off.wandering_until, undefined);
  const bulk = await call('POST', '/api/devices/bulk', { ids: ['dev-0001', 'dev-0002'], op: 'set_wandering', wandering: true, wandering_minutes: 60 });
  assert.equal(bulk.changed, 2);
  assert.equal((await call('GET', '/api/devices/dev-0002')).wandering, true);
  t = NOW + 2 * 3600000;
  assert.equal((await call('GET', '/api/devices/dev-0002')).wandering, false, 'expired timer clears like the server');
  assert.equal((await call('GET', '/api/devices/dev-0006')).wandering, false);
  assert.ok((await call('GET', '/api/devices/dev-0007')).wandering, 'untimed stays');
  // traffic from a wandering device is unfiltered and carries shadows
  const es = gen.range(NOW, NOW + 30 * 60000).filter((e) => e.client === '198.51.100.8');
  assert.ok(es.length > 30);
  assert.ok(es.every((e) => e.wandering && e.action !== 'blocked'));
  const shadows = es.filter((e) => e.shadow);
  assert.ok(shadows.length > 0 && shadows.every((e) => e.reason === 'wandering' && (e.action === 'allowed' || e.action === 'cached')));
  assert.ok(gen.range(NOW, NOW + 600000).some((e) => e.client === '192.0.2.14' && !e.wandering));
  assert.equal(d.deviceOf('203.0.113.250'), null);
});
