import { test } from 'node:test';
import assert from 'node:assert/strict';
import { wrapDelta, project, unproject, arcControl, bezier, subsolarPoint, terminatorLat } from '../js/flatmap.js';

const view = { cLon: 0, cLat: 0, k: 2, w: 720, h: 360 };

test('wrapDelta takes the short way round', () => {
  assert.equal(wrapDelta(190), -170);
  assert.equal(wrapDelta(-190), 170);
  assert.equal(wrapDelta(30), 30);
});

test('project and unproject round trip, centre maps to middle', () => {
  const c = project(0, 0, view);
  assert.deepEqual([c.x, c.y], [360, 180]);
  const p = project(40, -75, view);
  const ll = unproject(p.x, p.y, view);
  assert.ok(Math.abs(ll.lat - 40) < 1e-9 && Math.abs(ll.lon + 75) < 1e-9);
});

test('project picks the world copy nearest the view centre', () => {
  const v = { ...view, cLon: 170 };
  const east = project(0, -170, v); // 20 degrees east of centre across the seam
  assert.equal(east.x, 360 + 20 * 2);
});

test('arc bows toward the top of the screen whichever way it runs', () => {
  const a = arcControl(0, 100, 100, 100, 20);
  const b = arcControl(100, 100, 0, 100, 20);
  assert.ok(a.y < 100 && b.y < 100);
  const m = bezier(0, 100, a.x, a.y, 100, 100, 0.5);
  assert.ok(m.y < 100 && Math.abs(m.x - 50) < 1e-9);
});

test('bezier hits its endpoints', () => {
  assert.deepEqual(bezier(1, 2, 5, 9, 7, 3, 0), { x: 1, y: 2 });
  assert.deepEqual(bezier(1, 2, 5, 9, 7, 3, 1), { x: 7, y: 3 });
});

test('subsolar point matches known solstice and noon positions', () => {
  // 2024-06-20 12:00 UTC: sun near the Tropic of Cancer, over roughly 0 degrees E.
  const s = subsolarPoint(Date.UTC(2024, 5, 20, 12, 0, 0));
  assert.ok(Math.abs(s.lat - 23.4) < 0.5, `lat ${s.lat}`);
  assert.ok(Math.abs(s.lon) < 5, `lon ${s.lon}`);
  // Six hours later it has moved about 90 degrees west.
  const t = subsolarPoint(Date.UTC(2024, 5, 20, 18, 0, 0));
  assert.ok(Math.abs(t.lon + 90) < 5, `lon ${t.lon}`);
});

test('terminator is the boundary: the antisolar side is dark, the subsolar side is not', () => {
  const sun = { lat: 20, lon: 0 };
  assert.ok(terminatorLat(0, sun) < -60); // far south on the sun's meridian
  assert.ok(terminatorLat(180, sun) > 60); // far north opposite
});
