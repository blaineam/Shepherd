import test from 'node:test';
import assert from 'node:assert/strict';
import {
  latLonToVec3, vec3ToLatLon, greatCircleAngle, greatCircleKm, slerp, arcLift, arcPoint, segmentHitsSphere,
  dampVelocity, normalizeLon, validLatLon, clamp, dot3, EARTH_KM, SURFACE_EPS,
} from '../js/geo.js';

const near = (a, b, eps = 1e-9) => assert.ok(Math.abs(a - b) < eps, `${a} != ${b}`);

test('latLonToVec3 axes', () => {
  const p0 = latLonToVec3(0, 0);
  near(p0[0], 0); near(p0[1], 0); near(p0[2], 1);
  const east = latLonToVec3(0, 90);
  near(east[0], 1); near(east[2], 0, 1e-12);
  const north = latLonToVec3(90, 0);
  near(north[1], 1);
  const r2 = latLonToVec3(10, 20, 2);
  near(Math.hypot(...r2), 2);
});

test('lat/lon round trip', () => {
  for (const [lat, lon] of [[0, 0], [45, -120], [-33.9, 151.2], [89, 10], [-60, 179], [12.5, -179.5]]) {
    const v = latLonToVec3(lat, lon);
    const b = vec3ToLatLon(...v);
    near(b.lat, lat, 1e-9); near(b.lon, lon, 1e-9);
  }
  const scaled = vec3ToLatLon(0, 0, 5);
  near(scaled.lat, 0); near(scaled.lon, 0);
  assert.deepEqual(vec3ToLatLon(0, 0, 0), { lat: 0, lon: 0 });
});

test('validLatLon', () => {
  assert.ok(validLatLon(0, 0));
  assert.ok(validLatLon(-90, 180));
  assert.ok(!validLatLon(91, 0));
  assert.ok(!validLatLon(0, 181));
  assert.ok(!validLatLon(NaN, 0));
  assert.ok(!validLatLon('1', 1));
});

test('great circle angle and distance', () => {
  near(greatCircleAngle(0, 0, 0, 0), 0);
  near(greatCircleAngle(0, 0, 0, 90), Math.PI / 2);
  near(greatCircleAngle(90, 0, -90, 0), Math.PI);
  near(greatCircleAngle(0, 0, 0, 180), Math.PI, 1e-12);
  // New York to London is about 5570 km.
  const km = greatCircleKm(40.71, -74.0, 51.51, -0.13);
  assert.ok(km > 5500 && km < 5650, String(km));
  near(greatCircleKm(0, 0, 0, 90), (Math.PI / 2) * EARTH_KM, 1e-6);
  // symmetry
  near(greatCircleAngle(10, 20, -30, 140), greatCircleAngle(-30, 140, 10, 20));
});

test('slerp keeps unit length and hits endpoints', () => {
  const a = latLonToVec3(10, 20), b = latLonToVec3(-40, 130);
  const s0 = slerp(a, b, 0), s1 = slerp(a, b, 1), sm = slerp(a, b, 0.5);
  for (let i = 0; i < 3; i++) { near(s0[i], a[i]); near(s1[i], b[i]); }
  near(Math.hypot(...sm), 1);
  near(greatCircleAngle(...Object.values(vec3ToLatLon(...a)), ...Object.values(vec3ToLatLon(...sm))), greatCircleAngle(10, 20, -40, 130) / 2, 1e-9);
});

test('slerp degenerate cases', () => {
  const a = latLonToVec3(0, 0);
  const same = slerp(a, a, 0.5);
  near(Math.hypot(...same), 1);
  const anti = slerp(a, latLonToVec3(0, 180), 0.5);
  near(Math.hypot(...anti), 1);
  const exact = slerp([0, 0, 1], [0, 0, -1], 0.5);
  near(Math.hypot(...exact), 1);
});

test('arcLift grows with distance and is bounded', () => {
  assert.ok(arcLift(0) > 0);
  assert.ok(arcLift(0.2) < arcLift(1.0));
  assert.ok(arcLift(1.0) < arcLift(Math.PI));
  near(arcLift(10), arcLift(Math.PI));
  assert.ok(arcLift(Math.PI) < 0.6);
});

test('arcPoint starts and ends on the surface and peaks above it', () => {
  const a = latLonToVec3(40, -100), b = latLonToVec3(35, 139);
  const ang = greatCircleAngle(40, -100, 35, 139);
  const lift = arcLift(ang);
  const p0 = arcPoint(a, b, lift, 0), p1 = arcPoint(a, b, lift, 1), pm = arcPoint(a, b, lift, 0.5);
  near(Math.hypot(...p0), 1 + SURFACE_EPS); near(Math.hypot(...p1), 1 + SURFACE_EPS);
  near(Math.hypot(...pm), 1 + SURFACE_EPS + lift, 1e-9);
  // Every sample stays at or above the surface.
  for (let t = 0; t <= 1; t += 0.05) assert.ok(Math.hypot(...arcPoint(a, b, lift, t)) >= 1);
});

test('segmentHitsSphere', () => {
  const cam = [0, 0, 4];
  assert.equal(segmentHitsSphere(cam, [0, 0, 1], 1), false); // front of the globe
  assert.equal(segmentHitsSphere(cam, [0, 0, -1], 1), true); // behind the globe
  assert.equal(segmentHitsSphere(cam, [0, 2, 0], 1), false); // well off to the side
  assert.equal(segmentHitsSphere(cam, cam, 1), false);
  assert.equal(segmentHitsSphere(cam, [0, 0, 1.4], 1), false);
});

test('dampVelocity halves per half life', () => {
  near(dampVelocity(10, 0.35, 0.35), 5);
  near(dampVelocity(10, 0, 0.35), 10);
  assert.ok(Math.abs(dampVelocity(10, 5)) < 0.01);
});

test('normalizeLon and clamp and dot3', () => {
  near(normalizeLon(190), -170);
  near(normalizeLon(-190), 170);
  near(normalizeLon(0), 0);
  near(normalizeLon(540), 180);
  near(normalizeLon(180), 180);
  assert.equal(clamp(5, 0, 3), 3);
  assert.equal(clamp(-5, 0, 3), 0);
  assert.equal(clamp(2, 0, 3), 2);
  assert.equal(dot3([1, 2, 3], [4, 5, 6]), 32);
});
