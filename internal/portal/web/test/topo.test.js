import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  decodeArcs, stitchRing, landPolygons, ringContains, polygonContains, sampleLandPoints, coastSegments,
} from '../js/topo.js';

// A 10x10 square with a 4x4 hole, expressed as quantized TopoJSON.
const topo = {
  type: 'Topology',
  transform: { scale: [1, 1], translate: [0, 0] },
  arcs: [
    [[0, 0], [10, 0], [0, 10], [-10, 0], [0, -10]], // outer ring, closed
    [[3, 3], [4, 0], [0, 4], [-4, 0], [0, -4]], // hole
    [[20, 0], [5, 0]], // two-part ring: a
    [[25, 0], [0, 5], [-5, 0]], // two-part ring: b (closes back to a's start via reversed use)
  ],
  objects: {
    land: { type: 'GeometryCollection', geometries: [{ type: 'Polygon', arcs: [[0], [1]] }, { type: 'MultiPolygon', arcs: [[[2, 3]]] }] },
  },
};

test('decodeArcs applies delta decoding and the transform', () => {
  const arcs = decodeArcs({ ...topo, transform: { scale: [2, 3], translate: [10, 20] } });
  assert.deepEqual(arcs[0][0], [10, 20]);
  assert.deepEqual(arcs[0][1], [30, 20]);
  assert.deepEqual(arcs[0][2], [30, 50]);
  const raw = decodeArcs({ arcs: [[[1, 1], [1, 1]]], objects: {} });
  assert.deepEqual(raw[0], [[1, 1], [2, 2]]);
});

test('stitchRing joins forward and reversed arcs without duplicating joins', () => {
  const arcs = [[[0, 0], [1, 0]], [[1, 0], [1, 1]]];
  assert.deepEqual(stitchRing([0, 1], arcs), [[0, 0], [1, 0], [1, 1]]);
  assert.deepEqual(stitchRing([~1], arcs), [[1, 1], [1, 0]]);
});

test('landPolygons returns polygons with holes', () => {
  const polys = landPolygons(topo);
  assert.equal(polys.length, 2);
  assert.equal(polys[0].length, 2);
  assert.equal(polys[1].length, 1);
});

test('point in polygon respects holes', () => {
  const [sq] = landPolygons(topo);
  assert.ok(polygonContains(sq, 1, 1));
  assert.ok(!polygonContains(sq, 5, 5)); // inside the hole
  assert.ok(!polygonContains(sq, 11, 5));
  assert.ok(ringContains(sq[0], 5, 5));
});

test('sampleLandPoints only returns points on land', () => {
  const polys = landPolygons(topo);
  const pts = sampleLandPoints(polys, 1, 0, 12);
  assert.ok(pts.length > 0 && pts.length % 2 === 0);
  for (let i = 0; i < pts.length; i += 2) {
    const lat = pts[i], lon = pts[i + 1];
    assert.ok(polys.some((p) => polygonContains(p, lon, lat)));
  }
});

test('coastSegments skips seams', () => {
  const polys = [[[[-180, 0], [-180, 10], [-170, 10], [-170, 0], [-180, 0]], ]];
  const seg = coastSegments(polys);
  // the two points on the antimeridian form a seam edge and are skipped
  assert.equal(seg.length, 3 * 4);
  const polar = coastSegments([[[[0, -90], [10, -90], [10, -80], [0, -80], [0, -90]]]]);
  assert.equal(polar.length, 3 * 4);
  const wrap = coastSegments([[[[-179, 0], [179, 0]]]]);
  assert.equal(wrap.length, 0);
});

test('the vendored Natural Earth land data decodes and samples sensibly', () => {
  const data = JSON.parse(readFileSync(new URL('../vendor/land-110m.json', import.meta.url), 'utf8'));
  const polys = landPolygons(data);
  assert.ok(polys.length > 50);
  const land = (lat, lon) => polys.some((p) => polygonContains(p, lon, lat));
  assert.ok(land(40, -100), 'central North America is land');
  assert.ok(land(50, 10), 'central Europe is land');
  assert.ok(land(-25, 135), 'Australia is land');
  assert.ok(!land(0, -150), 'mid Pacific is ocean');
  assert.ok(!land(-40, -20), 'South Atlantic is ocean');
  const pts = sampleLandPoints(polys, 3);
  assert.ok(pts.length / 2 > 1000);
  assert.ok(coastSegments(polys).length / 4 > 1000);
});
