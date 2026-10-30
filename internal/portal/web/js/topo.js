// Minimal TopoJSON reader for the vendored Natural Earth land data, plus the
// point-in-polygon sampling that turns land polygons into a dot matrix. Pure
// functions, no canvas needed.

// Decode delta-encoded, quantized arcs to [lon, lat] points.
export function decodeArcs(topo) {
  const t = topo.transform;
  return topo.arcs.map((arc) => {
    let x = 0, y = 0;
    return arc.map((p) => {
      x += p[0]; y += p[1];
      return t ? [x * t.scale[0] + t.translate[0], y * t.scale[1] + t.translate[1]] : [x, y];
    });
  });
}

// Stitch arc references (negative = reversed, as ~index) into one ring.
export function stitchRing(refs, arcs) {
  const ring = [];
  for (const r of refs) {
    const pts = r >= 0 ? arcs[r] : arcs[~r].slice().reverse();
    for (let i = ring.length ? 1 : 0; i < pts.length; i++) ring.push(pts[i]);
  }
  return ring;
}

function collectPolygons(geom, arcs, out) {
  if (!geom) return;
  if (geom.type === 'GeometryCollection') { geom.geometries.forEach((g) => collectPolygons(g, arcs, out)); return; }
  if (geom.type === 'Polygon') out.push(geom.arcs.map((r) => stitchRing(r, arcs)));
  else if (geom.type === 'MultiPolygon') geom.arcs.forEach((poly) => out.push(poly.map((r) => stitchRing(r, arcs))));
}

// Returns polygons: each is [outerRing, ...holes], rings being [lon, lat][].
export function landPolygons(topo, objectName = 'land') {
  const arcs = decodeArcs(topo);
  const out = [];
  collectPolygons(topo.objects[objectName], arcs, out);
  return out;
}

export function ringContains(ring, lon, lat) {
  let inside = false;
  for (let i = 0, j = ring.length - 1; i < ring.length; j = i++) {
    const xi = ring[i][0], yi = ring[i][1], xj = ring[j][0], yj = ring[j][1];
    if ((yi > lat) !== (yj > lat) && lon < ((xj - xi) * (lat - yi)) / (yj - yi) + xi) inside = !inside;
  }
  return inside;
}

function bbox(ring) {
  let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
  for (const [x, y] of ring) {
    if (x < x0) x0 = x; if (x > x1) x1 = x;
    if (y < y0) y0 = y; if (y > y1) y1 = y;
  }
  return [x0, y0, x1, y1];
}

// Even-odd across the outer ring and its holes.
export function polygonContains(poly, lon, lat) {
  let n = 0;
  for (const ring of poly) if (ringContains(ring, lon, lat)) n++;
  return (n & 1) === 1;
}

// Equal-area-ish dot matrix: rings of latitude with fewer dots toward the
// poles. Returns a flat [lat, lon, lat, lon, ...] array of land points.
export function sampleLandPoints(polys, stepDeg = 1.6, minLat = -80, maxLat = 84) {
  const boxes = polys.map((p) => bbox(p[0]));
  const out = [];
  for (let lat = minLat; lat <= maxLat; lat += stepDeg) {
    const n = Math.max(1, Math.round((360 * Math.cos((lat * Math.PI) / 180)) / stepDeg));
    for (let i = 0; i < n; i++) {
      const lon = -180 + ((i + 0.5) * 360) / n;
      for (let k = 0; k < polys.length; k++) {
        const b = boxes[k];
        if (lon < b[0] || lon > b[2] || lat < b[1] || lat > b[3]) continue;
        if (polygonContains(polys[k], lon, lat)) { out.push(lat, lon); break; }
      }
    }
  }
  return out;
}

// Coastline segments as [lat1, lon1, lat2, lon2, ...]. Edges that run along
// the antimeridian cut or the polar edge are map seams, not coast, so skip them.
export function coastSegments(polys) {
  const out = [];
  for (const poly of polys) {
    for (const ring of poly) {
      for (let i = 1; i < ring.length; i++) {
        const [x1, y1] = ring[i - 1];
        const [x2, y2] = ring[i];
        if (Math.abs(x2 - x1) > 180) continue;
        if (Math.abs(x1) > 179.99 && Math.abs(x2) > 179.99) continue;
        if (y1 < -84 && y2 < -84) continue;
        out.push(y1, x1, y2, x2);
      }
    }
  }
  return out;
}
