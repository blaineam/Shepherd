// Pure geometry helpers: lat/lon <-> unit vectors, great-circle math and the
// arc a "flight" follows. Nothing here touches the DOM or WebGL, so it is unit
// tested directly. The vertex shader in globe.js mirrors arcPoint().

export const DEG = Math.PI / 180;
export const EARTH_KM = 6371.0088;

export const clamp = (v, lo, hi) => (v < lo ? lo : v > hi ? hi : v);

// Right-handed, y up, +z toward (lat 0, lon 0), +x toward lon 90E.
export function latLonToVec3(lat, lon, r = 1, out = [0, 0, 0]) {
  const phi = lat * DEG;
  const lam = lon * DEG;
  const c = Math.cos(phi);
  out[0] = r * c * Math.sin(lam);
  out[1] = r * Math.sin(phi);
  out[2] = r * c * Math.cos(lam);
  return out;
}

export function vec3ToLatLon(x, y, z) {
  const len = Math.hypot(x, y, z) || 1;
  const lat = Math.asin(clamp(y / len, -1, 1)) / DEG;
  const lon = Math.atan2(x, z) / DEG;
  return { lat, lon };
}

export function validLatLon(lat, lon) {
  return Number.isFinite(lat) && Number.isFinite(lon) && Math.abs(lat) <= 90 && Math.abs(lon) <= 180;
}

// Angle between two surface points in radians (haversine, stable for small angles).
export function greatCircleAngle(lat1, lon1, lat2, lon2) {
  const p1 = lat1 * DEG;
  const p2 = lat2 * DEG;
  const dp = p2 - p1;
  const dl = (lon2 - lon1) * DEG;
  const a = Math.sin(dp / 2) ** 2 + Math.cos(p1) * Math.cos(p2) * Math.sin(dl / 2) ** 2;
  return 2 * Math.asin(Math.min(1, Math.sqrt(a)));
}

export function greatCircleKm(lat1, lon1, lat2, lon2) {
  return greatCircleAngle(lat1, lon1, lat2, lon2) * EARTH_KM;
}

export function dot3(a, b) {
  return a[0] * b[0] + a[1] * b[1] + a[2] * b[2];
}

// Spherical interpolation of unit vectors. Falls back to a normalised lerp when
// the points are (anti)parallel, where slerp is degenerate.
export function slerp(a, b, t, out = [0, 0, 0]) {
  const d = clamp(dot3(a, b), -1, 1);
  const om = Math.acos(d);
  const s = Math.sin(om);
  if (s < 1e-3) {
    let x = a[0] + (b[0] - a[0]) * t;
    let y = a[1] + (b[1] - a[1]) * t;
    let z = a[2] + (b[2] - a[2]) * t;
    if (d < 0 && Math.hypot(x, y, z) < 1e-6) { x = 0; y = 1; z = 0; }
    const n = Math.hypot(x, y, z) || 1;
    out[0] = x / n; out[1] = y / n; out[2] = z / n;
    return out;
  }
  const k1 = Math.sin((1 - t) * om) / s;
  const k2 = Math.sin(t * om) / s;
  out[0] = a[0] * k1 + b[0] * k2;
  out[1] = a[1] * k1 + b[1] * k2;
  out[2] = a[2] * k1 + b[2] * k2;
  return out;
}

// How far above the surface an arc peaks, in globe radii. Short hops stay
// close to the ground, antipodal ones leap well clear of the globe.
export function arcLift(angle) {
  return 0.03 + 0.5 * Math.pow(clamp(angle / Math.PI, 0, 1), 0.9);
}

export const SURFACE_EPS = 0.004;

// Point on the arc at parameter t in [0,1]; matches arcAt() in the shader.
export function arcPoint(a, b, lift, t, out = [0, 0, 0]) {
  slerp(a, b, t, out);
  const k = 1 + SURFACE_EPS + lift * Math.sin(Math.PI * t);
  out[0] *= k; out[1] *= k; out[2] *= k;
  return out;
}

// Does the segment from the camera c to point p pass through a sphere of radius
// r at the origin? Used to decide whether an arc point is hidden by the globe.
export function segmentHitsSphere(c, p, r = 1) {
  const dx = p[0] - c[0], dy = p[1] - c[1], dz = p[2] - c[2];
  const len2 = dx * dx + dy * dy + dz * dz;
  if (len2 === 0) return false;
  let t = -(c[0] * dx + c[1] * dy + c[2] * dz) / len2;
  t = clamp(t, 0, 1);
  const x = c[0] + dx * t, y = c[1] + dy * t, z = c[2] + dz * t;
  return x * x + y * y + z * z < r * r;
}

// Exponential approach used for rotation inertia: returns the new velocity
// after dt seconds with the given half-life.
export function dampVelocity(v, dt, halfLife = 0.35) {
  return v * Math.pow(0.5, dt / halfLife);
}

export function normalizeLon(lon) {
  let l = ((lon + 180) % 360 + 360) % 360 - 180;
  if (l === -180 && lon > 0) l = 180;
  return l;
}
