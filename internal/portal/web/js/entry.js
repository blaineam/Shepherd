// Normalisation of API entries. Everything here treats the input as untrusted
// network data: values are coerced, never trusted to be the right type.

export const ACTIONS = ['allowed', 'cached', 'blocked', 'error'];

export function toStr(v, max = 256) {
  return typeof v === 'string' ? v.slice(0, max) : v == null ? '' : String(v).slice(0, max);
}

export function validDest(d) {
  return d && Number.isFinite(d.lat) && Number.isFinite(d.lon) && Math.abs(d.lat) <= 90 && Math.abs(d.lon) <= 180;
}

// Adds e.t (ms since epoch) and a sanitized action, and keeps only valid dests.
// Returns null when the object cannot be an entry at all.
export function normalizeEntry(e) {
  if (!e || typeof e !== 'object') return null;
  const t = Date.parse(e.time);
  e.t = Number.isFinite(t) ? t : Date.now();
  e.client = toStr(e.client);
  e.name = toStr(e.name);
  if (!ACTIONS.includes(e.action)) e.action = 'error';
  if (Array.isArray(e.dests)) e.dests = e.dests.filter(validDest);
  else e.dests = null;
  if (e.dests && e.dests.length === 0) e.dests = null;
  return e;
}

export function destKey(d) {
  return d.lat.toFixed(1) + ',' + d.lon.toFixed(1);
}

export function placeName(d) {
  const city = toStr(d.city, 64);
  const cc = toStr(d.country, 8);
  if (city && cc) return city + ', ' + cc;
  return city || cc || 'Unknown place';
}
