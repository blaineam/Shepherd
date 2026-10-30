// Investigation view logic: ranges, query building, paging backwards in time.
import { normalizeEntry } from './entry.js';

export const RANGES = [
  { id: '1h', label: 'Last hour', ms: 3600000 },
  { id: '24h', label: '24 hours', ms: 86400000 },
  { id: '7d', label: '7 days', ms: 7 * 86400000 },
  { id: 'custom', label: 'Custom', ms: 0 },
];

export function rangeFor(id, now, custom) {
  if (id === 'custom') {
    const from = Date.parse(custom && custom.from), to = Date.parse(custom && custom.to);
    return { from: Number.isFinite(from) ? from : now - 86400000, to: Number.isFinite(to) ? to : now };
  }
  const r = RANGES.find((x) => x.id === id) || RANGES[1];
  return { from: now - r.ms, to: now };
}

// `to` is moved back to the oldest entry already shown to fetch the previous page.
export function buildQuery({ from, to, client, q, action, limit = 100 }) {
  const p = { from: new Date(from).toISOString(), to: new Date(to).toISOString(), limit };
  if (client) p.client = client;
  if (q) p.q = q;
  if (action && action !== 'all') p.action = action;
  return p;
}

// Fresh response -> sorted newest first, normalised.
export function normalizeResponse(r) {
  const entries = [];
  for (const raw of Array.isArray(r && r.entries) ? r.entries : []) {
    if (!raw || typeof raw !== 'object') continue;
    const e = normalizeEntry({ ...raw });
    if (e) entries.push(e);
  }
  entries.sort((a, b) => b.t - a.t || (b.id || 0) - (a.id || 0));
  return {
    entries, source: r && r.source === 'encrypted' ? 'encrypted' : 'memory', locked: !!(r && r.locked),
    oldest: Date.parse(r && r.oldest), newest: Date.parse(r && r.newest), skipped: Number(r && r.skipped) || 0,
  };
}

const keyOf = (e) => (e.id != null && e.id !== 0 ? 'i' + e.id : e.t + '|' + e.client + '|' + e.name + '|' + e.type);

// Appends an older page, dropping repeats at the seam. Returns {entries, added}.
export function mergeOlder(existing, page) {
  const seen = new Set(existing.map(keyOf));
  const add = page.filter((e) => !seen.has(keyOf(e)));
  return { entries: existing.concat(add), added: add.length };
}

// Cursor for the next (older) page; null when the last page was short.
export function nextCursor(entries, limit, lastPageSize) {
  if (!entries.length || lastPageSize < limit) return null;
  return entries[entries.length - 1].t;
}

export function sane(t) { return Number.isFinite(t) && t > 946684800000; }

export function retainedSpan(r) {
  if (!r || !sane(r.oldest) || !sane(r.newest) || r.newest < r.oldest) return null;
  return { oldest: r.oldest, newest: r.newest, ms: r.newest - r.oldest };
}

export function fmtSpan(ms) {
  const m = Math.round(ms / 60000);
  if (m < 90) return m + ' min';
  const h = Math.round(ms / 3600000);
  if (h < 48) return h + ' hours';
  return Math.round(ms / 86400000) + ' days';
}

export function placeOf(e) {
  const d = e.dests && e.dests[0];
  if (!d) return e.action === 'blocked' ? 'Blocked at home' : '';
  const city = typeof d.city === 'string' ? d.city : '', cc = typeof d.country === 'string' ? d.country : '';
  return city && cc ? city + ', ' + cc : city || cc || '';
}

export function toLocalInput(ms) {
  const d = new Date(ms), p = (n) => String(n).padStart(2, '0');
  return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + 'T' + p(d.getHours()) + ':' + p(d.getMinutes());
}
