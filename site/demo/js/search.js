import { normType } from './devtypes.js';
import { isWandering } from './wander.js';

// Device search syntax: free text plus key:value filters, "-" negates.
// Pure and shared by the toolbar (chips), the demo backend and the tests.

export const FILTER_KEYS = ['group', 'vendor', 'type', 'ip', 'seen', 'excluded', 'unnamed', 'tag', 'wandering'];

export const FILTER_HELP = [
  { key: 'group', example: 'group:kids', text: 'Devices in a group' },
  { key: 'vendor', example: 'vendor:halcyon', text: 'Manufacturer contains' },
  { key: 'type', example: 'type:camera', text: 'Device type (tv, phone, camera, ...)' },
  { key: 'ip', example: 'ip:192.0.2.', text: 'Address starts with or contains' },
  { key: 'seen', example: 'seen:1h', text: 'Seen within 30m, 1h, 2d, 1w' },
  { key: 'excluded', example: 'excluded:true', text: 'Excluded from monitoring' },
  { key: 'unnamed', example: 'unnamed:true', text: 'No friendly name yet' },
  { key: 'tag', example: 'tag:guest', text: 'Has a tag' },
  { key: 'wandering', example: 'wandering:true', text: 'Wandering: not filtered, still watched' },
];

// Splits on whitespace, honouring double quotes (quotes are dropped).
export function tokenize(s) {
  const out = [];
  let cur = '', inQ = false, has = false;
  for (const ch of String(s || '')) {
    if (ch === '"') { inQ = !inQ; has = true; continue; }
    if (!inQ && /\s/.test(ch)) { if (has || cur) out.push(cur); cur = ''; has = false; continue; }
    cur += ch; has = true;
  }
  if (has || cur) out.push(cur);
  return out.filter((t) => t !== '');
}

export function parseQuery(s) {
  const words = [];
  const filters = [];
  for (const tok of tokenize(s)) {
    const m = /^(-?)([a-z]+):(.+)$/i.exec(tok);
    if (m && FILTER_KEYS.includes(m[2].toLowerCase())) filters.push({ key: m[2].toLowerCase(), value: m[3], neg: m[1] === '-' });
    else words.push(tok);
  }
  return { text: words.join(' '), filters };
}

export function formatFilter(f) {
  const v = /\s/.test(f.value) ? '"' + f.value + '"' : f.value;
  return (f.neg ? '-' : '') + f.key + ':' + v;
}

export function stringifyQuery(q) {
  const parts = [];
  if (q.text) parts.push(q.text);
  for (const f of q.filters) parts.push(formatFilter(f));
  return parts.join(' ');
}

export function addFilter(q, key, value, neg = false) {
  const same = (f) => f.key === key && f.value.toLowerCase() === String(value).toLowerCase() && f.neg === neg;
  if (q.filters.some(same)) return q;
  return { text: q.text, filters: [...q.filters, { key, value: String(value), neg }] };
}

export function removeFilter(q, index) {
  return { text: q.text, filters: q.filters.filter((_, i) => i !== index) };
}

export function setText(q, text) {
  return { text, filters: q.filters };
}

export function hasGroupFilter(q, name) {
  return q.filters.findIndex((f) => f.key === 'group' && !f.neg && f.value.toLowerCase() === String(name).toLowerCase());
}

const UNITS = { s: 1000, m: 60000, h: 3600000, d: 86400000, w: 604800000 };
export function parseDuration(v) {
  const m = /^(\d+(?:\.\d+)?)([smhdw])$/i.exec(String(v || '').trim());
  return m ? Math.round(Number(m[1]) * UNITS[m[2].toLowerCase()]) : null;
}

const truthy = (v) => /^(true|yes|1|on)$/i.test(v);

function hay(d) {
  const n = d.names || {};
  return [d.name, d.alias, n.mdns, n.hostname, n.rdns, d.vendor, d.type, ...(d.ips || []), ...(d.macs || []), ...(d.tags || []), d.notes]
    .filter(Boolean).join('\n').toLowerCase();
}

// groupName(id) -> display name, used to match group:<name>.
export function matchDevice(d, q, { now = Date.now(), groupName = (id) => id } = {}) {
  if (q.text) {
    const h = hay(d);
    for (const w of q.text.toLowerCase().split(/\s+/)) if (w && !h.includes(w)) return false;
  }
  for (const f of q.filters) {
    const v = f.value.toLowerCase();
    let ok;
    switch (f.key) {
      case 'group': ok = (d.groups || []).some((g) => g.toLowerCase() === v || String(groupName(g)).toLowerCase() === v); break;
      case 'vendor': ok = String(d.vendor || '').toLowerCase().includes(v); break;
      case 'type': ok = normType(d.type).includes(normType(v)); break;
      case 'ip': ok = (d.ips || []).some((ip) => ip.toLowerCase().includes(v)); break;
      case 'seen': { const ms = parseDuration(v); ok = ms !== null && Date.parse(d.last_seen) >= now - ms; break; }
      case 'excluded': ok = !!d.excluded === truthy(v); break;
      case 'unnamed': { const n = d.names || {}; ok = (!d.alias && !n.mdns && !n.hostname) === truthy(v); break; }
      case 'wandering': ok = isWandering(d, now) === truthy(v); break;
      case 'tag': ok = (d.tags || []).some((t) => t.toLowerCase() === v); break;
      default: ok = true;
    }
    if (f.neg ? ok : !ok) return false;
  }
  return true;
}

export function sortDevices(list, sort) {
  const a = [...list];
  if (sort === 'name') a.sort((x, y) => String(x.name).localeCompare(String(y.name), undefined, { sensitivity: 'base', numeric: true }));
  else a.sort((x, y) => Date.parse(y.last_seen) - Date.parse(x.last_seen));
  return a;
}
