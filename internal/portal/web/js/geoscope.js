// Per-scope blocked-country lists (see docs/GEOBLOCK.md). Blocks union
// across network, group and device scopes exactly like everything else in
// scope.js, but there is no allow mechanism here: a country blocked at a
// broader scope cannot be unblocked at a narrower one, only removed where
// it was set. Everything here is pure and immutable, like scope.js.
import { chainFor, sameScope } from './scope.js';

export function normalizeGeoBlock(g) {
  const q = g && typeof g === 'object' ? g : {};
  return {
    network: Array.isArray(q.network) ? q.network : [],
    groups: q.groups && typeof q.groups === 'object' ? q.groups : {},
    devices: q.devices && typeof q.devices === 'object' ? q.devices : {},
  };
}

export function listFor(gb, scope) {
  if (scope.kind === 'network') return gb.network;
  if (scope.kind === 'group') return gb.groups[scope.id] || [];
  return gb.devices[scope.id] || [];
}

function putList(gb, scope, list) {
  if (scope.kind === 'network') return { ...gb, network: list };
  if (scope.kind === 'group') return { ...gb, groups: { ...gb.groups, [scope.id]: list } };
  return { ...gb, devices: { ...gb.devices, [scope.id]: list } };
}

// How is `code` blocked at `scope`? here: set directly at this scope.
// inherited: the broader scopes (network, its groups) that block it too.
export function countryStatus(gb, scope, groupIds, code) {
  const here = listFor(gb, scope).includes(code);
  const inherited = [];
  for (const s of chainFor(scope, groupIds)) {
    if (sameScope(s, scope)) continue;
    if (listFor(gb, s).includes(code)) inherited.push(s);
  }
  return { here, inherited, effective: here || inherited.length > 0 };
}

export function setCountry(gb, scope, code, on) {
  const cur = listFor(gb, scope);
  const next = on ? (cur.includes(code) ? cur : [...cur, code]) : cur.filter((c) => c !== code);
  return putList(gb, scope, next);
}

// Every country blocked anywhere in the chain that reaches scope, for a
// summary line ("3 countries blocked here or above").
export function effectiveCountries(gb, scope, groupIds) {
  const out = new Set();
  for (const s of chainFor(scope, groupIds)) for (const c of listFor(gb, s)) out.add(c);
  return out;
}
