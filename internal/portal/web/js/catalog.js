// Blocking catalog helpers: indexing, search, grouping by category and
// per-item status from the lists report. Pure.
export function fmtCount(n) {
  n = Number(n) || 0;
  if (n >= 1e6) return (n / 1e6).toFixed(n >= 1e7 ? 0 : 1) + 'M';
  if (n >= 1e4) return Math.round(n / 1e3) + 'k';
  if (n >= 1e3) return (n / 1e3).toFixed(1) + 'k';
  return String(n);
}

const str = (v) => (typeof v === 'string' ? v : v == null ? '' : String(v));

// Defensive: unknown kinds fall back to "list", missing arrays to [].
export function normalizeCatalog(raw) {
  const entries = [];
  for (const e of (raw && raw.entries) || []) {
    if (!e || typeof e !== 'object' || !e.id) continue;
    entries.push({
      id: str(e.id), kind: e.kind === 'app' || e.kind === 'category' ? e.kind : 'list',
      name: str(e.name || e.id), category: str(e.category), description: str(e.description),
      license: str(e.license), homepage: str(e.homepage), approx_entries: Number(e.approx_entries) || 0,
      recommended: !!e.recommended, includes: Array.isArray(e.includes) ? e.includes.map(str) : null,
    });
  }
  const cats = Array.isArray(raw && raw.categories) ? raw.categories.map(str) : [];
  for (const e of entries) if (e.category && !cats.includes(e.category)) cats.push(e.category);
  return { entries, categories: cats };
}

export function matchesQuery(e, q) {
  if (!q) return true;
  const h = (e.name + ' ' + e.description + ' ' + e.category + ' ' + e.id + ' ' + e.license).toLowerCase();
  return q.toLowerCase().split(/\s+/).every((w) => !w || h.includes(w));
}

// Apps by category plus the category bundle entry; lists by category.
export function groupCatalog(catalog, q = '') {
  const apps = [], lists = [];
  const bundles = new Map();
  for (const e of catalog.entries) {
    if (e.kind === 'category') { bundles.set(e.category || e.name, e); continue; }
    if (!matchesQuery(e, q)) continue;
    (e.kind === 'app' ? apps : lists).push(e);
  }
  const rank = (c) => { const i = catalog.categories.indexOf(c); return i < 0 ? 999 : i; };
  const build = (items) => {
    const m = new Map();
    for (const e of items) { const c = e.category || 'Other'; if (!m.has(c)) m.set(c, []); m.get(c).push(e); }
    return [...m.entries()].sort((a, b) => rank(a[0]) - rank(b[0]) || a[0].localeCompare(b[0]))
      .map(([category, entries]) => ({ category, bundle: bundles.get(category) || null, entries: entries.sort((a, b) => (b.recommended - a.recommended) || a.name.localeCompare(b.name)) }));
  };
  return { apps: build(apps), lists: build(lists), appCount: apps.length, listCount: lists.length };
}

export function listStatus(policy, id) {
  const l = ((policy && policy.lists) || []).find((x) => x.id === id);
  const c = ((policy && policy.custom_lists) || []).find((x) => x.id === id);
  if (!l && !c) return null;
  return { count: Number((l && l.count) ?? (c && c.count)) || 0, size: Number(l && l.size_bytes) || 0, updated: l && l.updated ? Date.parse(l.updated) : NaN, error: str(l && l.error) };
}

// Unique sources for the attribution footer.
export function sources(catalog) {
  const seen = new Map();
  for (const e of catalog.entries) {
    if (e.kind !== 'list') continue;
    const k = e.homepage || e.name;
    if (!seen.has(k)) seen.set(k, { name: e.name, license: e.license, homepage: e.homepage });
  }
  return [...seen.values()].sort((a, b) => a.name.localeCompare(b.name));
}

// Only http(s) links are ever rendered as anchors.
export function safeHref(u) {
  try { const x = new URL(u); return x.protocol === 'https:' || x.protocol === 'http:' ? x.href : ''; } catch { return ''; }
}

// How many apps in a category bundle (or any bundle) are blocked given an isBlocked(id) predicate.
export function bundleProgress(bundle, apps, isBlocked) {
  const ids = bundle && bundle.includes ? bundle.includes : apps.map((a) => a.id);
  let on = 0;
  for (const id of ids) if (isBlocked(id)) on++;
  return { on, total: ids.length };
}
