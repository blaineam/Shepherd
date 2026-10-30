// A paged, lazily loaded device list. The view asks for the rows it can see;
// pages are fetched on demand, so thousands of devices stay cheap. Pure
// logic: the fetch function and change callback come in from outside.
export function createDeviceList({ fetchPage, pageSize = 100, onChange = () => {} }) {
  let query = '', sort = 'recent';
  let total = 0;
  let pages = new Map();
  let pending = new Set();
  let gen = 0;
  let error = null;
  let loadedOnce = false;

  async function load(p, g) {
    if (pages.has(p) || pending.has(p)) return;
    pending.add(p);
    try {
      const r = await fetchPage({ q: query, sort, offset: p * pageSize, limit: pageSize });
      if (g !== gen) return;
      const list = Array.isArray(r && r.devices) ? r.devices : [];
      pages.set(p, list);
      if (Number.isFinite(r && r.total)) total = r.total; else total = Math.max(total, p * pageSize + list.length);
      error = null;
      loadedOnce = true;
    } catch (e) {
      if (g !== gen) return;
      error = e;
    } finally {
      pending.delete(p);
      if (g === gen) onChange();
    }
  }

  const api = {
    get query() { return query; },
    get sort() { return sort; },
    get total() { return total; },
    get error() { return error; },
    get loading() { return pending.size > 0; },
    get ready() { return loadedOnce; },
    get pageSize() { return pageSize; },

    reset(q = query, s = sort) {
      query = q; sort = s; gen++;
      pages = new Map(); pending = new Set(); total = 0; error = null; loadedOnce = false;
      onChange();
      return load(0, gen);
    },

    // Re-fetches the pages already held, keeping scroll position and count.
    async refresh() {
      const g = ++gen;
      const held = [...pages.keys()].sort((a, b) => a - b);
      pending = new Set();
      const fresh = new Map();
      try {
        for (const p of held.length ? held : [0]) {
          const r = await fetchPage({ q: query, sort, offset: p * pageSize, limit: pageSize });
          if (g !== gen) return;
          fresh.set(p, Array.isArray(r.devices) ? r.devices : []);
          if (Number.isFinite(r.total)) total = r.total;
        }
        pages = fresh; error = null; loadedOnce = true;
      } catch (e) { if (g === gen) error = e; }
      if (g === gen) onChange();
    },

    get(i) {
      const p = Math.floor(i / pageSize);
      const pg = pages.get(p);
      return pg ? pg[i - p * pageSize] || null : null;
    },

    ensure(from, to) {
      if (total === 0 && loadedOnce) return;
      const last = total ? Math.min(to, total - 1) : to;
      for (let p = Math.floor(Math.max(0, from) / pageSize); p <= Math.floor(last / pageSize); p++) load(p, gen);
    },

    // Ids in list order; undefined where a page is not loaded yet.
    orderedIds() {
      const out = new Array(total);
      for (const [p, list] of pages) for (let k = 0; k < list.length; k++) { const d = list[k]; if (d) out[p * pageSize + k] = d.id; }
      return out;
    },

    loaded() {
      const out = [];
      for (const p of [...pages.keys()].sort((a, b) => a - b)) for (const d of pages.get(p)) out.push(d);
      return out;
    },

    // Mutates a held device in place (optimistic edit); returns it.
    patch(id, fn) {
      for (const list of pages.values()) {
        const i = list.findIndex((d) => d && d.id === id);
        if (i >= 0) { list[i] = fn(list[i]); return list[i]; }
      }
      return null;
    },

    remove(ids) {
      const set = new Set(ids);
      let removed = 0;
      for (const [p, list] of pages) {
        const kept = list.filter((d) => !set.has(d.id));
        removed += list.length - kept.length;
        pages.set(p, kept);
      }
      total = Math.max(0, total - removed);
    },

    // Fetches every matching device (pages of up to 500) for bulk-by-filter.
    async fetchAll(size = 500) {
      const out = [];
      for (let off = 0; ; off += size) {
        const r = await fetchPage({ q: query, sort, offset: off, limit: size });
        const list = Array.isArray(r.devices) ? r.devices : [];
        out.push(...list);
        if (!list.length || out.length >= (r.total ?? Infinity) || off > 200000) break;
      }
      return out;
    },
  };
  return api;
}
