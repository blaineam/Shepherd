// HUD state: lanes, filters, counters and recent events. Pure logic, no DOM.
import { ACTIONS } from './entry.js';
import { LaneTable } from './lanes.js';
import { hasBytes } from './weight.js';

export class Model {
  constructor({ laneCap = 300, recentCap = 400, halfLifeMs = 40000 } = {}) {
    this.lanes = new LaneTable({ cap: laneCap, halfLifeMs });
    this.recentCap = recentCap;
    this.recent = [];
    this.filters = { device: '', actions: new Set(ACTIONS), q: '', wandering: false, shadow: false };
    this.clients = new Map();
    this.reset();
    this.touched = [];
  }

  reset() {
    this.counters = { total: 0, blocked: 0, cached: 0, errors: 0, allowed: 0 };
    this.recent.length = 0;
    this.clients.clear();
    this.withDests = 0;
    this.withoutDests = 0;
    this.lanes.clear();
  }

  get mode() { return this.lanes.mode; }

  get blockedPct() {
    return this.counters.total ? (100 * this.counters.blocked) / this.counters.total : 0;
  }

  // True once real entries arrived but none carried destinations.
  get mapUnavailable() {
    return this.withDests === 0 && this.withoutDests >= 5;
  }

  setFilters(patch) {
    Object.assign(this.filters, patch);
  }

  matches(e) {
    const f = this.filters;
    if (f.device && e.client !== f.device) return false;
    if (!f.actions.has(e.action)) return false;
    if (f.q && !e.name.toLowerCase().includes(f.q.toLowerCase())) return false;
    if (f.wandering && !e.wandering) return false;
    if (f.shadow && !e.shadow) return false;
    return true;
  }

  laneVisible(lane) {
    const f = this.filters;
    if (f.device && lane.client !== f.device) return false;
    if (!f.actions.has(lane.action)) return false;
    if (f.wandering && !lane.wandering) return false;
    if (f.shadow && !lane.shadow) return false;
    if (f.q) {
      const q = f.q.toLowerCase();
      let hit = false;
      for (const name of lane.domains.keys()) if (name.toLowerCase().includes(q)) { hit = true; break; }
      if (!hit) return false;
    }
    return true;
  }

  // Returns 'filtered' | 'blocked' | 'lane' | 'nodest'. Lanes touched land in this.touched.
  ingest(e) {
    const c = this.counters;
    c.total++;
    if (e.action === 'blocked') c.blocked++;
    else if (e.action === 'cached') { c.cached++; c.allowed++; }
    else if (e.action === 'error') c.errors++;
    else c.allowed++;
    this.clients.set(e.client, (this.clients.get(e.client) || 0) + 1);
    this.recent.push(e);
    if (this.recent.length > this.recentCap * 2) this.recent.splice(0, this.recent.length - this.recentCap);
    this.touched.length = 0;
    if (e.dests) this.withDests++; else this.withoutDests++;
    if (!this.matches(e)) return 'filtered';
    if (e.action === 'blocked') return 'blocked';
    if (!e.dests) return 'nodest';
    if (hasBytes(e) && this.lanes.mode !== 'bytes') this.lanes.setMode('bytes');
    this.lanes.add(e, this.touched);
    return 'lane';
  }

  recentNewestFirst(limit = this.recentCap) {
    const r = this.recent;
    const out = [];
    for (let i = r.length - 1; i >= 0 && out.length < limit; i--) out.push(r[i]);
    return out;
  }
}
