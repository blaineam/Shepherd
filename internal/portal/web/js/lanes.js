// Lane aggregation. Repeated events for the same device -> destination merge
// into one persistent lane whose weight accumulates and decays, so heavy flows
// look visibly thicker than one-off lookups. Lanes live in fixed slots so the
// renderer can map them onto instanced GPU buffers without reallocation.
import { destKey } from './entry.js';
import { entryWeight, MODES } from './weight.js';
import { latLonToVec3, greatCircleAngle, arcLift } from './geo.js';

const MAX_DOMAINS = 8;

export class LaneTable {
  constructor({ cap = 300, halfLifeMs = 40000, mode = 'lookups', maxDests = 2 } = {}) {
    this.cap = cap;
    this.halfLifeMs = halfLifeMs;
    this.mode = mode;
    this.maxDests = maxDests;
    this.byKey = new Map();
    this.slots = new Array(cap).fill(null);
    this.free = [];
    for (let i = cap - 1; i >= 0; i--) this.free.push(i);
    this.home = null; // {lat, lon}
    this.removed = []; // reused result array for prune()
  }

  get size() { return this.byKey.size; }

  setMode(mode) {
    if (mode === this.mode) return;
    this.mode = mode;
    this.clear();
  }

  setHome(home) {
    this.home = home && Number.isFinite(home.lat) && Number.isFinite(home.lon) ? { lat: home.lat, lon: home.lon } : null;
    for (const lane of this.byKey.values()) this._geometry(lane);
  }

  clear() {
    this.byKey.clear();
    this.slots.fill(null);
    this.free.length = 0;
    for (let i = this.cap - 1; i >= 0; i--) this.free.push(i);
  }

  _geometry(lane) {
    if (!this.home) { lane.angle = 0; lane.lift = 0; return; }
    lane.angle = greatCircleAngle(this.home.lat, this.home.lon, lane.dest.lat, lane.dest.lon);
    lane.lift = arcLift(lane.angle);
    lane.from = latLonToVec3(this.home.lat, this.home.lon);
  }

  // Weight of a lane at virtual time `now` (ms), after exponential decay.
  valueAt(lane, now) {
    const dt = now - lane.wt;
    return dt <= 0 ? lane.w : lane.w * Math.pow(0.5, dt / this.halfLifeMs);
  }

  floor() { return MODES[this.mode].floor; }

  _evictOldest() {
    let victim = null;
    for (const lane of this.byKey.values()) if (!victim || lane.last < victim.last) victim = lane;
    if (victim) this._remove(victim);
    return victim;
  }

  _remove(lane) {
    this.byKey.delete(lane.key);
    this.slots[lane.slot] = null;
    this.free.push(lane.slot);
  }

  // Merge an entry (with dests) into lanes. Returns the touched lanes in
  // `out` (reused) and how many were created.
  add(entry, out = []) {
    out.length = 0;
    if (!entry.dests) return out;
    const w = entryWeight(entry, this.mode);
    const n = Math.min(entry.dests.length, this.maxDests);
    const share = w / n;
    const now = entry.t;
    for (let i = 0; i < n; i++) {
      const d = entry.dests[i];
      // Blocked traffic gets a lane of its own, so one place can show both
      // what got through and what was turned away rather than flickering
      // between the two colours.
      // Traffic that came from outside is its own lane too: it travels the
      // other way.
      const key = entry.client + '|' + destKey(d) + (entry.action === 'blocked' ? '|blocked' : '') + (entry.inbound ? '|in' : '');
      let lane = this.byKey.get(key);
      if (!lane) {
        if (!this.free.length) this._evictOldest();
        lane = {
          key, slot: this.free.pop(), client: entry.client,
          dest: { lat: d.lat, lon: d.lon, ip: d.ip, city: d.city, country: d.country },
          to: latLonToVec3(d.lat, d.lon),
          from: null, angle: 0, lift: 0,
          action: entry.action, inbound: !!entry.inbound, wandering: false, shadow: false, w: 0, wt: now, count: 0, bytes: 0,
          first: now, last: now, lastName: entry.name, lastComet: -Infinity,
          domains: new Map(), created: true,
        };
        this._geometry(lane);
        this.slots[lane.slot] = lane;
        this.byKey.set(key, lane);
      } else {
        lane.w = this.valueAt(lane, now);
        lane.wt = now;
        lane.created = false;
      }
      lane.w += share;
      lane.count += 1;
      lane.bytes += (entry.bytes_up || 0) + (entry.bytes_down || 0) > 0 ? ((entry.bytes_up || 0) + (entry.bytes_down || 0)) / n : 0;
      lane.action = entry.action;
      lane.wandering = !!entry.wandering;
      lane.shadow = !!entry.shadow;
      if (now > lane.last) lane.last = now;
      lane.lastName = entry.name;
      this._noteDomain(lane, entry.name, now);
      out.push(lane);
    }
    return out;
  }

  _noteDomain(lane, name, now) {
    if (!name) return;
    const d = lane.domains.get(name);
    if (d) { d.n++; d.last = now; return; }
    if (lane.domains.size >= MAX_DOMAINS) {
      let worst = null, worstKey = null;
      for (const [k, v] of lane.domains) if (!worst || v.n < worst.n || (v.n === worst.n && v.last < worst.last)) { worst = v; worstKey = k; }
      lane.domains.delete(worstKey);
    }
    lane.domains.set(name, { n: 1, last: now });
  }

  topDomains(lane, k = 5) {
    return [...lane.domains.entries()]
      .sort((a, b) => b[1].n - a[1].n || b[1].last - a[1].last)
      .slice(0, k)
      .map(([name, v]) => ({ name, n: v.n, last: v.last }));
  }

  // Drop lanes whose decayed weight fell below the visibility floor. Returns
  // the removed lanes (array reused between calls).
  prune(now) {
    this.removed.length = 0;
    const floor = this.floor();
    for (const lane of this.byKey.values()) {
      if (this.valueAt(lane, now) < floor) this.removed.push(lane);
    }
    for (const lane of this.removed) this._remove(lane);
    return this.removed;
  }
}

// A comet runs along a lane in the direction the traffic went. Most of it
// leaves home for somewhere; what arrived from outside, such as a
// connection the firewall turned away at the door, starts at its source
// and runs home.
//
// Something turned away never got in, so its comet does not land at home
// either. It stops short, against a dome around home that is only ever
// seen by what breaks on it. DOME_ANGLE is the dome's radius as an angle
// at the centre of the globe (about 900 km on the ground), big enough to
// see with the whole planet in view.
export const DOME_ANGLE = 0.14;

// domeStop is how far along its lane a comet gets, from 0 to 1: all the
// way, except for traffic from outside that was blocked. A lane shorter
// than the dome is wide still shows half of its length.
export function domeStop(lane) {
  if (!(lane.inbound && lane.action === 'blocked')) return 1;
  const angle = lane.angle || 0;
  if (!(angle > 0)) return 1;
  return 1 - Math.min(0.5, Math.max(0.05, DOME_ANGLE / angle));
}

// These two say which end is which, and where the comet stops, for the
// globe (unit vectors) and the flat map (latitude and longitude).
export function cometVectors(lane) {
  const stop = domeStop(lane);
  return lane.inbound ? { start: lane.to, end: lane.from, stop } : { start: lane.from, end: lane.to, stop };
}

export function cometLatLon(lane, home) {
  const far = { lat: lane.dest.lat, lon: lane.dest.lon };
  const near = { lat: home.lat, lon: home.lon };
  const stop = domeStop(lane);
  const start = lane.inbound ? far : near;
  const end = lane.inbound ? near : far;
  // Where it stops, going the short way round in longitude.
  const dLon = ((end.lon - start.lon + 540) % 360) - 180;
  const hit = { lat: start.lat + (end.lat - start.lat) * stop, lon: start.lon + dLon * stop };
  return { start, end, stop, hit };
}
