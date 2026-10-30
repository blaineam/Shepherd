// Synthetic traffic for demo mode, screenshots and public demos. Everything is
// made up: devices in the documentation ranges 192.0.2.0/24 and
// 198.51.100.0/24, domains under example.com/net/org, destination IPs in
// 203.0.113.0/24, and fictional city names. Generation is deterministic per
// (seed, minute), so a replayed window shows what the live feed showed.

export const DEMO_HOME = { lat: 39.1, lon: -94.6, label: 'Home' };

export function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function hash2(a, b) {
  let h = (Math.imul(a | 0, 0x9e3779b1) ^ Math.imul(b | 0, 0x85ebca6b)) >>> 0;
  h = Math.imul(h ^ (h >>> 16), 0x7feb352d) >>> 0;
  h = Math.imul(h ^ (h >>> 15), 0x846ca68b) >>> 0;
  return (h ^ (h >>> 16)) >>> 0;
}

export const DEVICES = [
  '192.0.2.11', '192.0.2.14', '192.0.2.23', '192.0.2.31', '192.0.2.47',
  '192.0.2.58', '198.51.100.8', '198.51.100.21', '198.51.100.60',
];

// Fictional places with real-looking coordinates.
export const PLACES = [
  ['Port Almer', 'US', 37.77, -122.42], ['Northgate', 'US', 47.61, -122.33], ['Copper Falls', 'US', 33.45, -112.07],
  ['Ashby Heights', 'US', 41.88, -87.63], ['Lakemont', 'US', 39.96, -83.0], ['Riverton', 'US', 38.9, -77.04],
  ['New Brannock', 'US', 40.71, -74.0], ['Gulfport Bay', 'US', 29.76, -95.37], ['Santa Orla', 'US', 25.77, -80.19],
  ['Maple Reach', 'CA', 43.65, -79.38], ['Fort Wren', 'CA', 49.28, -123.12], ['Villa Zocalo', 'MX', 19.43, -99.13],
  ['Rio Verde', 'BR', -23.55, -46.63], ['Puerto Alba', 'AR', -34.6, -58.38], ['Altamira', 'CL', -33.45, -70.67],
  ['Dunmore', 'IE', 53.35, -6.26], ['Westerhall', 'GB', 51.51, -0.13], ['Velden', 'DE', 50.11, 8.68],
  ['Lorrain', 'FR', 48.86, 2.35], ['Amsterhaven', 'NL', 52.37, 4.9], ['Nordvik', 'SE', 59.33, 18.07],
  ['Kallio', 'FI', 60.17, 24.94], ['Santa Ilaria', 'IT', 45.46, 9.19], ['Valmora', 'ES', 40.42, -3.7],
  ['Zlatna', 'PL', 52.23, 21.01], ['Tirgov', 'RO', 44.43, 26.1], ['Kestrel Bay', 'ZA', -33.92, 18.42],
  ['Port Amani', 'KE', -1.29, 36.82], ['Lagoa Nova', 'NG', 6.52, 3.38], ['Sahel Gate', 'EG', 30.04, 31.24],
  ['Dubar', 'AE', 25.2, 55.27], ['Hanover Ridge', 'IN', 19.08, 72.88], ['Kaveri', 'IN', 12.97, 77.59],
  ['Merlion Quay', 'SG', 1.35, 103.82], ['Kuro Bay', 'JP', 35.68, 139.69], ['Osari', 'JP', 34.69, 135.5],
  ['Hanbit', 'KR', 37.57, 126.98], ['Tai Shan', 'HK', 22.32, 114.17], ['Jindal', 'AU', -33.87, 151.21],
  ['Kauri Point', 'NZ', -36.85, 174.76], ['Moreton', 'AU', -27.47, 153.03], ['Ulan Reach', 'MN', 47.89, 106.91],
];

// [name, [place indexes], popularity, heavy]
export const SERVICES = [
  ['video.example.com', [3, 7], 9, true], ['stream.example.net', [1, 16], 8, true], ['cdn.example.net', [0, 17, 33], 10, false],
  ['api.example.org', [6, 19], 7, false], ['mail.example.com', [4, 16], 5, false], ['photos.example.com', [0, 18], 5, true],
  ['sync.example.org', [2, 17], 4, false], ['game.example.net', [5, 34], 4, true], ['update.example.com', [6, 21], 4, false],
  ['social.example.com', [7, 37], 6, false], ['chat.example.net', [9, 20], 5, false], ['music.example.org', [8, 22], 4, true],
  ['maps.example.com', [0, 23], 3, false], ['news.example.org', [15, 24], 3, false], ['shop.example.com', [10, 38], 3, false],
  ['docs.example.net', [1, 31], 3, false], ['search.example.com', [2, 35], 6, false], ['time.example.org', [12, 28], 2, false],
  ['iot.example.net', [13, 25], 4, false], ['camera.example.net', [11, 14], 3, true], ['backup.example.org', [26, 8], 2, true],
  ['wiki.example.org', [27, 29], 2, false], ['auth.example.com', [3, 18], 4, false], ['pay.example.com', [5, 16], 2, false],
  ['radio.example.org', [32, 36], 2, true], ['learn.example.com', [30, 31], 2, false], ['code.example.net', [4, 22], 3, false],
  ['weather.example.org', [39, 40], 2, false], ['ride.example.com', [35, 33], 1, false], ['travel.example.org', [41, 17], 1, false],
];

export const TRACKERS = [
  'ads.example.net', 'telemetry.example.org', 'pixel.example.com', 'metrics.example.net',
  'beacon.example.org', 'adserve.example.com',
];

const TRACKER_SHADOWS = ['core-ads', 'tracker-shield', 'core-ads'];
const APP_SHADOWS = ['instagram (group Kids)', 'tiktok (group Kids)', 'discord (group Kids)', 'tv-telemetry (Network)'];

const PLACE_DEF = PLACES.map(([city, country, lat, lon], i) => ({ city, country, lat, lon, ip: '203.0.113.' + (10 + i) }));

function gauss(rng) {
  return Math.sqrt(-2 * Math.log(1 - rng())) * Math.cos(2 * Math.PI * rng());
}

function pickWeighted(rng, weights, total) {
  let r = rng() * total;
  for (let i = 0; i < weights.length; i++) { r -= weights[i]; if (r <= 0) return i; }
  return weights.length - 1;
}

// Per-device favourites: a seeded permutation weighted by a Zipf curve, so
// each device leans on a few services and the traffic is heavy tailed.
function deviceProfiles(seed) {
  return DEVICES.map((ip, d) => {
    const rng = mulberry32(hash2(seed, 1000 + d));
    const order = SERVICES.map((s, i) => [i, rng() + 0.0001]).sort((a, b) => a[1] - b[1]).map((x) => x[0]);
    const weights = new Array(SERVICES.length);
    order.forEach((svc, rank) => { weights[svc] = SERVICES[svc][2] / Math.pow(rank + 1, 1.15); });
    return { ip, weights, total: weights.reduce((a, b) => a + b, 0), chatty: 0.4 + 1.6 * rng() };
  });
}

const TYPES = ['A', 'AAAA', 'A', 'HTTPS', 'A'];

export function diurnal(t) {
  const h = new Date(t).getHours() + new Date(t).getMinutes() / 60;
  return 0.55 + 0.45 * Math.sin(((h - 9) / 24) * 2 * Math.PI);
}

export class DemoGenerator {
  constructor({ seed = 7, rate = 5, bytes = false, deviceOf = null } = {}) {
    this.seed = seed;
    this.deviceOf = deviceOf;
    this.rate = rate;
    this.bytes = bytes;
    this.profiles = deviceProfiles(seed);
    this.cache = new Map();
    this.home = DEMO_HOME;
    this.kind = 'live';
    this.cursor = null;
    this.stats = { total: 0, blocked: 0, cached: 0, errors: 0 };
    // MARKETING-SITE DEMO BUILD ADDITION: a domain -> 'block'|'allow' map a
    // visitor builds by using the real block/allow controls (the HUD
    // Inspector, the Details view's rule form, the Blocking screen's
    // network-scope rules). _make() consults it below so a rule a visitor
    // sets is not just accepted and stored — it visibly changes what the
    // live feed does next, the same way a real policy rule would. See
    // demoapi.js and demomgmt.js for what calls setOverride().
    this.overrides = new Map();
  }

  // Called by demoapi.js (POST/DELETE /api/rules) and demomgmt.js (POST/
  // DELETE /api/policy/rules at network scope) whenever a visitor adds or
  // removes a block/allow rule for a domain. Clearing the whole minute
  // cache (rather than only the current minute) is deliberate and cheap —
  // at most ~6 minutes of synthetic traffic are ever cached (see _minute's
  // own size cap) — so the very next generated tick for this domain honors
  // the new rule instead of waiting for the current minute to roll over.
  // Already-drained (displayed) entries are never rewritten: drain()'s
  // cursor only moves forward, so nothing already on screen changes.
  setOverride(domain, kind) {
    if (!domain) return;
    const d = String(domain).trim().toLowerCase();
    if (!d) return;
    if (kind === 'block' || kind === 'allow') this.overrides.set(d, kind);
    else this.overrides.delete(d);
    this.cache.clear();
  }

  _make(rng, t, device, svcIdx, burst) {
    const [name, places] = SERVICES[svcIdx];
    const r = rng();
    let action = 'allowed';
    let domain = name;
    let dests = null;
    let reason = '';
    if (!burst && r < 0.065) {
      action = 'blocked';
      domain = TRACKERS[(rng() * TRACKERS.length) | 0];
      reason = 'blocklist: Demo list';
    } else if (!burst && r < 0.08) {
      action = 'error';
      reason = 'upstream timeout';
    } else {
      if (r > 0.8) action = 'cached';
      const pi = places[(rng() * places.length) | 0];
      const p = PLACE_DEF[pi];
      dests = [{ ip: p.ip, lat: p.lat + (rng() - 0.5) * 0.3, lon: p.lon + (rng() - 0.5) * 0.3, city: p.city, country: p.country }];
      if (rng() < 0.18 && places.length > 1) {
        const q = PLACE_DEF[places[(rng() * places.length) | 0]];
        if (q.city !== p.city) dests.push({ ip: q.ip, lat: q.lat, lon: q.lon, city: q.city, country: q.country });
      }
    }
    // MARKETING-SITE DEMO BUILD ADDITION: a visitor's explicit rule always
    // wins over the random roll above, the same precedence the real policy
    // engine gives an explicit rule over a catalog default.
    const override = this.overrides.get(domain);
    if (override === 'block' && action !== 'blocked') {
      action = 'blocked'; dests = null; reason = 'rule: you blocked this domain';
    } else if (override === 'allow' && action === 'blocked') {
      action = r > 0.5 ? 'cached' : 'allowed'; reason = '';
      const pi = places[(rng() * places.length) | 0];
      const p = PLACE_DEF[pi];
      dests = [{ ip: p.ip, lat: p.lat, lon: p.lon, city: p.city, country: p.country }];
    } else if (override === 'block' && action === 'blocked' && !reason) {
      reason = 'rule: you blocked this domain';
    }
    const e = {
      id: 0, time: new Date(t).toISOString(), t,
      client: device.ip, name: domain, type: TYPES[(rng() * TYPES.length) | 0],
      action, reason, upstream: action === 'cached' ? '' : '203.0.113.53:853',
      ms: action === 'cached' ? 0.1 + rng() * 0.4 : 4 + rng() * 40, rcode: action === 'blocked' ? 3 : action === 'error' ? 2 : 0,
    };
    if (dests) e.dests = dests;
    const dev = this.deviceOf && this.deviceOf(device.ip);
    if (dev) { e.device = dev.name; e.device_id = dev.id; }
    if (dev && dev.wandering) {
      // Unfiltered but watched: blocked queries go through, and some carry a shadow result.
      const h = hash2(Math.floor(t), device.ip.length * 131 + 7);
      e.wandering = true;
      if (e.action === 'blocked') {
        e.action = 'allowed'; e.rcode = 0; e.ms = 6 + (h % 30);
        const p = PLACE_DEF[h % PLACE_DEF.length];
        e.dests = [{ ip: p.ip, lat: p.lat, lon: p.lon, city: p.city, country: p.country }];
        e.upstream = '203.0.113.53:853';
        e.shadow = TRACKER_SHADOWS[h % TRACKER_SHADOWS.length];
      } else if (e.action !== 'error' && h % 9 === 0) e.shadow = APP_SHADOWS[h % APP_SHADOWS.length];
      if (e.shadow) e.reason = 'wandering';
    }
    if (this.bytes && dests) {
      const down = Math.min(3e9, Math.exp(8.5 + gauss(rng) * 2.4) * (burst ? 40 : 1));
      e.bytes_down = Math.max(1, Math.round(down));
      e.bytes_up = Math.max(1, Math.round(down * (0.01 + rng() * 0.15)));
    }
    return e;
  }

  _minute(minute) {
    const hit = this.cache.get(minute);
    if (hit) return hit;
    const rng = mulberry32(hash2(this.seed, minute));
    const start = minute * 60000;
    const mean = this.rate * 60 * diurnal(start + 30000);
    const n = Math.max(0, Math.round(mean + Math.sqrt(mean) * gauss(rng)));
    const list = [];
    const devWeights = this.profiles.map((p) => p.chatty);
    const devTotal = devWeights.reduce((a, b) => a + b, 0);
    for (let i = 0; i < n; i++) {
      const d = this.profiles[pickWeighted(rng, devWeights, devTotal)];
      const svc = pickWeighted(rng, d.weights, d.total);
      list.push(this._make(rng, start + rng() * 60000, d, svc, false));
    }
    // Bursts: one device hammers one heavy service, producing a thick lane.
    const bursts = rng() < 0.7 ? 1 + ((rng() * 2) | 0) : 0;
    for (let b = 0; b < bursts; b++) {
      const d = this.profiles[(rng() * this.profiles.length) | 0];
      const heavy = SERVICES.map((s, i) => (s[3] ? i : -1)).filter((i) => i >= 0);
      const svc = heavy[(rng() * heavy.length) | 0];
      const count = 12 + ((rng() * 70 * Math.min(2.5, this.rate / 5 + 0.5)) | 0);
      const t0 = start + rng() * 30000;
      const span = 8000 + rng() * 22000;
      for (let i = 0; i < count; i++) list.push(this._make(rng, t0 + (i / count) * span + rng() * 200, d, svc, true));
    }
    list.sort((a, b) => a.t - b.t);
    list.forEach((e, i) => { e.id = minute * 100000 + i + 1; });
    this.cache.set(minute, list);
    if (this.cache.size > 6) this.cache.delete(this.cache.keys().next().value);
    return list;
  }

  // Entries with from <= t < to, oldest first; fresh objects every call.
  range(from, to, limit = Infinity) {
    const out = [];
    for (let m = Math.floor(from / 60000); m <= Math.floor((to - 1) / 60000); m++) {
      for (const e of this._minute(m)) {
        if (e.t >= from && e.t < to) {
          out.push({ ...e, dests: e.dests ? e.dests.map((d) => ({ ...d })) : undefined });
          if (out.length >= limit) return out;
        }
      }
    }
    return out;
  }

  // Loader for ReplaySource.
  async load(from, to, limit) {
    return { entries: this.range(from, to, limit) };
  }

  history(now = Date.now()) {
    return { oldest: now - 24 * 3600 * 1000, newest: now };
  }

  // Event source interface: entries up to `nowMs`, tagged live.
  start(now = Date.now()) { this.cursor = now; }
  stop() {}
  drain(nowMs, out) {
    if (this.cursor == null) this.cursor = nowMs;
    if (nowMs <= this.cursor) return out;
    const from = Math.max(this.cursor, nowMs - 5000);
    for (const e of this.range(from, nowMs)) { e.live = true; out.push(e); }
    this.cursor = nowMs;
    return out;
  }
}
