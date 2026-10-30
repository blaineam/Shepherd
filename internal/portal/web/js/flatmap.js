// The 2D map: a Canvas 2D twin of the globe for browsers with no WebGL (Safari
// in Lockdown Mode, locked-down kiosks, headless browsers). It implements the
// same surface app.js drives -- sync, spawnComet, pick, projectLatLon and so on
// -- so the two are interchangeable. The projection is equirectangular with
// horizontal wrap, and arcs are drawn as curves bowing toward the top of the
// screen. Nothing here needs WebGL or the vendored three.js.
import { DEG, clamp, normalizeLon, dampVelocity } from './geo.js';
import { weightScale, widthPx, baseAlpha } from './weight.js';
import { landPolygons, polygonContains, coastSegments } from './topo.js';
import { LANE_CAP, COMET_CAP, PULSE_CAP, COLORS } from './palette.js';

const MIN_ZOOM = 1;
const MAX_ZOOM = 12;
const LAND_STEP = 1.25;
const HOME_COLOR = COLORS.allowed;

export function canvas2dAvailable() {
  try {
    const c = document.createElement('canvas');
    return !!(c.getContext && c.getContext('2d'));
  } catch { return false; }
}

// Longitude difference folded into [-180, 180): the short way round.
export function wrapDelta(d) {
  return ((((d + 180) % 360) + 360) % 360) - 180;
}

// Screen position of a point for a view {cLon, cLat, k (px per degree), w, h}.
// Longitude is unwrapped to the copy of the world nearest the view centre.
export function project(lat, lon, v, out = { x: 0, y: 0 }) {
  out.x = v.w / 2 + wrapDelta(lon - v.cLon) * v.k;
  out.y = v.h / 2 - (lat - v.cLat) * v.k;
  return out;
}

export function unproject(x, y, v, out = { lat: 0, lon: 0 }) {
  out.lon = normalizeLon(v.cLon + (x - v.w / 2) / v.k);
  out.lat = v.cLat - (y - v.h / 2) / v.k;
  return out;
}

// Quadratic bezier through a, bowed by `bow` pixels toward the top of the screen.
export function arcControl(ax, ay, bx, by, bow, out = { x: 0, y: 0 }) {
  const dx = bx - ax, dy = by - ay;
  const len = Math.hypot(dx, dy) || 1;
  let nx = dy / len, ny = -dx / len;
  if (ny > 0) { nx = -nx; ny = -ny; }
  out.x = (ax + bx) / 2 + nx * bow;
  out.y = (ay + by) / 2 + ny * bow;
  return out;
}

export function bezier(ax, ay, cx, cy, bx, by, t, out = { x: 0, y: 0 }) {
  const u = 1 - t;
  out.x = u * u * ax + 2 * u * t * cx + t * t * bx;
  out.y = u * u * ay + 2 * u * t * cy + t * t * by;
  return out;
}

// Where the sun is overhead at a given time: {lat, lon} in degrees (low-accuracy
// almanac formulae, good to well under a degree, which is plenty for shading).
export function subsolarPoint(ms) {
  const d = ms / 86400000 - 10957.5;
  const L = 280.46 + 0.9856474 * d;
  const g = (357.528 + 0.9856003 * d) * DEG;
  const lam = (L + 1.915 * Math.sin(g) + 0.02 * Math.sin(2 * g)) * DEG;
  const eps = (23.439 - 0.0000004 * d) * DEG;
  const dec = Math.asin(Math.sin(eps) * Math.sin(lam));
  const ra = Math.atan2(Math.cos(eps) * Math.sin(lam), Math.cos(lam)) / DEG;
  const gmst = 280.46061837 + 360.98564736629 * d;
  return { lat: dec / DEG, lon: normalizeLon(ra - gmst) };
}

// Latitude of the day/night boundary at a longitude.
export function terminatorLat(lon, sun) {
  const dec = Math.abs(sun.lat) < 0.5 ? 0.5 * DEG * Math.sign(sun.lat || 1) : sun.lat * DEG;
  return Math.atan(-Math.cos((lon - sun.lon) * DEG) / Math.tan(dec)) / DEG;
}

const rgba = (c, a) => `rgba(${Math.round(c[0] * 255)},${Math.round(c[1] * 255)},${Math.round(c[2] * 255)},${a})`;

export class FlatMap {
  constructor(container, { reducedMotion = false, onPick = () => {}, onHover = () => {}, onGlobeClick = () => {} } = {}) {
    this.container = container;
    this.reduced = reducedMotion;
    this.onPick = onPick;
    this.onHover = onHover;
    this.onGlobeClick = onGlobeClick;
    this.homeMode = false;
    this.autoRotate = !reducedMotion;
    this.time = 0;
    this.lanes = null;
    this.home = null;
    this.selectedKey = null;
    this.hoverKey = null;
    this.stats = { lanes: 0, comets: 0 };

    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d', { alpha: false });
    if (!ctx) throw new Error('canvas2d');
    this.canvas = canvas;
    this.ctx = ctx;
    canvas.className = 'globe-canvas';
    canvas.setAttribute('role', 'img');
    canvas.setAttribute('aria-label', 'Map of where this network’s DNS lookups go');
    container.appendChild(canvas);

    this.view = { cLon: -40, cLat: 20, k: 3, w: 1, h: 1 };
    this.userZoom = 1;
    this.latVel = 0;
    this.lonVel = 0;
    this.target = null;
    this.idleFor = 10;
    this.dpr = 1;
    this.land = new Float32Array(0);
    this.coast = new Float32Array(0);
    this.sun = subsolarPoint(Date.now());
    this.sunAt = 0;

    // Per-lane draw state, refreshed by sync().
    this.laneW = new Float32Array(LANE_CAP);
    this.laneA = new Float32Array(LANE_CAP);
    this.laneS = new Float32Array(LANE_CAP);
    this.laneSel = new Float32Array(LANE_CAP);

    // Comets: ring buffer of flights home -> destination, stored in lat/lon so
    // they follow the map while it is panned.
    this.cometNext = 0;
    this.cm = {
      t0: new Float64Array(COMET_CAP), dur: new Float32Array(COMET_CAP), on: new Uint8Array(COMET_CAP),
      hLat: new Float32Array(COMET_CAP), hLon: new Float32Array(COMET_CAP),
      dLat: new Float32Array(COMET_CAP), dLon: new Float32Array(COMET_CAP),
      lift: new Float32Array(COMET_CAP), w: new Float32Array(COMET_CAP), size: new Float32Array(COMET_CAP),
      sel: new Uint8Array(COMET_CAP), col: new Float32Array(COMET_CAP * 3),
    };
    this.pulseNext = 0;
    this.pl = {
      t0: new Float64Array(PULSE_CAP), dur: new Float32Array(PULSE_CAP), on: new Uint8Array(PULSE_CAP),
      lat: new Float32Array(PULSE_CAP), lon: new Float32Array(PULSE_CAP),
      kind: new Uint8Array(PULSE_CAP), size: new Float32Array(PULSE_CAP), col: new Float32Array(PULSE_CAP * 3),
    };
    this.pointers = new Map();
    this.pt = { x: 0, y: 0 };
    this.cp = { x: 0, y: 0 };
    this.g = { ax: 0, ay: 0, cx: 0, cy: 0, bx: 0, by: 0 };

    this._bindControls();
    this.ro = new ResizeObserver(() => this.resize());
    this.ro.observe(container);
    this.resize();
  }

  // ---------- data ----------
  setLanes(table) { this.lanes = table; }
  setHome(home) { this.home = home; }

  // Land as a regular lat/lon dot grid (the globe's equal-area rings would look
  // ragged toward the poles on a flat map) plus the coastline.
  loadLand(topo) {
    const polys = landPolygons(topo);
    const boxes = polys.map((p) => {
      let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
      for (const [x, y] of p[0]) { if (x < x0) x0 = x; if (x > x1) x1 = x; if (y < y0) y0 = y; if (y > y1) y1 = y; }
      return [x0, y0, x1, y1];
    });
    const pts = [];
    for (let lat = -58; lat <= 84; lat += LAND_STEP) {
      for (let lon = -180 + LAND_STEP / 2; lon < 180; lon += LAND_STEP) {
        for (let i = 0; i < polys.length; i++) {
          const b = boxes[i];
          if (lon < b[0] || lon > b[2] || lat < b[1] || lat > b[3]) continue;
          if (polygonContains(polys[i], lon, lat)) { pts.push(lat, lon); break; }
        }
      }
    }
    // Antarctica is one huge ring: a coarser grid keeps it from dominating.
    for (let lat = -90; lat < -58; lat += LAND_STEP * 1.6) {
      for (let lon = -180; lon < 180; lon += LAND_STEP * 1.6) {
        for (let i = 0; i < polys.length; i++) {
          const b = boxes[i];
          if (lon < b[0] || lon > b[2] || lat < b[1] || lat > b[3]) continue;
          if (polygonContains(polys[i], lon, lat)) { pts.push(lat, lon); break; }
        }
      }
    }
    this.land = Float32Array.from(pts);
    this.coast = Float32Array.from(coastSegments(polys));
    this.landDots = pts.length / 2;
  }

  // Refresh per-lane draw state (called ~10x/s, not per frame).
  sync(now, visible = () => true) {
    const t = this.lanes;
    if (!t) return;
    let active = 0;
    for (let i = 0; i < LANE_CAP; i++) {
      const lane = t.slots[i];
      if (!lane || !lane.from || !visible(lane)) { this.laneA[i] = 0; continue; }
      const s = weightScale(t.valueAt(lane, now), t.mode);
      lane.s = s;
      if (s <= 0) { this.laneA[i] = 0; continue; }
      active++;
      this.laneS[i] = s;
      this.laneW[i] = widthPx(s);
      this.laneA[i] = baseAlpha(s);
      this.laneSel[i] = lane.key === this.selectedKey ? 1 : lane.key === this.hoverKey ? 0.5 : 0;
    }
    this.stats.lanes = active;
  }

  spawnComet(lane, s) {
    if (!lane.from || !this.home) return;
    const i = this.cometNext, c = this.cm;
    this.cometNext = (i + 1) % COMET_CAP;
    const col = COLORS[lane.action] || COLORS.allowed;
    const boost = 0.75 + 0.6 * s;
    c.t0[i] = this.time;
    c.dur[i] = 1.0 + 1.5 * (lane.angle / Math.PI) + (this.reduced ? 0.4 : 0);
    c.hLat[i] = this.home.lat; c.hLon[i] = this.home.lon;
    c.dLat[i] = lane.dest.lat; c.dLon[i] = lane.dest.lon;
    c.lift[i] = lane.angle;
    c.w[i] = widthPx(s) * 0.7;
    c.size[i] = 0.035 + 0.06 * s;
    c.sel[i] = lane.key === this.selectedKey ? 1 : 0;
    for (let k = 0; k < 3; k++) c.col[i * 3 + k] = Math.min(1, col[k] * boost);
    c.on[i] = 1;
  }

  _pulse(lat, lon, col, kind, size, dur) {
    const i = this.pulseNext, p = this.pl;
    this.pulseNext = (i + 1) % PULSE_CAP;
    p.t0[i] = this.time; p.dur[i] = dur; p.lat[i] = lat; p.lon[i] = lon;
    p.kind[i] = kind; p.size[i] = size;
    for (let k = 0; k < 3; k++) p.col[i * 3 + k] = col[k];
    p.on[i] = 1;
  }

  // Blocked queries have no destination: a red shield ring at home instead.
  spawnShield(s = 0.3) {
    if (!this.home) return;
    this._pulse(this.home.lat, this.home.lon, COLORS.blocked, 1, 0.07 + 0.09 * s, this.reduced ? 1.0 : 1.5);
  }

  // ---------- selection / view ----------
  setSelected(key) { this.selectedKey = key; }
  setHover(key) { this.hoverKey = key; }

  focus(lat, lon) {
    this.target = { lat: clamp(lat, -70, 70), lon };
    this.idleFor = 0;
  }

  resetView() {
    this.userZoom = 1;
    this._applyZoom();
    if (this.home) this.focus(this.home.lat * 0.6, this.home.lon);
    else this.focus(20, -40);
  }

  // Centre on the middle of a lane so both ends stay in sight.
  focusLane(lane) {
    if (!lane.dest) return;
    if (!this.home) { this.focus(lane.dest.lat, lane.dest.lon); return; }
    this.focus((this.home.lat + lane.dest.lat) / 2, this.home.lon + wrapDelta(lane.dest.lon - this.home.lon) / 2);
  }

  setAutoRotate(on) { this.autoRotate = on && !this.reduced; }

  setHomeMode(on) {
    this.homeMode = on;
    this.canvas.style.cursor = on ? 'crosshair' : 'grab';
  }

  resize() {
    const w = Math.max(1, this.container.clientWidth), h = Math.max(1, this.container.clientHeight);
    this.width = w; this.height = h;
    this.dpr = Math.min(window.devicePixelRatio || 1, 2);
    this.canvas.width = Math.round(w * this.dpr);
    this.canvas.height = Math.round(h * this.dpr);
    this.canvas.style.width = w + 'px';
    this.canvas.style.height = h + 'px';
    this.view.w = w; this.view.h = h;
    this._applyZoom();
  }

  // Zoom 1 fits the whole world on screen; never zoom out past that.
  _applyZoom() {
    this.userZoom = clamp(this.userZoom, MIN_ZOOM, MAX_ZOOM);
    const v = this.view;
    v.k = Math.min(v.w / 360, v.h / 175) * this.userZoom;
    this._clampLat();
  }

  _clampLat() {
    const v = this.view, half = v.h / 2 / v.k;
    const lim = Math.max(0, 90 - half);
    v.cLat = clamp(v.cLat, -lim, lim);
  }

  _zoomAt(factor, mx, my) {
    const v = this.view;
    const before = unproject(mx, my, v);
    this.userZoom *= factor;
    this._applyZoom();
    v.cLon = normalizeLon(before.lon - (mx - v.w / 2) / v.k);
    v.cLat = before.lat + (my - v.h / 2) / v.k;
    this._clampLat();
  }

  // ---------- controls ----------
  _bindControls() {
    const el = this.canvas;
    let down = null;
    let lastMove = 0;
    let pinch = 0;
    el.style.touchAction = 'none';
    el.style.cursor = 'grab';
    const local = (e) => { const r = el.getBoundingClientRect(); return [e.clientX - r.left, e.clientY - r.top]; };
    el.addEventListener('pointerdown', (e) => {
      el.setPointerCapture(e.pointerId);
      this.pointers.set(e.pointerId, { x: e.clientX, y: e.clientY });
      if (this.pointers.size === 1) down = { x: e.clientX, y: e.clientY, t: performance.now(), moved: 0, lt: performance.now() };
      if (this.pointers.size === 2) { const [a, b] = [...this.pointers.values()]; pinch = Math.hypot(a.x - b.x, a.y - b.y); }
      this.latVel = this.lonVel = 0;
      this.target = null;
      this.idleFor = 0;
      if (!this.homeMode) el.style.cursor = 'grabbing';
    });
    el.addEventListener('pointermove', (e) => {
      const p = this.pointers.get(e.pointerId);
      if (p) {
        const px = p.x, py = p.y;
        p.x = e.clientX; p.y = e.clientY;
        this.idleFor = 0;
        if (this.pointers.size === 2) {
          const [a, b] = [...this.pointers.values()];
          const d = Math.hypot(a.x - b.x, a.y - b.y);
          if (pinch > 0 && d > 0) {
            const r = el.getBoundingClientRect();
            this._zoomAt(d / pinch, (a.x + b.x) / 2 - r.left, (a.y + b.y) / 2 - r.top);
          }
          pinch = d;
          return;
        }
        if (down) {
          const dx = e.clientX - px, dy = e.clientY - py;
          down.moved += Math.abs(dx) + Math.abs(dy);
          const v = this.view, kk = 1 / v.k;
          v.cLon = normalizeLon(v.cLon - dx * kk);
          v.cLat += dy * kk;
          this._clampLat();
          const now = performance.now(), dt = Math.max(1, now - down.lt) / 1000;
          this.lonVel = this.lonVel * 0.6 + (-dx * kk / dt) * 0.4;
          this.latVel = this.latVel * 0.6 + (dy * kk / dt) * 0.4;
          down.lt = now;
        }
        return;
      }
      const now = performance.now();
      if (now - lastMove < 33) return;
      lastMove = now;
      const hit = this.homeMode ? null : this.pick(e.clientX, e.clientY);
      el.style.cursor = this.homeMode ? 'crosshair' : hit ? 'pointer' : 'grab';
      this.onHover(hit, e.clientX, e.clientY);
    });
    const end = (e) => {
      this.pointers.delete(e.pointerId);
      if (this.pointers.size < 2) pinch = 0;
      if (!down || this.pointers.size > 0) { if (!this.pointers.size) down = null; return; }
      const wasClick = down.moved < 6 && performance.now() - down.t < 800;
      if (performance.now() - down.lt > 80) this.latVel = this.lonVel = 0;
      down = null;
      el.style.cursor = this.homeMode ? 'crosshair' : 'grab';
      if (!wasClick) return;
      this.latVel = this.lonVel = 0;
      if (this.homeMode) {
        const ll = this.pickLatLon(e.clientX, e.clientY);
        if (ll) this.onGlobeClick(ll);
      } else {
        this.onPick(this.pick(e.clientX, e.clientY));
      }
    };
    el.addEventListener('pointerup', end);
    el.addEventListener('pointercancel', end);
    el.addEventListener('wheel', (e) => {
      e.preventDefault();
      const [mx, my] = local(e);
      this._zoomAt(Math.exp(-e.deltaY * (e.deltaMode === 1 ? 0.04 : 0.0014)), mx, my);
      this.idleFor = 0;
    }, { passive: false });
  }

  _updateView(dt) {
    this.idleFor += dt;
    const v = this.view;
    const free = this.pointers.size === 0;
    if (this.target && free) {
      const k = 1 - Math.pow(0.5, dt / 0.18);
      const dl = wrapDelta(this.target.lon - v.cLon);
      v.cLon = normalizeLon(v.cLon + dl * k);
      v.cLat += (this.target.lat - v.cLat) * k;
      this._clampLat();
      if (Math.abs(dl) < 0.05 && Math.abs(this.target.lat - v.cLat) < 0.05) this.target = null;
    } else if (free) {
      v.cLon = normalizeLon(v.cLon + this.lonVel * dt);
      v.cLat += this.latVel * dt;
      this._clampLat();
      this.lonVel = dampVelocity(this.lonVel, dt);
      this.latVel = dampVelocity(this.latVel, dt);
      if (Math.abs(this.lonVel) < 0.01) this.lonVel = 0;
      if (Math.abs(this.latVel) < 0.01) this.latVel = 0;
      if (this.autoRotate && this.idleFor > 5 && !this.homeMode) v.cLon = normalizeLon(v.cLon + 2.4 * dt);
    }
  }

  // ---------- geometry ----------
  // Arc endpoints and control point in pixels, for the world copy shifted by
  // `shift` * 360 degrees, with the destination placed on the short side of home.
  _ends(hLat, hLon, dLat, dLon, angle, shift, g = this.g) {
    const v = this.view;
    const homeDx = wrapDelta(hLon - v.cLon);
    const destDx = homeDx + wrapDelta(dLon - hLon);
    const off = shift * 360;
    g.ax = v.w / 2 + (homeDx + off) * v.k; g.ay = v.h / 2 - (hLat - v.cLat) * v.k;
    g.bx = v.w / 2 + (destDx + off) * v.k; g.by = v.h / 2 - (dLat - v.cLat) * v.k;
    const len = Math.hypot(g.bx - g.ax, g.by - g.ay);
    const bow = len * (0.2 + 0.15 * clamp(angle / Math.PI, 0, 1));
    const c = arcControl(g.ax, g.ay, g.bx, g.by, bow, this.cp);
    g.cx = c.x; g.cy = c.y;
    return g;
  }

  // Which copies of the world are on screen: shifts in {-1, 0, 1}.
  _shifts() {
    const v = this.view, out = [];
    for (let s = -1; s <= 1; s++) {
      const left = v.w / 2 + (-180 - v.cLon + 360 * s) * v.k;
      const right = left + 360 * v.k;
      if (right >= 0 && left <= v.w) out.push(s);
    }
    return out;
  }

  pickLatLon(cx, cy) {
    const r = this.canvas.getBoundingClientRect();
    const ll = unproject(cx - r.left, cy - r.top, this.view);
    return Math.abs(ll.lat) <= 90 ? ll : null;
  }

  // Project a lat/lon to canvas pixels; visible=false when off screen. The
  // radius argument is only there to match the globe's signature.
  projectLatLon(lat, lon, r, out = { x: 0, y: 0, visible: false }) {
    project(lat, lon, this.view, this.pt);
    out.x = this.pt.x; out.y = this.pt.y;
    out.visible = out.x >= 0 && out.x <= this.width && out.y >= 0 && out.y <= this.height;
    return out;
  }

  // Nearest lane arc or destination under the cursor.
  pick(cx, cy) {
    const t = this.lanes, home = this.home;
    if (!t || !home) return null;
    const r = this.canvas.getBoundingClientRect();
    const mx = cx - r.left, my = cy - r.top;
    const shifts = this._shifts();
    const p = { x: 0, y: 0 };
    let best = null, bestD = Infinity;
    for (let i = 0; i < LANE_CAP; i++) {
      const lane = t.slots[i];
      if (!lane || !lane.from || this.laneA[i] <= 0) continue;
      const wpx = (this.laneW[i] || 1) * 0.35;
      for (const sh of shifts) {
        const g = this._ends(home.lat, home.lon, lane.dest.lat, lane.dest.lon, lane.angle, sh);
        for (let k = 0; k <= 12; k++) {
          bezier(g.ax, g.ay, g.cx, g.cy, g.bx, g.by, k / 12, p);
          const d = Math.hypot(p.x - mx, p.y - my) - wpx - (k === 12 ? 6 : 0);
          if (d < bestD) { bestD = d; best = { lane, kind: k === 12 ? 'dest' : 'arc' }; }
        }
      }
    }
    return best && bestD < 12 ? best : null;
  }

  // ---------- drawing ----------
  _background(ctx) {
    const { w, h } = this.view;
    const g = ctx.createRadialGradient(w / 2, h / 2, 0, w / 2, h / 2, Math.hypot(w, h) / 2);
    g.addColorStop(0, '#0a1620');
    g.addColorStop(1, '#04080d');
    ctx.fillStyle = g;
    ctx.fillRect(0, 0, w, h);
  }

  _graticule(ctx, shifts) {
    const v = this.view;
    ctx.strokeStyle = 'rgba(22,199,189,0.07)';
    ctx.lineWidth = 1;
    ctx.beginPath();
    for (let lat = -60; lat <= 60; lat += 30) {
      const y = v.h / 2 - (lat - v.cLat) * v.k;
      ctx.moveTo(0, y); ctx.lineTo(v.w, y);
    }
    for (const s of shifts) {
      for (let lon = -180; lon <= 180; lon += 30) {
        const x = v.w / 2 + (lon - v.cLon + 360 * s) * v.k;
        if (x < -1 || x > v.w + 1) continue;
        ctx.moveTo(x, 0); ctx.lineTo(x, v.h);
      }
    }
    ctx.stroke();
    // Equator and poles a touch brighter.
    ctx.strokeStyle = 'rgba(22,199,189,0.14)';
    ctx.beginPath();
    for (const lat of [0, 90, -90]) {
      const y = v.h / 2 - (lat - v.cLat) * v.k;
      ctx.moveTo(0, y); ctx.lineTo(v.w, y);
    }
    ctx.stroke();
  }

  _land(ctx, shifts) {
    const v = this.view, pts = this.land;
    const r = clamp(LAND_STEP * v.k * 0.26, 0.55, 3.2);
    ctx.fillStyle = 'rgba(42,214,203,0.5)';
    ctx.beginPath();
    for (const s of shifts) {
      const ox = v.w / 2 + (360 * s - v.cLon) * v.k, oy = v.h / 2 + v.cLat * v.k;
      for (let i = 0; i < pts.length; i += 2) {
        const x = ox + pts[i + 1] * v.k, y = oy - pts[i] * v.k;
        if (x < -r || x > v.w + r || y < -r || y > v.h + r) continue;
        ctx.rect(x - r, y - r, r * 2, r * 2);
      }
    }
    ctx.fill();

    const c = this.coast;
    ctx.strokeStyle = 'rgba(42,214,203,0.38)';
    ctx.lineWidth = 1;
    ctx.beginPath();
    for (const s of shifts) {
      const ox = v.w / 2 + (360 * s - v.cLon) * v.k, oy = v.h / 2 + v.cLat * v.k;
      for (let i = 0; i < c.length; i += 4) {
        const x1 = ox + c[i + 1] * v.k, y1 = oy - c[i] * v.k;
        const x2 = ox + c[i + 3] * v.k, y2 = oy - c[i + 2] * v.k;
        if ((x1 < 0 && x2 < 0) || (x1 > v.w && x2 > v.w) || (y1 < 0 && y2 < 0) || (y1 > v.h && y2 > v.h)) continue;
        ctx.moveTo(x1, y1); ctx.lineTo(x2, y2);
      }
    }
    ctx.stroke();
  }

  // Dim the hemisphere facing away from the sun, with a soft twilight band.
  _night(ctx, shifts) {
    const v = this.view;
    if (this.time - this.sunAt > 5 || !this.sunAt) { this.sun = subsolarPoint(Date.now()); this.sunAt = this.time || 0.001; }
    const sun = this.sun;
    const towardPole = sun.lat >= 0 ? -1 : 1; // night lies on the far side of the boundary
    const edgeY = towardPole < 0 ? v.h + 4 : -4;
    for (const [off, alpha] of [[8, 0.12], [3, 0.16], [0, 0.2]]) {
      ctx.fillStyle = `rgba(1,4,9,${alpha})`;
      for (const s of shifts) {
        ctx.beginPath();
        let first = true;
        for (let lon = -180; lon <= 180; lon += 4) {
          const lat = clamp(terminatorLat(lon, sun) - towardPole * off, -89.9, 89.9);
          const x = v.w / 2 + (lon - v.cLon + 360 * s) * v.k, y = v.h / 2 - (lat - v.cLat) * v.k;
          if (first) { ctx.moveTo(x, y); first = false; } else ctx.lineTo(x, y);
        }
        const xr = v.w / 2 + (180 - v.cLon + 360 * s) * v.k, xl = v.w / 2 + (-180 - v.cLon + 360 * s) * v.k;
        ctx.lineTo(xr, edgeY); ctx.lineTo(xl, edgeY);
        ctx.closePath();
        ctx.fill();
      }
    }
  }

  _arcs(ctx, shifts) {
    const t = this.lanes, home = this.home;
    if (!t || !home) return;
    ctx.lineCap = 'round';
    for (let i = 0; i < LANE_CAP; i++) {
      const lane = t.slots[i];
      if (!lane || !lane.from || this.laneA[i] <= 0) continue;
      const col = COLORS[lane.action] || COLORS.allowed;
      const s = this.laneS[i], sel = this.laneSel[i];
      const a = clamp(this.laneA[i] + sel * 0.3, 0, 1);
      const w = this.laneW[i] * 0.8 + sel * 1.5;
      ctx.setLineDash(lane.wandering ? [5, 6] : []);
      for (const sh of shifts) {
        const g = this._ends(home.lat, home.lon, lane.dest.lat, lane.dest.lon, lane.angle, sh);
        ctx.beginPath();
        ctx.moveTo(g.ax, g.ay);
        ctx.quadraticCurveTo(g.cx, g.cy, g.bx, g.by);
        if (s > 0.45 || sel > 0) { ctx.strokeStyle = rgba(col, a * 0.18); ctx.lineWidth = w + 5; ctx.stroke(); }
        ctx.strokeStyle = rgba(col, a);
        ctx.lineWidth = w;
        ctx.stroke();
        // Destination dot.
        ctx.fillStyle = rgba(col, 0.55 + 0.45 * s);
        ctx.beginPath();
        ctx.arc(g.bx, g.by, (3 + 6 * s + sel * 5) * 0.55, 0, Math.PI * 2);
        ctx.fill();
        if (sel === 1) {
          ctx.strokeStyle = 'rgba(255,255,255,0.85)';
          ctx.lineWidth = 1.2;
          ctx.beginPath();
          ctx.arc(g.bx, g.by, 8, 0, Math.PI * 2);
          ctx.stroke();
        }
      }
    }
    ctx.setLineDash([]);
  }

  _comets(ctx, shifts) {
    const c = this.cm, p = { x: 0, y: 0 }, q = { x: 0, y: 0 };
    const trail = this.reduced ? 0.14 : 0.3;
    let live = 0;
    for (let i = 0; i < COMET_CAP; i++) {
      if (!c.on[i]) continue;
      const age = this.time - c.t0[i];
      const f = age / c.dur[i];
      if (f >= 1) {
        c.on[i] = 0;
        this._pulse(c.dLat[i], c.dLon[i], [c.col[i * 3], c.col[i * 3 + 1], c.col[i * 3 + 2]], 0, c.size[i], this.reduced ? 0.9 : 1.3);
        continue;
      }
      live++;
      const col = [c.col[i * 3], c.col[i * 3 + 1], c.col[i * 3 + 2]];
      const tail = Math.max(0, f - trail);
      for (const sh of shifts) {
        const g = this._ends(c.hLat[i], c.hLon[i], c.dLat[i], c.dLon[i], c.lift[i], sh);
        const N = 9;
        bezier(g.ax, g.ay, g.cx, g.cy, g.bx, g.by, tail, p);
        for (let k = 1; k <= N; k++) {
          bezier(g.ax, g.ay, g.cx, g.cy, g.bx, g.by, tail + ((f - tail) * k) / N, q);
          const u = k / N;
          ctx.strokeStyle = rgba(col, 0.1 + 0.9 * u * u);
          ctx.lineWidth = Math.max(1, c.w[i] * (0.35 + 0.65 * u));
          ctx.beginPath();
          ctx.moveTo(p.x, p.y); ctx.lineTo(q.x, q.y);
          ctx.stroke();
          p.x = q.x; p.y = q.y;
        }
        const r = 2.5 + c.w[i] * 0.5;
        const gr = ctx.createRadialGradient(q.x, q.y, 0, q.x, q.y, r * 3);
        gr.addColorStop(0, 'rgba(255,255,255,0.95)');
        gr.addColorStop(0.25, rgba(col, 0.7));
        gr.addColorStop(1, rgba(col, 0));
        ctx.fillStyle = gr;
        ctx.beginPath();
        ctx.arc(q.x, q.y, r * 3, 0, Math.PI * 2);
        ctx.fill();
      }
    }
    this.stats.comets = live;
  }

  _pulses(ctx, shifts) {
    const pl = this.pl, v = this.view;
    for (let i = 0; i < PULSE_CAP; i++) {
      if (!pl.on[i]) continue;
      const f = (this.time - pl.t0[i]) / pl.dur[i];
      if (f >= 1) { pl.on[i] = 0; continue; }
      const col = [pl.col[i * 3], pl.col[i * 3 + 1], pl.col[i * 3 + 2]];
      const e = 1 - Math.pow(1 - f, 2);
      const shield = pl.kind[i] === 1;
      const radius = (shield ? 10 : 6) + pl.size[i] * (shield ? 340 : 280) * e;
      const alpha = Math.pow(1 - f, 1.6);
      const x0 = project(pl.lat[i], pl.lon[i], v, this.pt);
      for (const sh of shifts) {
        const x = x0.x + sh * 360 * v.k, y = x0.y;
        ctx.strokeStyle = rgba(col, alpha * 0.9);
        ctx.lineWidth = shield ? 2.2 : 1.5;
        ctx.beginPath();
        ctx.arc(x, y, radius, 0, Math.PI * 2);
        ctx.stroke();
        if (shield) {
          ctx.fillStyle = rgba(col, alpha * 0.12);
          ctx.fill();
        }
      }
    }
  }

  _homeMarker(ctx, shifts) {
    if (!this.home) return;
    const v = this.view;
    const p = project(this.home.lat, this.home.lon, v, this.pt);
    const ph = (this.reduced ? 0 : this.time) % 2.4 / 2.4;
    for (const sh of shifts) {
      const x = p.x + sh * 360 * v.k, y = p.y;
      ctx.strokeStyle = rgba(HOME_COLOR, 0.55 * (1 - ph));
      ctx.lineWidth = 1.4;
      ctx.beginPath();
      ctx.arc(x, y, 6 + 18 * ph, 0, Math.PI * 2);
      ctx.stroke();
      ctx.fillStyle = rgba(HOME_COLOR, 0.3);
      ctx.beginPath();
      ctx.arc(x, y, 9, 0, Math.PI * 2);
      ctx.fill();
      ctx.fillStyle = '#fff';
      ctx.beginPath();
      ctx.arc(x, y, 3.2, 0, Math.PI * 2);
      ctx.fill();
      ctx.strokeStyle = rgba(HOME_COLOR, 1);
      ctx.lineWidth = 1.6;
      ctx.beginPath();
      ctx.arc(x, y, 6, 0, Math.PI * 2);
      ctx.stroke();
    }
  }

  // ---------- frame ----------
  render(dtSec) {
    const dt = Math.min(dtSec, 0.1);
    this.time += dt;
    this._updateView(dt);
    const ctx = this.ctx;
    ctx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
    const shifts = this._shifts();
    this._background(ctx);
    this._graticule(ctx, shifts);
    this._land(ctx, shifts);
    this._night(ctx, shifts);
    ctx.globalCompositeOperation = 'lighter';
    this._arcs(ctx, shifts);
    this._comets(ctx, shifts);
    this._pulses(ctx, shifts);
    ctx.globalCompositeOperation = 'source-over';
    this._homeMarker(ctx, shifts);
  }

  dispose() {
    this.ro.disconnect();
    this.canvas.remove();
  }
}
