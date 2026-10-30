// The 3D globe: WebGL scene, controls and picking. All rendering state lives
// in preallocated typed arrays feeding instanced buffers, so a frame allocates
// nothing and ~900 ribbons (300 lanes + 600 comets) draw in a handful of calls.
import * as THREE from '../vendor/three.module.min.js';
import {
  DEG, latLonToVec3, vec3ToLatLon, slerp, arcPoint, segmentHitsSphere, dampVelocity, clamp, normalizeLon,
} from './geo.js';
import { weightScale, widthPx, baseAlpha } from './weight.js';
import { landPolygons, sampleLandPoints, coastSegments } from './topo.js';
import * as SH from './shaders.js';

export const LANE_CAP = 300;
export const COMET_CAP = 600;
export const PULSE_CAP = 192;
const SEG = 40;
const INSTANCES = LANE_CAP + COMET_CAP;
const FOV = 36;

export const COLORS = {
  allowed: [0.086, 0.78, 0.741],
  cached: [0.416, 0.651, 0.949],
  blocked: [0.949, 0.439, 0.42],
  error: [0.941, 0.714, 0.29],
};
const WHITE = [1, 1, 1];

export function webglAvailable() {
  try {
    const c = document.createElement('canvas');
    return !!(window.WebGL2RenderingContext && c.getContext('webgl2'));
  } catch { return false; }
}

function instAttr(arr, size) {
  const a = new THREE.InstancedBufferAttribute(arr, size);
  a.setUsage(THREE.DynamicDrawUsage);
  return a;
}

export class Globe {
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
    this.homeVec = [0, 0, 1];
    this.selectedKey = null;
    this.hoverKey = null;
    this.stats = { lanes: 0, comets: 0 };

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: false, powerPreference: 'high-performance' });
    renderer.setClearColor(0x04080d, 1);
    this.renderer = renderer;
    this.canvas = renderer.domElement;
    this.canvas.className = 'globe-canvas';
    container.appendChild(this.canvas);

    this.scene = new THREE.Scene();
    this.camera = new THREE.PerspectiveCamera(FOV, 1, 0.1, 200);
    this.globe = new THREE.Group();
    this.scene.add(this.globe);

    this.uniforms = {
      uTime: { value: 0 }, uPx: { value: 1 }, uRes: { value: new THREE.Vector2(1, 1) },
      uTrail: { value: this.reduced ? 0.14 : 0.3 }, uReduced: { value: this.reduced ? 1 : 0 },
      uSize: { value: 2 },
    };

    // View state: the surface point facing the camera, plus zoom.
    this.centerLat = 22;
    this.centerLon = -40;
    this.latVel = 0;
    this.lonVel = 0;
    this.camDist = 4;
    this.baseDist = 4;
    this.userZoom = 1;
    this.target = null;
    this.idleFor = 10;
    this.tmpV = new THREE.Vector3();
    this.tmpCam = [0, 0, 0];
    this.tmpP = [0, 0, 0];
    this.proj = { x: 0, y: 0, visible: false };

    this._buildStars();
    this._buildBody();
    this._buildArcs();
    this._buildPulses();
    this._buildDots();
    this._bindControls();

    this.ro = new ResizeObserver(() => this.resize());
    this.ro.observe(container);
    this.resize();
  }

  // ---------- scene ----------
  _buildStars() {
    const n = 1400;
    const pos = new Float32Array(n * 3);
    const size = new Float32Array(n);
    const phase = new Float32Array(n);
    let seed = 12345;
    const rnd = () => { seed = (seed * 1664525 + 1013904223) >>> 0; return seed / 4294967296; };
    for (let i = 0; i < n; i++) {
      const u = rnd() * 2 - 1, th = rnd() * Math.PI * 2, r = 60 + rnd() * 30, s = Math.sqrt(1 - u * u);
      pos[i * 3] = r * s * Math.cos(th); pos[i * 3 + 1] = r * u; pos[i * 3 + 2] = r * s * Math.sin(th);
      size[i] = 0.8 + Math.pow(rnd(), 4) * 2.4;
      phase[i] = rnd();
    }
    const g = new THREE.BufferGeometry();
    g.setAttribute('position', new THREE.BufferAttribute(pos, 3));
    g.setAttribute('aSize', new THREE.BufferAttribute(size, 1));
    g.setAttribute('aPhase', new THREE.BufferAttribute(phase, 1));
    const m = new THREE.ShaderMaterial({
      uniforms: this.uniforms, vertexShader: SH.STAR_VERT, fragmentShader: SH.STAR_FRAG,
      blending: THREE.AdditiveBlending, depthWrite: false, transparent: true,
    });
    const stars = new THREE.Points(g, m);
    stars.frustumCulled = false;
    this.scene.add(stars);
  }

  _buildBody() {
    const sphere = new THREE.Mesh(
      new THREE.SphereGeometry(0.992, 96, 64),
      new THREE.ShaderMaterial({ vertexShader: SH.SPHERE_VERT, fragmentShader: SH.SPHERE_FRAG }),
    );
    this.sphere = sphere;
    this.globe.add(sphere);

    const atmo = new THREE.Mesh(
      new THREE.SphereGeometry(1.2, 64, 48),
      new THREE.ShaderMaterial({
        vertexShader: SH.ATMO_VERT, fragmentShader: SH.ATMO_FRAG, side: THREE.BackSide,
        blending: THREE.AdditiveBlending, depthWrite: false, transparent: true,
      }),
    );
    this.scene.add(atmo);

    // Graticule every 30 degrees.
    const pts = [];
    const v = [0, 0, 0], w = [0, 0, 0];
    for (let lat = -60; lat <= 60; lat += 30) {
      for (let lon = -180; lon < 180; lon += 6) {
        latLonToVec3(lat, lon, 1.0008, v); latLonToVec3(lat, lon + 6, 1.0008, w);
        pts.push(v[0], v[1], v[2], w[0], w[1], w[2]);
      }
    }
    for (let lon = -180; lon < 180; lon += 30) {
      for (let lat = -84; lat < 84; lat += 6) {
        latLonToVec3(lat, lon, 1.0008, v); latLonToVec3(lat + 6, lon, 1.0008, w);
        pts.push(v[0], v[1], v[2], w[0], w[1], w[2]);
      }
    }
    const gg = new THREE.BufferGeometry();
    gg.setAttribute('position', new THREE.Float32BufferAttribute(pts, 3));
    this.globe.add(new THREE.LineSegments(gg, new THREE.LineBasicMaterial({ color: 0x16c7bd, transparent: true, opacity: 0.07 })));
  }

  // Land dots and coastline from the vendored Natural Earth TopoJSON.
  loadLand(topo) {
    const polys = landPolygons(topo);
    const pts = sampleLandPoints(polys, 1.2);
    const pos = new Float32Array((pts.length / 2) * 3);
    const v = [0, 0, 0];
    for (let i = 0, j = 0; i < pts.length; i += 2, j += 3) {
      latLonToVec3(pts[i], pts[i + 1], 1.001, v);
      pos[j] = v[0]; pos[j + 1] = v[1]; pos[j + 2] = v[2];
    }
    const g = new THREE.BufferGeometry();
    g.setAttribute('position', new THREE.BufferAttribute(pos, 3));
    const dots = new THREE.Points(g, new THREE.ShaderMaterial({
      uniforms: this.uniforms, vertexShader: SH.LAND_VERT, fragmentShader: SH.LAND_FRAG,
      blending: THREE.AdditiveBlending, depthWrite: false, transparent: true,
    }));
    dots.frustumCulled = false;
    this.globe.add(dots);

    const seg = coastSegments(polys);
    const cp = new Float32Array((seg.length / 4) * 6);
    for (let i = 0, j = 0; i < seg.length; i += 4, j += 6) {
      latLonToVec3(seg[i], seg[i + 1], 1.0015, v); cp[j] = v[0]; cp[j + 1] = v[1]; cp[j + 2] = v[2];
      latLonToVec3(seg[i + 2], seg[i + 3], 1.0015, v); cp[j + 3] = v[0]; cp[j + 4] = v[1]; cp[j + 5] = v[2];
    }
    const cg = new THREE.BufferGeometry();
    cg.setAttribute('position', new THREE.BufferAttribute(cp, 3));
    this.globe.add(new THREE.LineSegments(cg, new THREE.LineBasicMaterial({ color: 0x2ad6cb, transparent: true, opacity: 0.45 })));
    this.landDots = pts.length / 2;
  }

  _buildArcs() {
    const nV = (SEG + 1) * 2;
    const aT = new Float32Array(nV), aSide = new Float32Array(nV);
    for (let i = 0; i <= SEG; i++) {
      aT[i * 2] = aT[i * 2 + 1] = i / SEG;
      aSide[i * 2] = -1; aSide[i * 2 + 1] = 1;
    }
    const idx = [];
    for (let i = 0; i < SEG; i++) { const a = i * 2; idx.push(a, a + 1, a + 2, a + 1, a + 3, a + 2); }
    const g = new THREE.InstancedBufferGeometry();
    g.setIndex(idx);
    g.setAttribute('position', new THREE.BufferAttribute(new Float32Array(nV * 3), 3));
    g.setAttribute('aT', new THREE.BufferAttribute(aT, 1));
    g.setAttribute('aSide', new THREE.BufferAttribute(aSide, 1));
    this.A = {
      iA: new Float32Array(INSTANCES * 3), iB: new Float32Array(INSTANCES * 3), iGeo: new Float32Array(INSTANCES * 2),
      iStyle: new Float32Array(INSTANCES * 4), iColor: new Float32Array(INSTANCES * 3), iAnim: new Float32Array(INSTANCES * 2),
    };
    this.attrs = {
      iA: instAttr(this.A.iA, 3), iB: instAttr(this.A.iB, 3), iGeo: instAttr(this.A.iGeo, 2),
      iStyle: instAttr(this.A.iStyle, 4), iColor: instAttr(this.A.iColor, 3), iAnim: instAttr(this.A.iAnim, 2),
    };
    for (const k of Object.keys(this.attrs)) g.setAttribute(k, this.attrs[k]);
    g.instanceCount = INSTANCES;
    const m = new THREE.ShaderMaterial({
      uniforms: this.uniforms, vertexShader: SH.ARC_VERT, fragmentShader: SH.ARC_FRAG,
      blending: THREE.AdditiveBlending, depthWrite: false, transparent: true, side: THREE.DoubleSide,
    });
    const mesh = new THREE.Mesh(g, m);
    mesh.frustumCulled = false;
    mesh.renderOrder = 3;
    this.globe.add(mesh);
    this.arcDirty = false;
    this.cometNext = 0;
    this.cometArrive = new Float64Array(COMET_CAP);
    this.cometPending = new Uint8Array(COMET_CAP);
    this.cometDest = new Float32Array(COMET_CAP * 3);
    this.cometColor = new Float32Array(COMET_CAP * 3);
    this.cometSize = new Float32Array(COMET_CAP);
  }

  _buildPulses() {
    const quad = new Float32Array([-1, -1, 0, 1, -1, 0, 1, 1, 0, -1, 1, 0]);
    const g = new THREE.InstancedBufferGeometry();
    g.setIndex([0, 1, 2, 0, 2, 3]);
    g.setAttribute('position', new THREE.BufferAttribute(quad, 3));
    this.P = {
      pPos: new Float32Array(PULSE_CAP * 3), pCol: new Float32Array(PULSE_CAP * 3),
      pAnim: new Float32Array(PULSE_CAP * 2), pKind: new Float32Array(PULSE_CAP * 2),
    };
    this.pAttrs = {
      pPos: instAttr(this.P.pPos, 3), pCol: instAttr(this.P.pCol, 3), pAnim: instAttr(this.P.pAnim, 2), pKind: instAttr(this.P.pKind, 2),
    };
    for (const k of Object.keys(this.pAttrs)) g.setAttribute(k, this.pAttrs[k]);
    g.instanceCount = PULSE_CAP;
    const mesh = new THREE.Mesh(g, new THREE.ShaderMaterial({
      uniforms: this.uniforms, vertexShader: SH.PULSE_VERT, fragmentShader: SH.PULSE_FRAG,
      blending: THREE.AdditiveBlending, depthWrite: false, transparent: true, side: THREE.DoubleSide,
    }));
    mesh.frustumCulled = false;
    mesh.renderOrder = 4;
    this.globe.add(mesh);
    this.pulseNext = 1; // slot 0 is the home marker
    this.pDirty = false;
  }

  _buildDots() {
    const g = new THREE.BufferGeometry();
    this.D = {
      pos: new Float32Array(LANE_CAP * 3), size: new Float32Array(LANE_CAP),
      col: new Float32Array(LANE_CAP * 3), a: new Float32Array(LANE_CAP),
    };
    this.dAttrs = {
      position: instAttr(this.D.pos, 3), aSize: instAttr(this.D.size, 1), aCol: instAttr(this.D.col, 3), aAlpha: instAttr(this.D.a, 1),
    };
    for (const k of Object.keys(this.dAttrs)) g.setAttribute(k, this.dAttrs[k]);
    const pts = new THREE.Points(g, new THREE.ShaderMaterial({
      uniforms: this.uniforms, vertexShader: SH.DOT_VERT, fragmentShader: SH.DOT_FRAG,
      blending: THREE.AdditiveBlending, depthWrite: false, transparent: true,
    }));
    pts.frustumCulled = false;
    pts.renderOrder = 5;
    this.globe.add(pts);
  }

  // ---------- data ----------
  setLanes(table) { this.lanes = table; }

  setHome(home) {
    this.home = home;
    const P = this.P;
    if (!home) { P.pKind[0] = 0; P.pKind[1] = 0; this.pAttrs.pKind.needsUpdate = true; return; }
    latLonToVec3(home.lat, home.lon, 1, this.homeVec);
    P.pPos.set(this.homeVec, 0);
    P.pCol.set(COLORS.allowed, 0);
    P.pKind[0] = 2; P.pKind[1] = 0.11;
    for (const k of Object.keys(this.pAttrs)) this.pAttrs[k].needsUpdate = true;
  }

  // Push lane state into the instanced buffers (called ~10x/s, not per frame).
  sync(now, visible = () => true) {
    const t = this.lanes;
    if (!t) return;
    const A = this.A, D = this.D;
    let active = 0;
    for (let i = 0; i < LANE_CAP; i++) {
      const lane = t.slots[i];
      const st = i * 4;
      if (!lane || !lane.from || !visible(lane)) {
        A.iStyle[st + 1] = 0; D.a[i] = 0; D.size[i] = 0;
        continue;
      }
      const s = weightScale(t.valueAt(lane, now), t.mode);
      lane.s = s;
      if (s <= 0) { A.iStyle[st + 1] = 0; D.a[i] = 0; D.size[i] = 0; continue; }
      active++;
      const col = COLORS[lane.action] || COLORS.allowed;
      const sel = lane.key === this.selectedKey ? 1 : lane.key === this.hoverKey ? 0.5 : 0;
      A.iA[i * 3] = lane.from[0]; A.iA[i * 3 + 1] = lane.from[1]; A.iA[i * 3 + 2] = lane.from[2];
      A.iB[i * 3] = lane.to[0]; A.iB[i * 3 + 1] = lane.to[1]; A.iB[i * 3 + 2] = lane.to[2];
      A.iGeo[i * 2] = lane.angle; A.iGeo[i * 2 + 1] = lane.lift;
      A.iStyle[st] = widthPx(s); A.iStyle[st + 1] = baseAlpha(s); A.iStyle[st + 2] = lane.wandering ? -1 : 0; A.iStyle[st + 3] = sel;
      A.iColor[i * 3] = col[0]; A.iColor[i * 3 + 1] = col[1]; A.iColor[i * 3 + 2] = col[2];
      D.pos[i * 3] = lane.to[0] * 1.005; D.pos[i * 3 + 1] = lane.to[1] * 1.005; D.pos[i * 3 + 2] = lane.to[2] * 1.005;
      D.size[i] = 3 + 6 * s + sel * 5;
      D.col[i * 3] = col[0]; D.col[i * 3 + 1] = col[1]; D.col[i * 3 + 2] = col[2];
      D.a[i] = 0.55 + 0.45 * s;
    }
    this.stats.lanes = active;
    this.arcDirty = true;
    for (const k of Object.keys(this.dAttrs)) this.dAttrs[k].needsUpdate = true;
  }

  // A comet travelling home -> destination along the lane's arc.
  spawnComet(lane, s) {
    if (!lane.from) return;
    const i = this.cometNext;
    this.cometNext = (i + 1) % COMET_CAP;
    const slot = LANE_CAP + i, A = this.A;
    const dur = 1.0 + 1.5 * (lane.angle / Math.PI) + (this.reduced ? 0.4 : 0);
    const col = COLORS[lane.action] || COLORS.allowed;
    const boost = 0.75 + 0.6 * s;
    A.iA.set(lane.from, slot * 3); A.iB.set(lane.to, slot * 3);
    A.iGeo[slot * 2] = lane.angle; A.iGeo[slot * 2 + 1] = lane.lift;
    A.iStyle[slot * 4] = widthPx(s) * 0.95; A.iStyle[slot * 4 + 1] = 1; A.iStyle[slot * 4 + 2] = 1;
    A.iStyle[slot * 4 + 3] = lane.key === this.selectedKey ? 1 : 0;
    A.iColor[slot * 3] = col[0] * boost; A.iColor[slot * 3 + 1] = col[1] * boost; A.iColor[slot * 3 + 2] = col[2] * boost;
    A.iAnim[slot * 2] = this.time; A.iAnim[slot * 2 + 1] = dur;
    this.cometArrive[i] = this.time + dur;
    this.cometPending[i] = 1;
    this.cometDest.set(lane.to, i * 3);
    this.cometColor.set(col, i * 3);
    this.cometSize[i] = 0.035 + 0.06 * s;
    this.arcDirty = true;
  }

  _pulse(pos, po, col, co, kind, size, dur) {
    const i = this.pulseNext;
    this.pulseNext = i + 1 >= PULSE_CAP ? 1 : i + 1;
    const P = this.P;
    for (let k = 0; k < 3; k++) { P.pPos[i * 3 + k] = pos[po + k]; P.pCol[i * 3 + k] = col[co + k]; }
    P.pAnim[i * 2] = this.time; P.pAnim[i * 2 + 1] = dur;
    P.pKind[i * 2] = kind; P.pKind[i * 2 + 1] = size;
    this.pDirty = true;
  }

  // Blocked queries have no destination: a red shield ring at home instead.
  spawnShield(s = 0.3) {
    if (!this.home) return;
    this._pulse(this.homeVec, 0, COLORS.blocked, 0, 1, 0.07 + 0.09 * s, this.reduced ? 1.0 : 1.5);
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
    // Look at home from a little south-west of overhead so arcs curve across the view.
    if (this.home) this.focus(this.home.lat - 14, this.home.lon + 12);
    else this.focus(22, -40);
  }

  // Centre the view on the middle of a lane's arc so both ends stay in sight.
  focusLane(lane) {
    if (!lane.from) { this.focus(lane.dest.lat, lane.dest.lon); return; }
    const m = slerp(lane.from, lane.to, 0.5);
    const ll = vec3ToLatLon(m[0], m[1], m[2]);
    this.focus(ll.lat, ll.lon);
  }

  setAutoRotate(on) { this.autoRotate = on && !this.reduced; }

  resize() {
    const w = Math.max(1, this.container.clientWidth), h = Math.max(1, this.container.clientHeight);
    this.width = w; this.height = h;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    this.renderer.setPixelRatio(dpr);
    this.renderer.setSize(w, h, true);
    this.camera.aspect = w / h;
    this.camera.updateProjectionMatrix();
    const half = Math.atan(Math.tan((FOV * DEG) / 2) * Math.min(1, w / h));
    this.baseDist = 1 / Math.sin(half * 0.8);
    this.uniforms.uPx.value = dpr;
    const sz = this.renderer.getDrawingBufferSize(new THREE.Vector2());
    this.uniforms.uRes.value.copy(sz);
    this._applyZoom();
  }

  _applyZoom() {
    this.userZoom = clamp(this.userZoom, 0.34, 1.9);
    this.camDist = this.baseDist * this.userZoom;
    this.camera.position.set(0, 0, this.camDist);
  }

  // ---------- controls ----------
  _bindControls() {
    const el = this.canvas;
    this.pointers = new Map();
    let down = null;
    let lastMove = 0;
    let pinch = 0;
    el.style.touchAction = 'none';
    el.style.cursor = 'grab';
    const degPerPx = () => {
      const rpx = (this.height / 2) / Math.tan((FOV * DEG) / 2) / Math.sqrt(Math.max(0.2, this.camDist * this.camDist - 1));
      return 1 / DEG / Math.max(60, rpx);
    };
    el.addEventListener('pointerdown', (e) => {
      el.setPointerCapture(e.pointerId);
      this.pointers.set(e.pointerId, { x: e.clientX, y: e.clientY });
      if (this.pointers.size === 1) down = { x: e.clientX, y: e.clientY, t: performance.now(), moved: 0, lx: e.clientX, ly: e.clientY, lt: performance.now() };
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
          if (pinch > 0 && d > 0) { this.userZoom *= pinch / d; this._applyZoom(); }
          pinch = d;
          return;
        }
        if (down) {
          const dx = e.clientX - px, dy = e.clientY - py;
          down.moved += Math.abs(dx) + Math.abs(dy);
          const k = degPerPx();
          this.centerLon = normalizeLon(this.centerLon - dx * k);
          this.centerLat = clamp(this.centerLat + dy * k, -85, 85);
          const now = performance.now(), dt = Math.max(1, now - down.lt) / 1000;
          this.lonVel = this.lonVel * 0.6 + (-dx * k / dt) * 0.4;
          this.latVel = this.latVel * 0.6 + (dy * k / dt) * 0.4;
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
      // A stale velocity from a pause before release should not fling the globe.
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
      this.userZoom *= Math.exp(e.deltaY * (e.deltaMode === 1 ? 0.04 : 0.0014));
      this._applyZoom();
      this.idleFor = 0;
    }, { passive: false });
  }

  setHomeMode(on) {
    this.homeMode = on;
    this.canvas.style.cursor = on ? 'crosshair' : 'grab';
  }

  _updateView(dt) {
    this.idleFor += dt;
    const free = this.pointers.size === 0;
    if (this.target && free) {
      const k = 1 - Math.pow(0.5, dt / 0.18);
      let dl = this.target.lon - this.centerLon;
      dl = ((dl + 540) % 360) - 180;
      this.centerLon = normalizeLon(this.centerLon + dl * k);
      this.centerLat += (this.target.lat - this.centerLat) * k;
      if (Math.abs(dl) < 0.05 && Math.abs(this.target.lat - this.centerLat) < 0.05) this.target = null;
    } else if (free) {
      this.centerLon = normalizeLon(this.centerLon + this.lonVel * dt);
      this.centerLat = clamp(this.centerLat + this.latVel * dt, -85, 85);
      this.lonVel = dampVelocity(this.lonVel, dt);
      this.latVel = dampVelocity(this.latVel, dt);
      if (Math.abs(this.lonVel) < 0.01) this.lonVel = 0;
      if (Math.abs(this.latVel) < 0.01) this.latVel = 0;
      if (this.autoRotate && this.idleFor > 5 && !this.homeMode) this.centerLon = normalizeLon(this.centerLon + 3.2 * dt);
    }
    this.globe.rotation.set(this.centerLat * DEG, -this.centerLon * DEG, 0);
    this.globe.updateMatrixWorld(true);
  }

  // ---------- picking ----------
  pickLatLon(cx, cy) {
    const r = this.canvas.getBoundingClientRect();
    const nx = ((cx - r.left) / r.width) * 2 - 1, ny = -(((cy - r.top) / r.height) * 2 - 1);
    // Ray from the camera (on +z) through the pixel, intersected with the unit sphere.
    const th = Math.tan((FOV * DEG) / 2);
    const dx = nx * th * this.camera.aspect, dy = ny * th, dz = -1;
    const dl = Math.hypot(dx, dy, dz);
    const d = [dx / dl, dy / dl, dz / dl];
    const c = [0, 0, this.camDist];
    const b = c[0] * d[0] + c[1] * d[1] + c[2] * d[2];
    const disc = b * b - (c[2] * c[2] - 0.992 * 0.992);
    if (disc < 0) return null;
    const t = -b - Math.sqrt(disc);
    const wp = this.tmpV.set(c[0] + d[0] * t, c[1] + d[1] * t, c[2] + d[2] * t);
    this.globe.worldToLocal(wp);
    return vec3ToLatLon(wp.x, wp.y, wp.z);
  }

  // Project a lat/lon (at radius r) to canvas pixels; visible=false when on the far side.
  projectLatLon(lat, lon, r, out = this.proj) {
    latLonToVec3(lat, lon, r, this.tmpP);
    const v = this.tmpV.set(this.tmpP[0], this.tmpP[1], this.tmpP[2]).applyMatrix4(this.globe.matrixWorld);
    this.tmpCam[2] = this.camDist;
    out.visible = !segmentHitsSphere(this.tmpCam, [v.x, v.y, v.z], 0.99);
    v.project(this.camera);
    out.x = (v.x * 0.5 + 0.5) * this.width;
    out.y = (-v.y * 0.5 + 0.5) * this.height;
    return out;
  }

  // Nearest lane arc or destination under the cursor.
  pick(cx, cy) {
    const t = this.lanes;
    if (!t) return null;
    const r = this.canvas.getBoundingClientRect();
    const mx = cx - r.left, my = cy - r.top;
    const m = this.globe.matrixWorld;
    const cam = this.tmpCam; cam[0] = 0; cam[1] = 0; cam[2] = this.camDist;
    const v = this.tmpV;
    let best = null, bestD = Infinity;
    for (let i = 0; i < LANE_CAP; i++) {
      const lane = t.slots[i];
      if (!lane || !lane.from || this.A.iStyle[i * 4 + 1] <= 0) continue;
      const wpx = widthPx(lane.s || 0) * 0.5;
      for (let k = 0; k <= 12; k++) {
        const tt = k / 12;
        if (k === 12) { this.tmpP[0] = lane.to[0] * 1.004; this.tmpP[1] = lane.to[1] * 1.004; this.tmpP[2] = lane.to[2] * 1.004; }
        else arcPoint(lane.from, lane.to, lane.lift, tt, this.tmpP);
        v.set(this.tmpP[0], this.tmpP[1], this.tmpP[2]).applyMatrix4(m);
        if (segmentHitsSphere(cam, [v.x, v.y, v.z], 0.99)) continue;
        v.project(this.camera);
        const sx = (v.x * 0.5 + 0.5) * this.width, sy = (-v.y * 0.5 + 0.5) * this.height;
        const d = Math.hypot(sx - mx, sy - my) - wpx - (k === 12 ? 6 : 0);
        if (d < bestD) { bestD = d; best = { lane, kind: k === 12 ? 'dest' : 'arc' }; }
      }
    }
    return best && bestD < 12 ? best : null;
  }

  // ---------- frame ----------
  render(dtSec) {
    const dt = Math.min(dtSec, 0.1);
    this.time += dt;
    this.uniforms.uTime.value = this.time;
    this._updateView(dt);
    this.uniforms.uSize.value = clamp(1.9 * (this.baseDist / this.camDist) ** 0.8, 1.6, 6.5);

    // Arrival pings for comets that reached their destination.
    let live = 0;
    for (let i = 0; i < COMET_CAP; i++) {
      const slot = LANE_CAP + i;
      if (this.cometPending[i] && this.time >= this.cometArrive[i]) {
        this.cometPending[i] = 0;
        this._pulse(this.cometDest, i * 3, this.cometColor, i * 3, 0, this.cometSize[i], this.reduced ? 0.9 : 1.3);
      }
      if (this.time < this.cometArrive[i] + this.A.iAnim[slot * 2 + 1] * 0.35 + 0.1) live++;
      else if (this.A.iStyle[slot * 4 + 1] !== 0) { this.A.iStyle[slot * 4 + 1] = 0; this.arcDirty = true; }
    }
    this.stats.comets = live;

    if (this.arcDirty) {
      for (const k of Object.keys(this.attrs)) this.attrs[k].needsUpdate = true;
      this.arcDirty = false;
    }
    if (this.pDirty) {
      for (const k of Object.keys(this.pAttrs)) this.pAttrs[k].needsUpdate = true;
      this.pDirty = false;
    }
    this.renderer.render(this.scene, this.camera);
  }

  dispose() {
    this.ro.disconnect();
    this.renderer.dispose();
    this.canvas.remove();
  }
}
