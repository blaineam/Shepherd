// GLSL for the globe. Shaders are plain strings handed to WebGL (no eval, so
// they are fine under the portal's strict CSP).

// One instanced ribbon draws both a lane's resting arc (mode 0) and a comet
// travelling along an arc (mode 1). The arc itself is evaluated on the GPU
// from its two endpoints, so no per-frame CPU geometry is needed.
export const ARC_VERT = /* glsl */ `
uniform float uTime;
uniform float uPx;
uniform float uTrail;
uniform vec2 uRes;
attribute float aT;
attribute float aSide;
attribute vec3 iA;
attribute vec3 iB;
attribute vec2 iGeo;
attribute vec4 iStyle;
attribute vec3 iColor;
attribute vec2 iAnim;
varying vec3 vCol;
varying float vSide;
varying float vTrailPos;
varying float vMode;
varying float vAlpha;
varying float vCore;
varying float vHalf;
varying float vT;
varying float vSel;
const float PI = 3.14159265;

vec3 arcAt(float t) {
  float om = iGeo.x;
  float s = sin(om);
  vec3 p;
  if (s < 1e-3) p = normalize(mix(iA, iB, t) + vec3(0.0, 1e-3, 0.0));
  else p = (sin((1.0 - t) * om) * iA + sin(t * om) * iB) / s;
  return p * (1.004 + iGeo.y * sin(PI * t));
}

void main() {
  float mode = iStyle.z;
  float t = aT;
  float tp = 0.0;
  if (iStyle.y <= 0.001) { gl_Position = vec4(2.0, 2.0, 2.0, 1.0); return; }
  if (mode > 0.5) {
    float head = (uTime - iAnim.x) / iAnim.y;
    float t0 = clamp(head - uTrail, 0.0, 1.0);
    float t1 = clamp(head, 0.0, 1.0);
    if (head < 0.0 || t1 - t0 < 0.002) { gl_Position = vec4(2.0, 2.0, 2.0, 1.0); return; }
    t = mix(t0, t1, aT);
    tp = (t - (head - uTrail)) / uTrail;
  }
  vec3 p = arcAt(t);
  vec3 pa = arcAt(max(t - 0.012, 0.0));
  vec3 pb = arcAt(min(t + 0.012, 1.0));
  mat4 mvp = projectionMatrix * modelViewMatrix;
  vec4 c = mvp * vec4(p, 1.0);
  vec4 ca = mvp * vec4(pa, 1.0);
  vec4 cb = mvp * vec4(pb, 1.0);
  vec2 sa = ca.xy / ca.w * uRes * 0.5;
  vec2 sb = cb.xy / cb.w * uRes * 0.5;
  vec2 dir = sb - sa;
  float dl = length(dir);
  dir = dl < 1e-4 ? vec2(1.0, 0.0) : dir / dl;
  vec2 nrm = vec2(-dir.y, dir.x);
  float sel = iStyle.w;
  float w = iStyle.x * (1.0 + sel * 0.7);
  float core = w * 0.5;
  float half_ = core + 2.0 + w * 0.9;
  vec2 off = nrm * aSide * half_ * uPx;
  c.xy += off / (uRes * 0.5) * c.w;
  gl_Position = c;
  vCol = iColor;
  vSide = aSide;
  vTrailPos = tp;
  vMode = mode;
  vAlpha = iStyle.y;
  vCore = core;
  vHalf = half_;
  vT = t;
  vSel = sel;
}
`;

export const ARC_FRAG = /* glsl */ `
precision highp float;
uniform float uTime;
uniform float uReduced;
varying vec3 vCol;
varying float vSide;
varying float vTrailPos;
varying float vMode;
varying float vAlpha;
varying float vCore;
varying float vHalf;
varying float vT;
varying float vSel;
void main() {
  float d = abs(vSide) * vHalf;
  float core = 1.0 - smoothstep(vCore - 0.75, vCore + 0.75, d);
  float glow = exp(-max(d - vCore, 0.0) / (1.1 + vCore * 0.4));
  float inten;
  vec3 col = vCol;
  if (vMode > 0.5) {
    float tr = clamp(vTrailPos, 0.0, 1.0);
    float tail = pow(tr, 2.4);
    float head = smoothstep(0.9, 1.0, tr);
    inten = tail * 0.95 + head * 1.25;
    col = mix(vCol, vec3(1.0), head * 0.6);
  } else {
    float flow = uReduced > 0.5 ? 1.0 : 0.72 + 0.28 * sin(vT * 64.0 - uTime * 2.4);
    inten = vAlpha * flow;
  }
  col = mix(col, vec3(1.0), vSel * 0.35);
  gl_FragColor = vec4(col * inten * (core + glow * 0.5), 1.0);
}
`;

// Arrival pings, the red shield ring at home and the home marker itself.
export const PULSE_VERT = /* glsl */ `
uniform float uTime;
attribute vec3 pPos;
attribute vec3 pCol;
attribute vec2 pAnim;
attribute vec2 pKind;
varying vec2 vUv;
varying vec3 vCol;
varying float vP;
varying float vKind;
void main() {
  float kind = pKind.x;
  float p = kind > 1.5 ? 0.0 : (uTime - pAnim.x) / pAnim.y;
  if (pKind.y <= 0.0 || (kind < 1.5 && (p < 0.0 || p > 1.0))) { gl_Position = vec4(2.0, 2.0, 2.0, 1.0); return; }
  vec3 n = normalize(pPos);
  vec3 up = abs(n.y) > 0.99 ? vec3(1.0, 0.0, 0.0) : vec3(0.0, 1.0, 0.0);
  vec3 t = normalize(cross(up, n));
  vec3 b = cross(n, t);
  vec3 wp = n * 1.006 + (t * position.x + b * position.y) * pKind.y;
  vUv = position.xy;
  vCol = pCol;
  vP = p;
  vKind = kind;
  gl_Position = projectionMatrix * modelViewMatrix * vec4(wp, 1.0);
}
`;

export const PULSE_FRAG = /* glsl */ `
precision highp float;
uniform float uTime;
uniform float uReduced;
varying vec2 vUv;
varying vec3 vCol;
varying float vP;
varying float vKind;
float ring(float r, float c, float k) { float x = (r - c) * k; return exp(-x * x); }
void main() {
  float inten = 0.0;
  float rc = length(vUv);
  if (vKind < 0.5) {
    float p = uReduced > 0.5 ? 0.45 : vP;
    inten = ring(rc, p, 10.0) * (1.0 - p) * 1.3 + exp(-rc * rc * 30.0) * (1.0 - vP) * 0.9;
  } else if (vKind < 1.5) {
    float hx = max(abs(vUv.x) * 0.866 + abs(vUv.y) * 0.5, abs(vUv.y));
    float p = uReduced > 0.5 ? 0.6 : vP;
    float fade = 1.0 - vP;
    inten = (ring(hx, p, 11.0) + 0.6 * ring(hx, p * 0.62, 14.0)) * fade * 1.5;
    inten += (hx < p ? 0.16 : 0.0) * fade;
  } else {
    float breathe = uReduced > 0.5 ? 0.0 : 0.05 * sin(uTime * 2.0);
    float sweep = fract(uTime * 0.35);
    inten = ring(rc, 0.52 + breathe, 12.0) * 1.1 + exp(-rc * rc * 120.0) * 1.6;
    if (uReduced < 0.5) inten += ring(rc, sweep, 9.0) * (1.0 - sweep) * 0.7;
    inten += ring(rc, 0.9, 18.0) * 0.18;
  }
  gl_FragColor = vec4(vCol * inten, 1.0);
}
`;

export const DOT_VERT = /* glsl */ `
uniform float uPx;
attribute float aSize;
attribute vec3 aCol;
attribute float aAlpha;
varying vec3 vCol;
varying float vA;
void main() {
  vCol = aCol;
  vA = aAlpha;
  gl_PointSize = aSize * uPx;
  gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
}
`;

export const DOT_FRAG = /* glsl */ `
precision highp float;
varying vec3 vCol;
varying float vA;
void main() {
  float d = length(gl_PointCoord - 0.5) * 2.0;
  if (d > 1.0) discard;
  float core = 1.0 - smoothstep(0.35, 0.55, d);
  float halo = (1.0 - d) * 0.45;
  gl_FragColor = vec4(vCol * (core + halo) * vA, 1.0);
}
`;

// Dot-matrix land.
export const LAND_VERT = /* glsl */ `
uniform float uPx;
uniform float uSize;
uniform float uTime;
varying float vFace;
varying float vScan;
void main() {
  vec4 mv = modelViewMatrix * vec4(position, 1.0);
  vec3 n = normalize(mat3(modelViewMatrix) * position);
  vFace = dot(n, normalize(-mv.xyz));
  float lon = atan(position.x, position.z);
  vScan = smoothstep(0.985, 1.0, sin(lon * 2.0 - uTime * 0.25 + position.y * 2.0));
  gl_PointSize = uSize * uPx;
  gl_Position = projectionMatrix * mv;
}
`;

export const LAND_FRAG = /* glsl */ `
precision highp float;
varying float vFace;
varying float vScan;
void main() {
  float d = length(gl_PointCoord - 0.5) * 2.0;
  if (d > 1.0) discard;
  float a = 1.0 - smoothstep(0.55, 1.0, d);
  float lit = 0.28 + 0.72 * smoothstep(0.0, 0.55, vFace);
  vec3 base = vec3(0.09, 0.56, 0.56);
  vec3 col = base * lit + vec3(0.1, 0.5, 0.5) * vScan * lit;
  gl_FragColor = vec4(col * a, 1.0);
}
`;

export const SPHERE_VERT = /* glsl */ `
varying vec3 vN;
varying vec3 vV;
void main() {
  vec4 mv = modelViewMatrix * vec4(position, 1.0);
  vN = normalize(normalMatrix * normal);
  vV = -mv.xyz;
  gl_Position = projectionMatrix * mv;
}
`;

export const SPHERE_FRAG = /* glsl */ `
precision highp float;
varying vec3 vN;
varying vec3 vV;
void main() {
  float f = clamp(dot(normalize(vN), normalize(vV)), 0.0, 1.0);
  float rim = pow(1.0 - f, 2.6);
  vec3 col = mix(vec3(0.012, 0.028, 0.04), vec3(0.025, 0.065, 0.085), f);
  col += vec3(0.05, 0.42, 0.40) * rim * 0.42;
  gl_FragColor = vec4(col, 1.0);
}
`;

export const ATMO_VERT = /* glsl */ `
varying vec3 vN;
void main() {
  vN = normalize(normalMatrix * normal);
  gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
}
`;

export const ATMO_FRAG = /* glsl */ `
precision highp float;
varying vec3 vN;
void main() {
  float d = -dot(normalize(vN), vec3(0.0, 0.0, 1.0));
  float i = pow(clamp(d * 1.9, 0.0, 1.0), 2.6);
  gl_FragColor = vec4(vec3(0.08, 0.78, 0.74) * i * 0.8, 1.0);
}
`;

export const STAR_VERT = /* glsl */ `
uniform float uPx;
uniform float uTime;
attribute float aSize;
attribute float aPhase;
varying float vA;
void main() {
  vA = 0.55 + 0.45 * sin(uTime * (0.4 + aPhase) + aPhase * 40.0);
  gl_PointSize = aSize * uPx;
  gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
}
`;

export const STAR_FRAG = /* glsl */ `
precision highp float;
varying float vA;
void main() {
  float d = length(gl_PointCoord - 0.5) * 2.0;
  if (d > 1.0) discard;
  gl_FragColor = vec4(vec3(0.55, 0.72, 0.85) * (1.0 - d) * vA * 0.7, 1.0);
}
`;
