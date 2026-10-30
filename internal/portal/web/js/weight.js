// Weight encodes prominence. Thickness, brightness and glow all derive from one
// log-scaled number in [0,1], so a few heavy flows stand out from one-off
// lookups. The unit is honest about the data: lookups today, bytes when the
// backend starts reporting byte counts.

export const MODES = {
  lookups: { ref: 1, max: 150, floor: 0.2, unit: 'lookups' },
  bytes: { ref: 1024, max: 2 ** 30, floor: 64, unit: 'bytes' },
};

// A zero or missing weight is not drawn.
export function weightScale(w, mode = 'lookups') {
  const m = MODES[mode] || MODES.lookups;
  if (!(w > 0)) return 0;
  const s = Math.log1p(w / m.ref) / Math.log1p(m.max / m.ref);
  return s > 1 ? 1 : s;
}

// Inverse of weightScale, for legend labels.
export function weightFromScale(s, mode = 'lookups') {
  const m = MODES[mode] || MODES.lookups;
  const c = Math.min(Math.max(s, 0), 1);
  return m.ref * Math.expm1(c * Math.log1p(m.max / m.ref));
}

export function hasBytes(e) {
  return Number.isFinite(e.bytes_up) || Number.isFinite(e.bytes_down);
}

export function detectMode(e) {
  return hasBytes(e) ? 'bytes' : 'lookups';
}

// Weight one entry contributes in the given mode.
export function entryWeight(e, mode) {
  if (mode === 'bytes') return Math.max(0, (e.bytes_up || 0) + (e.bytes_down || 0));
  return 1;
}

// Pixel widths: a lone lookup is a hairline, the heaviest lane is chunky.
export const MIN_WIDTH = 1.1;
export const MAX_WIDTH = 8.5;
export function widthPx(s) {
  return MIN_WIDTH + (MAX_WIDTH - MIN_WIDTH) * s;
}

// Resting brightness of a lane's base arc.
export function baseAlpha(s) {
  return s <= 0 ? 0 : 0.16 + 0.5 * s;
}

export function legendText(mode) {
  return mode === 'bytes'
    ? 'Thickness shows bytes transferred (log scale)'
    : 'Thickness shows lookups merged into the lane (log scale)';
}

export function fmtBytes(n) {
  if (!Number.isFinite(n) || n < 0) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  let v = n;
  while (v >= 1000 && i < u.length - 1) { v /= 1024; i++; }
  return (i === 0 ? Math.round(v) : v < 10 ? v.toFixed(1) : Math.round(v)) + ' ' + u[i];
}

export function fmtWeight(w, mode) {
  if (mode === 'bytes') return fmtBytes(w);
  return w < 10 ? String(Math.max(1, Math.round(w))) : String(Math.round(w));
}
