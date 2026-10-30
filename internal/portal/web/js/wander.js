// Wandering mode: a device that is not filtered at all but still logged and
// watched. Pure helpers for mode, timers, patches and shadow notes.
export const TIMER_CHOICES = [
  { minutes: 15, label: '15 minutes' },
  { minutes: 60, label: '1 hour' },
  { minutes: 240, label: '4 hours' },
  { minutes: 1440, label: '24 hours' },
  { minutes: 0, label: 'Until I turn it off' },
];

export const MODES = [
  { id: 'protected', label: 'Protected', text: 'Filtered by your blocking settings.' },
  { id: 'wandering', label: 'Wandering', text: 'Not filtered at all, but every request is still logged and watched.' },
  { id: 'excluded', label: 'Excluded', text: 'Left alone: Shepherd keeps out of the way.' },
];

const untilMs = (d) => (d && d.wandering_until ? Date.parse(d.wandering_until) : NaN);

// True while wandering, honouring a timer that has already run out.
export function isWandering(d, now = Date.now()) {
  if (!d || !d.wandering) return false;
  const u = untilMs(d);
  return Number.isFinite(u) ? u > now : true;
}

export function deviceMode(d, now = Date.now()) {
  if (isWandering(d, now)) return 'wandering';
  return d && d.excluded ? 'excluded' : 'protected';
}

export const modeLabel = (id) => (MODES.find((m) => m.id === id) || MODES[0]).label;

// "42 min left", "3 h left", "until turned off" or '' when not wandering.
export function countdown(d, now = Date.now()) {
  if (!isWandering(d, now)) return '';
  const u = untilMs(d);
  if (!Number.isFinite(u)) return 'until turned off';
  const s = Math.max(0, Math.round((u - now) / 1000));
  if (s < 60) return 'under a minute left';
  if (s < 3600) return Math.ceil(s / 60) + ' min left';
  if (s < 86400) { const h = Math.floor(s / 3600), m = Math.round((s % 3600) / 60); return h + ' h' + (m ? ' ' + m + ' min' : '') + ' left'; }
  return Math.round(s / 86400) + ' d left';
}

// Short form for the table pill: "42m", "3h", "" for untimed.
export function countdownShort(d, now = Date.now()) {
  if (!isWandering(d, now)) return '';
  const u = untilMs(d);
  if (!Number.isFinite(u)) return '';
  const s = Math.max(0, Math.round((u - now) / 1000));
  if (s < 90) return '<1m';
  if (s < 5400) return Math.ceil(s / 60) + 'm';
  if (s < 172800) return Math.round(s / 3600) + 'h';
  return Math.round(s / 86400) + 'd';
}

// The PATCH body for switching one device to a mode.
export function modePatch(mode, minutes = 0) {
  if (mode === 'wandering') {
    const p = { wandering: true, excluded: false };
    if (minutes > 0) p.wandering_minutes = minutes;
    return p;
  }
  if (mode === 'excluded') return { excluded: true, wandering: false };
  return { excluded: false, wandering: false };
}

// Optimistic local result of a patch (mirrors what the server will return).
export function applyModeLocal(d, patch, now = Date.now()) {
  const n = { ...d };
  if (typeof patch.excluded === 'boolean') n.excluded = patch.excluded;
  if (typeof patch.wandering === 'boolean') {
    n.wandering = patch.wandering;
    if (!patch.wandering || !(patch.wandering_minutes > 0)) delete n.wandering_until;
    else n.wandering_until = new Date(now + patch.wandering_minutes * 60000).toISOString();
    if (patch.wandering) n.excluded = false;
  }
  return n;
}

export function shadowNote(e) {
  return e && typeof e.shadow === 'string' && e.shadow ? 'would have blocked: ' + e.shadow : '';
}
