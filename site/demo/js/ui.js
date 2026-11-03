// Shared UI pieces for the management screens: icons, switches, chips,
// popovers, menus, confirmation dialogs and toasts. All text goes in through
// textContent; nothing here ever uses innerHTML.
import { el } from './dom.js';

const NS = 'http://www.w3.org/2000/svg';
const P = {
  tv: ['M3 5h18v12H3z', 'M8 21h8M12 17v4'],
  phone: ['M7 2h10a2 2 0 0 1 2 2v16a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2z', 'M11 18h2'],
  tablet: ['M5 3h14a1 1 0 0 1 1 1v16a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1z', 'M11 18h2'],
  laptop: ['M5 6h14v10H5z', 'M2 19h20'],
  desktop: ['M3 4h18v12H3z', 'M8 20h8M12 16v4'],
  camera: ['M3 7h4l2-3h6l2 3h4v12H3z', 'M12 10a3.5 3.5 0 1 0 0 7 3.5 3.5 0 0 0 0-7z'],
  speaker: ['M7 2h10a1 1 0 0 1 1 1v18a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1V3a1 1 0 0 1 1-1z', 'M12 12a3 3 0 1 0 0 6 3 3 0 0 0 0-6z', 'M12 6h.01'],
  console: ['M7 8h10a5 5 0 0 1 5 5v1a3 3 0 0 1-5 2l-1-1H8l-1 1a3 3 0 0 1-5-2v-1a5 5 0 0 1 5-5z', 'M7 11v4M5 13h4M16 12h.01M18 14h.01'],
  printer: ['M7 9V3h10v6', 'M5 17H3V9h18v8h-2', 'M7 14h10v7H7z'],
  thermostat: ['M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z', 'M12 8v4l3 2'],
  iot: ['M8 8h8v8H8z', 'M10 3v3M14 3v3M10 18v3M14 18v3M3 10h3M3 14h3M18 10h3M18 14h3'],
  watch: ['M8 7h8a1 1 0 0 1 1 1v8a1 1 0 0 1-1 1H8a1 1 0 0 1-1-1V8a1 1 0 0 1 1-1z', 'M9 7l1-4h4l1 4M9 17l1 4h4l1-4'],
  router: ['M4 14h16v6H4z', 'M7 17h.01M11 17h.01', 'M8 14L6 8M16 14l2-6'],
  unknown: ['M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z', 'M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.7.4-1 .9-1 1.7', 'M12 17h.01'],
  search: ['M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14z', 'M20 20l-4-4'],
  x: ['M6 6l12 12M18 6L6 18'],
  check: ['M5 12l5 5 9-10'],
  chev: ['M6 9l6 6 6-6'],
  pencil: ['M4 20l1-5L16 4l4 4L9 19z', 'M14 6l4 4'],
  trash: ['M4 7h16', 'M9 7V4h6v3', 'M6 7l1 13h10l1-13'],
  plus: ['M12 5v14M5 12h14'],
  tag: ['M3 12V4h8l10 10-8 8z', 'M7.5 8h.01'],
  help: ['M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z', 'M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.7.4-1 .9-1 1.7', 'M12 17h.01'],
  lock: ['M6 11h12v10H6z', 'M8 11V8a4 4 0 0 1 8 0v3'],
  up: ['M12 19V5M6 11l6-6 6 6'],
  down: ['M12 5v14M6 13l6 6 6-6'],
  grip: ['M9 6h.01M15 6h.01M9 12h.01M15 12h.01M9 18h.01M15 18h.01'],
  history: ['M4 12a8 8 0 1 0 3-6.2', 'M4 4v4h4', 'M12 8v4l3 2'],
  shield: ['M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z'],
  refresh: ['M20 11a8 8 0 0 0-14-4', 'M4 4v4h4', 'M4 13a8 8 0 0 0 14 4', 'M20 20v-4h-4'],
  link: ['M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1', 'M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1'],
  users: ['M9 11a3 3 0 1 0 0-6 3 3 0 0 0 0 6z', 'M3 20c0-3.3 2.7-6 6-6s6 2.7 6 6', 'M16 5a3 3 0 0 1 0 6M18 14c2 .7 3 2.6 3 6'],
  import: ['M12 3v11', 'M8 10l4 4 4-4', 'M4 21h16'],
  archive: ['M3 5h18v4H3z', 'M5 9v10h14V9', 'M10 13h4'],
  // Watch mode. Not the wristwatch above (that is a device type).
  eye: ['M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6-10-6-10-6z', 'M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z'],
};

export function icon(name, size = 16, cls = '') {
  const svg = document.createElementNS(NS, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('width', String(size));
  svg.setAttribute('height', String(size));
  svg.setAttribute('fill', 'none');
  svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', '1.6');
  svg.setAttribute('stroke-linecap', 'round');
  svg.setAttribute('stroke-linejoin', 'round');
  svg.setAttribute('aria-hidden', 'true');
  svg.setAttribute('focusable', 'false');
  if (cls) svg.setAttribute('class', 'ico ' + cls); else svg.setAttribute('class', 'ico');
  for (const d of P[name] || P.unknown) { const p = document.createElementNS(NS, 'path'); p.setAttribute('d', d); svg.append(p); }
  return svg;
}

export const hasIcon = (n) => Object.prototype.hasOwnProperty.call(P, n);

export function button(label, cls = '', onClick, ico) {
  const b = el('button', cls);
  b.type = 'button';
  if (ico) b.append(icon(ico, 14));
  if (label) b.append(el('span', '', label));
  if (onClick) b.addEventListener('click', onClick);
  return b;
}

export function iconButton(name, label, onClick, cls = '') {
  const b = el('button', 'ibtn ' + cls);
  b.type = 'button';
  b.setAttribute('aria-label', label);
  b.title = label;
  b.append(icon(name, 15));
  if (onClick) b.addEventListener('click', onClick);
  return b;
}

// A labelled toggle switch. Returns {root, input}.
export function toggle({ checked = false, label = '', onChange, disabled = false, title = '' }) {
  const root = el('label', 'tgl');
  const input = el('input');
  input.type = 'checkbox';
  input.checked = checked;
  input.disabled = disabled;
  input.setAttribute('role', 'switch');
  if (label) input.setAttribute('aria-label', label);
  const track = el('span', 'tgl-track');
  track.setAttribute('aria-hidden', 'true');
  root.append(input, track);
  if (title) root.title = title;
  if (onChange) input.addEventListener('change', () => onChange(input.checked, input));
  return { root, input };
}

export function chip(text, { color = '', onRemove = null, cls = '', title = '' } = {}) {
  const c = el('span', 'tchip ' + cls);
  if (color) { const d = el('i', 'cdot'); d.style.background = color; c.append(d); }
  c.append(el('span', 'tchip-t', text));
  if (title) c.title = title;
  if (onRemove) {
    const x = el('button', 'tchip-x');
    x.type = 'button';
    x.setAttribute('aria-label', 'Remove ' + text);
    x.append(icon('x', 11));
    x.addEventListener('click', (e) => { e.stopPropagation(); onRemove(); });
    c.append(x);
  }
  return c;
}

// Segmented control. options: [{id,label}]. Returns {root, set(id)}.
export function segmented(options, value, onChange, label = '') {
  const root = el('div', 'seg');
  root.setAttribute('role', 'group');
  if (label) root.setAttribute('aria-label', label);
  const btns = new Map();
  const set = (id) => { for (const [k, b] of btns) b.setAttribute('aria-pressed', k === id ? 'true' : 'false'); };
  for (const o of options) {
    const b = el('button', '', o.label);
    b.type = 'button';
    b.addEventListener('click', () => { set(o.id); onChange(o.id); });
    btns.set(o.id, b);
    root.append(b);
  }
  set(value);
  return { root, set };
}

export function emptyState(title, text, action) {
  const d = el('div', 'empty');
  d.append(el('strong', '', title));
  if (text) d.append(el('p', 'muted', text));
  if (action) d.append(action);
  return d;
}

export const debounce = (fn, ms) => { let t = 0; const f = (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; f.cancel = () => clearTimeout(t); return f; };

export const reducedMotion = () => !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);

// ---------------------------------------------------------------- popovers
let openPop = null;

export function closePopover() { if (openPop) openPop.close(); }

// Anchors a floating panel under `anchor`. build(panel, close) fills it.
export function openPopover(anchor, build, { align = 'start', cls = '', label = 'Options' } = {}) {
  closePopover();
  const panel = el('div', 'pop ' + cls);
  panel.setAttribute('role', 'dialog');
  panel.setAttribute('aria-label', label);
  const prevFocus = document.activeElement;
  const close = () => {
    if (openPop !== api) return;
    openPop = null;
    document.removeEventListener('pointerdown', onDown, true);
    document.removeEventListener('keydown', onKey, true);
    window.removeEventListener('resize', place);
    panel.remove();
    anchor.setAttribute('aria-expanded', 'false');
    if (prevFocus && prevFocus.focus && document.contains(prevFocus)) prevFocus.focus();
  };
  const onDown = (e) => { if (!panel.contains(e.target) && !anchor.contains(e.target)) close(); };
  const onKey = (e) => { if (e.key === 'Escape') { e.stopPropagation(); close(); } };
  function place() {
    const r = anchor.getBoundingClientRect();
    const w = panel.offsetWidth, h = panel.offsetHeight;
    let left = align === 'end' ? r.right - w : r.left;
    left = Math.max(8, Math.min(left, window.innerWidth - w - 8));
    let top = r.bottom + 6;
    if (top + h > window.innerHeight - 8 && r.top - h - 6 > 8) top = r.top - h - 6;
    panel.style.left = Math.round(left) + 'px';
    panel.style.top = Math.round(top) + 'px';
  }
  const api = { close, el: panel, place };
  build(panel, close);
  document.body.append(panel);
  place();
  anchor.setAttribute('aria-expanded', 'true');
  document.addEventListener('pointerdown', onDown, true);
  document.addEventListener('keydown', onKey, true);
  window.addEventListener('resize', place);
  openPop = api;
  const first = panel.querySelector('input, button, [tabindex]');
  if (first) first.focus();
  return api;
}

// A menu of actions. items: [{label, onSelect, danger?, ico?, hint?}] or {sep:true}.
export function openMenu(anchor, items, opts = {}) {
  return openPopover(anchor, (panel, close) => {
    panel.classList.add('menu');
    panel.setAttribute('role', 'menu');
    const btns = [];
    for (const it of items) {
      if (it.sep) { panel.append(el('hr')); continue; }
      if (it.heading) { panel.append(el('div', 'menu-h', it.heading)); continue; }
      const b = el('button', 'menu-i' + (it.danger ? ' danger' : ''));
      b.type = 'button';
      b.setAttribute('role', 'menuitem');
      if (it.color) { const d = el('i', 'cdot'); d.style.background = it.color; b.append(d); }
      else if (it.ico) b.append(icon(it.ico, 14));
      b.append(el('span', 'grow', it.label));
      if (it.hint) b.append(el('span', 'muted small', it.hint));
      b.addEventListener('click', () => { close(); it.onSelect(); });
      panel.append(b);
      btns.push(b);
    }
    if (!btns.length) panel.append(el('div', 'menu-h', opts.empty || 'Nothing here'));
    panel.addEventListener('keydown', (e) => {
      const i = btns.indexOf(document.activeElement);
      if (e.key === 'ArrowDown') { e.preventDefault(); btns[(i + 1) % btns.length].focus(); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); btns[(i - 1 + btns.length) % btns.length].focus(); }
    });
  }, { ...opts, cls: 'menu-pop' });
}

// ---------------------------------------------------------------- dialogs
export function confirmDialog({ title, body, confirm = 'Confirm', danger = false, cancel = 'Cancel' }) {
  return new Promise((resolve) => {
    const prev = document.activeElement;
    const overlay = el('div', 'overlay dlg-overlay');
    const box = el('div', 'modal dlg');
    box.setAttribute('role', 'alertdialog');
    box.setAttribute('aria-modal', 'true');
    box.setAttribute('aria-label', title);
    const h = el('h2', '', title);
    const p = el('p', 'muted', body || '');
    const row = el('div', 'dlg-actions');
    const no = button(cancel, 'ghost', () => done(false));
    const yes = button(confirm, danger ? 'danger' : 'primary', () => done(true));
    row.append(no, yes);
    box.append(h, p, row);
    overlay.append(box);
    function done(v) { document.removeEventListener('keydown', onKey, true); overlay.remove(); if (prev && prev.focus) prev.focus(); resolve(v); }
    function onKey(e) {
      if (e.key === 'Escape') { e.stopPropagation(); done(false); }
      else if (e.key === 'Tab') { const f = [no, yes]; const i = f.indexOf(document.activeElement); e.preventDefault(); f[(i + (e.shiftKey ? -1 : 1) + 2) % 2].focus(); }
    }
    overlay.addEventListener('pointerdown', (e) => { if (e.target === overlay) done(false); });
    document.addEventListener('keydown', onKey, true);
    document.body.append(overlay);
    (danger ? no : yes).focus();
  });
}

// ---------------------------------------------------------------- toasts
export function createToaster(root) {
  let timer = 0;
  function show(message, { action = null, ms = 0, bad = false } = {}) {
    clearTimeout(timer);
    root.replaceChildren();
    const t = el('div', 'toast-i' + (bad ? ' bad' : ''));
    t.append(el('span', '', message));
    if (action) {
      const b = button(action.label, 'toast-act', async () => { hide(); try { await action.run(); } catch (e) { show('Could not undo: ' + (e && e.message ? e.message : e), { bad: true, ms: 5000 }); } });
      t.append(b);
    }
    const x = iconButton('x', 'Dismiss', hide, 'toast-x');
    t.append(x);
    root.append(t);
    root.hidden = false;
    timer = setTimeout(hide, ms || (action ? 9000 : 4500));
  }
  function hide() { clearTimeout(timer); root.hidden = true; root.replaceChildren(); }
  return { show, hide };
}

// Friendly relative time from an ISO string or ms.
export function relTime(v, now = Date.now()) {
  const t = typeof v === 'number' ? v : Date.parse(v);
  if (!Number.isFinite(t)) return 'never';
  const s = Math.max(0, Math.round((now - t) / 1000));
  if (s < 45) return 'just now';
  if (s < 3600) return Math.round(s / 60) + ' min ago';
  if (s < 86400) return Math.round(s / 3600) + ' h ago';
  if (s < 86400 * 14) return Math.round(s / 86400) + ' d ago';
  return new Date(t).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

export function unavailableCard(what) {
  return emptyState(what + ' is not available on this version', 'This Shepherd does not have that part of the API yet. Update the server to use it. Everything else keeps working.');
}
