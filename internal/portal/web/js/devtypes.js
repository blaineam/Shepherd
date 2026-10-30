// Device type vocabulary. The server's types are free-form strings such as
// "tv", "game console", "smart-home hub" and "router/infrastructure"; anything
// unfamiliar still renders with a generic icon and its own text.
export const TYPES = ['phone', 'tablet', 'laptop', 'tv', 'speaker', 'camera', 'printer', 'game console', 'smart-home hub', 'router/infrastructure', 'unknown'];

const LABEL = { tv: 'TV' };
export function typeLabel(t) {
  const s = String(t || '').trim();
  if (!s) return 'Device';
  if (LABEL[s.toLowerCase()]) return LABEL[s.toLowerCase()];
  return (s.charAt(0).toUpperCase() + s.slice(1)).slice(0, 32);
}

const ICON_RULES = [
  [/router|infra|gateway|access point|switch/, 'router'],
  [/smart|hub|iot|sensor|thermostat|plug|bulb/, 'iot'],
  [/console|game/, 'console'],
  [/phone|mobile/, 'phone'],
  [/tablet|ipad/, 'tablet'],
  [/laptop|notebook|computer/, 'laptop'],
  [/desktop|pc\b/, 'desktop'],
  [/\btv\b|television|stream/, 'tv'],
  [/speaker|audio|soundbar/, 'speaker'],
  [/camera|cam\b|doorbell/, 'camera'],
  [/printer/, 'printer'],
  [/watch|wearable/, 'watch'],
];
export function typeIcon(t) {
  const s = String(t || '').toLowerCase();
  for (const [re, icon] of ICON_RULES) if (re.test(s)) return icon;
  return 'unknown';
}

export const normType = (s) => String(s || '').toLowerCase().replace(/[\s_\-/]+/g, '');

export const GROUP_COLORS = ['#16c7bd', '#6aa6f2', '#f0b64a', '#f2706b', '#a78bfa', '#6fcf97', '#f28bb8', '#8aa0ad'];
