// Web Push in the browser: whether this page can subscribe at all and why
// not, the key conversion the Push API wants, and the wording for the
// Notifications panel. Pure, so test/push.test.js can cover it without a
// browser; alarmsview.js does the DOM and the actual subscribe call.

// pushSupport says whether the Push API is usable here and, when not, the
// one reason that matters most. env mirrors what the view reads from the
// window: secureContext, hasServiceWorker, hasPushManager, hasNotification,
// standalone (an iOS home-screen web app), and ios.
export function pushSupport(env) {
  const e = env || {};
  if (!e.secureContext) return { ok: false, reason: 'Notifications need the HTTPS portal. Open Shepherd at its https:// address (see docs/TLS.md) and subscribe there.' };
  if (e.ios && !e.standalone) return { ok: false, reason: 'On an iPhone or iPad, add Shepherd to the Home Screen (Share, then Add to Home Screen) and open it from there; Safari only delivers notifications to a home-screen web app.' };
  if (!e.hasServiceWorker || !e.hasPushManager || !e.hasNotification) return { ok: false, reason: 'This browser does not support Web Push.' };
  return { ok: true, reason: '' };
}

// permissionLine words the Notification permission state.
export function permissionLine(permission) {
  switch (permission) {
    case 'granted': return { tone: 'good', text: 'This browser allows notifications.' };
    case 'denied': return { tone: 'bad', text: 'This browser has blocked notifications for Shepherd. Allow them in the browser\'s site settings, then try again.' };
    default: return { tone: 'muted', text: 'This browser has not been asked for permission yet.' };
  }
}

// urlBase64ToUint8Array turns the VAPID public key (base64url, as the
// server hands it out) into the bytes PushManager.subscribe wants.
export function urlBase64ToUint8Array(b64) {
  const s = String(b64 || '').replace(/-/g, '+').replace(/_/g, '/');
  const padded = s + '='.repeat((4 - (s.length % 4)) % 4);
  const raw = typeof atob === 'function' ? atob(padded) : Buffer.from(padded, 'base64').toString('binary');
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

// subscribeBody is what the server's subscribe endpoint takes: the
// PushSubscription's own JSON and the owner's name for this browser.
export function subscribeBody(subscriptionJSON, name) {
  const sub = subscriptionJSON || {};
  return { subscription: { endpoint: String(sub.endpoint || ''), keys: { p256dh: String((sub.keys || {}).p256dh || ''), auth: String((sub.keys || {}).auth || '') } }, name: String(name || '').trim().slice(0, 60) };
}

// defaultDeviceName guesses a label for this browser from its user agent.
export function defaultDeviceName(ua) {
  const u = String(ua || '');
  if (/iPhone/.test(u)) return 'iPhone';
  if (/iPad/.test(u)) return 'iPad';
  if (/Android/.test(u)) return 'Android phone';
  if (/Macintosh/.test(u)) return 'Mac';
  if (/Windows/.test(u)) return 'Windows PC';
  if (/Linux/.test(u)) return 'Linux PC';
  return 'This browser';
}

// deviceLine is one subscribed browser's status, for the list.
export function deviceLine(d, now = Date.now()) {
  const dev = d || {};
  const name = dev.name || dev.user_agent || dev.id || 'A browser';
  if (dev.last_error) return { name, tone: 'warn', text: 'Last push failed: ' + dev.last_error + (dev.failures > 1 ? ' (' + dev.failures + ' in a row)' : '') };
  const ok = dev.last_ok ? Date.parse(dev.last_ok) : NaN;
  if (Number.isFinite(ok)) {
    const mins = Math.max(0, Math.round((now - ok) / 60000));
    return { name, tone: 'good', text: 'Last delivered ' + (mins < 1 ? 'just now' : mins < 60 ? mins + ' min ago' : mins < 1440 ? Math.round(mins / 60) + ' h ago' : Math.round(mins / 1440) + ' d ago') + (dev.service ? ' via ' + dev.service : '') };
  }
  return { name, tone: 'muted', text: 'Subscribed; nothing delivered yet' + (dev.service ? ' (via ' + dev.service + ')' : '') };
}

// isThisBrowser matches a listed device to this browser's subscription by
// the server's stable ID rule: the first 12 hex characters of SHA-256 of
// the endpoint. The server computes it; the view passes the ID it was
// given at subscribe time.
export const isThisBrowser = (d, thisID) => !!thisID && d && d.id === thisID;

// ------------------------------------------------------------------ ntfy
// ntfy delivers alarms to a phone app without Web Push, which is how a
// phone in Lockdown Mode or one that cannot reach the HTTPS portal gets
// them. It is configured in shepherd.toml, so this is the walk-through the
// Alarms screen shows, plus the one line saying where it stands.

export const NTFY_DEFAULT_SERVER = 'https://ntfy.sh';

// suggestTopic makes a topic nobody will guess. On a public ntfy server
// anyone who knows the name can read it, so it ends in random letters.
// bytes is any array of byte values (crypto.getRandomValues in the view).
export function suggestTopic(bytes) {
  const alphabet = 'abcdefghijkmnpqrstuvwxyz23456789';
  let s = '';
  for (const b of bytes || []) s += alphabet[(Number(b) || 0) % alphabet.length];
  return 'shepherd-' + (s || 'alarms');
}

// ntfyStatusLine says whether ntfy is set up, switched off, or delivering.
export function ntfyStatusLine(ntfy) {
  const n = ntfy || {};
  if (!n.configured && !n.server) return { tone: 'muted', text: 'ntfy is not set up. Fill in the server and topic below.' };
  const where = (n.server || '') + (n.topic ? ' / ' + n.topic : '');
  if (!n.enabled) return { tone: 'warn', text: 'ntfy is set up for ' + where + ' but switched off, so no alarms are published to it.' };
  return { tone: 'good', text: 'ntfy is on and publishing alarms to ' + where + '. Subscribe to that topic in the ntfy app, then send a test notification.' };
}

// ntfyFields is what the form shows for a stored (or empty) ntfy document:
// the values to prefill, and placeholders that say when a credential is
// already stored without ever carrying it. The API never sends a saved
// token or password back, so "leave blank to keep it" is the only honest
// thing the form can say.
export function ntfyFields(ntfy, suggested) {
  const n = ntfy || {};
  return {
    server: n.server || NTFY_DEFAULT_SERVER,
    topic: n.topic || suggested || 'shepherd-alarms',
    username: n.username || '',
    tokenPlaceholder: n.has_token ? 'a token is stored; leave blank to keep it' : 'only for a server that needs a login',
    passwordPlaceholder: n.has_password ? 'a password is stored; leave blank to keep it' : '',
    enabled: n.enabled !== false,
  };
}

// ntfySaveBody is the PUT body for what was typed. A blank credential means
// "keep what is stored", which the server honours only for the same server,
// so moving to another server always asks for it again.
export function ntfySaveBody(form, ntfy) {
  const n = ntfy || {};
  const body = {
    server: (form.server || '').trim(),
    topic: (form.topic || '').trim(),
    username: (form.username || '').trim(),
    enabled: form.enabled !== false,
  };
  const token = (form.token || '').trim();
  if (token) body.token = token;
  else if (n.has_token && form.clearToken) body.clear_token = true;
  const password = form.password || '';
  if (password) body.password = password;
  else if (n.has_password && form.clearPassword) body.clear_password = true;
  return body;
}

// NTFY_STEPS is what the owner does on their phone. Shepherd's own side is
// the form below them, not a file to edit: no feature of Shepherd should
// need shepherd.toml opened.
export const NTFY_STEPS = [
  'Install the ntfy app on your phone (App Store or Google Play), or open the ntfy web app. The free public server at ntfy.sh works with no account; you can also run your own.',
  'In the app, tap + and subscribe to the topic below. Pick one nobody can guess: on a public server anyone who knows the topic can read it.',
  'Press Save. Shepherd publishes one notification straight away to prove it works; it should arrive within a few seconds.',
];
