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
