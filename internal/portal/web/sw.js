// Shepherd's service worker: Web Push only. It caches nothing and intercepts
// no fetches; its one job is to show each pushed alarm as a notification
// and open the portal on the alarm when it is tapped. A push whose handler
// shows nothing gets the subscription revoked on iOS, so every push shows
// something, even a malformed one. Only same-origin paths from the payload
// are ever opened (docs/ALARMS.md, "Web Push in the browser").
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));

function parsePayload(event) {
  try {
    const p = event.data ? event.data.json() : {};
    return (p && typeof p === 'object') ? p : {};
  } catch {
    return {};
  }
}

function samePath(url) {
  const u = String(url || '');
  if (!u.startsWith('/') || u.startsWith('//')) return '/';
  return u;
}

self.addEventListener('push', (event) => {
  const p = parsePayload(event);
  const title = String(p.title || 'Shepherd');
  const options = {
    body: String(p.body || ''),
    tag: String(p.tag || p.id || ''),
    icon: 'icon.png',
    badge: 'icon.png',
    data: { url: samePath(p.url), id: String(p.id || ''), severity: String(p.severity || '') },
    renotify: false,
  };
  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const path = samePath(event.notification.data && event.notification.data.url);
  // The portal routes alarms as "/alarms/<id>" in payloads; the app itself
  // lives at one page with a hash route, so land on the Alarms screen.
  const target = new URL(path.startsWith('/alarms') ? '/#alarms' : path, self.location.origin).href;
  event.waitUntil((async () => {
    const all = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const c of all) {
      if (new URL(c.url).origin === self.location.origin && 'focus' in c) {
        await c.focus();
        if ('navigate' in c) { try { await c.navigate(target); } catch { /* keep the focused window */ } }
        return;
      }
    }
    if (self.clients.openWindow) await self.clients.openWindow(target);
  })());
});
