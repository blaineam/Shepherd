# Locked by default: demo data until you unlock

Planned. The portal never shows real data to someone who has not unlocked it.

## Behavior

- **Locked** is the default. Opening the portal shows the full interface running on **synthetic demo data**, generated in the browser. It makes no API calls for real data, so there is nothing to leak from a screen on a wall, a screen share or a passer-by. A clear "Locked, showing demo data" banner and an **Unlock** button are always visible.
- **Unlock** with the portal token, or with a passcode you choose (stored only as an Argon2id hash). Unlocking switches the interface to your real data and opens the live stream.
- **Idle relock.** After a period with no activity (default 10 minutes, configurable, 0 disables it) the portal locks itself: the session ends on the server, the live stream and polling stop, everything real is cleared from the page, and the interface falls back to demo data until you unlock it again.
- **Explicit lock.** A Lock button locks immediately.

## How it is enforced

The lock is enforced on the server, not just hidden in the page:

- Signing in creates a random session with a sliding idle timeout held on the server. The session cookie is `HttpOnly`, `SameSite=Strict` and never contains the token. An expired or ended session gets `401` from every data endpoint, so a copied page or a revived tab cannot read anything.
- The page also locks itself on idle and on losing the session, so the demo takes over immediately instead of showing stale real data.
- The bearer token still works for scripts and the command line, and is not affected by idle locking.
- Failed unlock attempts are slowed and rate limited.

## Settings

`portal.idle_lock_minutes` in the configuration (and the portal's settings screen) controls the idle time. A passcode can be set or cleared from the settings screen while unlocked.
