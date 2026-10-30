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

## Settings: auto-lock is optional

Auto-lock is on by default but you can change or turn it off, in the configuration or from the portal's settings screen (a change in the portal is saved and wins over the configuration file):

| Setting | Choices | Behavior |
|---|---|---|
| Auto-lock after idle | **Never**, 5, 10 (default), 30, 60 minutes, or a custom number | **Never** keeps you unlocked until you press Lock or sign out. |
| Passcode | none, or one you choose | Faster than pasting the token. Set or clear it while unlocked. |

```toml
[portal]
idle_lock_minutes = 10   # 0 = never auto-lock
```

With auto-lock off the session still ends if the server restarts, and a session cookie is never valid for more than 30 days.
The locked-by-default demo view still applies to anyone who has not unlocked: turning off auto-lock only stops the
portal from locking *you* out while you are using it.

Changing these settings needs an unlocked session, so someone looking at the demo view cannot turn the lock off.
