# Locked by default: demo data until you unlock

Built. The portal never shows real data to someone who has not unlocked it.

## Behavior

- **Locked** is the default. Opening the portal shows the full interface running on **synthetic demo data**, generated in the browser exactly like `/?demo=1` always has (see [PORTAL.md](PORTAL.md)). It makes no API calls for real data, so there is nothing to leak from a screen on a wall, a screen share or a passer-by. A "Locked" card sits over the demo view with **Unlock with PIN** and **Unlock with token** forms.
- **Unlock** with a PIN, once you have set one, or with the portal token. The very first unlock uses the token; right after it (when no PIN is set yet) the portal sends you straight to the Locking screen to set one, so you do not have to paste the long token again next time. Unlocking reloads the page into the real, authenticated view.
- **Idle relock.** After a period with no real activity (default 10 minutes, configurable, 0 disables it) the server-side session expires. The next request the page makes gets `401`, which bounces it back to the locked demo view, the same one shown on first visit.
- **Explicit lock.** A **Lock** button (next to the demo-data toggle, hidden while already showing demo data) ends the session immediately and locks.

## How it is enforced

The lock is enforced on the server, not just hidden in the page:

- Signing in (with the token or a PIN) creates a random session, held only in memory, with a sliding idle timeout. The session cookie (`shepherd_session`) holds only that random session id — never the token or the PIN — and is `HttpOnly`, `SameSite=Strict`. An expired or ended session gets `401` from every data endpoint, so a copied page or a revived tab cannot read anything. Even with auto-lock off, a session is never honored past 30 days, and every session ends when the server restarts.
- **Idle tracking distinguishes real activity from background polling.** The frontend polls `/api/status`, `/api/queries` and `/api/stream` automatically every few seconds just to keep the HUD live; if that alone reset the idle timer, idle locking would never trigger while a tab merely sat open. So those three endpoints check that the session is still within its idle window without extending it, while every other authenticated endpoint (viewing devices, searching history, changing a rule, opening Settings, and so on) both checks and extends it. See the comment above `authorized` in `internal/portal/portal.go`.
- The bearer token (`Authorization: Bearer <token>`) still works for scripts and the command line and is a stateless, constant-time comparison against the token — it is never affected by idle locking or sessions at all.
- Failed token and PIN unlocks are slowed down (currently a flat 400ms for the token; a growing delay, capped at 1.5s, per wrong PIN attempt).
- The frontend never builds its own notion of "locked": losing a session (or never having one) always shows the same locked, demo-backed view — first visit, idle relock and the Lock button all funnel through one `showLogin()` that reloads the page with `?demo=1&locked=1`, reusing the existing demo-mode code path instead of a second rendering path that could drift out of sync with it. A reload-based switch is also what the manual demo-data toggle already did, so this is the same trick, not a new one. One consequence: the very first visit briefly attempts the real view before bouncing into the locked one (a reload, not a visible flash in practice) — simpler than teaching every `if (DEMO)` branch in `app.js` to react to a mode change in place.

## PIN

A PIN is short, so it is only accepted together with something an attacker does not have:

- **Trusted browsers.** Setting a PIN (while unlocked) registers that browser as trusted: the server issues it a long random secret in an `HttpOnly`, `SameSite=Strict` cookie (`shepherd_trusted`, kept roughly 13 months) and records the device (its user-agent string as a name, created and last-used times — never the secret itself, only its hash). Unlocking with a PIN needs **both** that cookie and the PIN: someone who learns your PIN but is on a different browser gets nowhere, and a stolen trusted cookie alone is useless without the PIN. The PIN itself is shared across every trusted browser; changing it does not re-register browsers that are already trusted. There is a cap of 20 trusted browsers at once, so a leaked PIN cannot be ground against an unbounded number of registered devices to dodge one device's lockout.
- **Strength.** 6 to 12 letters and digits. Stored only as an Argon2id hash (time=3, 64 MiB memory, 1 thread — the same cost convention `internal/history` uses for its passphrase), never in plain text. Obviously guessable PINs (every character the same, or a simple ascending/descending run of digits such as `123456` or `654321`) are refused.
- **Lockout.** 5 wrong PINs in a row from one trusted browser lock that browser's PIN out for 15 minutes; the response is also slowed down a little more with each attempt. An attempt made during the lockout still counts (and still gets no PIN check at all, right or wrong, so the lockout cannot itself be used to probe the PIN) — it both extends the lockout and keeps moving the browser toward outright revocation at 10 wrong attempts total, when its trusted-device record is deleted and only the token (or a fresh PIN setup) unlocks that browser again.
- **Management.** The portal's **Locking** screen (a tab beside Details, hidden while viewing demo data since there is no real session to manage) lists trusted browsers with when each was added and last used, and lets you revoke any of them, or set, change or turn off the PIN. Turning the PIN off revokes every trusted browser at once, since a trusted cookie with no PIN to pair it with cannot unlock anything. Forgot the PIN? Unlock with the token and set a new one.
- **Token rotation.** The lock state file (`locking.json` in the data directory) records a hash of the token it was written under. If the portal starts with a different token than that hash matches — because `portal-token` was regenerated, for instance — every PIN and trusted browser is wiped at that startup, before anything can use them. Sessions do not need separate handling here: they are in-memory only and do not survive a restart regardless.

## Passkeys: designed, not built

Passkeys (Face ID, Touch ID, Windows Hello, a phone, or a hardware security key) would unlock the portal with a
biometric and nothing to type, using the WebAuthn standard. **This is out of scope for the locking work in this
change and is not implemented.** The reason is a hard platform requirement, not an oversight:

- Browsers only allow WebAuthn on a secure (HTTPS) page with a real hostname, or on `localhost` — never on a plain
  `http://` address or a bare LAN IP, which is how the portal is reached today. Shepherd has no HTTPS story yet; that
  is a separate, larger roadmap item (a reverse proxy / Cloudflare Tunnel in front of the portal — see
  [ROADMAP.md](ROADMAP.md), item 15) that has to land first.
- Once the portal has a stable HTTPS hostname to act as the passkey's relying-party ID, passkeys can be added the
  same way the PIN was here: a settings-screen registration flow, a credential store next to the trusted-device
  registry, and "Order of preference: passkey, then PIN on a trusted browser, then the token" ahead of the PIN at
  unlock time. Rotating the token should revoke passkeys the same way it revokes PINs and trusted browsers.

So this is a known, deliberate gap, not a forgotten one: do not build WebAuthn against the plain-HTTP portal.

## Settings: auto-lock is optional

Auto-lock is on by default but you can change or turn it off, in the configuration or from the portal's own **Locking** screen (a change made there is saved to `locking.json` and wins over the configuration file from then on; changing it needs an unlocked session, so someone looking at the demo view cannot turn the lock off):

| Setting | Choices | Behavior |
|---|---|---|
| Auto-lock after idle | **Never**, 5, 10 (default), 30, 60 minutes — plus whatever value is already saved, if it is not one of those | **Never** keeps you unlocked until you press Lock or sign out. |
| PIN | none, or one you choose | Faster than pasting the token, bound to trusted browsers. Set, change or clear it while unlocked. |
| Trusted browsers | however many are registered (up to 20) | Listed with when each was added and last used; revoke any of them individually. |

```toml
[portal]
listen = "127.0.0.1:8787"
idle_lock_minutes = 10   # 0 = never auto-lock
```

With auto-lock off the session still ends if the server restarts, and a session cookie is never valid for more than 30 days.
The locked-by-default demo view still applies to anyone who has not unlocked: turning off auto-lock only stops the
portal from locking *you* out while you are using it.
