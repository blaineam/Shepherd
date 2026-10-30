# Locked by default: demo data until you unlock

Planned. The portal never shows real data to someone who has not unlocked it.

## Behavior

- **Locked** is the default. Opening the portal shows the full interface running on **synthetic demo data**, generated in the browser. It makes no API calls for real data, so there is nothing to leak from a screen on a wall, a screen share or a passer-by. A clear "Locked, showing demo data" banner and an **Unlock** button are always visible.
- **Unlock** with a PIN, once you have set one, or with the portal token. The very first unlock uses the token; right after it Shepherd offers to set a PIN for that browser so you never have to paste the long token again. Unlocking switches the interface to your real data and opens the live stream.
- **Idle relock.** After a period with no activity (default 10 minutes, configurable, 0 disables it) the portal locks itself: the session ends on the server, the live stream and polling stop, everything real is cleared from the page, and the interface falls back to demo data until you unlock it again.
- **Explicit lock.** A Lock button locks immediately.

## How it is enforced

The lock is enforced on the server, not just hidden in the page:

- Signing in creates a random session with a sliding idle timeout held on the server. The session cookie is `HttpOnly`, `SameSite=Strict` and never contains the token. An expired or ended session gets `401` from every data endpoint, so a copied page or a revived tab cannot read anything.
- The page also locks itself on idle and on losing the session, so the demo takes over immediately instead of showing stale real data.
- The bearer token still works for scripts and the command line, and is not affected by idle locking.
- Failed unlock attempts are slowed and rate limited.

## PIN

A PIN is short, so it is only accepted together with something an attacker does not have:

- **Trusted browsers.** Setting a PIN (while unlocked with the token) registers that browser as a trusted device: the server issues it a long random secret in an `HttpOnly`, `SameSite=Strict` cookie and records the device (name, browser, created, last used). Unlocking needs **both** that cookie and the PIN. Someone who guesses or watches your PIN but is on another computer gets nowhere.
- **Strength.** 6 to 12 digits (letters allowed). Stored only as an Argon2id hash, never in plain text. Obvious PINs (all the same digit, runs such as 123456) are refused.
- **Lockout.** Wrong PINs are slowed down, and 5 wrong tries in a row lock that browser's PIN for 15 minutes with growing delays. After 10 the trusted-device record is revoked and only the token can unlock again. There is also a global limit across all browsers, so many devices cannot be used to share the guesses.
- **Management.** Settings lists trusted browsers (with last used) and lets you remove any of them, change the PIN, or turn the PIN off. Forgot the PIN? Unlock with the token and set a new one. Changing the token's secret (rotating it) revokes every trusted browser.
- **Later.** Passkeys (Face ID, Touch ID, a security key) through WebAuthn would replace the PIN with a biometric on devices that support it.

## Settings: auto-lock is optional

Auto-lock is on by default but you can change or turn it off, in the configuration or from the portal's settings screen (a change in the portal is saved and wins over the configuration file):

| Setting | Choices | Behavior |
|---|---|---|
| Auto-lock after idle | **Never**, 5, 10 (default), 30, 60 minutes, or a custom number | **Never** keeps you unlocked until you press Lock or sign out. |
| PIN | none, or one you choose | Faster than pasting the token, bound to trusted browsers. Set, change or clear it while unlocked. |

```toml
[portal]
idle_lock_minutes = 10   # 0 = never auto-lock
```

With auto-lock off the session still ends if the server restarts, and a session cookie is never valid for more than 30 days.
The locked-by-default demo view still applies to anyone who has not unlocked: turning off auto-lock only stops the
portal from locking *you* out while you are using it.

Changing these settings needs an unlocked session, so someone looking at the demo view cannot turn the lock off.
