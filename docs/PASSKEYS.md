# Passkeys: unlock the portal with Face ID, Touch ID, a phone or a security key

Built, and **not yet tried with a real browser and a real authenticator.** Every automated test runs
against a software authenticator (see [What is verified](#what-is-verified-and-what-is-not)). Read
[Before you rely on this](#before-you-rely-on-this) before trusting it.

A passkey unlocks the portal with a biometric or a device PIN and nothing to type, using the WebAuthn
standard. It is the step [LOCKING.md](LOCKING.md) designed and deliberately deferred until the portal had a
real HTTPS hostname, which [`[tls]`](TLS.md) now gives it. The package is `internal/passkeys`; the API is
`internal/portal/api_passkeys.go`; the UI is a Passkeys card on the Locking screen and a **Sign in with a
passkey** button on the lock screen.

## What it does, and what it never does

- **Additive.** The token and the PIN keep working exactly as before. Nothing in the passkey code reads,
  changes or disables either; registering, renaming or removing a passkey cannot lock you out. Turning the
  PIN off leaves passkeys alone, and removing passkeys leaves the PIN alone.
- **Never the first way in.** A passkey can only be *added* from a session that is already unlocked with the
  token or the PIN. The lock screen's passkey sign-in has nothing to offer until one exists.
- **The same session as any other unlock.** A passkey sign-in opens exactly the session a token or PIN
  sign-in does: the same `shepherd_session` cookie, the same idle lock, the same 30-day cap, the same "every
  session ends at restart". There is no second kind of "unlocked".
- **Several passkeys.** Up to 20 at once (the same cap as PIN-trusted browsers): a phone, a laptop's Touch ID
  or Windows Hello, a hardware key. Each has a name you choose (renamable), when it was added and last used,
  and whether it is a synced passkey (iCloud Keychain, Google Password Manager, a password manager) or bound
  to one device. Remove any one individually; removing it also ends every session it opened, the way
  revoking a trusted browser does.
- **Order on the lock screen:** passkey (when available), then PIN, then token — the order
  [LOCKING.md](LOCKING.md) planned.

## Why a library, and which one

WebAuthn has enough cryptographic and protocol subtlety — client-data and origin checks, RP ID hashing,
CBOR attestation objects in several formats, COSE public keys, signature verification, the signature counter,
backup flags — that hand-rolling it for a security feature would be the wrong call. Shepherd uses
**[`github.com/go-webauthn/webauthn`](https://github.com/go-webauthn/webauthn) v0.18.2** (BSD-3-Clause; released
2026-09-19), the most widely used and actively maintained Go implementation. Every check that decides
whether a ceremony succeeds is the library's; `internal/passkeys` only configures it, stores what it returns,
and holds each ceremony's state.

This is a deliberate exception to the project's usual "no new dependencies" preference (compare
[TLS.md](TLS.md), which chose `golang.org/x/crypto/acme` over `lego` precisely to avoid one). It brings in:
`go-webauthn/x`, `fxamacker/cbor` (and `x448/float16`), `google/go-tpm` (TPM attestation), `google/uuid`,
`golang-jwt/jwt` (FIDO metadata statements), `go-viper/mapstructure`, `tinylib/msgp` (and `philhofer/fwd`) —
licenses in [THIRD-PARTY.md](THIRD-PARTY.md). Most of that serves attestation formats Shepherd never asks
for, but the library links them regardless; the `shepherd` binary grows by about 3 MB (roughly 21 MB to
25 MB on arm64 macOS).

## The relying party: one HTTPS hostname

A passkey is bound for life to a **relying party ID** (a hostname) and checked against the page's
**origin**. Shepherd uses:

| | Value |
|---|---|
| RP ID | `[tls].hostname`, lowercased, e.g. `shepherd.example.com` |
| Origins accepted | `https://shepherd.example.com:8443` (the port of `tls.listen`) and `https://shepherd.example.com` (the same name on 443, for a port mapping such as a container publishing 443 onto the listener's port; cookies are shared across ports by browsers anyway) |

With `tls.listen` on 443 there is only the one origin. A passkey registered here works only there: never at
the LAN IP, never over plain HTTP, never at another hostname — that is WebAuthn's design, not a Shepherd
choice.

### What happens when that is not where you are

Every ceremony is refused **before it starts**, with a sentence, whenever the browser could not complete it —
never a WebAuthn exception in the console halfway through:

| Where you are | Locking screen | Lock screen |
|---|---|---|
| `[tls]` off, or no hostname | Passkeys card says passkeys need `[tls]` with a hostname; **Add a passkey** disabled; `POST /api/passkeys/register/begin` answers 409 with the same message | No passkey button |
| The plain-HTTP portal (`http://<LAN IP>:8787`) with `[tls]` on | Card names both this page and `https://<hostname>:<port>`, with a link there (`#locking`); Add disabled; begin answers 409 with that message | No passkey button; `POST /api/login/passkey/begin` answers 409 *without* the hostname |
| The HTTPS listener but by IP (after clicking through the certificate warning) | Same as above | Same as above |
| `https://<hostname>:<port>` | Add enabled (if the browser supports WebAuthn) | Button shown once a passkey for this hostname exists |
| A browser without WebAuthn | "This browser does not support passkeys"; Add disabled | No passkey button |
| `http://localhost` on the Shepherd host itself | Refused like the plain-HTTP portal: browsers would allow WebAuthn on localhost, but a passkey made there would be for the RP ID `localhost` and useless at the real hostname, so Shepherd does not offer it | No passkey button |

The early refusal is a convenience; the binding that matters is the library checking the origin and the RP ID
hash the authenticator signed, which no request header can forge. A request is "at the right place" when it
arrived over TLS (`r.TLS` set) with a `Host` of the RP ID (any port).

**If `[tls].hostname` changes**, every existing passkey is bound to the old name and can never sign in again.
Each passkey records the RP ID it was registered for; after a change the old ones stay listed, flagged
("Registered for old.example.com, not new.example.com"), so you can remove them, but they are never offered
at sign-in. Register new ones at the new address.

**Not supported yet:** reaching the portal through `[reverseproxy]` (or any proxy) rather than `[tls]`'s own
listener. The portal then sees a plain-HTTP request and refuses, as above. That is the next step if the
portal ever moves behind the reverse proxy; it needs the portal to trust the proxy's forwarded scheme and
host, which it deliberately does not today.

## The ceremonies

**Registration** (`POST /api/passkeys/register/begin`, then `…/finish`, both needing an unlocked session and
the `X-Shepherd` header like every other change): the name and the 20-passkey cap are checked first, so a
ceremony that could not be saved never starts. The options ask for:

- **User verification required.** A passkey stands in for a PIN plus a trusted browser — two factors — so the
  authenticator must verify the person (biometric or device PIN), not merely that someone touched it. A
  hardware key with no PIN set will be asked to set one by the browser, or will fail.
- **No attestation** (`attestation: "none"`). Shepherd does not restrict authenticator makes, so it has no use
  for a vendor certificate.
- **Discoverable credentials preferred, not required**, so a hardware key without room for resident
  credentials still works.
- **Already-registered passkeys excluded**, so the same authenticator is not registered twice (and if a
  browser ignores that, the store refuses the duplicate anyway).
- The `credProps` extension, to learn whether the credential is discoverable. Extension outputs a browser or
  password manager adds unprompted are ignored rather than failing the ceremony, since no extension output
  feeds any decision here.

**Sign-in** (`POST /api/login/passkey/begin`, then `…/finish`, unauthenticated like the token and PIN
sign-ins): the options list the credential ids of every passkey registered for this hostname, with user
verification required. On success the library returns the credential's new signature counter and flags,
which are saved before the session is opened — if the save fails, the sign-in fails, since the next clone
check would otherwise be blind.

**Ceremony state** stays on the server: the challenge and the rest of the library's session data are held in
memory under a random id. The browser holds only that id, in a `shepherd_passkey` cookie (`HttpOnly`,
`Secure`, `SameSite=Strict`, path `/api/`, 5 minutes), so a ceremony can only be finished by the browser that
began it. Each ceremony is **single use** — any finish attempt consumes it, right or wrong — and **expires
after 5 minutes** (the timeout the browser is told, enforced both by Shepherd's clock and by the library's
own). At most 32 are pending; past that the oldest is dropped. A registration ceremony cannot finish a
sign-in or the other way round.

**Signature counter.** If an authenticator reports a counter at or below the stored one (when either is
non-zero), WebAuthn's signal that its key may have been cloned, the sign-in is **refused** and the counter is
left alone; remove that passkey and use the PIN or token. Synced passkeys (iCloud Keychain, Google Password
Manager) always report 0, which never trips this. The stored counter never moves backwards, even if two
sign-ins race.

**Failures** on the lock screen get a flat 400 ms delay and a generic "that passkey was not accepted" (or
"expired; try again", or the clone message). On the Locking screen, where the owner is already signed in, a
refused registration shows the library's own reason (for example "Error validating origin").

## What is stored

`<data_dir>/passkeys.json`, mode 0600, written atomically (temporary file, then rename) on every change and
only then made visible — the same convention as `reverseproxy.json` and `locking.json`. Nothing is written
until the first passkey is added. It holds:

- the owner's WebAuthn **user handle** (64 random bytes, created at the first registration; every passkey is
  bound to it);
- per passkey: a random id, its name, the RP ID it was made for, when it was added and last used, and the
  library's credential record as returned — credential id, **COSE public key**, signature counter, flags,
  AAGUID, transports and the registration's attestation data;
- the hash of the portal token it was written under.

None of it is secret: a passkey's **private key never leaves its authenticator**, so there is nothing here
that would let anyone sign in. The 0600 permission is the same discipline every other file Shepherd persists
gets, not a claim that the contents need hiding. Nothing passkey-related is ever logged.

- **Token rotation wipes every passkey**, on disk as well as in memory, at the first startup with the new
  token — the same rule as the PIN and trusted browsers ([LOCKING.md](LOCKING.md)). A suspected compromise is
  therefore recoverable by rotating `portal-token`.
- **A file that cannot be read** (corrupt, or from a future version) disables passkeys alone: every passkey
  route answers 503 naming the file, the lock screen hides the option, the file is never overwritten, and the
  token and PIN keep working. Fix or remove it and restart.
- **Removing a passkey in Shepherd** stops it signing in here; the passkey itself stays on the device or in the
  keychain until you delete it there too.

## API

| Route | Auth | What it does |
|---|---|---|
| `GET /api/login/passkey` | none | `{"available": bool}`: whether the lock screen should offer a passkey. True only at the HTTPS address with at least one passkey for this hostname. Never reveals the hostname or a count. |
| `POST /api/login/passkey/begin` | none | Options for `navigator.credentials.get`; sets the ceremony cookie. 409 when not available here. |
| `POST /api/login/passkey/finish` | none | Body: the assertion. On success, the session cookie, exactly like `POST /api/login`. 401 when refused. |
| `GET /api/passkeys` | session or token | `configured`, `here`, `problem` (why not, naming where to go), `rp_id`, `origin`, `max`, and the list (id, name, rp_id, created, last_used, synced). No key material. |
| `POST /api/passkeys/register/begin` | session or token | Body `{"name": "..."}` (≤64 characters, empty means "Passkey"). Options for `navigator.credentials.create`. 409 when not possible from here or at the cap, 400 for a bad name. |
| `POST /api/passkeys/register/finish` | session or token | Body: the attestation. 400 when refused (with the reason), 409 for a duplicate. |
| `PATCH /api/passkeys/{id}` | session or token | Body `{"name": "..."}`: rename. |
| `DELETE /api/passkeys/{id}` | session or token | Remove, and end the sessions it opened. |

Two things the unauthenticated routes do reveal, deliberately: whether passkey sign-in is available at the
HTTPS address, and, to anyone who can reach that address and calls `begin`, the credential ids of the
registered passkeys (WebAuthn's `allowCredentials`, which is what lets hardware keys without discoverable
credentials work). Credential ids are not secrets and cannot be used to sign in, but they do show how many
passkeys exist.

## What is verified, and what is not

**Verified by automated tests:**

- *The ceremonies, against a software authenticator.* `internal/passkeys/passkeystest` builds and signs real
  WebAuthn payloads — authenticator data, CBOR attestation objects, COSE ES256 keys, ECDSA P-256 signatures —
  the way go-webauthn's own `es256k_e2e_test.go` tests the library. Registration followed by sign-in
  succeeds, including a synced passkey with a counter stuck at 0 and the standard-port origin. Each of these
  is refused, **and checked to be refused by the specific check it targets** (the test asserts the library's
  reason, so a response failing for some incidental reason would not pass): the LAN IP over plain HTTP,
  `localhost`, another HTTPS origin, another RP ID, a different challenge, the wrong ceremony type, no user
  verification, a backed-up-but-not-eligible flag, a changed backup-eligible flag, someone else's user handle,
  the right credential id signed by the wrong key, an unregistered authenticator, a passkey revoked
  mid-ceremony, a replayed response (same ceremony and a fresh one), an expired ceremony, swapped ceremony
  kinds, a backwards counter (cloned key), and malformed bodies.
- *The HTTP API end to end over a real TLS listener* (`httptest.NewTLSServer`), with requests addressed to the
  RP hostname the way a browser at that origin sends them: register from a token session, lock, sign in with
  the passkey, idle relock of that session; refusal with the right message over plain HTTP and over HTTPS by
  IP; no hostname leaked to the unauthenticated plain-HTTP routes; registration needing an unlocked session;
  a finish from a different browser (no ceremony cookie); duplicate, cap, bad name and oversized bodies;
  rename and remove, with removal ending that passkey's sessions but not others; the PIN and token still
  working after a passkey is added and the PIN being turned off not touching passkeys; token rotation wiping
  passkeys; a corrupt `passkeys.json` disabling only passkeys and staying untouched; disk failures answering
  500 and never unlocking; passkeys from an earlier hostname listed but not offered.
- *The store:* 0600, atomic save with no stray temporary file, reload, a failed save leaving memory unchanged,
  corrupt/future/duplicate-id files refused, token rotation wiping on disk, the counter never moving backwards.
- *`cmd/shepherd`:* with `[tls]` on, the real `run()` hands its hostname and port to the portal, and
  `GET /api/passkeys` over the real HTTPS listener reports `here: true` while the plain-HTTP listener reports
  `here: false` and points at the right origin; with `[tls]` off, passkeys report unconfigured.
- *The frontend's pure logic* (`js/passkeys.js`, `node --test internal/portal/web/test/*.test.js`): base64url,
  decoding the server's options, serializing credentials, the early-refusal decisions and error wording. A
  shared fixture (`web/test/fixtures/passkeys.json`) of real server options and software-authenticator
  responses ties the two sides together: a Go test checks it still parses with go-webauthn's own parsers, and
  the JS test checks `registrationJSON`/`assertionJSON` turn the same bytes back into exactly the same bodies.
- *By hand, in a browser*, against a loopback-only scratch instance with `[tls]` off: the lock screen hides
  the passkey option; the Locking screen's card explains that `[tls]` is needed and disables **Add a passkey**;
  with the passkey list stubbed to "configured, wrong address", the card shows the message, the link to the
  right origin, stale and synced labels and the inline rename.

**Not verified — no automated test can reach these:**

- **No real browser has run `navigator.credentials.create()` or `.get()` against this code.** The browser's
  WebAuthn API, the platform's passkey UI and real authenticators cannot be driven by `go test` or
  `node --test`, and the software authenticator signs whatever it is asked to, producing only `none`
  attestation from an ES256 key. Real authenticators send other algorithms (RS256 from Windows Hello, EdDSA
  from some keys), other attestation formats even when none is requested, authenticator extension outputs
  (`credProtect` from some hardware keys), and browser- and password-manager-specific quirks. The library
  supports these; whether this configuration accepts every real combination is a claim until tried.
- **No real `[tls]` deployment** has served the passkey UI, so the exact origin a real browser reports through
  the real listener (and through any port mapping in front of it) is reasoned about, not observed.
- Hybrid sign-in (scanning a QR code with a phone to sign in on a laptop), iCloud Keychain / Google Password
  Manager sync across devices, a hardware key's own PIN prompt, and the lock screen's button layout at phone
  width have not been seen.

## Before you rely on this

This is the honest list. Do it once, at the real HTTPS address, before treating passkeys as a way in.

1. **Make sure the fallback works first.** Confirm you can unlock with the token (`shepherd -print-token`)
   and, if you use one, the PIN, on the device you are about to use. Passkeys never replace them; do not
   discard the token or forget the PIN because a passkey exists.
2. **Open the portal at `https://<tls.hostname>:<port>`**, not the LAN IP, and unlock with the token or PIN.
   The Locking screen's Passkeys card should have **Add a passkey** enabled. If it explains why not instead,
   that message is the fix (enable `[tls]`, or go to the address it names).
3. **Add one passkey on one device** and give it a name you will recognize.
4. **Verify it actually signs you in before assuming it works:** press **Lock**, then **Sign in with a
   passkey** on the lock screen, and check you land in the real, unlocked portal. The Locking screen should
   now show "last used" for it. A passkey that registered but never signed in is not yet proven.
5. **Repeat 3–4 for every kind of authenticator you intend to use** — a phone (including hybrid sign-in from a
   laptop, if you want that), a laptop's Touch ID or Windows Hello, a hardware key — since each behaves
   differently and none has been tried yet. Note any that fail and what the screen said.
6. **Try a removal:** remove one test passkey and confirm it no longer signs in (and that a session it had
   opened in another tab ends).
7. **Check the token and PIN again** after all of the above.
8. **Remember what changes the picture:** changing `[tls].hostname` orphans every passkey (re-register at the
   new name); rotating `portal-token` wipes them all; reaching the portal any way other than `[tls]`'s own
   listener (a reverse proxy, the LAN IP) offers no passkey sign-in at all.
9. **Anyone with an unlocked session can add a passkey**, just as they can set or change the PIN. Glance at
   the list now and then; remove anything you do not recognize, and rotate the token if you suspect a session
   was used by someone else.
