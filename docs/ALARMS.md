# Alarms

Every Shepherd feature reports problems through one engine, so a new device, a dead upstream and a
rejected list update all look, mute and notify the same way. The alarm system is three self-contained
Go packages that depend only on the standard library:

| Package | What it is |
|---|---|
| `internal/alarms` | The engine (model, dedupe, storm control, muting, quiet hours, learning mode, batch management, persistence) and the `Router` that delivers alarms. |
| `internal/webpush` | A Web Push sender: VAPID keys, RFC 8291 encryption, a subscription store. |
| `internal/ntfy` | A client for publishing to an ntfy server. |

This page describes what is built. The portal API, the portal UI, the service worker and mesh sync are
not built yet; the last section lists them. Design background is in [DESIGN.md](DESIGN.md) ("Alarm
system", "Mesh dataset sync"); the test approach is in [TESTING.md](TESTING.md).

## Delivery channels at a glance

- **Portal.** Every alarm is recorded and listed in the portal, whatever else happens.
- **Web Push** goes to every browser that subscribed. It is the primary phone channel.
- **ntfy** is the fallback: it is used when there are no push subscriptions, when every push attempt
  failed or the subscriptions are gone, and, if you turn on "always", in addition to Web Push.

The two outbound channels are independent. A failing ntfy server never delays Web Push, and a stuck push
service never delays an always-on ntfy message.

# Web Push (`internal/webpush`)

## What it speaks

- **RFC 8030**: the push protocol. One HTTPS `POST` to the subscription's endpoint with `TTL`,
  `Urgency` and `Topic` headers.
- **RFC 8291**: message encryption. ECDH on P-256, HKDF-SHA-256, AES-128-GCM, using the `aes128gcm`
  content coding of RFC 8188 (`Content-Encoding: aes128gcm`). One record, at most 4096 bytes in total, so
  the plaintext is capped at `webpush.MaxPayload` (3993 bytes). The encryption is tested against the
  RFC 8291 Appendix A test vector byte for byte, and fresh messages are decrypted by an independent
  receiver written from the RFC.
- **RFC 8292**: VAPID. An ES256 JWT in `Authorization: vapid t=<jwt>, k=<public key>`. The audience is
  the push service origin, and the expiry is never more than 24 hours ahead, because Apple's push
  service rejects longer lifetimes. The signature is the raw `r||s` pair JOSE requires, not DER.

It works with Apple (home-screen web apps on iOS 16.4 and later), Mozilla and
Google push services.

## VAPID keys

A VAPID key pair identifies the Shepherd instance to push services. Generate it once and keep it:
browsers subscribe against the public key, so replacing the pair invalidates every existing
subscription.

```go
keys, created, err := webpush.LoadOrCreateVAPIDKeys(filepath.Join(stateDir, "vapid.json"))
// keys.Public is the browser's applicationServerKey (base64url, 65 bytes decoded).
```

The file is JSON, mode 0600, written atomically (temp file, fsync, rename). A corrupt or mismatched file
is an error and is never silently replaced.

## Sending

```go
sender, err := webpush.NewSender(keys, "mailto:admin@example.com") // RFC 8292 contact
res := sender.Send(ctx, webpush.Subscription{Endpoint: ep, P256dh: p, Auth: a}, payload,
    webpush.Options{TTL: time.Hour, Urgency: webpush.UrgencyHigh, Topic: dedupeKey})
```

`Send` never retries and never panics; it classifies the answer in `Result.Outcome`:

| Outcome | Meaning | What to do |
|---|---|---|
| `OutcomeOK` | 200, 201 or 202. | Done. |
| `OutcomeGone` | 404 or 410. The subscription is dead. | Retire it (the `Broadcaster` does). |
| `OutcomeRejected` | Another 4xx, or a redirect (redirects are never followed). A 401 or 403 usually means the VAPID key changed. | Do not retry blindly. |
| `OutcomeTransient` | 429, 5xx, or a network error. | Retry later; `Result.RetryAfter` carries the `Retry-After` header. |
| `OutcomeTooLarge` | Over 4096 bytes locally, or a 413. | Shrink the payload. |
| `OutcomeInvalid` | Nothing was sent: bad endpoint, bad keys, bad VAPID key. | Fix the input. |

`Topic` is passed through `webpush.TopicFor`, so any string (an alarm's dedupe key) becomes a valid
RFC 8030 topic. A newer message with the same topic replaces an undelivered older one at the push
service.

## Subscriptions

`webpush.Store` keeps one record per browser: endpoint, `p256dh`, `auth`, a name, the user agent,
`last_ok`, `last_error`, a failure streak and the sync fields every Shepherd record carries (HLC stamp,
writer node, tombstone). The device ID is derived from the endpoint (`webpush.DeviceID`, the first 12
hex characters of its SHA-256), so a browser always gets the same ID and the ID reveals nothing usable.

```go
store := webpush.NewStore(webpush.StoreOptions{NodeID: node})
store.Load(path)                                  // missing file: errors.Is(err, os.ErrNotExist)
dev, err := store.Add(browserSub, "Alice's phone", userAgent) // the JSON from PushSubscription.toJSON()
store.List()      // safe views: no endpoint, no keys
store.Rename(id, "Tablet"); store.Remove(id)
store.Save(path)  // atomic, mode 0600, through the Codec
```

- Re-subscribing the same endpoint updates and revives it (browsers re-subscribe with fresh keys).
- A subscription the push service reports gone is **retired**: tombstoned with a reason, so the
  retirement replicates, and revived if the browser subscribes again.
- `Codec` has the same two methods as the one in `internal/devices` (`Encode` and `Decode`), so a single
  encryption codec can serve every store. The default stores plain JSON.
- At most 64 live subscriptions.

`webpush.Broadcaster{Store, Sender}.Broadcast(ctx, payload, opts)` sends to every live subscription
(four at a time), records `last_ok` or `last_error` on each, retires the gone ones and returns a
per-device `Report`.

## SSRF safety

A subscription endpoint is attacker-influenced input (any signed-in browser can post one), so a
malicious subscription must not make the server call an internal address.

- `webpush.ValidateEndpoint` (the default validator of the `Store` and the `Sender`) accepts only
  `https`, no credentials, port 443 or none, and refuses `localhost`, bare names, `.local`, `.internal`,
  `.lan`, `.home.arpa` and similar names, and IP literals that are private (RFC 1918, ULA), loopback,
  link-local, multicast, unspecified or in the CGNAT range (Tailscale addresses).
- `webpush.NewHTTPClient` repeats the check **at dial time** on the resolved address, so a public-looking
  name that resolves to an internal address is refused too, and it never follows redirects. The `Sender`
  also forces no-redirect on any client injected into it.
- Tests inject `webpush.AllowAnyEndpoint` and an `httptest` TLS client to reach loopback. Never use that
  override outside tests.
