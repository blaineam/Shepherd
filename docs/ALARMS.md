# Alarms

Every Shepherd feature reports problems through one engine, so a new device, a dead upstream and a
rejected list update all look, mute and notify the same way. The alarm system is three self-contained
Go packages that depend only on the standard library:

| Package | What it is |
|---|---|
| `internal/alarms` | The engine (model, dedupe, storm control, muting, quiet hours, learning mode, batch management, persistence) and the `Router` that delivers alarms. |
| `internal/webpush` | A Web Push sender: VAPID keys, RFC 8291 encryption, a subscription store. |
| `internal/ntfy` | A client for publishing to an ntfy server. |

This page describes what is built. `cmd/shepherd` wiring, the portal API and the portal's Alarms tab are
now built too (see "Wiring into `cmd/shepherd` and the portal" below); the service worker, Web Push
subscribe UI and mesh sync are not built yet — the last section lists them. Design background is in
[DESIGN.md](DESIGN.md) ("Alarm system", "Mesh dataset sync"); the test approach is in
[TESTING.md](TESTING.md).

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

# ntfy (`internal/ntfy`)

ntfy is a simple publish-subscribe notification service with phone apps. It is
Shepherd's fallback channel and can run self-hosted on the LAN or the tailnet.

```go
c := &ntfy.Client{Server: "https://ntfy.example.com", Token: token} // or Username and Password
res, err := c.Publish(ctx, ntfy.Message{
    Topic: "shepherd-alarms", Title: "New device", Body: "A device joined.",
    Priority: ntfy.PriorityHigh, Tags: []string{"rotating_light"},
    Click: "https://shepherd.example.com/alarms/a1",
    Actions: []ntfy.Action{{Kind: "view", Label: "Open", URL: "https://shepherd.example.com/alarms/a1"}},
})
```

- The message is the request body of a `POST` to `{server}/{topic}`; `Title`, `Priority`, `Tags`, `Click`
  and `Actions` are headers. A server URL with a path prefix works (`https://host/ntfy`).
- `Authorization` is a bearer token, or basic auth when only a username and password are set.
- **Header injection safety.** Every value that becomes a header (title, tags, click URL, action label
  and URL, token, username, password) is rejected if it contains a control character, CR and LF
  included. Non-ASCII text is sent RFC 2047 encoded, which ntfy decodes. Topics are 1 to 64 letters,
  digits, `-` or `_`. Click and action URLs must be `http(s)`. Bodies over 4096 bytes are cut on a rune
  boundary.
- **Severity mapping:** `ntfy.PriorityFor` maps `info`, `low`, `medium`, `high`, `critical` to `min`,
  `low`, `default`, `high`, `urgent`. `ntfy.TagsFor` adds emoji short codes: `information_source`,
  `white_check_mark`, `warning`, `rotating_light`, and `rotating_light` plus `skull` for critical.
- **Errors** are `*ntfy.Error` with a `Kind` (invalid, auth, not-found, too-large, rate-limited, server,
  network, rejected), the HTTP status and `RetryAfter`; `ntfy.IsRetryable(err)` is true for rate limits,
  5xx and network failures. Network errors never include the URL. A publish times out after 10 seconds
  by default.
- The server URL is operator configuration, so unlike Web Push this client does not refuse private
  addresses: a self-hosted ntfy normally lives on one.

# The engine (`internal/alarms`)

## Model

An `Alarm` has: `ID`, `Type`, `Severity`, `Title`, `Body`, `Key` (the dedupe key), `Source`, `DeviceID`,
`DeviceClass`, `GroupIDs`, `Domain`, `Evidence` (a list of label and value pairs), `URL` (the portal route to
open, defaulting to `/alarms/<id>`), `State`, `FirstSeen`, `LastSeen`, `Count`, `AckedAt`, `ResolvedAt`,
`MutedBy` (a rule ID, or `snooze`), `MutedUntil`, `Learning`, `Bundle` and `ParentID`, plus the
sync-ready fields of the device registry: an HLC stamp (`Updated`), the writing `Node` and a `Deleted`
tombstone.

**Severities**, lowest first: `info`, `low`, `medium`, `high`, `critical`.

**States:** `new` (the unread state, what badges count), `acknowledged` (seen), `muted` (recorded but never
notified) and `resolved` (closed; a resolved alarm fires again, as a new alarm, the next time its key is
raised).

Alarms are values: the engine returns copies.

## Alarm types

Types are a registry. Each has a title, a description, a default severity, default channels and a flag
saying whether learning mode suppresses it. Third parties add types with `Engine.Register` (a type ID is
never silently replaced, and the built-in IDs cannot be reused). An unregistered type ID still works: the
alarm is recorded at medium severity on all channels, so a typo never loses an alarm.

| Type | Default severity | Channels | Learning suppresses |
|---|---|---|---|
| `new-device` | high | portal, push, ntfy | yes (install period only) |
| `device-left` | low | portal | yes (install period only) |
| `upstream-down` | high | all | no |
| `upstream-recovered` | low | all | no |
| `list-update-rejected` | medium | all | no |
| `history-locked` | medium | all | no |
| `history-error` | medium | all | no |
| `map-data-failed` | low | portal | no |
| `dns-error-spike` | medium | all | yes (install and device) |
| `blocked-spike` | low | portal | yes (install and device) |
| `private-relay-attempt` | info | portal | no |
| `port-opened` (ports feature, future) | high | all | yes (install and device) |
| `new-inbound-exposure` (future) | critical | all | no |
| `threat-match` (future) | critical | all | no |
| `self-update` (future) | low | all | no |
| `vulnerability-found` (internal/vulnscan) | high (the finding's own severity overrides this per event) | all | no |
| `test` | high | all | no, and it **bypasses** mute rules, quiet hours and learning mode |

"Install and device" means the type is also suppressed for a device that was first seen recently (see
Learning mode). `new-device` is deliberately install-only: a per-device period would silence the very alarm
that announces the device.

## Raising alarms

```go
eng.Raise(alarms.Event{
    Type: alarms.TypeNewDevice, DeviceID: id, DeviceClass: "camera",
    Title: "New device: Camera", Key: "new-device|" + id + "|",
    Evidence: []alarms.Evidence{{Label: "Address", Value: "192.0.2.10"}},
})
```

`Raise` is the single entry point and never blocks: it queues the event for a worker and returns whether it
was queued. When the queue (default 1024) is full the event is dropped and counted (`Engine.Dropped()`, also in
`Summary.Dropped`), so it is safe on the DNS hot path. `RaiseSync` processes on the caller's goroutine and
returns the resulting alarm (use it for "send a test notification"); `Drain` waits for the queue to empty.
Titles, bodies, evidence and URLs are length-bounded, and an `Event.URL` that is not a same-site path
starting with `/` is replaced by the default.

## Dedupe and storm control

**Dedupe.** An event whose `Key` matches an open (not resolved) alarm that was last seen within the dedupe
window (default 1 hour) folds into it: `Count` and `LastSeen` increase, the body and evidence are refreshed,
and **nobody is notified again**. The window is measured from the last sighting, so a steady trickle stays
one alarm. Two things let an alarm fire again: resolving it, or a quiet gap longer than the window. The one
exception is escalation: a repeat with a higher severity raises the alarm's severity, returns it to `new` if it
was acknowledged, and notifies once. The default key is `<type>|<device>|<domain>`. End your own keys with a
delimiter if prefix muting must not catch longer keys.

**Storm control.** More than a threshold (default 5) of new alarms of one type for one device within a window
(default 1 minute) collapse into a **bundle**. The bundle is one alarm titled, for example, `47 similar
alerts: Blocked-query spike`; it carries the highest severity of its members and notifies once, when it forms.
Further events absorb into it (it keeps counting), the earlier members stay recorded as its children
(`ParentID`, `Engine.Children`) and are hidden from lists and counts while the bundle exists, and acting on the
bundle (acknowledge, resolve, mute, delete) acts on its members. A quiet gap, or resolving the bundle, ends
the storm. A burst therefore produces at most threshold plus one notifications. This is checked with
property-style tests over random bursts: no event is lost (counts of visible alarms add up) and notifications
stay bounded.

## Muting

**Rules.** A mute rule matches by device, group, type, domain or key prefix. Within a field the entries are
alternatives; every non-empty field must match; a rule needs at least one field. Domains match exactly or as a
parent (`example.com` matches `ads.example.com`). Alarms matching an active rule are recorded with state
`muted` and `MutedBy` set to the rule, and are never notified. Creating a rule also mutes matching alarms that
are still new. A rule lasts for a duration:

| Preset | Ends |
|---|---|
| `1h` | One hour from now. |
| `tomorrow` | The next time the wall clock reads the morning hour (default 08:00) in the household's time zone: 23:30 mutes until 08:00 the next day, 02:00 until 08:00 the same day. |
| `days` + `Days` | That many calendar days from now, same wall-clock time (DST-safe). |
| `forever` | Never. |
| `until` + `Until` | A specific time. |

An expired rule stops applying at its boundary; the next sweep (every 30 seconds, or `Tick`) returns the
alarms it muted to `new`. If such an alarm was still being seen, channels are told once ("the mute ended on a
live problem").

**Snooze.** `Engine.Snooze(id, spec)` mutes one alarm without a rule. Repeats stay quiet; it returns to `new`
when the snooze ends.

**Quiet hours.** Global windows in `Preferences.Quiet`: `Start` and `End` as `HH:MM` in the preferences' time
zone (End before Start wraps midnight, `22:00` to `07:00`), optional `Days` (weekdays on which the window
starts), and `Allow`, the lowest severity that still gets through (default `critical`; empty lets nothing
through). Quiet hours do not mute: the alarm stays `new` and is recorded, and its notification is **held**
until the window ends and then delivered with the digest. A digest that falls due inside a window waits for it
too.

```go
p := eng.Preferences()
p.Timezone = "America/Chicago"
p.Quiet = alarms.QuietPref{Enabled: true, Windows: []alarms.QuietWindow{
    {Start: "22:00", End: "07:00", Allow: alarms.SeverityCritical},
    {Start: "09:00", End: "17:00", Days: []int{1, 2, 3, 4, 5}, Allow: alarms.SeverityHigh}, // weekdays
}}
err := eng.SetPreferences(p)
```

**Learning mode.** For a configurable period after install (default 72 hours) alarms of types flagged
"learning suppresses" are recorded as `info` (`RawSeverity` keeps the real one, `Learning` is set) and not
notified, while baselines form. Types flagged for device learning are also suppressed for a device for a
period (default 24 hours) after it was first seen (`Raise` notes devices; `NoteDeviceSeen` lets the registry
tell the engine earlier). Mute rules win over learning; the `test` type ignores both. `LearningUntil()` tells
the UI when learning ends.

Order of decisions for a new alarm: bypass type, then mute rule, then learning mode, then quiet hours, then
notify.

## Batch management

All batch calls take a `Selector`: explicit `IDs`, a `Filter`, or both (an alarm must be in the IDs and match
the filter), or `All`. An empty selector is an error, never "everything". They return a `BatchResult` with
`Matched`, `Changed`, `Skipped` (unknown IDs), the IDs of any `Rules` created and an undo `Handle`.

```go
// Acknowledge everything that is new and medium or lower.
res, _ := eng.Acknowledge(alarms.Selector{Filter: &alarms.Filter{
    States: []alarms.State{alarms.StateNew}, Severities: []alarms.Severity{alarms.SeverityLow, alarms.SeverityMedium}}})

// Mute these alarms' type and device pair for a week, then undo.
res, _ = eng.Mute(alarms.Selector{IDs: ids}, alarms.MuteRequest{
    By: alarms.MuteByTypeDevice, Duration: alarms.MuteSpec{Preset: alarms.MuteDays, Days: 7}})
eng.Undo(res.Handle)
```

- `Acknowledge`: new alarms become acknowledged. `Resolve`: closes alarms of any open state.
- `Mute` builds rules from the selection by `MuteBy`: `alarm` (snooze each, no rule), `key` (one rule per
  key), `type`, `device`, `type+device` (one rule per pair), or `domain`. It mutes the other new alarms the
  rules match as well, and returns `ErrNothingToMute` when the selection has nothing to build a rule from
  (a device mute over alarms with no device).
- `Delete` tombstones (so the deletion replicates); retention purges them later. It cannot be undone.
- `Undo(handle)` reverses an acknowledge, resolve, mute, snooze or `CreateRule`. It removes created rules and
  restores each alarm's previous state, but leaves alone any alarm changed again since (counted in
  `Skipped`). A handle works once and lives for 10 minutes (the last 50 are kept).
- Filters match `Types`, `Severities` or `MinSeverity`, `States`, `DeviceID`, `GroupID`, a `Since`/`Until`
  time range (alarms whose first-to-last sighting overlaps it) and `Text` (case-insensitive over title, body,
  key, source, domain, device, type and evidence).
- `List(Query)` filters, sorts (`last_seen` default, `first_seen`, `severity`, `count`, `title`; newest or
  highest first unless `Asc`), and pages (`Offset`, `Limit` default 50, at most 500) with a stable order.
  `Summary()` returns counts by state, counts by severity of the new alarms (the badge numbers), the highest
  new severity, the active rule count and the drop counter in one call.
- Large batches (over 100 alarms) emit one `ChangeBulk` instead of one change per alarm.

## Delivery

`NewRouter` consumes the engine's change stream (`eng.Subscribe(rt.Handle)`) and delivers alarms the engine
decided to notify about.

**Which alarms go where.** A type that is switched off (`Preferences.Types[id].Off`, or `OffForClasses` for the
alarm's device class) is not delivered. Otherwise a channel carries the alarm when it is enabled, listed in
the type's channels (overridable per type) and the alarm's severity is at least the channel's minimum.

**When.** Severity at or above `ImmediateMin` (default `high`) is delivered at once. Lower severities go into
a digest (when enabled): one summary notification sent `Every` (default 6 hours) after its first alarm was
queued, or at a set time of day (`Digest.At`, in the preferences' time zone). A digest with one alarm is sent
as that alarm. Alarms held by quiet hours are delivered when the window ends. With the digest off, everything
is immediate.

**Fallback.** Per alarm: Web Push is tried first, to every subscribed device. ntfy is used instead when push
could not deliver:

| Push result | ntfy |
|---|---|
| Delivered to at least one device | not used |
| No subscriptions | sends |
| Every subscription gone (404/410, retired) | sends |
| Every attempt failed or errored | sends at once; push keeps retrying |
| Push not applicable (disabled, or below its minimum) | sends if it passes its own minimum |
| `NtfyAlways` on | sends **in addition**, independently of push |

**Retries.** A failed delivery is retried with backoff (30 seconds, 2 minutes, 10 minutes by default), then
recorded as `failed`. A permanent error (gone endpoints, bad ntfy credentials) is not retried. A retry resends
the same notification; devices collapse repeats by the notification tag (the dedupe key).

**Delivery log.** `Router.Log(channel, limit)` returns per-delivery records (status `ok`, `retrying`,
`failed`, `skipped`; attempts; error; detail such as `2 of 3 delivered, 1 gone`), updated in place across
retries and bounded (500 records, 14 days). `Router.Status()` returns, per channel, whether it is configured,
`LastOK`, `LastError`, `LastErrorAt` and counts: show the error when `LastErrorAt` is after `LastOK`.

**Payload.** Web Push gets `{title, body, url, tag, severity, id}` as JSON, well under 1 KB (text is bounded
and control characters are stripped), with `tag` set to the dedupe key and `url` a portal path. ntfy gets the
same title and body, a priority and tags from the severity, and `Click` set to `PortalURL` plus the route when
`Preferences.PortalURL` is set.

## Preferences

`Preferences` (JSON, durations as strings like `"6h"`) holds the per-channel `Enabled` and `MinSeverity`
(defaults: push and ntfy both on, `low` and above), `NtfyAlways`, `ImmediateMin`, `Digest`, `Quiet`,
`Learning`, per-type switches (`Types`), `Timezone` (an IANA name, `UTC`, or empty for the server's local
zone), `MorningHour` and `PortalURL`. `Validate` rejects bad values, so `SetPreferences` never stores a bad
setting. A container image without time zone data must import `time/tzdata` to use named zones.

## Persistence

With `Options.Dir` set, the engine keeps `alarms.json` (alarms and rules, tombstones included),
`alarm-prefs.json` (preferences, the install time and the device first-seen times) and, with
`RouterOptions.Path`, `deliveries.json` (the log, channel status, pending retries and the digest queue). Files
are JSON, written atomically with mode 0600 through a `Codec` (same interface as the device registry, so
encryption can be plugged in), loaded on start and saved at most every 5 seconds and on `Close`. A corrupt or
unsupported file stops startup with an error; it is never silently discarded. Retention is bounded: resolved,
acknowledged and muted alarms last 30 days, new ones twice that, the store is capped at 5000 alarms (resolved
go first), tombstones are purged after 30 days, the delivery log keeps 500 records.

Records carry HLC stamps, so `Export` and `Import` already merge by last-writer-wins and converge in any
order (property-tested); imports are silent so a synced replica does not re-announce.

## Go API for wiring

```go
// Engine
eng, err := alarms.New(alarms.Options{Dir: stateDir, Node: nodeID /* Codec, Clock, Queue, DedupeWindow, ... */})
defer eng.Close()
eng.Raise(ev) bool;  eng.RaiseSync(ev) (Alarm, error);  eng.Drain();  eng.Dropped() uint64
eng.Subscribe(func(alarms.Change)) (unsubscribe func());  eng.Events(buffer) (<-chan Change, cancel func())
eng.List(Query) Page;  eng.Get(id);  eng.Children(id);  eng.Summary() Summary
eng.Acknowledge / Resolve / Delete(Selector) (BatchResult, error)
eng.Mute(Selector, MuteRequest);  eng.Snooze(id, MuteSpec);  eng.Undo(handle)
eng.CreateRule(RuleSpec);  eng.ListRules(includeInactive);  eng.RemoveRule(id)
eng.Preferences();  eng.SetPreferences(p);  eng.LearningUntil();  eng.NoteDeviceSeen(id, at)
eng.Register(AlarmType);  eng.Types();  eng.Type(id)
eng.Export() Snapshot;  eng.Import(Snapshot) int;  eng.Save() error;  eng.Prune() PruneResult;  eng.Tick()

// Delivery
store := webpush.NewStore(webpush.StoreOptions{NodeID: nodeID});  store.Load(path)
keys, _, _ := webpush.LoadOrCreateVAPIDKeys(vapidPath)
sender, _ := webpush.NewSender(keys, "mailto:admin@example.com")
push := alarms.NewWebPushPusher(&webpush.Broadcaster{Store: store, Sender: sender})
nt := alarms.NewNtfyPublisher(&ntfy.Client{Server: url, Token: tok}, "shepherd-alarms")
rt := alarms.NewRouter(alarms.RouterOptions{Source: eng, Pusher: push, Ntfy: nt, Path: alarms.DefaultRouterPath(stateDir)})
rt.Load();  eng.Subscribe(rt.Handle);  go rt.Run(ctx)
rt.Status() []ChannelStatus;  rt.Log(channel, limit) []DeliveryRecord;  rt.Pending() (retries, digest int)
```

Pass `nil` for `Pusher` or `Ntfy` when a channel is not set up. For tests of your own wiring,
`alarms.NewFakeClock` is a manually advanced `Clock`, and `Pusher`, `NtfyPublisher` and `Source` are small
interfaces to fake.

For the portal's live updates, stream `eng.Events(n)`: every `Change` has a `Kind` (`raised`, `updated`,
`escalated`, `state`, `deleted`, `bulk`, `rule`, `prefs`) and the affected alarm. A full buffer drops changes
rather than blocking the engine, so re-fetch with `List` after a `bulk` change or a reconnect.

# Wiring into `cmd/shepherd` and the portal

`[alarms]` in `shepherd.toml` (see `shepherd.example.toml`) turns the engine on (`enabled`, default
true) and configures the one delivery channel wired in, ntfy (`[alarms.ntfy]`: `enabled`, `server`,
`topic`, and `token` or `username`/`password`). `cmd/shepherd/alarms.go`'s `startAlarms` builds the
engine under `<data_dir>/alarms`, builds a `Router` with an `ntfy.Client` adapter when
`alarms.ntfy.enabled` is set (`nil` otherwise, so the channel simply carries nothing), subscribes and
runs it, and is wired into `main.go` the same way `startDevices` and `startClassify` are. Web Push is
not wired in: it needs a secure context (HTTPS) the portal does not have yet (see "Web Push in the
browser" below), so `RouterOptions.Pusher` stays `nil` and `[alarms]` has no VAPID or subscription
settings. This is a deliberate scope decision, not an oversight — adding it later needs no engine or
Router change, only a `webpush.NewSender`/`Store` plugged into the same `Router`.

**Upstream health events.** `TypeUpstreamDown` and `TypeUpstreamRecovered` are raised from a new,
minimal hook on `dnsengine.Pool`: an `OnHealthChange func(addr string, healthy bool)` field, in the same
style as `Engine.Observe` and `Engine.ClientSeen` (a plain callback field the DNS engine already uses to
let other features observe its state without a parallel tracking system). `Upstream.record` — the single
place the prober and `Pool.Exchange` already report success or failure — now detects a change in that
upstream's own `healthy` flag and calls it, outside its lock. `wireUpstreamAlarms` in
`cmd/shepherd/alarms.go` subscribes to it: a transition to unhealthy checks `Pool.Status()` for every
other upstream and raises `TypeUpstreamDown` (severity high) only when none are healthy, matching the
type's "every upstream resolver in a pool stopped answering" description exactly — a single flaky
resolver in an otherwise healthy pool never pages anyone. A transition to healthy always raises
`TypeUpstreamRecovered` (severity low) for that one resolver, without waiting for the whole pool: the
type's low severity and the engine's own dedupe/storm control make per-resolver recovery noise
acceptable, and it is useful signal on its own (a flapping resolver recovering is worth knowing even
while a different one is still down). No parallel health tracker was added — this hook sits on top of the
pool's own existing failover/health state.

**Portal API**, under `/api/alarms`, follows the same conventions as `/api/devices`: `GET /api/alarms`
(filters as query params: `types`, `severities`, `min_severity`, `states`, `device_id`, `group_id`,
`since`/`until` as RFC3339, `text`, `include_children`, plus `sort`/`asc`/`offset`/`limit`), `GET
/api/alarms/{id}` (with `children` when it is a storm bundle), `PATCH /api/alarms/{id}` (`{"state":
"acknowledged"|"resolved"}`), `DELETE /api/alarms/{id}`, `POST /api/alarms/{id}/mute` (a `MuteSpec`
body, snoozes just that alarm), `POST /api/alarms/bulk` (`{ids|filter|all, op: "acknowledge"|"resolve"|
"delete"|"mute", mute: {by, duration, reason}}`, mirroring `/api/devices/bulk`'s op-based shape), `POST
/api/alarms/undo` (`{"handle": "..."}`), `GET /api/alarms/summary`, `GET /api/alarms/types`, and rules
CRUD at `GET`/`POST /api/alarms/rules` and `DELETE /api/alarms/rules/{id}`. Every handler goes through
the same token-and-CSRF-header `auth` middleware as the rest of the portal.

**Portal UI.** A new Alarms tab (`internal/portal/web/js/alarmsview.js`, pure helpers in `js/alarms.js`)
matches the Devices tab's structure: a `pg-head` with a severity/state filter and search box, a
`panel-lite` table with per-row severity badges, state and relative last-seen time, single-row
acknowledge/resolve/mute/delete, a `Selection`-backed checkbox column with a `bulkbar` for batch
acknowledge/resolve/mute/delete (mute offers the same scopes as `alarms.MuteBy`, with sensible default
durations — the Rules sub-view gives full control over match criteria and duration), and toasts with an
Undo action for batch changes that return a handle. A segmented control switches to a Rules sub-view:
create a mute rule (name, types, device IDs, domains, duration, reason) and remove existing ones.

# Web Push in the browser

Web Push is not something the server can do alone; the portal side is still to be built, and these are the
constraints it must respect.

- **HTTPS is required.** Browsers expose the Push API only in a secure context. The portal must be served
  over HTTPS with a valid certificate (the tailnet's automatic HTTPS, or the planned reverse proxy with
  Let's Encrypt). Plain HTTP, even on the LAN, cannot subscribe.
- **A service worker is required.** The page registers a service worker, calls
  `registration.pushManager.subscribe({userVisibleOnly: true, applicationServerKey})` with the VAPID public
  key, and posts the resulting `PushSubscription.toJSON()` to the server (`Store.Add`). The worker's `push`
  handler must always show a notification (iOS revokes a subscription whose pushes show nothing), and its
  `notificationclick` handler should open only same-origin paths from the payload's `url`.
- **iOS needs a home-screen web app.** Safari on iOS 16.4 and later delivers Web Push only to a web app that
  was added to the Home Screen (Share, then Add to Home Screen) and opened from there; a plain Safari tab
  cannot subscribe. The permission prompt must follow a tap inside that app. Android Chrome and desktop
  browsers need no install.
- **Lockdown Mode silently drops Web Push.** An iPhone in Apple's Lockdown Mode never receives the
  notification, and the push service still answers success, so Shepherd cannot see the failure. That is the
  main reason ntfy exists: set `NtfyAlways` for a household with a Lockdown Mode phone, or have that phone
  use the ntfy app. The same applies to browsers that block notifications or have Focus modes that hide them.
- Subscriptions expire or are revoked when the user clears site data, uninstalls the app or reinstalls the
  OS; the push service then answers 404 or 410 and the subscription is retired automatically.

# Not built yet

- **Web Push end to end: deferred on purpose, not forgotten.** The sender, VAPID keys and subscription
  store (`internal/webpush`) are fully built and tested, but nothing in `cmd/shepherd` or the portal uses
  them: no VAPID key generation/config, no `RouterOptions.Pusher`, no subscribe endpoint, no service
  worker, no manifest, no home-screen install prompt. The reason is simple and will not change until the
  portal is served over HTTPS: browsers only expose the Push API in a secure context (see "Web Push in the
  browser" below), and the portal today is plain HTTP (loopback/LAN). Wiring it up before then would be
  dead code that cannot work in production. ntfy is the one working delivery channel in the meantime.
  Revisit once the portal has TLS (the tailnet's automatic HTTPS, or the planned reverse proxy).
- **Preferences API and UI.** `Engine.Preferences`/`SetPreferences` (channels, digest, quiet hours,
  learning mode, per-type switches, time zone, portal URL) have no `/api/alarms/preferences` endpoint or
  settings screen yet; they currently only take the engine's own defaults (`DefaultPreferences`).
- **"Send a test notification."** `TypeTest` and `RaiseSync` are ready for it, but no endpoint or button
  calls them yet.
- **Delivery log and channel status in the portal.** `Router.Log` and `Router.Status` are not exposed over
  the API or shown anywhere in the UI yet, so a failing ntfy delivery is currently only visible in the
  server's own logs.
- **Mesh sync.** Records carry HLC stamps and `Export`/`Import` merge by last-writer-wins, but there is no
  transport, no high-water-mark exchange, and no audit log of mutes and rule changes. A pending retry or
  digest queue lives on one node only. Replicas should also agree on which node delivers, or each will
  notify.
- **Encryption at rest.** The `Codec` seam exists; the encrypted implementation (shared with encrypted
  history) does not.
- **A real-device check.** Everything is tested against fakes, loopback servers and (for the upstream
  health hook) real but local UDP listeners. Nothing here has been sent to a real push service or a real
  ntfy server.
