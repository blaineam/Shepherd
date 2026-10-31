# Accountability-partner email alerts

`internal/accountability` lets someone invite a trusted contact to be emailed when a device in a
group they chose accesses a category they chose. It is a recovery and awareness tool — the
self-hosted, free equivalent of Covenant Eyes or Accountable2You — built for someone who **wants**
this visibility into their own behavior shared with a person they trust, not a parental-control or
surveillance feature. It is **not** an alarm type: it does not use `internal/alarms` (not merged at
the time this was written) and has its own model, its own digest engine and its own email templates,
built in the same style (injectable `Clock`, atomic JSON persistence, a classified `Sender` outcome)
for consistency, not by sharing code.

This document is the full design: the privacy and tone rules every default follows, the matching and
digest semantics, both example emails in full, the SMTP configuration shape, honest limits, and what
is deliberately not built here.

## Design rules

These are not aspirations; they are what the code actually does, and each one is load-bearing.

1. **Privacy-preserving by default.** A subscription's `Detail` is `"summary"` by default: the email
   names the category, roughly when, and roughly which device or group — never a domain name.
   `"detailed"` additionally names the exact domain. Nothing upgrades a subscription's detail level
   except whoever configured it choosing `"detailed"` explicitly. See `TestSortedItemLinesSummaryOmitsDomains`
   and `TestRenderEmailSummaryDigestSnapshot`'s domain assertion for the test that keeps this true.
2. **Digest by default, not real-time pings.** A subscription's `Mode` is `"digest"` unless set to
   `"immediate"`. Digest mode rolls up accesses over a window (`DigestInterval`, default a day,
   settable to a week or any custom duration) into one email. Even `"immediate"` mode is not
   real-time: it still coalesces a burst within a short dedupe window (default 5 minutes,
   `Options.ImmediateWindow`) into one email, never one per attempt. A burst of the same category in
   one sitting is always one line with a count, not twenty emails or twenty lines.
3. **Compassionate, non-shaming language.** No "VIOLATION DETECTED," no clinical surveillance tone.
   The copy lives in `internal/accountability/template.go`, in two `text/template` strings
   (`digestTemplateText`, `immediateTemplateText`) deliberately separated from the matching and
   digest logic, so a reviewer can read and improve the wording without following any control flow.
   Both are reproduced in full below, rendered with real (synthetic) data, and pinned by a
   snapshot test (`template_test.go`) so a future wording change shows up as a visible diff.
4. **Scoped and explicit, never silent.** A `Subscription` always names one scope (`"group"` or
   `"device"` — there is deliberately no network-wide scope in this package) and a set of watched
   items (catalog, list or app IDs, or the wildcard `"*"` for "anything this scope was evaluated
   against"). There is no "email everyone about everything" mode: nothing is watched until a contact
   is subscribed to a specific scope and a specific set of items.
5. **No new attack surface for the accountability partner.** The partner receives email only. There
   is no portal login for them, no link in the email that reveals more than the email's own text
   already states, and this package adds no new multi-user portal authentication of any kind. See
   "What is not built" for the one-way acknowledgement this leaves as a future option rather than
   something built now.
6. **Honest about what it protects against and doesn't.** See "Honest limits" below — in particular,
   the distinction this package makes between *disclosure* (the default) and *enforcement*
   (`blocked_only`), and the fact that DNS-level visibility is trivially bypassed by a technical user
   who controls their own device.

## Model

```go
type Contact struct {
	ID        string
	Name      string
	Email     string
	CreatedAt time.Time
}

type Scope struct {
	Kind ScopeKind // "group" or "device" — accountability.ScopeGroup / accountability.ScopeDevice
	ID   string
}

type Subscription struct {
	ID             string
	ContactID      string
	Scope          Scope
	Items          []string      // catalog/list/app IDs, or "*" (accountability.Wildcard) for any
	Detail         Detail        // "summary" (default) | "detailed"
	Mode           Mode          // "digest" (default) | "immediate"
	Trigger        TriggerOn     // "any" (default) | "blocked_only"
	DigestInterval time.Duration // digest mode only; 0 means "daily"
	CreatedAt      time.Time
}
```

A contact is a name and an email address, nothing more (design rule 5). One contact can hold several
subscriptions — for example, both an "any Gaming access, weekly digest, summary" subscription for a
family's shared devices and a separate "any Adult Content access, immediate, detailed" subscription
for one person's own laptop, each configured and removed independently.

Contacts and subscriptions persist together as atomic JSON, mode 0600, in `<dir>/accountability.json`
(`accountability.ContactsFile`) — the same convention as `devices.json` and `policy.json` elsewhere in
this project: a temp file in the same directory, `fsync`, then rename, through a pluggable `Codec` (the
same `Encode`/`Decode` shape as `internal/devices`, so an encrypting codec can be plugged in later
without changing this package). Removing a contact cascades to its subscriptions (and discards any
digest in progress for them), matching the project's "deleting a device forgets its policy" convention
in `docs/DEVICES.md`.

## Intake: `AccessEvent` and `Intake`

This package has **no dependency on `internal/dnsengine` or `internal/devices`**. It is fed by a small
event type that the maintainer's own wiring (not built here) constructs from whatever the policy
engine actually decided for a query that matched a watched item:

```go
type AccessEvent struct {
	Time     time.Time
	ClientID string   // the device ID, when known
	GroupIDs []string // the groups that device belongs to
	Item     string   // catalog/list/app ID the caller matched this access against
	Domain   string   // the exact domain queried
	Action   string   // "blocked", "allowed", or whatever Entry.Action says (dnsengine also uses "cached", "error")
}

type Intake interface { Record(ev AccessEvent) }
```

`Engine` implements `Intake`. **Note what this is not tied to:** `AccessEvent` does not mean
"blocked." It means "this access matched something being watched," whatever the policy engine
decided to do about it. That distinction is the whole point of the next section.

### Why access isn't the same as blocked

The maintainer's own motivating example: someone sets up a subscription so that an external friend is
emailed if a device in their "Family Devices" group accesses a "Gaming" category resource — say,
Roblox — whether or not Roblox is even on that group's blocklist. This is monitor-and-disclose, the
way Covenant Eyes and similar tools actually work in practice: **voluntary disclosure to a trusted
person, independent of whether anything was blocked.** Blocking invites circumvention (a determined
person routes around a block); disclosure invites an honest conversation instead. That's why:

- `Subscription.Trigger` defaults to `TriggerAny`: it matches every watched access, allowed or
  blocked. `TriggerBlockedOnly` exists for whoever genuinely wants the alert tied to an actual block
  (the classic Covenant-Eyes-style "tell my partner when this was blocked" setup), but it is an
  opt-in narrowing, not the default.
- The email copy never implies wrongdoing from an access alone. An item is only ever annotated
  `(blocked)` in an email when *every* occurrence counted in that window really was blocked
  (`itemLine.AllBlocked`, computed in `template.go`'s `sortedItemLines`); a mix of allowed and
  blocked, or an access that was never blocked at all, gets no annotation — just the plain count. The
  running text throughout both templates says "accessed," "what happened," never "attempted,"
  "violation," or "caught."

## Matching

For every `AccessEvent` passed to `Record`, each stored `Subscription` is checked against it; a match
queues the event into that subscription's accumulating digest. A subscription matches when **all
three** agree:

1. **Scope.** A `"device"` scope matches when `ev.ClientID` equals the scope's ID. A `"group"` scope
   matches when the scope's ID is any one of `ev.GroupIDs`. (The event carries both the device and its
   groups; the subscription's scope decides which one it's watching.)
2. **Items.** The subscription's `Items` contains `ev.Item`, or contains the wildcard `"*"`.
3. **Trigger.** `TriggerAny` always agrees. `TriggerBlockedOnly` agrees only when `ev.Action` is
   `"blocked"` (case-insensitively).

### Examples

A subscription with `Scope: GroupScope("family-devices")`, `Items: ["roblox"]`, `Trigger: TriggerAny`:

| Event | Matches? | Why |
|---|---|---|
| `GroupIDs: ["family-devices"]`, `Item: "roblox"`, `Action: "allowed"` | yes | group matches, item matches, `TriggerAny` accepts any action |
| `GroupIDs: ["family-devices"]`, `Item: "roblox"`, `Action: "blocked"` | yes | same, just a different action |
| `GroupIDs: ["other-group"]`, `Item: "roblox"`, `Action: "allowed"` | no | wrong group |
| `GroupIDs: ["family-devices"]`, `Item: "discord"`, `Action: "allowed"` | no | wrong item |

The same subscription with `Trigger: TriggerBlockedOnly` instead: only the second row matches.

A subscription with `Scope: DeviceScope("laptop-1")`, `Items: ["*"]` matches any watched item on that
one device, whatever it is, because the wildcard stands in for "every item this scope was evaluated
against" — useful for "tell me about anything from this specific device" without listing every
category by hand.

## Digest and immediate timing

Every subscription accumulates matching events into one **pending digest** per subscription (keyed by
subscription ID, never by item, so a burst across several watched items still becomes one email). The
first matching event after a quiet period opens a window; the window's length is `DigestInterval` for
digest mode (0 means a day) or `Options.ImmediateWindow` for immediate mode (default 5 minutes).
Every later matching event before the window closes folds into the same accumulator — incrementing a
per-item count, a per-item domain-count map, and a per-device count — without sending anything. When
the window closes (checked by `Tick`, called by a background loop driven by an injectable `Clock`, no
real sleeps), exactly one email goes out summarizing everything the window accumulated, and a fresh
window opens on the next matching event.

Concretely, for a digest subscription with the default daily interval: three accesses at 9:03am,
2:17pm and 11:40pm the same day fold into the one email sent when the window first opened plus 24
hours, reporting all three. For an immediate subscription (5-minute window): five accesses inside one
browsing session fold into one email reporting "5 times," not five emails.

**Persistence across restarts.** The pending digest for every subscription is written, mode 0600,
atomically, to `<dir>/accountability-pending.json` (`accountability.PendingFile`) every time it
changes. On restart, `Engine.New` reloads it, so a digest already in progress keeps its original
window-open time and its accumulated counts — a restart neither loses a count nor starts counting the
same access twice. `TestPersistenceSurvivesRestart` exercises this directly: two accesses recorded,
the engine closed and reopened against the same directory, a third access recorded after "restart,"
and the eventual email reports all three.

## The email templates, in full

Both are real renders from `template_test.go`'s snapshot tests — this is the literal text the code
produces today, not a paraphrase. Every name, address, domain and group label here is synthetic.

### Example 1: summary digest

Scenario: a household subscribed an accountability partner, "Jordan," to the "Adult Content"
category for their "Family Devices" group, as a weekly — well, in this render, several-day — digest at
the default `"summary"` detail level, with `Trigger: TriggerBlockedOnly` (the classic "tell my partner
when this was blocked" setup). Four occurrences happened across the window, all blocked.

> Subject: `A check-in about the Family Devices group`

```
Hi Jordan,

You're set up as an accountability contact for the Family Devices group, so here's the check-in for Oct 19 to Oct 25.

There were 4 accesses in a category you're both keeping an eye on:

  - Adult Content: 4 times (blocked)

That's everything for this check-in — nothing else to see, no log to review. This is meant as a starting
point for a conversation, not a verdict, so however it comes up, it might be worth asking how things are
going.

No reply is needed. You're getting this because someone chose you as an accountability partner for
the Family Devices group; if that ever changes, these emails stop.

— Shepherd
```

Notice what is absent: no domain name, no exact timestamps, no clinical language, no suggestion that
this is anything other than a prompt for a conversation.

### Example 2: detailed immediate (the maintainer's worked example)

Scenario: the maintainer's own motivating case. A console in a "Family Devices" group accessed a
"Roblox" category resource — **allowed, not blocked at all** — and an external friend, "Avery," who
was subscribed immediately (not on a digest) at `"detailed"` level with the default `Trigger: TriggerAny`,
is told about it right away (within the 5-minute coalescing window).

> Subject: `A heads-up about a console in the Family Devices group`

```
Hi Avery,

A quick heads-up from a console in the Family Devices group, around Oct 25 at 4:12 PM UTC:

  - Roblox: 1 time
      play.example.com

This is just what happened, not an accusation — plenty of browsing crosses categories without meaning
anything. If it's useful, it might be worth checking in.

No reply is needed. You're getting this because someone chose you as an accountability partner for
a console in the Family Devices group; if that ever changes, these emails stop.

— Shepherd
```

Note the item is **not** marked `(blocked)` — it never was — and the copy explicitly frames this as
"what happened," not an accusation, exactly because an access that was never blocked is not evidence
of anything on its own (design rule 6, and the correction to the original brief this package was built
against). `play.example.com` is a synthetic placeholder; a real deployment would show the actual
domain the device queried, which is exactly what `"detailed"` mode is for and exactly what
`"summary"` mode above withholds.

## SMTP configuration shape

This package itself needs only the shape below; **`internal/config` is not touched by this
package**. The shape is:

```go
type SMTPConfig struct {
	Host               string
	Port               int
	Username           string
	Password           string // see "Honest limits" below
	From               string
	TLS                TLSMode // "starttls" | "tls" | "none"
	Timeout            time.Duration
	InsecureSkipVerify bool // test-only; never set this in real configuration
}
```

This matches the project's free, keyless, bring-your-own-credentials convention (the same spirit as
`internal/webpush` and `internal/ntfy`): no paid transactional-email API, just a relay the person
already has — a Gmail app password, an iCloud app-specific password, a self-hosted relay like
Postfix. `SMTPSender` (`internal/accountability/sender.go`) speaks SMTP with only the standard
library (`net/smtp`), supporting STARTTLS (port 587 convention), implicit TLS (port 465 convention),
or no TLS at all (only sane against a local, trusted relay).

### Setting up the relay: the portal, not `shepherd.toml`

The relay is set, changed and removed on the **Accountability** tab's **Mail relay** card (host, port, TLS
mode, username, password, From), entirely from the browser, and kept with the DNS provider token in
`<data_dir>/secrets.json` (`internal/secrets`: JSON, atomic save, mode 0600, the same shape as
`devices.json` and `policy.json`).

- **Write-only password.** Nothing ever sends the password back: the card's password field is always
  empty, saying only that one is saved. Leaving it empty on a later save keeps the saved password — but only
  for the same host and username. Change either and the password must be typed again, so a saved password
  can never be pointed at a different server (which would be a way to read it back). `clear_password`
  removes it, for an unauthenticated local relay.
- **Checked before it is saved.** `SMTPSender.Verify` does every step `Send` does before `MAIL FROM` —
  connect, STARTTLS or implicit TLS as chosen, AUTH — then `QUIT`s. Nothing is ever sent (a test proves the
  fake server never sees `MAIL`, `RCPT` or `DATA`). A wrong password, port or TLS mode is refused right away
  (HTTP 422, with the classified reason), and the working relay, if any, stays in place.
- **No restart.** The engine sends through an `accountability.RelaySender`; a saved relay is swapped into it
  at once, and a cleared one removed, so the next digest uses whatever the card says now. `From` comes from
  the relay itself, so it changes with it too.
- **The engine is always there when `[accountability]` is enabled** (the default), relay or not, so contacts
  and subscriptions can be managed before a relay exists and the tab no longer answers 404 everywhere — the
  state that, before this, looked broken rather than "needs two minutes of setup". Without a relay it costs
  nothing: `dnsengine.Engine.OnAccessWanted` skips even the item lookup on the DNS hot path, and no access is
  queued, recorded or persisted, so nothing piles up to be sent later. Only `enabled = false` turns the
  routes back into 404s (the card still answers, and says so).

**Upgrading from a `shepherd.toml` relay.** `[accountability.smtp]` is now a read-once seed, the
`[[lists]]` precedent applied to this one secret: the first time Shepherd starts without a portal-managed
relay, a relay set there (`host` non-empty, `password` or `password_file` — never both — included) is
imported, and from then on the section is ignored (a startup line says so when it differs). An existing
setup keeps sending across the upgrade with nothing re-entered. A `password_file` that cannot be read at
that moment is retried at the next start rather than lost, and a relay cleared in the portal stays cleared.

**The tradeoff, plainly:** `secrets.json` is protected only by its 0600 permissions — the same honest limit
this project states for the portal token, the history key file and the ACME keys. Moving the password out of
`shepherd.toml` does mean a config file that is shared, backed up or pasted into an issue no longer carries
it. Encrypting it at rest (a key file or passphrase, Argon2id, the way `history.json` can be encrypted)
remains a possible future improvement; it is not built.

### Send-outcome classification

Matching the pattern in `internal/webpush`'s `Outcome` and `internal/ntfy`'s `Error.Kind`,
`SMTPSender.Send` classifies exactly which step of the SMTP exchange failed, so a caller (or this
package's own `Engine.SendLog`) can tell "this will never work until the configuration changes" from
"try again later":

| Outcome | Meaning |
|---|---|
| `OutcomeOK` | The server accepted the message. Acceptance is not delivery — see "Honest limits." |
| `OutcomeAuthFailed` | The server rejected the configured username/password. |
| `OutcomeConnectionFailed` | Could not reach the server, or could not negotiate STARTTLS with it. |
| `OutcomeRecipientRejected` | The server refused the recipient address (no such mailbox, etc.). |
| `OutcomeTransient` | A temporary failure (4xx during `MAIL`/`DATA`, a dropped connection mid-exchange). Worth retrying later; this package does not retry on its own. |
| `OutcomeInvalid` | The message or configuration itself is unusable; nothing was sent. |

## Honest limits

- **This is disclosure by default, not enforcement.** In the default `TriggerAny` mode, an email
  means "this was accessed," nothing more. It is not evidence of a policy violation unless the
  subscription is also `TriggerBlockedOnly` (or the item happens to say `(blocked)` because every
  occurrence that window really was blocked). Reading more into a summary email than it actually says
  defeats the compassionate framing the templates work to establish.
- **DNS-level visibility is bypassable.** Exactly like the rest of this project's DNS filtering (see
  `docs/POLICY.md`, `docs/DESIGN.md`): a technically capable person who controls their own device can
  point it at a different DNS resolver, use a VPN, or (once Watch mode ships) use its documented
  bypasses, and this package will simply never see the access. This is an accountability tool that
  works when someone wants it to work for them — it is not a guarantee, the same way Shepherd
  guarantees nothing else about its blocking.
- **Email is store-and-forget, not guaranteed delivery.** `SMTPSender.Send` reports what the remote
  server said about *accepting* the message, not whether it was ever delivered to an inbox, and this
  package **does not retry a failed send**. A failed attempt is recorded in `Engine.SendLog` with its
  classified outcome for observability, but the digest window it belonged to is still cleared, not
  held for a retry (`TestSendFailureIsLoggedAndWindowCleared`). This is a deliberate simplicity choice
  given the explicit non-goal of guaranteed delivery; a future version could add bounded retries if
  that trade-off ever changes.
- **The SMTP password is a real secret, protected today only by file permissions.** It is kept in
  `<data_dir>/secrets.json` (entered in the portal, or imported once from `shepherd.toml`), whose only
  protection is its own 0600 permissions — there is no encryption. This is the same gap `docs/DEVICES.md`
  and `docs/HISTORY.md` already note for other secrets in this project (an API token, an encryption
  passphrase); see "Setting up the relay" above. Encrypting it the way `history.json` can be encrypted (a key file or passphrase,
  Argon2id) is a reasonable future improvement; it is not built here, and this package's own `Codec`
  interface (the same shape used throughout the project) is where that encryption would plug in
  without changing anything else.

## Wiring: the DNS engine, `cmd/shepherd` and the portal

This package itself still has no dependency on `internal/dnsengine` or `internal/devices` (see
`doc.go`); everything below lives in the callers that feed it.

- **`dnsengine.Engine.OnAccess` (`internal/dnsengine/engine.go`).** A new, additive field,
  `func(AccessInfo)`, called by `ServeDNS` for every *completed* query — blocked, allowed or
  cached, never one that errored, since nothing was actually accessed then — whose name matches at
  least one catalog or custom list item (`Filter.ItemsFor`, which ignores scope on purpose: a
  category can be watched whether or not it is actually blocked for that client, exactly this
  package's design rule 6). This is the opposite filter from the existing `Observe` field, which
  exists for the automatic classifier and deliberately *skips* blocked queries; `Observe` itself is
  untouched; `OnAccess` is a new, separate hook. `AccessInfo` carries the time, client IP, every
  matched item ID, the domain and the action, from which a caller builds one `AccessEvent` per
  matched item.
- **`cmd/shepherd/accountability.go`'s `startAccountability`.** Builds the `SMTPSender` and
  `accountability.Engine` from `cfg.Accountability`, and wires `Engine.OnAccess` to a closure that
  resolves `ClientID`/`GroupIDs` from the device registry's `ScopesFor` (already lock-free and
  built for the hot path) and then hands the resulting `AccessEvent`s to a small buffered channel
  drained by one worker goroutine, which is what actually calls `Engine.Record`. This indirection
  exists because `Record` can write the pending digest to disk (`fsync` + rename) on every call
  that matches a subscription, and `OnAccess` itself runs synchronously inside `ServeDNS` — on the
  DNS hot path, a disk write must never happen inline. A full queue drops the event rather than
  blocking a DNS response, the same choice `ClientSeen` and `Observe` already make elsewhere in
  `dnsengine`. Gated by `cfg.Accountability.Enabled` alone: the engine is built relay or not, sending
  through a `RelaySender` the portal swaps relays into live, and `Engine.OnAccessWanted` (the relay is
  set) keeps the hook free on the DNS hot path until there is a relay. With the feature disabled,
  `startAccountability` returns nil values — not wired, not an error.
- **Portal API (`internal/portal/api_accountability.go`), routes under `/api/accountability/...`:**
  `GET`/`POST /contacts`, `DELETE /contacts/{id}`, `GET`/`POST /subscriptions` (optionally filtered
  by `?contact_id=`), `DELETE /subscriptions/{id}`. A subscription's scope accepts only `"group"`
  or `"device"` (never `"network"` — this package has no network-wide scope, design rule 4) and is
  resolved against the device registry the same way `/api/policy/*` resolves a blocking scope.
  Items are validated against the catalog and custom lists (`Server.knownItem`, reused from
  `api_policy.go`) or the wildcard `"*"`. When `Deps.Accountability` is nil (not wired up), every
  route answers 404, the same "not available on this version" shape the portal's own frontend
  already recognises (`mgmt.js`'s `unavailable()`), not a panic — which now happens only when
  `[accountability] enabled = false`. The relay itself: `GET /api/accountability/smtp` (host, port,
  username, From, TLS mode, `password_set`, `configured`, `active`, `enabled`, `source`, `updated_at` —
  never the password), `PUT` (checked with `SMTPSender.Verify` first; 400 for a malformed relay, 422 when
  the check fails, nothing saved either way) and `DELETE` (clear, remembered). These answer even when
  the feature is disabled.
- **Portal UI (`internal/portal/web/js/accountability.js`), a new Accountability tab:** add or
  remove a contact (name, email), and per contact, add or remove a subscription — a scope picker
  (group or device), an item picker (every catalog entry, plus a "watch anything" wildcard toggle),
  and detail/mode/trigger selectors, plus the **Mail relay** card above them (pure form logic in
  `js/secrets.js`, with its own tests). Built in the same style
  as the Blocking screen's panels and list rows, not a copy of `scope.js` (that module computes
  blocking-policy "effective" status, which has no meaning for a subscription).

## What is not built here

- **No acknowledgement mechanism.** The brief allows for "a one-way, unauthenticated-safe
  acknowledgement" in the email that must not leak anything beyond what the email already states.
  That is optional, and building it well (a one-way confirmation link with no session, no portal
  access, and no information disclosure beyond the email's own text) is itself a small feature with
  its own security review; it is left as a clearly scoped future addition rather than rushed in here.
- **No multi-user portal authentication of any kind**, by design rule 5 — the accountability partner
  never gets anything but email.
- **No encryption of the SMTP password at rest**, beyond `secrets.json`'s 0600 permissions (see
  "Setting up the relay" above).
- **No "send a test email" button.** The save-time check proves the relay accepts the connection and the
  credentials, not that mail to a given recipient is delivered.

## Go API for wiring

```go
sender, err := accountability.NewSMTPSender(accountability.SMTPConfig{
	Host: "smtp.example.com", Port: 587, Username: "shepherd@example.com", Password: appPassword,
	From: "shepherd@example.com", TLS: accountability.TLSStartTLS,
})
eng, err := accountability.New(accountability.Options{
	Dir: stateDir, Sender: sender, From: "shepherd@example.com",
	// ImmediateWindow, TickEvery, MaxDomains, ScopeLabel, ItemLabel all have defaults.
})
defer eng.Close()

contact, err := eng.AddContact("Avery", "avery@example.com")
sub, err := eng.AddSubscription(accountability.Subscription{
	ContactID: contact.ID, Scope: accountability.GroupScope(groupID),
	Items: []string{"roblox"}, Detail: accountability.DetailDetailed,
	Mode: accountability.ModeImmediate, Trigger: accountability.TriggerAny,
})

// The wiring (cmd/shepherd/accountability.go): dnsengine.Engine.OnAccess fires for
// every completed query matching a watched item, blocked or allowed; a worker
// goroutine drains a small queue and calls, once per matched item:
eng.Record(accountability.AccessEvent{
	Time: info.Time, ClientID: deviceID, GroupIDs: groupIDs,
	Item: item, Domain: info.Domain, Action: info.Action,
})

eng.Contacts() []Contact;         eng.Contact(id) (Contact, error);         eng.RemoveContact(id) error
eng.Subscriptions() []Subscription; eng.SubscriptionsFor(contactID) []Subscription; eng.RemoveSubscription(id) error
eng.SendLog() []SendRecord;       eng.Pending() int;       eng.Tick();       eng.Save() error
```

For tests of your own wiring, `accountability.NewFakeClock` is a manually advanced `Clock`, and
`accountability.FakeSender` is a `Sender` that records every call and returns scripted `Result`s —
exactly how this package's own tests avoid a real network and real sleeps.
