# Automatic device classification

Shepherd guesses what each device is (camera, TV, phone, printer...) from evidence it already has,
and says why in plain words. The package is `internal/classify`; this page is its reference.

> "If the devices automatically got categorized via their ASN or MAC addresses that would be cool."

Today the registry guesses a type from the MAC vendor and mDNS service types. The classifier replaces
that with a scored, explainable guess built from three families of evidence, and never overrides the
user.

## What exists and what does not

| Built and tested | Not built yet |
|---|---|
| The engine, its rules and their evidence (`internal/classify`) | Portal screens: showing the guess, its reasons and confidence, "correct this", and the one-click suggested groups |
| ASN lookups and the monthly ASN database (`internal/geo`) | Wiring: `cmd/shepherd` creating the classifier, the DNS engine calling `Observe`, the ASN adapter, the timer |
| Guessed-versus-chosen types in the registry (`internal/devices`) | Smart groups whose membership follows a search (specified below) |
| Suggested groups (`Classifier.Suggestions`) | A user-facing "teach it" flow that submits rule corrections |

## Evidence families and how they are weighted

Each family turns into a strength between 0 and 1 for every class. A class's total is the noisy-or of
its families, `1 - (1-a)(1-b)...`, so independent clues add up without ever passing 1, and no single
weak clue can reach the threshold alone.

| Family | Where it comes from | Strength |
|---|---|---|
| **Domains** (strong) | The DNS names a device looks up, matched against suffix rules (`rules/domains.json`) | `1 - exp(-h/2.5)`, where `h` is the sum of rule weights over recognised lookups, at most 5 counted per registrable domain, so a heartbeat proves a class once, not a thousand times |
| **Name or model** | The device's alias, mDNS name, hostname or model string, through the registry's keyword table | 0.75 |
| **mDNS services** | `_ipp`, `_sonos`, `_hap`... (`rules/services.json`, kept in step with the registry's own table by a test) | the rule weight, once per kind of service |
| **Manufacturer** | The OUI vendor name, matched as whole words, longest rule wins (`rules/vendors.json`) | the rule weight; **ignored when the MAC is randomized** |
| **ASNs** (weak) | The network of each answer address (`rules/asn.json`) | `0.4 * (1 - exp(-h/2))`, the same counting; capped, so a network alone can never name a device |
| **Private address** | A randomized (locally administered) MAC | a small prior: phone 0.22, laptop 0.10, tablet 0.08. A private address hides the manufacturer, so the vendor is not used |

Shared CDN, cloud and backbone networks (Akamai, Cloudflare, Amazon, Google, Microsoft and so on) are
listed with **zero weight**: an answer from one of them says nothing about the device. They are counted
only so the reasons can say so.

### From scores to an answer

- **Confidence** is the winner's total minus a share of the runner-up's: half of it, a fifth when the two
  are close relatives (TV and streaming box, camera and doorbell, speaker and smart-home hub...). Conflicting
  strong evidence therefore lowers confidence, sometimes below the threshold.
- **Threshold 0.5.** Below it the result is `unknown`, never a wild guess. For `unknown`, `Confidence` is the
  best candidate's, so a screen can say "weak hint", and `Alternatives` lists the candidates.
- **Alternatives** are the other classes with a total of at least 0.15, at most three.
- **ASN versus domains.** An ASN hint is at most 0.4 and is scored with a further cap, so it can add to a
  borderline device but cannot outvote a domain. Tests pin this: ASN-only traffic on a streaming network
  stays `unknown`, and a camera cloud wins even when every answer is on a streaming network.

A worked example. A device with a private MAC looks up `ius.hik-connect.com` 120 times and an unrelated
site 40 times. The domain rule gives camera 0.9 per credited lookup; five are credited, `h = 4.5`, and
`1 - exp(-1.8) = 0.83`. The private-address prior gives phone 0.22. Camera 0.83, phone 0.22: confidence
`0.83 - 0.5 * 0.22 = 0.72`, a camera.

### Accuracy on the synthetic corpus

`TestScenarioCorpus` classifies 25 invented device profiles (a camera that only talks to its cloud, a TV
that streams, a phone with mixed use, a printer, a smart speaker, a randomized-MAC device with unfamiliar
domains, a device with conflicting signals, and others). All 25 come out right: 20 named correctly with
the stated minimum confidence and 5 hard cases correctly left `unknown`. This is a regression guard on
invented traffic, not a measurement of real-world accuracy; real homes will be messier.

## How reasons read

Reasons are short plain sentences, strongest first, at most three plus a note:

- `Most of its recognised lookups go to a camera cloud service`
- `12 lookups to a streaming service`
- `Manufacturer (Sonos) is known for smart speakers`
- `Advertises a printing service on the network`
- `Its name or model contains "camera"`
- `5 lookups resolve to a streaming network` (the weak ASN family)
- `Some evidence also points to a TV, so confidence is lower`
- `Uses a private (randomized) address, so the manufacturer is hidden`

`Result.Reasons` carries the counts. The text stored in the registry (`Result.Summary()`) is the same story
without numbers (`Lookups go to a streaming service`), so it only changes when the story changes and does
not churn the sync log.

## What is retained, and for how long

The classifier keeps, per device, in memory only:

- one score per class from domains, one from ASNs, and a handful of counters (lookups, recognised lookups,
  answers on shared networks, lookups per reason label);
- at most **24 registrable domains** with a decayed lookup count (`example.com`, never
  `my-search.example.com`), and at most **16 ASN numbers** with counts;
- the manufacturer name, the mDNS service labels (at most 16), the one classification the name or model
  gave, and the randomized flag;
- one "last seen" time and one "last decayed" time.

It does **not** keep a query history, the time of any individual lookup, a full host name, a subdomain,
an answer address, or a client address once the registry can name the device (before that, evidence waits
under the client IP and is folded into the device on the next pass). Reverse lookups (`.arpa`), local names
(`.local`, `.lan`, `.home`, `.internal`) and single labels are not recorded at all. `Classifier.Retained(key)`
returns exactly what is kept, for a "what do you know about this device" screen, and a test dumps the whole
internal state looking for names, subdomains and addresses that should not be there.

- **Decay:** everything halves every 7 days (`Options.HalfLife`), so a device that changes role fades out
  of its old class. A domain or ASN whose count falls below 0.2 is dropped.
- **Forgetting:** a device not heard from for 30 days is dropped (`Options.IdleTTL`, `Prune`, run by
  `Run`). `Forget(key)` drops one now.
- **Bounds:** 1024 devices (`MaxDevices`; the least recently seen is evicted), 24 domains and 16 ASNs
  each. A flood of random domains cannot grow memory (a test floods 300,000 names), and cannot push out the
  domains a device really talks to: a newcomer only displaces an entry that is itself a one-off, except a
  recognised domain, which always earns a place because it is the evidence.
- **Nothing is persisted.** A restart loses the evidence, not the guess: the registry stores the result
  (`type`, `reason`, `confidence`), and a guess is never withdrawn just because there is no evidence yet.

### Hot path

`Observe` runs on the DNS goroutine. It allocates nothing for a name it has seen (tested), takes one of 16
shard locks, does bounded work (at most 3 answer addresses looked up, small linear scans, one decay step
at most once a minute) and with `Options.NonBlocking` drops the observation instead of waiting when its lock
is busy (`Dropped()` counts them). The DNS engine should set `NonBlocking`.

## The user's choice always wins

`Device.TypeUser` is set only by `Registry.SetType`. `Registry.SetGuessedType` does nothing for such a
device, the registry's own re-guessing leaves a classifier guess alone, and `Classifier.Apply` skips typed
devices (it still counts them for suggested groups). Returning a device to "auto" clears the user's choice
and lets the classifier speak again. A guess is marked `TypeAuto` with its `TypeConfidence`, so the portal can
say "guessed, 82% sure" next to "set by you".

## Changing its mind: hysteresis

`Apply` is idempotent and safe to call from a timer and on demand (`Run` does both).

- A device with no current guess is named as soon as the result reaches the threshold.
- A device keeps its guess unless a challenger's score beats the guess's own score by **0.12**, and the
  guess's own score is still at least **0.35** (`Release`). A device whose lookups swing between two classes
  therefore does not flap (tested: 40 alternating rounds, at most one change).
- A guess is withdrawn (back to the registry's own vendor/service/name guess) only when its own evidence
  has fallen below 0.35 **and** there are at least 5 decayed lookups to judge by. No evidence is not
  evidence against.
- A confidence wobble under 0.05 is not written.

## Suggested groups

`Classifier.Suggestions()` proposes groups from the classes assigned at the last `Apply`:

| Group | Classes |
|---|---|
| Cameras | camera, doorbell |
| TVs and streaming | tv, streaming box |
| Phones and tablets | phone, tablet |
| Smart home | smart-home hub, smart plug/sensor, thermostat |
| Speakers, Computers, Printers, Game consoles, Wearables, E-readers | the class itself |
| Servers and storage | NAS/server |
| Network equipment | router/infrastructure |

Each suggestion has a `Label` like `Cameras (4 devices)`, the member device IDs and the classes folded in.
A group of fewer than 2 devices is not offered, a group the user already has (by name) is not offered
again, types the user set count like guessed ones, and `unknown` devices are never grouped. The portal turns
a suggestion into a group with `CreateGroup` and `BulkAssignGroup`.

### Spec: smart groups (not built)

A **smart group** is a group whose membership follows a search query, so a policy set on "Cameras" covers a
new camera the moment it is classified. The registry already has the pieces: `Search` (`type:camera`,
`vendor:`, `group:`...) and `ScopesFor`, which resolves a client IP to its device and group IDs.

- **Model.** A group gains an optional `Query string` (a `Search` query, for example `type:camera OR
  type:doorbell`; today's query language has no OR, so either add OR or allow a list of queries) and a
  `Smart bool`. A smart group's explicit member list is derived, never stored per device.
- **Evaluation.** `rebuildScopes` already builds an immutable scope snapshot on every change. It evaluates each
  smart group's query against each live device and adds the group ID to the device's scope entry. The hot-path
  `ScopesFor` stays a lock-free map read; the cost moves to registry changes, which are rare. A guess
  changing (`SetGuessedType`) is a registry change, so membership follows classification automatically.
- **Hysteresis.** Because classification already has hysteresis, membership does not flap. A group may also
  require a minimum confidence in its query (`confidence:>=0.7`, a new search key).
- **User choice.** A user-set type is a type like any other, so it moves the device in or out. A device can
  also be pinned in or out of a smart group by hand (`Include` and `Exclude` ID lists on the group), which
  win over the query.
- **Sync.** `Query`, `Smart`, `Include` and `Exclude` replicate with the group like any field, with the same
  last-writer-wins stamp. Derived membership is recomputed on every replica and never synced.
- **Events.** A membership change emits `EventGroupMembers` with the affected device IDs, as manual changes do.
- **Portal.** Creating a suggested group from `Suggestions()` can offer "keep this group up to date", which
  creates it as a smart group with the query for its classes.
- **Open questions.** How to show a device that is in a smart group because of a guess (badge it "automatic");
  whether a smart group may also have manual members; how to order evaluation when a query references groups.

## Adding or correcting a rule

The rules are JSON files in `internal/classify/rules/`, embedded in the binary, each rule with its evidence;
`rules/README.md` lists them all with their sources. To add or correct one:

1. **Verify it from a public source** and record how: a certificate organization, DNS contact, vendor or
   platform documentation, the site's own content, or an AS announced by the vendor (the evidence codes are
   in `rules/README.md`). Do not add what you only believe. Do not add a domain that is mostly a general
   site people browse unless its weight says so.
2. **Pick a weight** with the rubric in `rules/README.md`: 0.8 to 0.9 only for a service that exists for
   that kind of device; low for anything phones and laptops also touch. Shared infrastructure gets no weight.
3. **Edit the JSON** (`domains.json`, `vendors.json`, `asn.json`, `services.json`) and add the row to
   `rules/README.md`. Suffix rules match the name and every subdomain on a label boundary; the most specific
   suffix wins. A child suffix may not name a different top class than its parent.
4. **Run `go test ./internal/classify`.** The validation tests reject unknown classes, weights out of range
   or ASN hints above 0.4, shared networks that carry weight, duplicates, contradictory parent and child
   suffixes, missing evidence, bad suffix syntax, vendor rules that match no real manufacturer in the OUI
   table, service rules that disagree with the registry, and any rule missing from the README.
5. If it changes a class, add or adjust a profile in `TestScenarioCorpus`.

To correct a wrong class for one device, the user sets the type; that is permanent and the classifier will
not touch it.

## The ASN database

An autonomous system (AS) is a network, and its number (ASN) and holder name say who runs the network an
address lives on: "Netflix Streaming Services Inc.", "Roku Inc.". Shepherd looks up the addresses in DNS
answers to learn which networks a device talks to.

- **Source:** the free monthly DB-IP "IP to ASN Lite" database, published as
  `<base>/dbip-asn-lite-YYYY-MM.mmdb.gz` (`https://download.db-ip.com/free` by default).
- **Licence and credit:** CC BY 4.0. The portal must show the attribution string
  `IP to ASN data by DB-IP.com (CC BY 4.0)` (`geo.ASNAttribution`, also in `ASNManager.Status()`).
- **How it is kept fresh** (`geo.ASNManager`, the same guarantees as the map database): it loads the file on
  disk, refreshes it when older than 35 days, tries this month's file and falls back to last month's when the
  new one is not published yet, and only trusts a download whose database type mentions ASN and that opens as
  a valid database. A failed, truncated, wrong-kind or corrupt download never replaces a working database,
  and the temporary file is removed. Both managers share one downloader, so they cannot drift apart.
- **Privacy:** only the database is downloaded. Every lookup happens locally; no address is sent anywhere.
- **API:** `geo.ASNLocator` (`Open`, `Ready`, `Lookup(net.IP)`, `LookupAddr(netip.Addr)`) returns
  `geo.ASN{Number, Org}`. The city and ASN databases live side by side in `<data dir>/geo/`.
- **Records:** `autonomous_system_number` and `autonomous_system_organization`, database type
  `DBIP-ASN-Lite (compat=GeoLite2-ASN)`, checked against the 2026-10 file.

## Registry changes

All additive:

- **New device types:** `streaming box`, `smart plug/sensor`, `doorbell`, `thermostat`, `e-reader`, `wearable`,
  `NAS/server`, with `ParseType` aliases (`plug`, `sensor`, `nas`, `server`, `thermo`, `smartwatch`, ...).
- **A guess is not a choice.** `Device.TypeAuto` marks a type chosen by the classifier and
  `Device.TypeConfidence` records how sure it was. `Registry.SetGuessedType` writes a guess and does nothing
  for a device whose type the user set. `Registry.ClearGuessedType` withdraws a guess. `SetType` (the user)
  always wins, clears the guess and survives every later guess.
- **One service table.** `devices.ServiceTypeRules()` exports the mDNS service-type table `GuessType` uses, so
  the classifier and the registry never disagree about what `_ipp` means.
- `devices.KnownVendors()` lists the OUI manufacturer names, so tests can prove each vendor rule matches a
  name that exists.

## Wiring it in (for the change that connects it)

```go
c, _ := classify.New(classify.Options{NonBlocking: true})
c.UseRegistry(registry)                                   // client IP -> device, lock-free
c.SetASN(func(a netip.Addr) (classify.ASNInfo, bool) {    // adapt geo.ASNLocator; classify must not import geo
    r, ok := asn.LookupAddr(a)
    return classify.ASNInfo{Number: r.Number, Org: r.Org}, ok
})
go c.Run(ctx, registry, 5*time.Minute)                    // Apply on a timer and prune
// in the DNS engine, for every answered query:
c.Observe(clientIP, qname, answerIPs)
// on demand: c.Apply(registry); c.Suggestions()
```

`classify` imports `devices` only. It must not import `geo` or `dnsengine`: the DNS engine will import
`classify`, and `geo` imports the engine.

## Limits

- **Randomized MACs.** A private address hides the manufacturer, so a phone, tablet or laptop with one is
  classified only by what it looks up, its services and its name. Most modern phones randomize, so expect
  `unknown` until it has been seen doing something recognisable.
- **Shared infrastructure.** Most device makers run on shared clouds and CDNs, which say nothing about the
  device. That is why domains carry most of the weight and ASNs only a nudge.
- **Devices that talk to nothing.** A device that never uses DNS (hard-coded addresses, or DNS over HTTPS to
  another resolver) leaves no evidence, and falls back to manufacturer, services and name.
- **Ambiguity.** A TV and a streaming stick look up the same services; a phone and a laptop both stream and
  sync. Related classes are scored softly for this reason, and the registry keeps the user's last word.
- **Browsing.** A phone's lookups are dominated by whatever its owner does. Weights for services people use
  on any device are low on purpose.
- **Coverage.** About 85 domains, 50 manufacturers and 40 networks, all verified, and no more. Many real
  device clouds are missing because they could not be verified; see `rules/README.md`.
- **Real-world accuracy is not measured.** The corpus is invented. Expect to correct rules once it runs on a
  real network.
