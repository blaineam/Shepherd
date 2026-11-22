# Backends: Shepherd as a dashboard over your router

Shepherd started as a DNS server with a portal on top. A **backend** lets the same portal sit on
top of a router or firewall you already run, read what it sees and change what it enforces, instead
of (or beside) answering DNS itself. `internal/backends` defines the contract and one package per
product implements it.

## One contract, many abilities

Products disagree about what they expose, so a backend is not one big interface. Each ability is its
own small interface (`DeviceReader`, `FlowReader`, `AlarmReader`, `RuleManager`, `DeviceRenamer`,
`AlarmDismisser`) and a backend implements the ones its API really supports.
`backends.Capabilities` reports the result, and the portal shows only what is on that list.

Write abilities (`rules:write`, `devices:rename`, `alarms:dismiss`) are advertised only when the
owner has not marked the credential read-only. A write through a read-only connection returns
`ErrReadOnly` before any request is made.

| Ability | Firewalla MSP | UniFi (Integration API) | Shepherd's own DNS |
|---|---|---|---|
| Devices | `GET /v2/devices` | clients and adopted devices | registry |
| Requests (flows) | `GET /v2/flows`, with destination domain, bytes, blocked | **none documented** | DNS query history |
| Alarms | `GET /v2/alarms` | **none documented** | alarm engine |
| Rules (list) | `GET /v2/rules` | firewall policies, ACL rules, DNS policies | allow and block lists |
| Rules (change) | create block or allow, pause, resume, delete | create, update, delete firewall policies | policy store |
| Rename device | `PATCH /v2/boxes/:gid/devices/:id` | not documented | registry |
| Block a device | rule with a device scope | block a client | quarantine |
| Dismiss alarm | `DELETE /v2/alarms/:gid/:aid` | n/a | alarm engine |

UniFi's documented API manages the network (devices, clients, firewall and DNS policy) but does not
report requests or raise alarms. That is the case for pairing: with a UniFi network, Shepherd's DNS
history supplies the requests, and the backend supplies the controls.

## Connections

Every router and firewall is connected in one place: **Connections**, at the top of the **Router**
screen. Each kind has its own row with a connect form, a switch and **Disconnect**:

| Connection | Credential | What it is read for |
|---|---|---|
| Firewalla, on the box | none | dashboard, exact live bandwidth, device names |
| Firewalla, through MSP | MSP personal access token | dashboard, exact bandwidth, device names |
| UniFi console | Integration API key | dashboard |
| eero | account sign-in with an emailed or texted code | device names, estimated bandwidth |
| UniFi controller sign-in | controller username and password | exact bandwidth |

More than one can be connected at once, and that is the point: a Firewalla supplies the dashboard
and the bandwidth while an eero account, whose mesh still knows every device by the name someone
typed into its app, supplies names. When two could supply the same thing, one is used: for bandwidth
a UniFi controller, then Firewalla, then eero ([TRAFFIC.md](TRAFFIC.md)); for the dashboard a
Firewalla, then a UniFi console. Each row says what it is being used for. `GET /api/connections`
returns all of them and no credential.

Connections used to be split between this screen and Bandwidth, where only one could be set up at a
time. The Bandwidth screen now shows what the reader is doing and links here.

## Device names

One device, one name, everywhere. **Device names** on the Router screen matches devices by MAC
address across Shepherd's own registry and every connected place that has names (a Firewalla, an
eero account) and keeps them the same (`internal/namesync`).

**The first sync keeps the most readable name.** For each device the names are scored, and the best
one is written to the others:

| Name | Example | Rank |
|---|---|---|
| Words a person would say | `Kitchen speaker` | best |
| Words joined like a hostname | `Kitchen-Speaker` | |
| One plain word, or words with a serial among them | `iPhone`, `Hue Bridge 41D7` | |
| A model or serial | `XP200M`, `PS5-1B3C5D` | |
| Only the maker's name | `ExampleCo Networks` | never copied |
| A MAC or IP address, `Unknown`, empty | `02005E00A1B2` | never replaces anything |

A name the place knows somebody typed (an alias in Shepherd, a nickname in eero) ranks above the
same kind of name a device reported for itself. When two names rank the same, Shepherd's wins, then
eero's, then the router's.

**After that, an edit anywhere goes everywhere.** Shepherd remembers the name it last saw for each
device in each place, so it can tell a rename from a name that was different all along. Rename a
device in the Firewalla app, the eero app or Shepherd and the other two follow. If two places are
edited between runs, the more readable name wins. Clearing a name is not an edit: the agreed name is
written back.

**Nothing is written until you have seen it.** *Check what would change* reads every place and lists
each device: the name it would get, why, what it is called now in each place, and where the name
would be written. *Sync now* does it once. *Keep in sync* repeats it every two minutes, and within
seconds of a rename made in Shepherd. Both ask first, and the API refuses either without
`confirm: true`. Every name written is kept, with the name it replaced, under **Recent changes** (the
last 200), so any of them can be put back by hand.

Things to know:

- **Case and punctuation do not count.** `xp200m` and `XP200M`, or a typed and a typographic
  apostrophe, are the same name and are left as they are in each place.
- **A place that cannot be written is still read.** With **Allow changes** off, or a Read Only
  token, a Firewalla's names are read and an edit made there still goes out, but nothing is written
  to it; the screen says how many names are waiting, and they are caught up once it can be written.
  UniFi's API cannot rename a device, so a UniFi console is only ever read.
- **Firewalla names are at most 32 characters**, so a longer name is cut there and kept whole
  elsewhere.
- **A name that fails to write** is reported, left alone for 30 minutes, then tried again.
- **Slow services.** After writing a name, a place may answer with the old one for a while. For ten
  minutes that is taken as a late answer rather than someone renaming it back.
- **With sync on, a name cannot be removed from one place only**: it comes back. Rename it instead.
- **The eero rename is unofficial**, like the rest of the eero client: it uses the call eero's own
  app makes (`PUT /2.2/networks/<id>/devices/<mac>` with a `nickname`). It was written from public
  open-source clients and tested against a fake, not yet against a live account.

State is kept in `names-sync.json` in the data directory. `GET /api/names` is the status,
`POST /api/names/preview` the dry run, `POST /api/names/sync` and `POST /api/names/auto` the writes.

## UniFi

Connect a UniFi console under **Connections** on the **Router** screen with an Integration API key (UniFi Network 9 or
newer: *Settings, Control Plane, Integrations, API Keys*). The address is your console's, such as
`https://192.0.2.10`; a console's certificate is usually self-signed, so there is a switch to accept
it, off unless you turn it on. The key is checked by reading the console once before it is stored,
is kept in `secrets.json` and never returned by any endpoint, and redirects are refused so it is
sent only where you typed. A site can be named; the default one is used otherwise.

What the published API gives Shepherd, and so what the screen offers:

- **Reading:** connected clients and UniFi devices, and the user-defined firewall policies (UniFi's
  built-in ones are left out, because pausing or deleting one is not something a dashboard should
  offer).
- **Changing**, behind **Allow changes**: pause or resume a policy (disable or enable it), delete a
  policy, and **block** a client. Policies also take schedules, below.
- **Not available:** creating a policy (the published reference does not describe the zone and
  traffic-filter bodies, and Shepherd does not guess at a firewall's), requests and alarms (UniFi's
  API has neither), renaming a device. For requests on a UniFi network, use Shepherd's own DNS.

One backend runs at a time. If a Firewalla and a UniFi console are both connected, the Firewalla
is used, because it also reports requests; switch it off to use the console.

## Firewalla, on the box

A Firewalla box is an ordinary Linux machine, and Shepherd is one static binary, so Shepherd can
run on the box itself ([FIREWALLA.md](FIREWALLA.md) installs it). There it reads the API the box serves on its own loopback address
(`http://127.0.0.1:8834`), the one Firewalla's app talks to (`internal/backends/fwlocal`). On the
Firewalla row under **Connections**, **Use this box** appears when that API answers; there is
nothing to type.

Compared with MSP:

| | On the box | Through MSP |
|---|---|---|
| Account and token | none | MSP account, personal access token |
| Requests and bandwidth | as the traffic happens | about six minutes late, in batches |
| Rules listed | all of them | the ones MSP exposes |
| Device names | knows which a person typed | cannot tell |
| Blocked requests | not read yet | included |
| Create a rule | not built | yes |
| Published API | **no** | yes |

That last row is the cost. The local API is not published: it is read from Firewalla's open source
(`controllers/netbot.js`, `api/routes/encipher.js` in github.com/firewalla/firewalla) and a firmware
update can change it. Shepherd makes only the calls that were checked against a running box:
`get hosts`, `get flows`, `get alarms`, `get policies`, and, behind **Allow changes**,
`set host` (rename), `cmd policy:enable`, `policy:disable`, `policy:delete` and `alarm:delete`.

The API has no authentication, which is safe only because it listens on loopback. Shepherd
therefore refuses any address for it that is not this machine's loopback address: it cannot be
pointed at a box across the network. For a Shepherd running anywhere else, use MSP.

Everything below about what the dashboard reads and changes applies to both, except where the table
above says otherwise.

## What it does today (Firewalla)

Connect an account under **Connections** on the **Router** screen: your MSP address, a personal
access token, and optionally one box's ID.

**Expect a delay.** A Firewalla box hands its flows to MSP in batches, and MSP's API shows them
several minutes after the traffic (about six minutes on the box this was checked against). So
requests and bandwidth appear some minutes after connecting, then arrive in steps. The screens say
so while they wait. Devices, rules and alarms are read straight away.

**Reading** (always on once connected, every 30 seconds):

- **Requests.** Each flow becomes a history entry of type `FLOW`, so it appears in Activity and
  History beside the lookups Shepherd answers itself, with the device resolved by MAC. A flow MSP
  blocked is a blocked entry. Each flow is ingested once, and a restart resumes from the last flow
  seen rather than repeating the last few minutes.
- **Alarms.** MSP's active alarms are raised as `backend-alarm` alarms, once each. Alarms older
  than a day when Shepherd first connects are shown but not announced.
- **Devices and rules** are listed on the screen. Devices are matched to Shepherd's by MAC.
- **Bandwidth** comes from the same flows ([TRAFFIC.md](TRAFFIC.md#firewalla-msp)).

**Changing** is a separate switch, **Allow changes**, off by default and independent of what the
token permits, so connecting for reading never gives the portal the power to change a firewall.
With it on:

- **Block** a request: one click on a request row proposes "block this domain for that device",
  DNS-only (Firewalla's default and the gentlest block).
- **Add a rule** from a form: block or allow, a domain, address, network, category, app, region or
  target list, for every device or one.
- **Pause, resume, delete** a rule. **Rename** a device. **Dismiss** an alarm.

Every change is previewed in words, confirmed in a dialog, and refused by the server unless it says
`confirm: true`, so nothing can change a rule by accident. A rule that applies to every device says
so before it is made. Each attempt, successful or not, is recorded in the change log on the screen
and in Shepherd's log. A Read Only token is refused up front, before any request is sent.

A rule with no box named applies to every box on the account, which is how MSP treats a rule with
no `gid`.

## Dashboard mode

Set `dns.enabled = false` and Shepherd serves no DNS at all: no listener is bound, the DNS
self-test, the link watch on the DNS address and the lookup-based behaviour checks are not started
(they would only report that nothing asks Shepherd anything), and the process is the portal plus
whatever backend you connected. Your router or firewall keeps doing the filtering; Shepherd shows
and controls it. Remove the line, or set it to `true`, to serve DNS again; nothing else changes.

## Schedules (time-window rules)

Neither product lets Shepherd create its native time-limit rules over the API (Firewalla's
`POST /v2/rules` takes `block` and `allow` only), but both let it pause and resume a rule. So
Shepherd holds the window itself: on a rule, **Schedule** picks days and a start and end time, and
Shepherd pauses the rule outside that window and resumes it inside, checking every 30 seconds.
"Block games on school nights, 21:00 to 07:00" is a block rule with a schedule. A window that ends
before it starts runs past midnight; the morning part belongs to the day it started on. Times are
in the browser's time zone, because a container's own clock is usually UTC.

A scheduled rule follows its schedule: resume it by hand outside the window and the next check
pauses it again, so remove the schedule to take the rule back. A change that fails (a box offline)
is retried every five minutes rather than every check. Schedules need **Allow changes** and are
kept in `backend-schedules.json` in the data directory.

Firewalla's own **time-limit** rules (a daily quota of minutes) are shown with how much is used,
and can be paused, resumed and deleted, but not created from Shepherd.

## Filtering requests by device

The request list can be narrowed to one device. That asks Firewalla itself
(`device.id:"AA:BB:..."` in the query), so it reaches past the recent requests Shepherd already
holds.

## Blocked devices

UniFi stops listing a client once it is blocked. Shepherd remembers each device it blocks (stored in
`backend-<name>-blocked.json` beside the other state), keeps it on the Devices list marked
**blocked**, and offers **Unblock** there. If the console later reports the client connected, it was
unblocked elsewhere and Shepherd forgets it. A device blocked in the console itself, not through
Shepherd, is not known to Shepherd and still has to be unblocked there.

## Not built yet

- Target-list management.
- Creating UniFi firewall policies.

## Verified against

Reading has been run against a live MSP account and a box in router mode (2026-11-21): devices,
flows with the `ts:` range query, alarms, rules and boxes all answer as documented. The on-box
backend's reading was run against the same box the same day (`TestLiveBoxReadOnly`, which is
skipped unless `FWLOCAL_LIVE_URL` points at a box's local API); its writes have been run against a
fake only. Writes (rules,
renames, dismissing alarms) were written from Firewalla's published documentation and run against a
fake MSP; they have not yet been exercised against a real box. The eero rename is in the same state.
Preview a name sync before applying one.
