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

## UniFi

Connect a UniFi console on the **Router** screen with an Integration API key (UniFi Network 9 or
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

## What it does today (Firewalla)

Connect an account under **Read from your router** on the Bandwidth screen, then open **Router**
in the sidebar.

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

Everything here was written from Firewalla's published documentation and examples and run against a
fake MSP, not a live account. The query syntax (`ts:`, `box:`, `status:`) and the data models were
checked against docs.firewalla.net; the request and response shapes of writes were not exercised
against a real box. Run it read-only first.
