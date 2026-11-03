# DHCP mode: Shepherd serves the leases and translates what it forwards

A design, written 2026-11-03, for the half of [GATEWAY.md](GATEWAY.md) that can be had **without a
second NIC, without a WAN client, and without demoting the eero**.

Status: **design agreed 2026-11-03, implementation in progress.** The decisions are listed at the
end, each marked with who made it. Three of them went against this document's own recommendation and
are recorded as the maintainer's, with the recommendation left visible rather than rewritten away.

## The name, first, because the obvious name is wrong

This is what Firewalla calls **DHCP mode**, not Simple mode. Firewalla's *Simple* mode is ARP
spoofing — it is what Shepherd's Watch mode already is. Firewalla's *DHCP* mode is this: you turn
the router's DHCP server off, the box serves the leases, hands chosen devices itself as their
gateway, and masquerades their traffic out to the router. Firewalla's own page for it lists the same
two costs this document lists: **double NAT**, and **the router's DHCP has to be off**. Worth
knowing before anyone leans on the comparison: Firewalla now steers people away from both modes
toward Bridge or Router mode on its newer hardware.

So Shepherd would have three *placements* rather than three profiles, and DHCP mode slots between
the two that exist:

| Placement | How traffic reaches Shepherd | Second NIC | The eero still |
|---|---|---|---|
| **Guard** | It does not; only DNS does | no | routes, serves DHCP, does Wi-Fi, does IPv6 |
| **Watch** | One-sided ARP steering, outbound only | no | routes, serves DHCP, does Wi-Fi, does IPv6 |
| **DHCP mode** (this document) | The lease says Shepherd is the gateway | **no** | routes (for Shepherd), does Wi-Fi, does IPv6 |
| **Gateway** ([GATEWAY.md](GATEWAY.md)) | Shepherd is the router | yes | is radios only |

The row that matters is the third column. DHCP mode needs no hardware that is not already in the
rack, which is why it can be built and staged now while Gateway mode waits on a NIC.

## Why this is buildable now, when GATEWAY.md ruled it out

[GATEWAY.md](GATEWAY.md) has a table of placements that do not work, and one of its rows is exactly
this shape:

> One-armed router on the existing flat `/24` — devices point at Shepherd, which forwards to the
> eero → *Forwarding a subnet back onto the segment it arrived from is the hairpin hazard Watch mode
> already refuses on this host.*

That row was right about the hazard and wrong about the conclusion, and the measurement of
2026-11-02 is why. The eero reflects a forwarded frame back at Shepherd when that frame leaves the
interface it arrived on **carrying a foreign source address**. Source NAT removes the foreign source
address, and with it the reflection. Measured live, one host steered to the NAS:

| | without NAT | with `MASQUERADE` |
|---|---|---|
| big first segment delivered | 0–1 of 10 | 10 of 10 |
| `gh api`, 25 calls | 1–9 ok | 25 ok |
| reflected frames, 3 trials | ~1400 | 0 |
| throughput | — | 24 MB/s up, 46–75 MB/s down |

So the hairpin is answered by **translation**, not avoided by topology. That is the whole unlock,
and it is the same unlock Gateway mode needs: NAT is not an incidental part of this design, it is
the part that makes it work at all.

Two things that measurement does **not** say, and this document should not pretend otherwise:

- It was one host on one evening. It establishes that the reflection stops; it does not establish
  that a household's traffic through one NIC, hairpinned, behaves well. That is what the staging
  below is for, and it is why the per-device switch exists.
- It says nothing about the eero's own behaviour under load when a large share of the LAN's traffic
  arrives from one MAC. Nobody has measured that, on this network or any other.

## What DHCP mode gets, and what it costs

**Gets**, and these are the things Watch mode structurally cannot have:

- **Both directions of every routed device's IPv4 traffic**, because the return path comes back
  through Shepherd's NAT by construction. Downloads are *measured*, not estimated from
  acknowledgements ([TRAFFIC.md](TRAFFIC.md)), and QUIC and other UDP stop being blind spots.
- **Per-destination bytes**, once accounting is wired up, for the same reason.
- **A real pause**, and later rate limits: a device whose gateway is Shepherd can actually be
  stopped, which is not true of one-sided steering.
- **No ARP spoofing anywhere.** The lease is the mechanism. Nothing lies to anything, there is no
  loop brake, no steering health check, and nothing to recover from when Shepherd stops talking.
- **DHCP-sourced device identity**, which the registry already has a name for
  (`devices.SourceDHCP`) and no source for: hostname, client identifier, vendor class and
  requested-option fingerprint, straight from the client, for every device, including ones that
  never send mDNS and never ask Shepherd for a name.

**Costs**, each of which is real:

- **Double NAT for routed devices.** Shepherd translates to the eero, the eero translates to the
  internet. What breaks is inbound reachability for *routed* devices: a port forward on the eero
  now points at Shepherd, not at the device; UPnP and NAT-PMP requests from a routed device arrive
  at Shepherd, which does not implement the server side (`internal/upnpigd` is a *client*, for
  reading the eero's table); and a game console's NAT type gets worse. The **PS5 should not be
  routed**, and the design makes that the default rather than a warning (see below).
- **Every routed byte crosses the one NIC twice.** 10 Gb of NIC is 5 Gb of hairpinned throughput at
  best, before NAT and conntrack. For a household on a consumer internet service that is not a real
  ceiling, but it is the ceiling, and it is worth stating that this is the price of not having a
  second NIC.
- **Shepherd becomes load-bearing for the routed devices' internet.** Not for everything, which
  is the main difference from Gateway mode — but for every eligible device once routing is on, which
  is close enough to the whole house to be treated as the whole house. The failure behaviour below is
  the most important section of this document for that reason.
- **The eero's DHCP has to be off.** There is no way around this one, and it is the step that cannot
  be staged per device. It is also the only step that is not reversible in seconds, which is why the
  rollback is written down and timed before it is needed.
- **No WAN-side visibility.** Shepherd sees LAN-to-eero, which is after nothing and before the
  eero's own NAT. That is fine for per-device accounting and useless for anything that needs the
  public address of a flow.

## The shape: the lease decides, not a filter

The single idea the whole design rests on:

> **Whether Shepherd routes a device is a property of the lease it hands out, not of a packet rule.**

DHCP option 3 (`router`) is one address per lease. Shepherd chooses it:

- **the eero's address** → that device talks to the eero directly, exactly as today. Shepherd is
  not on its path at all. No NAT, no forwarding, no hairpin, no risk.
- **Shepherd's own LAN address** → that device sends everything off-segment to Shepherd, which
  forwards and masquerades it to the eero.

What follows from it is worth holding onto: there is no per-packet classification, no set of client
addresses to keep in sync with a policy, and no "which rule won" to debug. A device is routed if and
only if its lease says so, and unrouting it is a lease renewal rather than a rule change.

### Routing is all-or-nothing (the maintainer's decision, 2026-11-03)

**Decided: when routing is on, every eligible device is routed.** There is no per-device opt-in to
work through. This is the maintainer's call and it is recorded as such, because this document
recommended the opposite.

The recommendation was per-device opt-in, defaulting to not routed, on the grounds that the unit of
risk would then be one device and the rollout could be one device a night. The argument that wins
instead is that a household bandwidth picture assembled from whichever devices someone remembered to
tick is a half-truth presented as a number, and that half-truths are the specific failure this whole
line of work exists to end — Watch mode's download estimate was exactly that.

So "eligible" carries the weight, and it means the same thing it means in Watch mode
(`internal/watch/policy.go`): every device, minus a refusal list that is a safety property rather
than a preference, minus the per-device **opt-out**. Concretely:

- **Routing has one switch**, `[dhcp] route = true`, and turning it on routes the whole eligible
  segment at the next renewal. There is no "route this one device" setting.
- **The refusal list below still applies**, and is not overridable by that switch. It is not an
  opt-in mechanism; it is the set of devices for which routing is wrong, the way Watch mode refuses
  to steer the gateway or its own interfaces.
- **A device can still be opted out individually** (`Device.Route = "off"`), the same three-position
  switch the registry already has for Watch (`auto` / `on` / `off`), where `auto` now means
  "whatever the mode says". That is an escape hatch for the device that turns out to hate it, not a
  rollout mechanism.
- **The staged rollout therefore happens in the stages, not in the device list.** Stage C is a
  parallel segment with chosen devices; Stage D is the whole house leased by Shepherd and routed by
  the eero, which is `route = false` and a complete, safe resting place; Stage E flips `route` on.
  The granularity that the per-device design would have given on Stage E is traded for a rollout
  that cannot end in a permanently half-measured house.

The cost of the trade, said plainly: **Stage E is one step, and it moves the whole household's
IPv4 traffic onto the NAS at once.** Mechanism 1 under "Failure behaviour" is what makes that
survivable — an unhealthy Shepherd hands out the eero again and the house drifts back by itself
within a renewal interval — and the kill switch is what makes it reversible on purpose. Both are
load-bearing in a way they would not have been under per-device opt-in, so both are tested first.

### What is never routed

Refused the way Watch mode refuses to steer (`internal/watch/policy.go`), and for mostly the same
reasons, checked both where the lease is composed and again at the NAT reconcile:

| Never routed | Why |
|---|---|
| The eero itself, and anything holding its address | It is the next hop; routing it through Shepherd is a loop |
| **Every one of this host's own interfaces**, by MAC and by address | A NAS with wired and wireless on one LAN looks like two devices. Routing Shepherd through Shepherd is the failure Watch mode has a whole paragraph about |
| Network infrastructure: routers, mesh nodes, access points, switches, bridges | The network depends on them, and a mesh node that NATs through a NAS is a new kind of bad day |
| **Thread border routers and Matter devices** (`_meshcop`, `_thread`, `_matter`) | A whole smart home hangs off these and the failure is silent ([IPV6.md](IPV6.md)) |
| **Game consoles**, by default and by type | Double NAT is what makes a console's NAT type worse, and this household has a PS5. Overridable per device, with the consequence stated in the portal where it is overridden |
| Devices marked **Excluded** | Excluded means opted out, and this is a thing to be opted out of |
| Anything whose own route switch is **off** | The per-device opt-out |

Two notes on that table. The **game console** row is the one place where an all-or-nothing switch
needs a knob anyway: `route_consoles` is off by default, because double NAT is what makes a
console's NAT type worse and this household has a PS5 that would notice within one match. It is a
single setting rather than a per-device decision, and the portal states the consequence where it is
turned on.

And note what is **not** on the list, deliberately: a device can still be *leased* by Shepherd while
being routed to the eero. The refusals above are about the `router` option only. Shepherd serves the
whole segment's DHCP or none of it — a half-served segment is two servers answering, which is the
thing the next section exists to prevent.

## The two servers must not both answer, and that needs a mechanism

This is the part that can take the house offline, so it gets a mechanism rather than a note in a
README. Two DHCP servers on one segment is not a conflict the protocol resolves: the client takes
whichever `DHCPOFFER` it likes, which in practice means whichever arrived first, which in practice
means it varies per device and per boot. Half the house on each gateway, non-deterministically, is
the worst state this feature can reach, and it is reachable by one forgotten checkbox.

So DHCP mode has **three states**, not a boolean:

### `off` (the default, and what every existing install keeps)

No socket is opened. Nothing changes. The configuration key exists and is `false`.

### `observe` — listen, decide, log, transmit nothing

Shepherd opens a **receive-only** listener and watches the segment's DHCP traffic: the eero's
`DHCPOFFER`s and `DHCPACK`s, and every client's `DHCPDISCOVER` and `DHCPREQUEST`. It:

- **feeds the device registry** from what it hears — hostname, vendor class, client identifier,
  parameter-request-list fingerprint — which makes `devices.SourceDHCP` real on day one and is
  useful on its own, whatever happens to the rest of this;
- **builds the lease picture** the eero is actually handing out, so the portal can show real
  current leases before Shepherd serves anything;
- **runs the allocator in dry run**: for every real `DHCPDISCOVER`, it composes the lease it *would*
  have offered and records it, including whether its answer differs from the eero's;
- **never writes to a socket.** Not once. The listener has no send path.

This is the part of the design that is most worth having and is not in GATEWAY.md. GATEWAY.md
worries, correctly, that under "the eero keeps DHCP until cutover" the DHCP implementation gets its
only test on a parallel segment and then meets the whole household at once. Observe mode is how it
meets the whole household first, safely: every awkward device in the house — the printer, the TV,
the Thread gear, whatever has historically been fussy — exercises Shepherd's decoder and allocator
for days or weeks, with zero network risk, because the code physically cannot answer. A decoder that
has parsed every real client in the house without an error is a different proposition from one that
has parsed a parallel segment's laptop.

It is not a complete test. It exercises **receive and decide**; it does not exercise **transmit**,
and transmit is where broadcast flags, relay agents and the unicast-to-an-unconfigured-client case
live. Those get tested on the bench. But it removes the larger half of the risk from cutover day.

### `serve` — answer, and refuse to if something else is answering

Serving is gated on all of the following, and Shepherd reports which one is unmet rather than
failing silently:

1. **The configuration says so** (`[dhcp] mode = "serve"`), and
2. **the portal confirmation has been given** — a typed confirmation, like the destructive actions
   the portal already guards, because this one is destructive to the household's internet, and
3. **no other DHCP server has answered on this segment** for a configurable settling period
   (default 60 seconds), and
4. **the lease store loaded**, or was absent and started empty, without a parse error.

Rule 3 is the live interlock, and it does not stop at startup: the listener keeps running while
Shepherd serves. A `DHCPOFFER` or `DHCPACK` from any address that is not Shepherd's, at any time,
means the eero's DHCP came back — a firmware update, a factory reset, a second eero introduced — and
Shepherd **stops serving**, raises a critical alarm (`internal/alarms`), and says so in the portal.
It does not try to win the race. Two servers answering is worse than one, and the one that should
survive is the one that was there first.

The symmetric case, Shepherd starting while the eero is still serving, is caught by the same
listener before Shepherd ever answers. Which means the maintainer can set `mode = "serve"` *before*
turning the eero's DHCP off, watch the portal say "another DHCP server is answering; not serving",
turn the eero's DHCP off, and watch it start — rather than having to get the order right under time
pressure.

## Failure behaviour: fail closed is the wrong answer here

[GATEWAY.md](GATEWAY.md) chose **fail closed** for Gateway mode, and that choice was right for a
Shepherd that holds the WAN: there, the alternative is a router that keeps forwarding unfiltered
traffic after its policy engine has died.

DHCP mode is a different situation and takes the opposite decision, which should be explicit rather
than a quiet inconsistency:

**DHCP mode fails open, by three mechanisms, and still cannot avoid taking routed devices offline if
Shepherd dies outright.** Both halves of that sentence are true and both matter.

What fails open:

1. **Unrouting is a renewal, and renewals are frequent.** The lease time is short on purpose
   (default 10 minutes, so renewal at about 5). A Shepherd that is *running but unhealthy* — it
   cannot install NAT rules, the forwarding sysctl is not set, its uplink check is failing — stops
   putting its own address in the `router` option and hands out the eero's instead. Every routed
   device migrates back to the eero within one renewal interval, on its own, with no action from
   anybody. This is the mechanism that matters most, because "running but broken" is the common
   failure, not the dramatic one.
2. **The kill switch.** One button, in the idiom of Watch mode's: unroute everything now. It
   rewrites every lease's `router` option to the eero, sends a `DHCPFORCERENEW` where the client
   supports it, drops the NAT rules, and **stays off across restarts** until re-armed in the same
   place. Worst case without `FORCERENEW` is one renewal interval.
3. **Shepherd keeps serving leases with the eero as gateway** when routing is off for any reason. A
   device that asks still gets an address. DHCP service and routing are separate failures.

What cannot fail open, stated plainly because it is the thing to weigh:

- **If the Shepherd process dies, routed devices lose IPv4 internet** until either Shepherd comes
  back or their lease is renewed by something. Nothing is renewing it — the eero's DHCP is off — so
  the recovery is Shepherd restarting (`restart: unless-stopped` does this in seconds) or the
  manual rollback.
- **If the host dies, so does DHCP for the whole segment.** Devices keep their current leases and
  keep working until those expire; new arrivals get nothing. A short lease time, which helps
  everything else in this design, *hurts* here: 10-minute leases mean the segment starts failing
  about 10 minutes after the NAS goes down, where a 24-hour lease would have hidden it for a day.
  This trade-off is real, it has no clever resolution, and the configurable lease time is how the
  maintainer picks a point on it. The recommended default sits on the side of fast recovery because
  a NAS that is down is a problem to be fixed, not survived.
- **The manual rollback is: turn the eero's DHCP back on.** It is one checkbox, it needs no
  Shepherd, and every device converges within a lease time. Practise it once at Stage 1 so it is a
  known two-minute job rather than a discovery.

There is deliberately **no dead man's switch** here and no nftables element with a timeout. That
mechanism exists in GATEWAY.md to make the kernel stop forwarding when Shepherd stops proving it is
healthy. In DHCP mode its effect would be to cut off routed devices *faster* when Shepherd breaks,
which is precisely backwards: here the kernel's rules outliving the process is the benign case, not
the dangerous one. Mechanism 1 above is the inversion that fits this mode — Shepherd must keep
*asserting* that a device should be routed, once per renewal, or the device drifts back to the eero
by itself.

## IPv6: the hard rules are kept, not rescoped

[GATEWAY.md](GATEWAY.md) has to rescope two of [IPV6.md](IPV6.md)'s hard rules, because a router
advertises itself. **DHCP mode does not, and this is a genuine advantage of it:**

- Hard rule 1, *never run a Router Advertisement or DHCPv6 server on the LAN* — **kept.** Shepherd
  sends no RAs and no DHCPv6. The eero stays the IPv6 router.
- Hard rule 5, *never change a client's IPv6 default gateway* — **kept.** Nothing in this design
  touches IPv6 routing.
- Rules 2 and 3 (never filter or rewrite neighbour discovery or mDNS; never strip AAAA) — kept, as
  everywhere.

The consequence is the honest cost: **a routed device's IPv6 traffic does not pass through Shepherd
and is not accounted.** On this LAN that is nearly free, because [GATEWAY.md](GATEWAY.md) already
established there is no global IPv6 route — unique-local only, so no IPv6 internet. On a LAN that
*does* have IPv6 internet, DHCP mode's accounting would be an IPv4-shaped view of a dual-stack
household, and the portal must say so rather than imply completeness. Full coverage needs Gateway
mode, and that is one more thing Gateway mode is for.

The Thread and Matter risk, which is the scariest line in GATEWAY.md's risk list, is therefore
**mostly absent from DHCP mode**: no second source of Router Advertisements, no change to IPv6
neighbour discovery. What remains is that a Thread border router needs an IPv4 lease like anything
else, which is why it is on the never-routed list and why the lease path has to be boring and
correct for it.

## Choosing which range the LAN uses

The addresses a household sees are a preference, not a fact: somebody who wants their LAN to read
`10.0.0.x` rather than `192.168.1.x` should be able to say so. So the range is a thing the operator
picks in the portal — the prefix, Shepherd's address in it, the router's address in it, and the
part of it handed out dynamically — and it overrides what the configuration file and the interface
say, with no restart.

**But Shepherd is not the router here.** It serves the leases and masquerades what it forwards; the
router is still the way off the segment for every device Shepherd does not route, and the next hop
for the ones it does. So a range the router does not itself use cannot be served, and the valuable
part of this feature is not the picker — it is being told exactly what has to change before it can
work, rather than finding out at two in the morning.

That is what the collision check is. A chosen range is compared against the network as Shepherd can
actually see it — this host's own addresses, the gateway the default route points at, and every
address the device registry knows is in use (which it learns from DNS queries, the neighbour table,
mDNS, and, once this mode is watching, from DHCP itself). The result is a list, blocking first,
each written as what to change:

| | Severity | Why |
|---|---|---|
| This host has no address in the chosen range | **blocking** | Shepherd could not answer a client it had just addressed |
| The router answers somewhere else | **blocking** | Every device Shepherd does not route would be handed a gateway that does not exist |
| A device holds an address inside the new pool that Shepherd did not hand out | **blocking** | The pool would hand it out a second time, and both devices would then be wrong |
| Devices are outside the new range | warning | They move at their next renewal; anything hand-configured has to be changed by hand |
| A reservation is outside the new range | warning | It cannot be honoured there |

**A range that does not fit yet is stored anyway**, and that is deliberate: the point is to write
down where you are going and be told what to change. Serving simply stops while a blocking conflict
stands, in the same place and the same way it stops when another DHCP server is answering. The
intended order is: pick the range, read the list, change the router's LAN to match, watch the list
empty, and only then is anything served.

The range must be a private one — one of RFC 1918's three — between a /16 and a /30. A household LAN is one of those three, and a public range typed in by mistake would be a
network that cannot reach the thing it is pretending to be.

## The lease store

Two files in `data_dir`, for a reason:

- **`dhcp.json` — reservations and the mode's own state.** User intent, edited in the portal, rarely
  written, the same kind of file as `policy.json`. It also holds the kill switch's armed/disarmed
  state so that survives a restart.
- **`dhcp-leases.json` — the leases.** Observed and churning: written on every allocation and on a
  timer for renewals, the same shape as the device registry's own snapshot
  (`internal/devices/persist.go`): atomic temp-file-and-rename, mode 0600, a version field, and a
  dirty flag so an unchanged store is not rewritten.

Keeping them apart means a renewal storm never rewrites the file holding the maintainer's typed
reservations, and a corrupt lease file never loses them. A lease file that fails to parse is moved
aside and started empty — leases are recoverable in one renewal interval; refusing to start is not
recoverable at all. A `dhcp.json` that fails to parse **does** refuse to start, because silently
dropping reservations is how a printer changes address.

A lease record is: MAC, client identifier (option 61, which is the real key when a client sends
one), address, hostname, vendor class, the fingerprint, allocated-at, expires-at, last-renewed, the
`router` option actually handed out, and the device ID the registry resolved it to. That last field
is what lets the portal's lease list and device list be the same list.

## Reservations

A reservation is the maintainer's statement that a MAC gets a particular address, and it is the
feature the maintainer asked for by name. The model:

- **Keyed by MAC**, with the client identifier recorded when one was seen but not used as the key: a
  MAC is what the portal shows, what the device registry indexes, and what a person reads off a
  label.
- **Address optional.** A reservation with no address is still useful: it is where a reserved
  *hostname* and the per-device routing choice live for a device that does not need a fixed address.
- **Reservations win over leases, and over the pool.** On a `DHCPDISCOVER` from a reserved MAC,
  Shepherd offers the reserved address whatever the lease store says. If another device currently
  holds that address, its lease is revoked (and it gets a new one on its next request) — the
  reservation is the intent, the lease is a cache.
- **An address inside the dynamic pool is allowed**, and it is the ordinary case: pinning a device
  to the address it already holds, which is nearly always a pool address. An earlier draft of this
  document refused one, on the grounds that handing an address out twice is the commonest way to
  break a DHCP server. That was right about the danger and wrong about where it is handled — the
  allocator already takes somebody else's reservation out of the pool walk, so an in-pool
  reservation can only ever go to the device it names. The portal says when a reserved address sits
  inside the pool, because shrinking the pool past it is tidier, and says it as a note rather than
  a refusal.
- **Creating one from a device is the primary path, and it is one switch.** Every device on the
  Devices screen carries a **Reserve this address** switch while DHCP mode is wired in: on pins it
  to the address it holds now, off unpins it. The DHCP screen's own lease list has the same action,
  and typing a MAC by hand works too, for a device that is not on the network yet. A device the
  registry knows only by address — a container, or one seen only through DNS — is offered no switch
  at all, because a reservation is keyed on hardware and a switch that cannot work is worse than
  none.
- **Reservations are not the routing opt-out.** Which gateway a device gets is a property of the
  *device* (`Device.Route`, alongside the existing `Device.Watch`), not of its reservation, so it
  can be set from the device screen for any device whether or not it has a reserved address. The
  registry already has the exact idiom for this: a three-position switch, `auto` / `on` / `off`.

`auto` means **whatever the mode says** — routed when `route = true` and the device is eligible,
otherwise not. `off` is the escape hatch for a device that turns out to hate being routed, and `on`
overrides the eligibility refusals for everything except this host's own interfaces and the eero,
which can never be routed whatever a device record says. That mirrors Watch mode's "Always watch",
including the part where some refusals cannot be overridden from the portal.

## How forwarding and NAT get configured

The line from GATEWAY.md holds without change: **Shepherd configures the kernel, it is not the
datapath.** No Shepherd code on the per-packet path, no inheritance from `internal/intercept`.

What has to be true on the host while any device is routed:

```
net.ipv4.ip_forward = 1
net.ipv4.conf.<lan>.send_redirects = 0     # a redirect would tell the client to bypass Shepherd
nft table ip shepherd {
  chain postrouting { type nat hook postrouting priority srcnat;
    ip saddr @routed oifname "<lan>" masquerade }
  chain forward { type filter hook forward priority filter;
    ip saddr @routed accept; ip daddr @routed ct state established,related accept }
  set routed { type ipv4_addr; }           # the routed devices' current addresses
}
nf_conntrack_acct = 1                      # per-flow byte counters, both directions
```

`send_redirects = 0` is easy to miss and undoes the whole thing when missed: the kernel's default
behaviour, on being asked to forward a packet back out the interface it arrived on, is to tell the
client "go direct next time". That is a correct ICMP redirect and the exact opposite of what this
mode wants.

The set `routed` is the one piece of state the kernel needs, and it is reconciled from the leases:
Shepherd owns the table `shepherd` entirely, so it can be replaced atomically and deleted
completely, and nothing Shepherd writes can disturb another tenant's rules.

**Recommended mechanism, v1: drive the `nft` binary**, behind an interface with an injectable
command runner — the seam `internal/devices/neighbor.go` already uses for the neighbour table, and
the same testability story as `watch.Platform`. Reasons: it is what every router distribution does,
the ruleset Shepherd intends is a string that can be logged and read by a human before it is
applied, and it is perhaps 150 lines rather than the 1,000-odd of a hand-written `nf_tables` netlink
client. The cost is a dependency on a binary in the runtime image: `deploy/docker/Dockerfile` is
Alpine, so it is one `apk add nftables`, and a host install needs `nft` present — which Shepherd
must check and report, not discover at the moment it matters. A native netlink client is the right
follow-up when that dependency becomes a problem, and it is the thing GATEWAY.md leaves open.

Accounting over ctnetlink is **explicitly not in this piece of work.** It is item 4 of GATEWAY.md's
build list, it is the same code whichever mode feeds it, and it is a substantial piece on its own.
DHCP mode's job here is to create the return path that makes accounting possible. Until accounting
lands, a routed device's bandwidth can come from the kernel's own counters on the `routed` set,
which is per-device but not per-destination, and the portal should label it as such.

## The DHCP implementation: the library's codec, Shepherd's socket

There was no DHCP code in the tree and no DHCP library in `go.mod`. The options were
`github.com/insomniacslk/dhcp` (the maintained general-purpose Go DHCP library, the basis of
CoreDHCP), the heavier `coredhcp` server framework, or writing it.

**Decided by the maintainer, 2026-11-03: use `github.com/insomniacslk/dhcp`.** This document
recommended hand-rolling it, in the house pattern of `internal/arp/codec.go`, `internal/ndp`,
`internal/upnpigd`'s SOAP and SSDP, and the standard-library-only SMTP client in
`internal/accountability`. The argument that wins instead is the one the recommendation itself
named as its own risk: **the long tail of odd clients**. The ways DHCP servers surprise people are
almost all in that tail — the broadcast flag, a client that unicasts a `DHCPREQUEST` to a server it
is not talking to, `DHCPINFORM`, a client re-requesting an address it holds from a different
network, Windows address-conflict detection, option-82 insertion — and a library that has been
parsing real clients in production for years has met more of them than this project's tests will.
The code that decides what address every device in the building gets is a reasonable place to prefer
someone else's mileage over our own reading of RFC 2132.

How it is used, which is narrower than "use the library":

- **`dhcpv4` for the wire format only**: decode, encode, and the typed option accessors. This is the
  part the decision is about and the part where the mileage lives.
- **Shepherd owns the socket and the serve loop**, rather than the library's `server4`. Three
  reasons, each of which `server4` would fight: observe mode must be *physically unable to
  transmit*, which means a listener with no send path rather than a handler that chooses not to
  reply; the rogue-server interlock has to see the eero's own `DHCPOFFER`s, which a server loop
  filtering for requests addressed to it will not surface; and the decision of what to put in
  option 3 belongs to Shepherd's device policy, not to a handler signature.
- **One new module in the build graph.** `dhcpv4` and its siblings `iana`, `rfc1035label` and
  `interfaces` need only `github.com/u-root/uio` beyond `golang.org/x/sys`, which is already a
  dependency. `server4` is what would have pulled in `mdlayher/packet`, `mdlayher/socket`,
  `jsimonetti/rtnetlink` and `mdlayher/netlink`; not using it keeps all four out.
  `docs/THIRD-PARTY.md` gains one entry (BSD-3-Clause).

What stays from the hand-rolled plan, because it was never really about the codec:

- **The conservative subset.** `DISCOVER`/`OFFER`/`REQUEST`/`ACK`/`NAK`/`DECLINE`/`RELEASE`/`INFORM`
  and nothing else. No relay-agent support — this is one flat segment, and a relayed request is
  logged and refused rather than half-handled. No PXE, no option 82, no failover protocol.
- **Observe mode on the live LAN** as the main interop test: the library's decoder, Shepherd's
  allocator, and every real client in the house, for as long as the maintainer likes, with no
  ability to answer.
- **A fuzz test** (`go test -fuzz`) over Shepherd's own handler, seeded from what observe mode
  collects, so what is fuzzed is the decision layer rather than the library's parser.
- **Stage C's awkward-device list** from GATEWAY.md, unchanged and still required.

## What has been verified, and what has only been reasoned about

Worth separating, because this is the kind of feature where the difference
matters more than usual.

**Verified in software, with tests that run in CI:**

- A whole lease over real UDP sockets with the real encoder on both sides:
  `DISCOVER` → `OFFER` → `REQUEST` → `ACK`, a renewal, a refusal of somebody
  else's address, and a release.
- The allocator's order of preference, the reservation rules (including the
  one that refuses an address inside the dynamic pool), the lease store's
  persistence and its recovery from a corrupt file.
- The serve gate refusing for each of its reasons, including another DHCP
  server answering — and stopping, with a critical alarm, when one appears
  while it is already serving.
- The fail-open path: a kernel that will not take the rules makes routing
  stop by itself, and the next lease carries the router's own address in
  option 3 while leasing carries on.
- The exact nftables rule set, as a string, before it is applied.
- The portal screen against a running build on loopback, including the
  reservation form refusing an address inside the pool.

**Not verified, and only reasoned about:**

- **Port 67 itself.** Every test binds a high port; nothing here has bound 67
  or 68, or set `SO_BROADCAST` or `SO_BINDTODEVICE`.
- **Broadcasting to a client that has no address yet**, which is every client
  the first time. See the note on `replyTo` in the code: a UDP socket cannot
  unicast to an unconfigured client, so Shepherd broadcasts, and a raw frame
  socket is the proper fix.
- **Any real client.** No printer, television, console or phone has spoken to
  this code. That is what observe mode on the live LAN is for, and it is why
  it comes before serving.
- **The hairpin under a household's load.** The NAT measurement was one host
  on one evening. It establishes that the reflection stops; it does not
  establish that a whole household's traffic through one NIC behaves well.
- **nft on the target host.** The reconciler is tested through an injected
  command runner, so what is verified is what Shepherd would run, not that
  the NAS accepts it.

## Staging

Each stage is finishable and verifiable on its own, and the first three carry no risk to the
household at all.

**Stage A — the codec and the allocator, on a bench.** Unit tests, fuzzing, and a loopback test that
runs a real client against the server over a pair of virtual interfaces. No live network. The CI
gates cover this stage entirely.

**Stage B — observe mode on the live LAN, off to one side.** `mode = "observe"`, which cannot
transmit. Run it for days. What it proves: the decoder handles every device in the house, the
registry gains DHCP-sourced names, and the allocator's dry-run answers match what the eero actually
hands out. What it cannot prove: anything about transmitting.

**Stage C — serve on a parallel segment.** A spare switch, a handful of deliberately awkward devices,
the eero still serving the household. This is where transmit, NAT and the hairpin get exercised for
real, and where the rollback gets practised and timed.

**Stage D — cutover, with nothing routed.** Shorten the eero's lease time a day or two in advance,
set Shepherd to `serve` and watch it refuse because the eero is still answering, turn the eero's DHCP
off, watch Shepherd start. The whole house is now leased by Shepherd and **routed by the eero** —
`route = false`, nothing on Shepherd's data path. This is a resting place, not a half-step: it is
worth sitting here for a week, because it proves the DHCP half completely while the routing half
still cannot hurt anybody.

Note what Stage D does *not* need, all of which Gateway mode's cutover does: no second NIC, no WAN
DHCP client, no WAN MAC cloning, no taking the eero's LAN address, no bridge mode on the eero, and no
IPv6 story. That is the argument for doing this first.

**Stage E — turn routing on.** One setting, and the household's eligible devices move onto
Shepherd's NAT over one renewal interval. The consoles stay out unless `route_consoles` is turned on
deliberately. Before this stage, rehearse the two things it depends on: pull the kill switch and time
how long the house takes to come back, and make Shepherd unhealthy on purpose (stop `nft` from
working) to watch it hand out the eero again without being told to.

**Stage F — accounting**, which is GATEWAY.md item 4 and a separate piece of work.

## What this means for Gateway mode

DHCP mode is not a detour from GATEWAY.md; it is the first four items of its build list, done
without the hardware the rest needs, and it leaves Gateway mode strictly closer:

- the DHCP server (item 1) is **the same code**, with a different pool and a different gateway;
- forwarding and NAT configuration (item 3) is **the same code**, with a different output interface;
- accounting (item 4) is **the same code**, reading the same conntrack table;
- the features the return path unlocks (item 5) are **the same features**, for a subset of devices.

What Gateway mode still needs afterwards is the WAN DHCP client, the second NIC, the IPv6 rescope,
the dead man's switch, and the eero in bridge mode. In other words, this work removes the half of
Gateway mode that is software and leaves the half that is hardware and household risk.

## Decisions, and who made them

1. **Routing is all-or-nothing**, with a refusal list and a per-device opt-out. *The maintainer's,
   2026-11-03, against this document's recommendation of per-device opt-in.* Reasoning and the cost
   of the trade are under "Routing is all-or-nothing".
2. **`github.com/insomniacslk/dhcp`'s `dhcpv4` for the wire format**, with Shepherd owning the
   socket and the serve loop. *The maintainer's, 2026-11-03, against this document's recommendation
   of hand-rolling it.* One new module.
3. **`nft` as an external binary in v1**, rather than a hand-written netlink client. *Agreed
   2026-11-03, as recommended.* Adds `nftables` to the Docker image and a startup check.
4. **Fail open, with no dead man's switch**, departing from GATEWAY.md's fail-closed decision for a
   stated reason. *Agreed 2026-11-03, as recommended.*
5. **Default lease time of 10 minutes**, trading "the segment starts failing ~10 minutes after the
   NAS goes down" for "a bad routing decision undoes itself in ~5".
6. **Everything in one change, off by default.** *The maintainer's, 2026-11-03:* the codec wrapper,
   the three modes, the lease store, reservations, the rogue-server interlock, the NAT reconcile,
   the kill switch and the portal screens all land together behind `[dhcp] mode = "off"`, rather
   than observe mode first and serving second.
7. **Not in this work:** conntrack accounting, IPv6 of any kind, UPnP/NAT-PMP proxying for routed
   devices, rate limits and pause.
