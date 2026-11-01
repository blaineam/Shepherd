# Gateway: Shepherd as the router

A design and a staged migration, written 2026-11-01 after the Watch-mode investigation of that
night established that the thing this is for cannot be had any other way.

Status: **design only.** Nothing here is built. The purpose of the document is to make the
decisions visible before any of it is, and to record which of them are the maintainer's rather
than mine.

## Why this and not Watch mode

The goal is **per-device bandwidth, and ideally per-destination bandwidth**, alongside the DNS
features that already work. Watch mode cannot deliver it, and the reasons are structural rather
than a matter of polish:

- **It is outbound-only by construction.** One-sided ARP steering touches the device's side of the
  conversation; the gateway's ARP table is never touched, so every download takes the normal path
  and is invisible. [WATCH-MODE-COMPARISON.md](WATCH-MODE-COMPARISON.md) states it plainly: a
  device's real traffic volume is always understated.
- **Its counters are per device, not per destination.** Nothing keys bytes by destination today.
- **On the maintainer's own network it does not reliably steer at all.** A device the portal
  reported as steered and healthy had **zero** of a 100 MB transfer relayed; the relayed frames
  were background chatter. See [WATCH.md](WATCH.md). A number like that is worse than none.
- **And one-sided ARP loops there.** The router returns relayed frames off the wire within tens of
  microseconds, the loop brake stops the storm in about three seconds, and four attempts to prevent
  rather than contain it were each refuted by measurement.

So the feature is not blocked on fixing Watch mode. It is blocked on the return path, and only a
router has it.

## The constraint that decides the shape

**Per-device bidirectional accounting requires Shepherd to be the point that routes and translates
the traffic.** This is worth spelling out because the cheaper-looking placements do not work:

| Placement | Why it does not give the number |
|---|---|
| Beside the router, steering with ARP (today's Watch mode) | Outbound only; no return path |
| One-armed router on the existing flat `/24` — devices point at Shepherd, which forwards to the eero | Forwarding a subnet back onto the segment it arrived from is the hairpin hazard Watch mode already refuses on this host. It needs two subnets or VLANs, and consumer mesh routers are poor at VLANs |
| Transparently bridging between the eero and the LAN | Internet traffic flows through the eero either way; a bridge on the LAN side sees only what crosses it, and the eero is also the Wi-Fi AP |
| Bridging on the WAN side, between the eero and the ONT | Sees every byte, but after the eero's NAT every device looks like one address, so per-device identity is gone |

Each row removes an option, and what is left is Gateway: the eero demoted to radios, Shepherd
holding the WAN and the LAN, doing DHCP, DNS, forwarding and NAT. That is the maintainer's own
stated direction in [DESIGN.md](DESIGN.md), and the measurements above are the missing argument for
scheduling it.

## The central design decision: do not write a datapath

Shepherd should be the **control plane and the observer**, not the forwarder. The Linux kernel
already forwards, translates and accounts for traffic at line rate; Shepherd configures it and
reads it.

- **Forwarding and NAT:** the kernel's own, configured through `nftables`. No Shepherd code on the
  per-packet path.
- **Accounting:** `nf_conntrack` with accounting enabled gives per-flow byte and packet counters in
  **both directions**, keyed by source address, destination address and ports. That is per-device
  and per-destination bandwidth, by construction, with no new datapath.
- **Names:** joined against the DNS engine's own log, so a destination reads as a domain rather than
  an address. Shepherd is the resolver already, which is what makes that join possible.

Reasons to hold this line hard. It is the only way 10 Gb is credible without a serious datapath
project. It keeps the blast radius of a Shepherd bug away from whether the house has internet. And
it reuses what already works rather than reimplementing it: the relay in `internal/intercept` is a
Watch-mode mechanism, and Gateway mode should **not** inherit it.

The one thing this costs: Shepherd's visibility is then as good as conntrack's, which means flows
rather than packets. That is the right granularity for the goal and is not enough for deep
inspection later. Recorded as a known boundary, not a surprise.

### Accounting has one detail that is easy to get wrong

Polling the conntrack table for in-flight flows **undercounts**, because a short flow can start and
finish between two polls and never be seen. The correct shape is both halves:

- subscribe to conntrack **destroy events**, which carry the flow's final counters, and
- dump the table periodically for flows still open, diffing against the previous dump for rates.

Verified on the maintainer's NAS, because both affect what has to be built:

```
kernel 6.18.15, nftables present (nft and iptables binaries exist)
net.netfilter.nf_conntrack_acct = 0        <- off by default; must be enabled
/proc/net/nf_conntrack                     <- absent on this kernel
conntrack CLI                              <- not installed
```

So accounting must be enabled deliberately, and must be read over **ctnetlink** rather than procfs
or by shelling out. A minimal netlink client in pure Go fits the project's no-CGO constraint and its
precedent of writing small clients rather than taking dependencies (the standard-library-only SMTP
client in `internal/accountability`). Whether that is a dependency or hand-written is a decision,
not a conclusion.

## Hardware reality

The NAS has **one** 10 Gb NIC and a Wi-Fi adapter:

```
eth0   atlantic   10000 Mb
wlan0  iwlwifi    (wireless)
12 cores, 62 GB RAM
```

Gateway mode needs two wired interfaces. `wlan0` is not a candidate for a WAN or LAN leg. So this
needs a second NIC before anything can be rehearsed, and that is the first item on the list below.
A Thunderbolt or PCIe 10 Gb adapter is the obvious choice; the WAN side does not need 10 Gb unless
the internet service does.

## What has to be built

In dependency order, each item being something that can be finished and verified on its own.

1. **A DHCP server.** Today Shepherd deliberately avoids this. It is a prerequisite and, usefully,
   it can be run and proven on the live network long before any traffic path changes.
2. **A WAN client.** DHCP, and PPPoE if the service needs it — **an open question** (below). Plus
   uplink health reporting, which `internal/nethealth` already does in part.
3. **Forwarding and NAT configuration** through nftables, with the rule set owned and reconciled by
   Shepherd the way it already reconciles the steered set.
4. **Flow accounting** over ctnetlink, as above, feeding per-device and per-destination byte
   counters, with the DNS join for names.
5. **The features the return path unlocks**, which is the reason for all of it: real per-device
   bandwidth, per-destination bandwidth, genuine pause, rate limits, and the inbound half of
   anything resembling intrusion detection.
6. **A rescoped IPv6 design** (see the conflict below).
7. **Failure behaviour**: a watchdog, config rollback, and an explicit decision about what happens
   to forwarding when Shepherd's own process dies.

## Staged migration

The staging exists so that the risky step is last and short, and so each stage proves something the
next one depends on.

**Stage 0 — rehearse off the live network.** Second NIC installed. A spare switch and one
throwaway device. Prove the accounting story end to end *before* anything else: enable conntrack
accounting, read it over ctnetlink, and confirm the numbers for one device and one destination match
what the device actually transferred. If that does not work, nothing later is worth building.

**Stage 1 — DHCP on the live network, nothing else.** Shepherd serves DHCP; the eero stays the
gateway and keeps routing. No traffic path change, fully reversible by turning the eero's DHCP back
on. This proves the DHCP implementation against every real device in the house, including the
awkward ones, with no outage risk.

**Stage 2 — Gateway on a parallel segment.** The second NIC, the spare switch and a handful of
volunteer devices behind Shepherd, with the eero still serving everyone else. NAT, WAN handling and
accounting all exercised for real while the household is unaffected.

**Stage 3 — cutover.** The eero to bridge/AP mode, Shepherd inline. Short, rehearsed, and with the
rollback timed beforehand: re-plugging the eero as the router is a few minutes' work and should be
practised at Stage 2, not discovered at Stage 3.

**Stage 4 — the features.** Per-device and per-destination bandwidth in the portal, then pause and
rate limits.

## Risks, and the guard rails that answer them

- **A router outage is a total outage.** This is the one that changes Shepherd's character, and
  [DESIGN.md](DESIGN.md) already says so. The answers are: the kernel forwards, not Shepherd, so
  Shepherd crashing should not stop traffic; a watchdog; and a physical rollback that has been
  practised.
- **Shepherd becomes a single point of failure for the house.** Guard mode's DNS already fails open.
  The forwarding path needs an equivalent stance decided explicitly rather than inherited.
- **The Thread border router.** Hard rule 1 exists because two sources of Router Advertisements
  break Thread meshes. In Gateway mode Shepherd is one of those sources by necessity, and the smart
  home has Thread and Matter gear. This needs its own testing and is a good reason for Stage 2 to
  include a Thread device.
- **Scope creep into a datapath project.** The temptation will be to handle packets in Shepherd for
  some feature. The line above is the guard rail: if a feature needs per-packet handling, it is a
  separate, separately justified piece of work.

## The IPv6 hard rules have to be rescoped, explicitly

[IPV6.md](IPV6.md)'s hard rules were written for a Shepherd that sits *beside* the router, and two
of them forbid what a router must do:

> 1. **Never run a Router Advertisement or DHCPv6 server on the LAN.**
> 5. **Never change a client's IPv6 default gateway.**

A router advertises itself and is the default gateway. There is no way to be the router and keep
those rules, so they must be **rescoped rather than quietly broken**: they hold for the Guard and
Watch profiles, and Gateway mode gets its own reviewed IPv6 design. Rule 2 (never filter or rewrite
neighbour discovery or mDNS) and rule 3 (never strip AAAA) still hold in Gateway mode and should be
restated there rather than assumed.

This is called out here because quietly violating a documented hard rule is how the Thread mesh
gets broken, and because the rules are good ones for the profile they were written for.

## Open decisions, which are the maintainer's

1. **What does the WAN need?** DHCP from the ISP, or PPPoE? This decides part of item 2 and is not
   something to guess at.
2. **Who serves DHCP during and after the transition?** Stage 1 assumes Shepherd takes it over
   early, because it de-risks the hardest compatibility work. Keeping it on the eero until Stage 3
   is defensible and shortens Stage 1 to nothing.
3. **What happens to traffic when Shepherd's process is not running?** Keep forwarding (the kernel's
   rules persist, the house stays online, protection is off) or stop it (fail closed). Guard mode's
   precedent is to fail open.
4. **Is Watch mode retired, kept, or left off?** It is off on the NAS now. Its one capability that
   Gateway mode does not subsume is nothing — a router sees everything it sees and more — so the
   honest options are to keep it for installs that cannot be the router, or to retire it.
5. **Does the eero stay as an access point, or get replaced?** Bridge mode on the eero is the
   assumption throughout; it is also the rollback path, so it should not be given up.
