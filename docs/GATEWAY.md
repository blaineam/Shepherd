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

1. **A DHCP server.** Today Shepherd deliberately avoids this. It is a hard prerequisite: a bridged
   eero stops handing out leases, so Shepherd must serve them from the moment of cutover. Since the
   eero keeps DHCP until that day, this gets its only real test on the parallel segment at Stage 1,
   which is why that stage's device list matters more than it looks.
2. **A WAN client: DHCP** (decided, 2026-11-01 — not PPPoE). That is the simpler end of this item
   and removes a few things from the list: no PPP session to keep up, no credentials to store, and
   no 1492-byte MTU, so no MSS clamping is needed by default. What it still needs is a DHCP client
   that renews properly and survives the lease going away, and the judgement to **ignore the DNS
   servers the ISP offers** in favour of Shepherd's own configured upstreams. Plus uplink health
   reporting, which `internal/nethealth` already does in part.
3. **Forwarding and NAT configuration** through nftables, with the rule set owned and reconciled by
   Shepherd the way it already reconciles the steered set.
4. **Flow accounting** over ctnetlink, as above, feeding per-device and per-destination byte
   counters, with the DNS join for names.
5. **The features the return path unlocks**, which is the reason for all of it: real per-device
   bandwidth, per-destination bandwidth, genuine pause, rate limits, and the inbound half of
   anything resembling intrusion detection.
6. **A rescoped IPv6 design** (see the conflict below).
7. **Failure behaviour: fail closed** (decided, 2026-11-01). When Shepherd is not running, devices
   do not reach the internet. See "Failing closed needs a dead man's switch" below, because this is
   the item on this list whose implementation is least like what it sounds like.

## Staged migration

Decided 2026-11-01: **the eero keeps DHCP until cutover.** That is a reasonable call -- it leaves
the live network alone until the day it has to change -- and it has a consequence worth being
explicit about, because it moves a risk rather than removing one.

Shepherd must still serve DHCP *from the moment of cutover*, since a bridged eero stops handing out
leases. So the DHCP implementation still has to be built; what changes is that it is no longer
proven gradually against every real device in the house with no outage risk. It gets proven on a
parallel segment and then meets the whole household at once. The mitigations below exist for exactly
that, and the first two are the ones that make the cutover survivable.

**Stage 0 — rehearse off the live network.** Second NIC installed. A spare switch and one throwaway
device. Prove the accounting story end to end *before* anything else: enable conntrack accounting,
read it over ctnetlink, and confirm the numbers for one device and one destination match what the
device actually transferred. If that does not work, nothing later is worth building.

**Stage 1 — Gateway on a parallel segment, with the awkward devices on purpose.** The second NIC, a
spare switch, and devices behind Shepherd while the eero still serves everyone else. NAT, the WAN
DHCP client and accounting all exercised for real with the household unaffected.

Because this is now the *only* place DHCP gets tested before the whole house depends on it, the
devices here should be chosen for being difficult rather than for being convenient: a Thread or
Matter device, a printer, a TV, and whatever in the house has historically been fussy about
addressing. A stage that only proves a laptop works has not proved anything that matters.

**Stage 2 — cutover.** Short, rehearsed, and with the rollback timed beforehand: re-plugging the
eero as the router is a few minutes' work and should be practised at Stage 1, not discovered here.
Three things to do before the day, each of which removes a way for this to go badly.

*Take the eero's LAN address.* Shepherd's LAN leg should become the address the eero had, so every
device's existing lease -- its default gateway, its DNS server -- stays correct, and ARP re-resolves
to Shepherd's MAC by itself. Without this, every device holds a lease pointing at a gateway that no
longer exists and the cutover is only as fast as the slowest renewal.

*Shorten the eero's lease time well in advance.* Hours or days of remaining lease is hours or days
of devices ignoring the new arrangement. Dropping the lease to minutes a day or two beforehand costs
nothing and means the network converges in minutes instead.

*Clone the eero's WAN MAC.* This one belongs to the DHCP WAN specifically and turns a ten-minute job
into an evening if missed: **many ISPs tie the lease to the MAC address that currently holds it**,
which is the eero's WAN port. A different MAC can mean a refused lease, or a wait measured in hours.
Read and record that MAC before touching anything and clone it onto Shepherd's WAN interface rather
than hoping. It makes the rollback symmetric too, since the eero takes its own MAC back when it is
re-plugged.

**Stage 3 — the features.** Per-device and per-destination bandwidth in the portal, then pause and
rate limits.

## Risks, and the guard rails that answer them

- **A router outage is a total outage**, and with fail-closed chosen, so is a Shepherd outage.
  [DESIGN.md](DESIGN.md) already names this as the risk that changes Shepherd's character. The
  remaining answers are a watchdog, config rollback, and a physical rollback that has been
  practised.
- **Shepherd becomes a single point of failure for the house, deliberately.** Guard mode's DNS fails
  open; Gateway mode is a considered departure from that precedent rather than an inconsistency, and
  the departure should be stated wherever the principle is.
- **The Thread border router.** Hard rule 1 exists because two sources of Router Advertisements
  break Thread meshes. In Gateway mode Shepherd is one of those sources by necessity, and the smart
  home has Thread and Matter gear. This needs its own testing and is a good reason for Stage 2 to
  include a Thread device.
- **Scope creep into a datapath project.** The temptation will be to handle packets in Shepherd for
  some feature. The line above is the guard rail: if a feature needs per-packet handling, it is a
  separate, separately justified piece of work.

## Failing closed needs a dead man's switch, not a shutdown hook

Fail closed was chosen, and it is the item on the build list least like what it sounds like, because
of the design decision above: **the kernel forwards, not Shepherd.** If Shepherd exits, the kernel's
rules are still loaded and traffic keeps flowing. Doing nothing therefore fails *open*, whatever the
intent.

Hooking process shutdown is not enough either. A handler that installs a drop rule on the way out
covers a clean stop and misses everything that matters: `SIGKILL`, the out-of-memory killer, a
kernel panic, a container destroyed from under it, a wedged process that is still technically
running. Those are the cases fail-closed is *for*.

What does work is to invert it, so that forwarding is permitted only while Shepherd is actively
saying so. nftables sets support per-element timeouts, which makes the kernel the enforcer:

- forwarding is allowed only while a particular element is present in a set;
- that element carries a timeout of, say, 30 seconds;
- Shepherd refreshes it every few seconds while it is healthy.

Stop refreshing for any reason -- crash, kill, panic, hang -- and the element expires on the
kernel's own schedule and forwarding stops. Nothing depends on Shepherd getting a chance to act,
which is the whole point.

The timeout is a real trade-off and should be configurable: too short and a garbage-collection
pause or a slow reconcile drops the house offline for no good reason, too long and "closed" is a
loose promise. Thirty seconds with a refresh every five is a reasonable starting point, and the
refresh must be driven by something that proves Shepherd is *working* rather than merely alive.

### One exception, so a bug is still fixable

Failing closed has a cost worth naming: it takes out remote access along with everything else.
Shepherd's Tailscale path needs the internet, so a Shepherd bug serious enough to stop forwarding
also removes the means of fixing it from anywhere but the house.

So the dead man's switch should apply to **forwarded traffic** -- the devices -- and not to the
host's own outbound traffic. Devices are cut off as intended; Shepherd itself, and therefore
Tailscale and the portal, stay reachable. Local access survives either way, since LAN-to-LAN traffic
is not forwarded through the WAN path, but local access means being in the house.

That split is the difference between a fail-closed router and a brick.

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

## IPv6 scope is smaller than it looks, for now

Worth stating before anyone sizes the IPv6 work. The LAN has **no global IPv6 route today**: the
addresses on it are unique-local only, which is also why Watch mode's own IPv6 steering sits idle
there. So IPv6 internet is not in use on this network.

That makes the IPv6 requirement for stages 1 to 3 **"do not break what is there"** — unique-local
addressing, Thread, Matter and mDNS — rather than "provide IPv6 internet", which is a much smaller
and much less risky target. Rules 2 and 3 of [IPV6.md](IPV6.md) carry most of it.

Providing global IPv6 would mean a DHCPv6 client with prefix delegation on the WAN and advertising
that prefix on the LAN, which is where the rescope of hard rules 1 and 5 actually bites. It should
be a separate, later piece of work, and it needs one fact nobody has checked: **whether the ISP
delegates a prefix at all.**

## Open decisions, which are the maintainer's

1. ~~**What does the WAN need?**~~ **Answered: DHCP** (2026-11-01). Consequences folded into item 2
   of the build list and into the Stage 3 MAC-cloning note above.
2. ~~**Who serves DHCP during and after the transition?**~~ **Answered: the eero keeps it until
   cutover** (2026-11-01). The staging above is rewritten around that, including the three
   pre-cutover steps it makes necessary and the reason the parallel segment now has to include the
   difficult devices rather than the convenient ones.
3. ~~**What happens to traffic when Shepherd's process is not running?**~~ **Answered: fail closed**
   (2026-11-01), a considered departure from Guard mode's fail-open precedent. The mechanism it
   requires, and the one exception that keeps a bug remotely fixable, are above.
4. **Is Watch mode retired, kept, or left off?** It is off on the NAS now. Its one capability that
   Gateway mode does not subsume is nothing — a router sees everything it sees and more — so the
   honest options are to keep it for installs that cannot be the router, or to retire it.
5. **Does the eero stay as an access point, or get replaced?** Bridge mode on the eero is the
   assumption throughout; it is also the rollback path, so it should not be given up.
