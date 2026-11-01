# Watch mode

Watch mode is the second of Shepherd's three profiles (see [DESIGN.md](DESIGN.md)). Guard mode
filters DNS: it catches the overwhelming majority of what devices do, costs the network nothing,
and is always on. Watch mode adds the thing DNS filtering can never do by definition — seeing
what a device actually connects to, even when it never asks Shepherd to look up a name.

**It is on by default**, on any host that can run it, and it steers every eligible device. This
page is the operator's view: what it does, what it never touches, how to stop it, and what it
costs. [INTERCEPT.md](INTERCEPT.md) is the engineering document underneath it, and
[IPV6-WATCH.md](IPV6-WATCH.md) is the IPv6 design.

## What it does

Shepherd sends one chosen device periodic unicast ARP replies claiming that the gateway's IP
address belongs to Shepherd's own MAC. The device believes it — that is what ARP is — and sends
its **outbound** traffic to Shepherd instead of straight to the router. Shepherd rewrites both
MAC addresses and puts the frame back on the wire, unchanged otherwise: no NAT, no address
rewriting, no new ports. The router's own ARP table is never touched, and no other device on the
network is affected in any way.

Nothing is blocked. Watch mode is visibility only, today.

## What it does not see: downloads

Because the router's ARP table is never touched, traffic coming **back** from the internet to the
device goes straight to the device over the normal path and never passes through Shepherd. This
is a deliberate, accepted boundary, not a bug:

- **Seen:** everything the device sends out. Connection attempts, destination addresses, the
  names in TLS and QUIC handshakes, upload volume — including from an app that hardcodes its own
  DNS-over-HTTPS resolver and never asks Shepherd anything.
- **Not seen:** the matching downloads. A device's traffic total as reported here is the upload
  half only, and most home traffic is download-heavy, so the number is always an undercount. The
  portal says so where it shows it.

Closing that gap needs two-sided interception or Gateway mode, both of which are future work in
[DESIGN.md](DESIGN.md).

## What is never steered

Watch mode steers a device once it has been seen with a MAC address and an IPv4 address. These
are never steered, and the engine refuses each one twice — once when it decides what to steer,
and again inside the interception library at the moment steering is requested:

| Never steered | Why |
|---|---|
| Your router (the gateway) | Steering the gateway to itself is meaningless and would break the network |
| **Every one of this host's interfaces**, not just the one the relay runs on, by MAC *and* by address | A host whose interfaces share a subnet — a NAS with wired and wireless both on the LAN is the ordinary case — has other interfaces that look exactly like LAN devices. Steering one makes Shepherd relay its own traffic to itself, in the kernel, at line rate. See the warning below |
| Any device holding one of this host's addresses, or the gateway's, whatever MAC it arrived under | Catches the same machine under a MAC the registry has not tied to it: a merged record, a randomised MAC, or one learned from Shepherd's own steering frames |
| Any device marked **Excluded** | Excluded means opted out of protection, and that includes this |
| Any device whose **Watch** switch is off | The per-device opt-out, in the portal |
| **Network infrastructure**: routers, mesh nodes, access points, switches, hubs and bridges | The network itself depends on them. Includes anything typed `router/infrastructure` or `smart-home hub`, and anything from a vendor that only makes network equipment |
| **Thread border routers and Matter devices** (anything advertising `_meshcop`, `_matter`, `_thread` over mDNS) | A whole smart home hangs off these, and the failure would be silent. See [IPV6.md](IPV6.md) |
| Devices not seen recently (15 minutes by default) | Nothing to steer; it starts again on its own when the device comes back |
| Any device **not on the relay interface's own subnet** | An ARP reply there cannot reach it, so steering it is meaningless. This is what the host's own Docker containers look like in the registry: a `172.x` address from the host's neighbour table, several MACs each, otherwise indistinguishable from a LAN device |

**Wandering and quarantined devices are steered like any other.** Wandering means "do not filter
this device, but still watch it", so watching it is exactly the point; quarantine is a group with
its own rules, and Watch mode changes nothing about either. Watch mode blocks nothing, so
steering a device never restricts it.

Any device can be switched to **Always watch**, which steers it even if it looks like
infrastructure — with one exception that cannot be overridden from the portal: it never enables
IPv6 steering for smart-home, Thread or Matter gear (see below).

## Stopping it: the kill switch

The Watch screen has one button that unsteers every device at once and tells each one the
router's real address again. It takes effect immediately, it does not wait for anything on the
network, and **it stays off across restarts** until you re-arm it in the same place. Press it if
anything looks wrong; nothing else in Shepherd is affected, DNS filtering included.

Underneath it, Watch mode is designed to give up on its own:

- Every three seconds, each steered device is checked for **real relayed traffic**. A device that
  has relayed nothing for 15 seconds (30 seconds for one that has never relayed anything yet) is
  unsteered automatically, with a corrective ARP reply, and the reason is recorded.
- Any failure to send while relaying unsteers that device immediately.
- A device that keeps failing is retried on a widening backoff rather than flapped.
- **An idle device is not treated as a failing one.** The check above cannot tell a device with
  nothing to relay from one whose steering never took, and it fails both open, which is correct.
  The engine can tell them apart, and does: if frames really were relayed for that device, or if
  nothing other than the relay has seen it for a minute, it is simply quiet. That is not counted
  as a failure and does not widen anything. The device is then left alone until something sees it
  again, rather than being steered afresh every few seconds while it sleeps. This matters on a
  real network: most devices on a hundred-device LAN are idle most of the time, and without it
  every one of them flips its ARP entry to Shepherd and back continuously, while the widening
  backoff leaves a waking phone unwatched for up to ten minutes.
- If the relay itself dies, every device is unsteered at once and Shepherd keeps running.
- If the router's MAC address changes, everything is unsteered and the engine starts again with
  the new one. The passive ARP monitor's `gateway-mac-changed` event prompts this, but the event
  is never taken on trust: the kernel's own neighbour table is re-read and only a real change
  acts.

Every one of those is visible in the portal, with the reason, under "Recently stopped watching".

## What it costs

A software relay is never free, but on real hardware it is not the bottleneck. Measured live on
2026-10-30 against the maintainer's own phone, a real eero mesh network, and a 12-core x86_64 NAS
(Debian 12, kernel 6.18):

| Relay | Peak relayed | Result |
|---|---|---|
| Userspace (`ParallelRelay`) | 167,000 frames/s, about 1.6 Gbit/s | Full gigabit Wi-Fi, no perceivable slowdown |
| In-kernel (XDP, native driver) | 180,000 frames/s, about 1.77 Gbit/s | Same, with only counters crossing into userspace |

That is the upload half of a speed test, every byte of which crossed the relay. For months before
that, steering capped a device at roughly 300 Mbps; the cause was found and fixed on the same day
(the relay was teaching the switch the wrong port for the device — see INTERCEPT.md's "The cause
the evidence points at"). The numbers above are what the fix produced, on the first try, on real
hardware.

## Which relay is used

`watch.mode` picks it, and `auto` (the default) tries them in this order:

1. **XDP in the network card's driver.** A small eBPF program rewrites and bounces each steered
   frame straight back out of the card, before the packet ever becomes a kernel buffer. Nothing
   crosses into Shepherd's process but a counter read once a second. The fastest path by a wide
   margin, and the one the NAS uses.
2. **XDP in the kernel's generic path**, when the driver does not support XDP. Slower, still never
   reaches userspace.
3. **The userspace relay**, when neither can load: several parallel capture-and-send workers, one
   per core by default.

The relay is attached **once**, at startup, and only the set of steered devices changes after
that. This matters: a native XDP attach makes the driver tear down and rebuild its receive rings,
which took about eight seconds on the NAS — so attaching per device would stall traffic every
time a phone woke up.

> **A native XDP attach resets the network interface, and on some drivers that means the link.
> Shepherd now handles this for you; you should not have to.**
> On the maintainer's NAS — a 10G Aquantia/Marvell card on the `atlantic` driver — a native attach
> took the interface down and up. A sequence of container restarts, each attaching and detaching,
> left it with `NO-CARRIER` and off the network until it was brought up again by hand. It also cost
> the network its wired DNS listener, because the address vanished in the seconds between the
> attach and the DNS bind.
>
> Shepherd therefore **never attaches native XDP on a driver known to drop the link**, and attaches
> **generic** XDP instead: still in the kernel, still no frame copied to userspace, and it does not
> reinitialise the interface. `atlantic` ships in that list. For any other driver, Shepherd reads
> the kernel's own `carrier_changes` counter either side of the attach; if the link went down and
> up, it says so in the log, records the driver in `<data_dir>/watch.json`, and uses generic from
> the next start. So an unlisted bad driver costs **one** flap ever, not one per restart, and a
> listed one costs none.
>
> This is not a reason to restart Shepherd in a tight loop on such hardware anyway. If you are
> iterating on the configuration, `enabled = false` never touches the interface at all.
>
> **`mode = "userspace"` is not the safe alternative on this card, either.** It has to turn GRO
> off, and with GRO off every frame reaches the stack on its own instead of coalesced. Run at a
> few hundred megabits through the software relay and the `atlantic` driver reset repeatedly:
> measured on the maintainer's NAS, `carrier_changes` went from 1 to 9 in about twelve minutes,
> with no XDP program attached at any point. So on this hardware the two flap for two different
> reasons — native XDP at attach time, userspace under load — and **generic XDP is the one path
> that avoids both**, because it neither reinitialises the driver nor needs GRO touched.

The userspace relay needs **GRO** (generic receive offload) off on the interface, because it
retransmits what it captures and a GRO-coalesced super-frame is bigger than Ethernet allows.
Shepherd turns GRO off itself for as long as that relay runs and restores it on shutdown. The XDP
paths see frames before GRO happens and need none of this.

## IPv6

**Off by default** (`watch.ipv6`). The design is in [IPV6-WATCH.md](IPV6-WATCH.md); the mechanism
is the exact IPv6 mirror of the IPv4 one — unsolicited **unicast** Neighbor Advertisements sent
only to a device being steered, claiming the router's link-local address for Shepherd's MAC.

**Shepherd never sends Router Advertisements, under any setting.** That is the one thing
[IPV6.md](IPV6.md) forbids outright: an RA is a broadcast every device on the network processes,
and a second RA speaker silently corrupts the routing of Thread border routers and everything
behind them. Watch mode's IPv6 steering is per-device and unicast precisely so it never needs one.

Even switched on, IPv6 steering engages only where it can actually do something, and says so in
the portal when it cannot:

- The network needs an **IPv6 default route** whose next hop is a link-local address.
- The network needs a **global IPv6 route** (a `2000::/3` address on the interface). With
  unique-local addresses only — which is the maintainer's own network, and a common case — there
  is no off-link IPv6 traffic to steer at all, so Shepherd idles instead of taking the risk for
  nothing.
- The device needs an IPv6 address of its own to advertise to; its link-local is preferred.
- A device the registry merged from several MAC addresses is left IPv4-only: which of its MACs
  holds its IPv6 address cannot be known from the IPv4 neighbour table, and that is not something
  to guess at.
- **Smart-home hubs, Thread border routers and Matter devices are never IPv6-steered**, and
  unlike IPv4 the per-device "Always watch" switch cannot override it. Only
  `watch.steer_infrastructure` in the configuration file can, which is the operator saying so
  deliberately rather than a switch in a web page.

A device steered for both families shows "Watching v4+v6"; one that is IPv4-only while IPv6
steering is on says why, per device.

## Configuration

```toml
[watch]
enabled = true           # on by default
interface = ""           # empty: the interface the default route leaves through
mode = "auto"            # auto | xdp | userspace | off
workers = 0              # userspace relay workers; 0 = automatic
ipv6 = false             # IPv6 steering; see above
steer_infrastructure = false
allow_routing_host = false    # run even on a dual-homed forwarding host; see below
diagnostics = false           # log what the relay is carrying; see below
active_window_seconds = 900
health_interval_seconds = 0   # 0 keeps the engine's defaults (3 / 15 / 30 s)
idle_grace_seconds = 0
startup_grace_seconds = 0
```

`mode = "xdp"` refuses to fall back to the userspace relay: use it when you would rather have no
Watch mode at all than a software relay. `mode = "off"` is the same as `enabled = false`.

**Set `interface` explicitly on a host with more than one interface on the same
network.** Left empty, Shepherd follows the default route, and a machine with
both a wired and a wireless connection can briefly publish that route through
the wrong one — a Wi-Fi DHCP renewal is enough. Shepherd handles it: it stays on
the interface it settled on, and if it ever does end up somewhere the gateway
does not resolve it refuses to steer anything there and comes back on its own.
But naming the interface removes the ambiguity, and on the maintainer's own NAS
that means `interface = "eth0"`.

> **Naming the interface does not protect the host's *other* interfaces, and for a
> while nothing did.** Watch mode used to treat only the relay's own interface and
> the gateway as "this host". On a NAS with eth0 and wlan0 both on the LAN, wlan0
> therefore looked like an ordinary device: its own MAC, its own address, seen by
> the ARP monitor, typed by the classifier. Steering it made Shepherd relay its own
> traffic back to itself. Measured live: **9 Gbit/s and about a million packets per
> second in each direction on a 10 GbE link, sustained**, with the host's load
> average above 20.
>
> Two things made it hard to spot, and both are worth remembering when judging this
> feature's cost. Shepherd's own CPU stayed **under 4%**, because the loop ran in
> the kernel at the driver, so every resource reading looked excellent. And the
> portal showed no traffic worth speaking of, which was correct and was the real
> clue: the traffic was not the network's.
>
> Watch mode now asks the operating system for **every** MAC and address on the
> host, refreshed every 15 seconds, and refuses any device matching any of them, by
> address as well as by MAC. If that list cannot be read at all, it steers nothing
> and says so in the log: refusing costs visibility, steering the host costs the
> network.

## Three things that stop it by themselves

**The duplicate brake, which is what actually stops a loop.** A relay loop is one frame arriving
and being relayed over and over. Every storm on real hardware looked the same once there was a way
to look at all: a handful of frames, one IP identification field each, a TTL that never
decremented, the device's own source MAC and Shepherd's destination MAC, going round thousands of
times a second.

So the relay fingerprints every frame it relays -- the identification field, the lengths, both
addresses, the protocol and the first sixteen bytes of the transport header -- and **drops** a
frame it has already relayed inside 100 ms. Dropped rather than passed up: IPv4 forwarding is on
on many hosts, and passing it would hand the kernel a frame it would route straight back out of
the interface it came from.

The window is placed between two real numbers. A loop's round trip is microseconds. The shortest
TCP retransmission timeout Linux will use is 200 ms. So a frame going round is caught the second
time it is seen, and a genuine retransmission is never suppressed. A frame that really is a
network-level duplicate is dropped, which is what should happen to it, because the first copy
already reached the gateway.

It covers IPv4 and IPv6 alike. IPv6 has no identification field, so its fingerprint leans on the
traffic class and flow label, the payload length, the next header, both 16-byte addresses and the
same sixteen bytes of transport header. IPv6 steering is off by default and every loop seen was
IPv4, but a loop there would be just as severe, and a safety stop covering one family is worse
than no claim at all.

`GET /api/watch` reports the count as `duplicates_suppressed`, overall and per device, and the
diagnostics digest names the devices whose frames came back. Per device matters: the overall
figure cannot say whether the frames belong to one device or to all of them, which is exactly what
is still unknown about the cause. A healthy relay reports zero for as
long as it runs. On the maintainer's NAS it runs at about 80% of relayed frames, which says
plainly that whatever re-delivers those frames is still doing it and is now contained rather than
catastrophic.

**The relay self-test, before a single device is steered.** On attach Shepherd relays one frame of
its own and checks what happens to it: a 60-byte UDP datagram inside 198.51.100.0/24 (TEST-NET-2,
which nothing answers) to the discard port, from a locally administered MAC no real device can
hold.

The program only ever sees frames the interface *receives*, and a frame this host transmits is not
one of them. So a healthy relay relays the probe **zero** times: it goes out, the switch declines
to send it back out the port it arrived on, and that is the end of it. That much was measured here
before it was relied on. A probe the program *does* see is a frame that came back and was relayed
again, which is a loop, and the relay is then refused with nothing steered. A relay found to loop
is recorded per interface in `watch.json` (`looping_relays`) and never attached there again, the
way a flapping driver already is: running the test costs a short burst of looping frames and the
answer does not change.

**The loop brake**, the backstop for anything the first two do not catch. Every second the engine
compares the relay's own throughput against the interface's kernel counters and looks for mirrored
traffic -- the interface receiving and transmitting the same amount -- at a rate a home network
does not reach. Three consecutive seconds of that and it panic-stops, unsteering every device with
its corrective reply, and latches like the kill switch so a restart does not resume it. It logs
what it measured, the devices that were relaying most, and the sampled-frame digest described
below -- and writes the same thing to `watch.json` as `last_loop_stop`, reported on
`GET /api/watch`.

Persisting it is not tidiness. Those log lines *are* the evidence the first unexplained loop
lacked, and twice a container rebuild has discarded them, the second time during the very
investigation that produced this brake. The kill switch survived a restart; its reason should too.
Read `duplicates_suppressed` in that record first: a trip with a high figure is a loop the
duplicate brake could not break, while a trip with zero means the mirrored traffic was not
duplicate frames at all, and the cause is somewhere else.

Symmetry is the whole test; the rate floor only keeps a quiet network from tripping it. Measured on
the live host with nothing steered, six clean two-second samples ran 12,325 to 39,521 packets a
second received against 1,324 to 3,008 transmitted -- 89 to 92% apart, routinely above any floor
worth setting. Looping ran within 0.03 to 10% apart. The brake deliberately does not ask how much
the relay itself is carrying: the relay's counter lags a storm by seconds, reading 8 packets a
second while the interface was already mirrored at 27,000, so gating on it costs exactly the
seconds in which stopping is cheap.

## Seeing what the relay is carrying

A frame the in-kernel relay bounces back out with `XDP_TX` never reaches an `AF_PACKET` socket, so
no packet capture on the host can show it. That is why three line-rate storms were diagnosed by
argument rather than measurement, and why two of those arguments were wrong.

The relay now samples every 256th frame it relays -- the first 60 bytes, as the frame arrived and
before either MAC was rewritten -- into a small ring the engine drains once a second. Set
`watch.diagnostics` and it logs a digest every few seconds while traffic is moving; the loop brake
logs one whenever it trips, whatever the setting. Addresses, ports, TTL and identification fields
only, never payload:

```
watch: diagnostics at 69878 relayed pkt/s: 128 sampled frames in 4 flows (0 not IPv4)
watch: ...   78  02:00:5e:00:00:37 -> 02:00:5e:00:00:20  udp 192.0.2.37->203.0.113.9 :59418->:443
             ttl 64  1 ids, SAME IDs, SAME TTL: circulating at layer 2  avg 1196 B
```

The verdict on each line is the point of it. Repeated identification fields with a falling TTL is a
frame circulating through a router; repeated identification fields with one TTL is a Layer 2 loop;
all-distinct fields are ordinary traffic. The engine also reports two counters for Shepherd's own
output coming back to it -- frames with its source MAC, and frames addressed to the gateway's.

## What was ruled out, and how

Worth keeping, because the same wrong answers are easy to reach twice. Each of these was excluded
by counting it, not by reasoning about it.

| Candidate | Reading | Verdict |
|---|---|---|
| Steering one of this host's own interfaces | `wlan0` steered, relay fed itself | **confirmed and fixed** (incident 1) |
| A polluted registry record that had merged the gateway in | steering one phone by explicit MAC loops too | excluded |
| Kernel IPv4 forwarding | `ForwDatagrams` moved by **1** during a 24,500 packet/s storm | excluded |
| Same-segment hairpin routing | a rule counting `in eth0, out eth0` dropped **0** | excluded |
| The relay's own output returning | both return-path counters read **0** throughout | excluded |
| Shepherd's transmitted frames coming back | a probe frame addressed to `eth0`'s own MAC never returned | excluded |
| Local duplication before the hook | `examined` was **0.972** of the interface's `rx_packets` over 30 s | excluded |

What is left, and is measured rather than inferred: the duplicate frames **genuinely arrive over
the wire**, bearing the device's original source MAC, Shepherd's destination MAC, one
identification field and an undecremented TTL, and they only arrive while the relay is running.
Something on the segment re-delivers a steered device's frames once the relay starts rewriting and
retransmitting them. Which part of the network does that has not been identified, and identifying
it needs a capture on the router rather than on this host.

One structural feature is worth writing down for whoever picks that up, because it was only
noticed at the end. The device behind the worst storms is **itself dual-homed on this segment**,
exactly like the host: a wired interface and a wireless one, each with its own address on the same
`/24`, each with its own default route to the same router, and the two holding *different* MAC
addresses for that router -- the steered interface has the gateway cached at Shepherd's MAC while
the other has it cached at the router's own (documentation addresses below).

```
eth0  192.0.2.86   gateway 192.0.2.1 at Shepherd's MAC    (steered)
wlan0 192.0.2.122  gateway 192.0.2.1 at the router's MAC  (not steered)
```

That is not a proven mechanism and it is not enough on its own -- a single-homed phone produced a
storm too -- so it is recorded as the next thing to test, not as an answer. The test is cheap:
steer one single-homed wired device on its own and see whether the duplicate count stays at zero.

That is why the refusal below is kept as the default, and why it is only a default.

## The dual-homed refusal, and the knob that lifts it

Shepherd refuses to relay when IPv4 forwarding is on **and** another of this host's interfaces has
an address inside the relay interface's own prefix. The maintainer's NAS has exactly that shape --
forwarding on, `eth0` and `wlan0` both on one `/24` -- and it is the only host on which the relay
has ever looped.

The refusal rests on correlation alone. The mechanism it originally stood in for, the kernel
routing a steered device's return traffic back onto the segment, is excluded above by direct count.
Clearing `net.ipv4.ip_forward` would not help either, and would break things: on that host
forwarding is bursty and load-bearing, a median of 34 datagrams a second with a peak of 8,607, and
every burst is the relay interface's inbound traffic routed to a container bridge for a service its
owner runs on purpose.

So the refusal stays on by default, because it is cheap and the thing it guards against melts a
home network in seconds, and `watch.allow_routing_host = true` lifts it. With the duplicate brake
and the loop brake both armed, that is how a dual-homed host runs Watch mode -- measured on the one
that used to storm within four seconds of steering anything, now steering 13 devices with no loop.

## What it needs

Linux, and three capabilities:

| Capability | For |
|---|---|
| `CAP_NET_RAW` | Sending the ARP replies, and the userspace relay's capture and send sockets |
| `CAP_NET_ADMIN` | Attaching the XDP program to the interface, and toggling GRO |
| `CAP_BPF` | Loading the XDP program (`CAP_SYS_ADMIN` before kernel 5.8) |
| `CAP_PERFMON` | **Also required for the in-kernel relay**, and easy to miss. The kernel gates the pointer arithmetic the program does on `perfmon_capable()`, so with `CAP_BPF` alone the verifier refuses to load it (`pointer -= pointer prohibited`) and Watch mode falls back to the userspace relay. `CAP_SYS_ADMIN` covers it too, but is far broader |

Only `CAP_NET_RAW` is needed for the userspace relay. The other three are what
the in-kernel relay needs, and all three have to be present: miss `CAP_PERFMON`
and everything still works, just through the slower path, with the reason in the
log and on the Watch screen. This is worth checking after any change to how
Shepherd is run — it was found on the live host, where the container had
`CAP_BPF` but not `CAP_PERFMON` and had quietly been using the userspace relay.

In Docker, with host networking:

```yaml
services:
  shepherd:
    network_mode: host
    cap_add: [NET_BIND_SERVICE, NET_RAW, NET_ADMIN, BPF, PERFMON]
```

`net.ipv4.ip_forward` is **not** needed and is never touched: this is a Layer 2 relay done
entirely in Shepherd's own process over raw `AF_PACKET` sockets (or in the kernel, under XDP), so
no frame ever reaches a routing decision, netfilter or conntrack.

Anywhere Watch mode cannot run — a non-Linux host, a missing capability, no usable interface — it
logs one clear reason, reports itself unavailable on the Watch screen, retries quietly on a
backoff, and changes nothing else. DNS filtering, the device registry, the scanners and the portal
all behave exactly as they would without it.

## In the portal

- **Watch screen:** whether it is running and through which relay, the router and Shepherd's own
  addresses, live relayed throughput in bits and packets per second, every watched device with its
  own rate, why each unwatched device is unwatched, the IPv6 state, the recent "stopped watching"
  log, and the kill switch.
- **Devices screen:** a Watch column per device (Watching, Watching v4+v6, No traffic yet,
  Waiting, Not on the network, Never watched, Watch off), with the reason on hover. Each device's
  drawer has its own three-way Watch switch (Automatic, Always watch, Never watch) and its live
  numbers. The switch is also a bulk action, and `watch:off` is a search filter.

## API

Under the portal token, `X-Shepherd: 1` on every change.

| Endpoint | Does |
|---|---|
| `GET /api/watch` | The whole state: phase, relay, IPv6, rates, every device, the unsteer history |
| `POST /api/watch/kill` | The kill switch. Unsteers everything; persists until re-armed |
| `POST /api/watch/rearm` | Lifts it |
| `PATCH /api/devices/{id}` with `{"watch":"auto\|on\|off"}` | One device's switch |
| `POST /api/devices/bulk` with `{"op":"set_watch","watch":"off"}` | In bulk |

Every device in `GET /api/devices` also carries `watch` (the switch) and, when Watch mode is
wired in, `watch_state` (what it is actually doing, and why).

## Where the state lives

`<data_dir>/watch.json` (mode 0600) holds exactly one thing: whether the kill switch is down.
Nothing else about Watch mode is persisted — the steered set is rebuilt from the device registry
and the network every time Shepherd starts, which is what makes a restart a clean slate.
