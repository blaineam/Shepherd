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
| Shepherd's own interfaces | Same |
| Any device marked **Excluded** | Excluded means opted out of protection, and that includes this |
| Any device whose **Watch** switch is off | The per-device opt-out, in the portal |
| **Network infrastructure**: routers, mesh nodes, access points, switches, hubs and bridges | The network itself depends on them. Includes anything typed `router/infrastructure` or `smart-home hub`, and anything from a vendor that only makes network equipment |
| **Thread border routers and Matter devices** (anything advertising `_meshcop`, `_matter`, `_thread` over mDNS) | A whole smart home hangs off these, and the failure would be silent. See [IPV6.md](IPV6.md) |
| Devices not seen recently (15 minutes by default) | Nothing to steer; it starts again on its own when the device comes back |

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

> **A native XDP attach resets the network interface, and on some drivers that means the link.**
> On the maintainer's NAS — a 10G Aquantia/Marvell card on the `atlantic` driver — a sequence of
> container restarts, each attaching and detaching the program, left the interface with
> `NO-CARRIER` and took it off the network until it was brought down and up again by hand. The
> kernel's own counters recorded five up/down transitions across those restarts. One attach is
> fine and is what normal operation does; **repeatedly restarting Shepherd in quick succession on
> such a driver is not.** If you are iterating on the configuration, or if a crash loop is
> restarting Shepherd over and over, set `mode = "userspace"` (or `enabled = false`) first, and
> check `ip link` afterwards. `mode = "userspace"` never touches the interface this way; generic
> XDP does not reinitialise the driver either.

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
