# Passive ARP monitor

`internal/arp` listens to ARP on the LAN and turns it into two things: device observations with
real MAC addresses for the device registry, and security events about the ARP layer itself. It is
the zero-risk first stage of the ARP work described in [DESIGN.md](DESIGN.md). It is
useful on its own and Watch-mode interception will build on it later.

It is wired into `cmd/shepherd` (the `[arp]` config section, `cmd/shepherd/arp.go`'s `startARP`,
and `GET /api/arp/stats`); see "Wiring" below. It still needs `CAP_NET_RAW` and is read-only.

## What it does

- Reads ARP requests, replies, probes and announcements (EtherType 0x0806) on one interface.
- Sends an `Observation{Source: "arp", MAC, IP, Time}` to the registry (`devices.Sink`) the
  first time it sees a MAC and IP pair, then at most once per five minutes per pair.
- Raises events: a new MAC, an IP that changed hands, a gateway MAC change, duplicate IPs,
  one MAC claiming many IPs, gratuitous ARP floods, reply storms, and a conservative summary
  when several signals combine.
- Keeps counters for the portal (`Monitor.Stats()`).

## What it does not do

- It never transmits anything. `Source` has two methods, `Next` and `Close`. The Linux socket
  is only ever read, and promiscuous mode is not enabled. Nothing sets or changes a kernel
  setting.
- No ARP interception, no spoofing, no corrective replies. The frame builders (`NewRequest`,
  `NewReply`, `NewProbe`, `NewAnnounce`, `NewGratuitousReply`, `Frame.Marshal`) exist for tests and
  for the future interceptor. The monitor never calls them.
- IPv4 only. IPv6 and NDP are ignored entirely ([IPV6.md](IPV6.md)).
- It does not see unicast ARP between two other hosts on a switched network. It sees broadcast
  ARP and anything addressed to the host. That is enough for inventory and for spoofing
  signatures, which have to be broadcast or sent to victims.
- Linux only for capture. Other platforms get `arp.ErrUnsupported` from `arp.Open`; the codec,
  the monitor and `FakeSource` work everywhere.

## Capability

Reading raw packets needs `CAP_NET_RAW`. In a container:

```yaml
services:
  shepherd:
    network_mode: host      # the monitor must share the LAN interface
    cap_add: [NET_RAW]
```

Without the capability `arp.Open` fails with a clear permission error and nothing else is
affected. By default the interface of the default route is chosen (read from
`/proc/net/route`); pass a name to override. The gateway IP is learned from the same file
unless one is configured.

## Wiring

`cmd/shepherd/arp.go`'s `startARP` is the one place that opens the real socket and runs the
`Monitor`, gated by the `[arp]` config section:

```toml
[arp]
enabled = true
interface = ""     # empty auto-detects the default route's interface
```

```go
func startARP(ctx context.Context, cfg config.Config, reg *devices.Registry, onEvent func(arp.Event)) (*arp.Monitor, error)
```

It is started after the device registry, run in a goroutine, and torn down by cancelling `ctx`
(`Monitor.Run` closes the source on return). `onEvent` receives every `arp.Event`; `cmd/shepherd`
currently passes `nil`, so `startARP` just logs each one through the standard `log` package. A
future alarm engine wiring passes a non-nil callback instead, keyed by `Event.Key`. ARP never
fails Shepherd's startup: if `cfg.ARP.Enabled` is false, or `arp.Open` fails (wrong platform, no
`CAP_NET_RAW`), `startARP` logs a clear warning and returns `(nil, nil)`, and the rest of Shepherd
starts normally.

`Monitor.Stats()` is exposed at `GET /api/arp/stats` (`internal/portal/api_arp.go`), returning
`{"enabled": false}` when the monitor is not running, or `{"enabled": true, "stats": {...}}`
otherwise.

Using the library directly, outside `cmd/shepherd`, looks like:

```go
src, iface, err := arp.Open("")                  // "" = default-route interface
cfg := arp.DefaultConfig()
cfg.Sink = registry                              // *devices.Registry, or any devices.Sink
cfg.GatewayFunc = arp.DefaultGatewayFunc(os.ReadFile)
cfg.OnEvent = func(e arp.Event) { /* map to an alarm, keyed by e.Key */ }
mon := arp.NewMonitor(src, cfg)
go mon.Run(ctx)                                  // arp.Monitor is a devices.Discoverer
stats := mon.Stats()
```

`Event.Key` is stable per finding. Use it as the alarm dedupe key. `Event.Severity` is
`info`, `low`, `medium` or `high`, a hint and not a verdict. `Event.Baseline` is true for the
first two minutes after start, when every device looks new, so a consumer can record without
alerting. Events carry `Evidence` (string pairs) and a plain-language `Summary`.

## Event types and thresholds

Every threshold is a field of `arp.Config` (defaults shown). After an event fires, the same
`Key` is suppressed for `EventCooldown` (1 hour).

| Event | Fires when | Severity | What it means at home |
|---|---|---|---|
| `new-mac-seen` | A MAC is seen for the first time since start. | info | A new device joined, or a phone rotated its private Wi-Fi address (`randomized` evidence). |
| `ip-moved-to-new-mac` | An IP is now claimed by a different MAC. Previous owner silent for `QuietPeriod` (10m) and both MACs randomized: info (a rotation). Previous owner silent otherwise: low (a lease changed hands). Previous owner still active: medium. | info, low, medium | Usually a lease handover. An active old owner is worth a look. Not raised for the gateway IP, which has its own event. |
| `gateway-mac-changed` | The gateway IP is claimed by a MAC other than the one learned first (or pinned with `GatewayMAC`). | **high** | The classic ARP spoofing signature. It can also be a replaced or reset router. Raised once per transition; the key includes both MACs. |
| `duplicate-ip` | An IP changes owner `DuplicateFlips` (3) times within `DuplicateWindow` (2m), or a probe targets an IP whose owner spoke within `OwnerLive` (5m). | medium (flips, or a probe of the gateway); low (probe) | Two devices share an address, usually a static address that clashes with DHCP. |
| `mac-claims-many-ips` | One MAC claims `ManyIPsThreshold` (8) distinct IPs within `ManyIPsWindow` (10m). The gateway MAC and `TrustedMACs` are exempt. | medium | A scanner, or a poisoner answering for others. Routers doing proxy ARP and hosts running virtual machines can trigger it: add them to `TrustedMACs`. |
| `gratuitous-arp-flood` | `GratuitousLimit` (20) gratuitous frames from one MAC within `RateWindow` (1m). | low (medium for the gateway IP) | A few gratuitous ARPs on wake or roam are normal and ignored. A stream is a misbehaving device or an attack. |
| `arp-reply-without-request-storm` | `UnsolicitedLimit` (10) replies from one MAC within `RateWindow`, none answering a request seen within `RequestWindow` (30s). | medium | Poisoning replies. On a network where the host cannot see requests (some Wi-Fi bridges) this can be noisy; raise the limit. |
| `arp-spoofing-suspected` | One suspect MAC accumulates `SpoofMinSignals` (3) distinct signals within `SpoofWindow` (10m), or a gateway-mac-changed plus any one other. Signals: the gateway change, an ip-moved with an active old owner, many-ips, duplicate-ip, gratuitous flood, reply storm. New-MAC events, rotations and quiet handovers never count. | **high** | Several independent signs from one device. Treat it as real. |

Observations are separate from events: a chatty device is observed once per
`ObserveInterval` (5m) per MAC and IP pair. Broadcast, multicast and all-zero MACs are ignored,
as are sender IPs of 0.0.0.0 (probes), multicast, loopback, broadcast and 0.x.x.x. A probe
yields no observation because it carries no IP. Randomized (locally administered) MACs
are passed through unchanged; the registry already recognises them.

## Bounds and failure behaviour

All tables (MACs, IPs, pairs, recent requests, cooldowns, signals) are LRU-capped at
`MaxTracked` (16384), and each MAC remembers at most 64 addresses. Truncated or garbage frames
are counted (`malformed`, `not_arp`) and skipped. `Run` returns nil when the context ends or the
source closes, and closes the source on the way out. Capture errors are returned.

## Privacy

The monitor only reads ARP, which is already broadcast to every device on the local network. It
keeps nothing but MAC and IP pairs and a few counters, in memory. Nothing is written to disk and
nothing leaves the host except the observations that go to the local device registry. Frames are
decoded and dropped; payloads are never stored.

## Foundation for interception (not implemented)

Watch mode will need to know who is on the segment, the gateway's real MAC, and when
another party is already spoofing. This monitor supplies all three, and its codec builds the
frames the interceptor will need. Interception itself, with its single-active-interceptor lease
and corrective replies, is a separate, reviewed piece of work described in
[DESIGN.md](DESIGN.md). It is IPv4 only and nothing in this package does it.

## Tests

`go test -race ./internal/arp`: codec round trips and fuzzing (random and truncated input), the
route parser, the monitor with crafted frames (DHCP then ARP, IP change, MAC randomization
rotation, gateway MAC change raised once, spoofing burst, garbage), memory bounds and shutdown.
No real network is used. The raw socket in `open_linux.go` needs `CAP_NET_RAW`, so it cannot run
unprivileged; it is a thin file that only reads, and everything around it is tested through fakes.

`cmd/shepherd`'s `startARP` and `internal/portal`'s `/api/arp/stats` have their own tests
(`cmd/shepherd/arp_test.go`, `internal/portal/api_arp_test.go`), injecting a `FakeSource` through
a test seam over `arp.Open` so the wiring is exercised without `CAP_NET_RAW` either.
