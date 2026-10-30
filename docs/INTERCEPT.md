# Watch mode: the ARP interception engine

`internal/intercept` is the implementation of Watch mode's first interception method described in
[DESIGN.md](DESIGN.md) ("Watch interception methods", method 1: ARP). It builds on the passive
monitor in [internal/arp](ARP.md) — reusing its Frame/MAC codec — but it is a different package
with a different risk profile: this one transmits.

**This package is a library only.** Nothing in Shepherd calls any of it automatically. No code in
`cmd/shepherd`, `internal/portal`, or any startup path constructs a `Controller` or calls `Steer`.
The only thing that ever invokes a real `Sender` outside this package's own tests is the maintainer,
later, deliberately, by wiring a trial UI or API — and that wiring is out of scope for this change.
Everything below documents what the package *can* do once something chooses to use it.

## What one-sided ARP steering does

Shepherd sends a chosen device periodic ARP replies claiming that Shepherd's own MAC owns the
gateway's IP. The device's ARP cache believes it, so the device sends its outbound (device-to-
internet) traffic to Shepherd's MAC instead of the gateway's. Shepherd rewrites the destination MAC
back to the gateway's real MAC and retransmits the frame on the wire, unchanged otherwise: no NAT,
no IP rewrite, no new source port. The gateway's own ARP table is never touched.

## What it sees, honestly: outbound only

Because the gateway's ARP table is never touched, inbound (gateway-to-device) return traffic goes
straight to the device over the normal path. **This is a known, accepted scope boundary, not a bug
to fix.** One-sided ARP steering gives upload/outbound-direction visibility and control only:

- Seen and controllable: everything the device sends outward — DNS-bypassing traffic, connection
  attempts, TLS/QUIC SNI on the way out, upload volume, destinations.
- Not seen: the matching downloads and responses coming back from the internet to the device. A
  device's total traffic volume as reported by Watch mode understates its real usage, sometimes by
  a lot (most home traffic is download-heavy).
- Two-sided interception (spoofing the device's IP to the gateway too) or Gateway mode would close
  this gap; that is tracked as future work in DESIGN.md, not something this package attempts.

## IPv4 only, no exceptions

IPv6 and NDP are never touched anywhere in this package. This is a hard rule carried over from
[IPV6.md](IPV6.md): Thread border routers and Matter devices depend on IPv6 neighbor discovery and
RAs working undisturbed, and a second actor on the LAN sending RAs or spoofing NDP breaks them
silently. The `Relay` filters out IPv6-ethertype frames before anything else runs, and the `Spoofer`
only ever builds plain IPv4-over-Ethernet ARP frames; both are proven with a fuzz/property test that
feeds random and adversarial bytes at them (`go test -fuzz FuzzRelayHandleFrame`, and the Spoofer's
own frame-builder property test).

## The safety model

This is the part of the package that is the most tested, deliberately. Four independent layers,
each able to act alone:

1. **Exclusion, enforced at the call, not just documented.** `Controller.Steer` itself rejects:
   - the gateway's own IP or MAC,
   - Shepherd's own MAC,
   - any MAC in the static `ExcludedMACs` list (infrastructure, Shepherd's other interfaces),
   - any MAC the `Excluder` interface reports excluded — wired to the device registry's `Excluded`
     flag, so a device the operator opted out of can never be steered even if something asks.
   - anything that is not a concrete, usable IPv4 address (no IPv6, no multicast, no loopback, no
     unspecified or broadcast address).

2. **Health verification, not just "we sent ARP replies."** Every `HealthInterval` (default 3s), the
   Controller checks each steered device for *real relayed traffic*, observed by the `Relay`, within
   a grace window:
   - `IdleGrace` (default 15s) once a device has relayed at least once — a device that is briefly
     idle (phone asleep, user not browsing) is not flapped on silence alone.
   - `StartupGrace` (default 30s) for a device that was just added and has never relayed anything —
     longer, because ARP convergence and the device's first outbound packet can take a moment.
   - Any relay send error unsteers the device immediately, without waiting for the next tick.

3. **Fail open.** The moment a steered device looks unhealthy for any reason, the Controller calls
   `Unsteer` on it itself and records why (`Controller.History`). A device defaults back to its real
   gateway the instant something looks wrong; it is never left stuck mid-steering. `Unsteer`'s
   corrective ARP reply is sent best effort and bounded: a wedged or erroring `Sender` cannot block
   the health loop, because every send anywhere in this package goes through a bounded timeout
   (`SendTimeout`, default 2s) that runs the send in its own goroutine and gives up on it, rather than
   blocking the caller.

4. **A panic button that always works.** `Controller.PanicStop()` immediately removes every steered
   device from the active set (so the `Relay` stops matching their traffic at once) and disables new
   `Steer` calls until `Rearm()` is called. It never waits on a `Sender`: even a completely wedged
   Sender cannot delay `PanicStop` itself, because `PanicStop` does not wait for the corrective
   reverts it triggers — those happen best effort, in the background, same as any other unsteer.

On top of all four: **trial mode**. `Steer(dev, SteerOptions{Trial: true, Duration: d})` auto-reverts
after `d` even if nothing else calls `Unsteer`, using the Controller's injectable `Clock` so tests
(and, later, a real trial) never depend on anything actually waiting out a wall-clock duration.

## Capability and kernel requirements

Transmitting needs `CAP_NET_RAW`, the same capability the passive monitor already needs to read:

```yaml
services:
  shepherd:
    network_mode: host
    cap_add: [NET_RAW]
```

`net.ipv4.ip_forward` is **not** required, and this is verified against the actual implementation,
not assumed: both `internal/arp`'s read path and this package's `open_linux.go` send path use raw
`AF_PACKET` sockets that hand complete Ethernet frames straight to the network interface. A frame
read this way, or sent this way, never enters the kernel's IP stack — no routing lookup, no
netfilter, no conntrack, because there is no IP-layer socket involved at any point. `ip_forward`
only affects frames the kernel itself chooses to route between interfaces at Layer 3; this is a pure
Layer 2 relay performed entirely in Shepherd's own process. Nothing in this package reads or writes
`net.ipv4.ip_forward`, and nothing needs to.

## How a future trial would use this

Once the maintainer decides to wire a trial (a UI button, a CLI flag, a portal API — none of which
exist yet):

1. Build a `Controller` with the real gateway's IP/MAC, Shepherd's own MAC, a real `Sender`
   (`intercept.Open(iface)` on Linux), and the device registry wrapped to satisfy `Excluder`.
2. `Steer(dev, SteerOptions{Trial: true, Duration: 2 * time.Minute})` (or whatever short window feels
   safe for a first run).
3. Watch `Status()` for `Healthy` and `BytesRelayed` moving.
4. Call `PanicStop()` at the first sign of trouble; it works even if something else has gone wrong.
5. Let the trial auto-revert on its own otherwise — nothing else needs to remember to clean up.

None of this is wired up yet. Doing so, and running it against a real network, happens later, only
with the maintainer's explicit go-ahead.

## Package layout

- `sender.go` — the `Sender` interface (`Send(Frame) error`, the one-method mirror of
  `internal/arp`'s `Source.Next`), `FakeSender` for tests, and the bounded `sendWithTimeout` helper
  every send in this package goes through.
- `open_linux.go` *(build-tagged `linux`)* — the only code that touches a socket: an `AF_PACKET`
  `SOCK_RAW` sender, write-only, needing `CAP_NET_RAW`. Thin by necessity and not exercised by this
  package's own tests, the same pattern `internal/arp/open_linux.go` already uses on the read side.
  `open_other.go` reports `ErrUnsupported` everywhere else.
- `clock.go` — the `Clock` interface and `FakeClock`, so the Spoofer's periodic resend and the
  Controller's health loop and trial timers are all tested with no real sleeps.
- `spoofer.go` — `Spoofer`: one device's periodic claim and its corrective revert on stop, panic, or
  context cancellation.
- `relay.go` — `Relay`: rewrites and retransmits a steered device's outbound frames; filters out ARP
  and IPv6 before anything else runs.
- `controller.go` — `Controller`: the safety-governed authority described above. `Steer`, `Unsteer`,
  `PanicStop`, `Rearm`, `Status`, `History`, `Close`, `HandleFrame`.

## Tests

`go test -race ./internal/intercept`: every scenario in this document, plus concurrent
`Steer`/`Unsteer`/`Status`, a fuzz test proving IPv6 is never relayed under any input, and a property
test proving the Spoofer's frame builder never produces anything but a plain IPv4 ARP reply. No real
interface and no real network anywhere; `FakeSender` and `FakeClock` throughout. `open_linux.go`
needs `CAP_NET_RAW` and cannot run unprivileged, so it is the one file this package's coverage floor
excludes, same as `internal/arp`'s equivalent file.
