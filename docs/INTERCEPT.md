# Watch mode: the ARP interception engine

`internal/intercept` is the implementation of Watch mode's first interception method described in
[DESIGN.md](DESIGN.md) ("Watch interception methods", method 1: ARP). It builds on the passive
monitor in [internal/arp](ARP.md) — reusing its Frame/MAC codec — but it is a different package
with a different risk profile: this one transmits.

**This package is a library only.** Nothing in Shepherd calls any of it automatically. No code in
`cmd/shepherd`, `internal/portal`, or any startup path constructs a `Controller` or calls `Steer`.
The only thing that ever invokes a real `Sender` outside this package's own tests is the maintainer,
later, deliberately, by wiring a trial UI or API — and that wiring is out of scope for this change.
Everything below documents what the package *can* do once something chooses to use it. For what
Watch mode would actually add over the DNS-only baseline, row by row, see
[WATCH-MODE-COMPARISON.md](WATCH-MODE-COMPARISON.md).

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

## Throughput: a real cost while a device is steered

Measured live, against a real phone pushing a sustained transfer: throughput dropped sharply while
steered (observed ~1.1 Gbps unsteered, down to roughly a third to a quarter while steered) and came
straight back the instant the trial ended. Nothing broke in any of this — every frame was still
relayed correctly, with zero errors — it was simply slower.

Three things were investigated in turn, live, against the real finding each time rather than the
first plausible guess:

1. **A single capture-and-relay goroutine**, suspected first since it serializes every packet
   through one blocking read, one lookup, and one blocking write. `Controller.ParallelRelay` fixes
   that real inefficiency by splitting capture across several `PACKET_FANOUT` workers
   (`capture_linux.go`), each with its own socket and its own `Sender` (`OpenMany`). It did measurably
   increase the total bytes relayed in a fixed window — but the slowdown the phone showed did not
   go away, which was the signal that this was not the dominant cause.
2. **GRO on the capturing interface**, ruled out directly: disabling it by hand, with no steering at
   all running, produced no slowdown whatsoever. Still a correct, necessary fix for the separate
   `EMSGSIZE` problem it causes (see below), just not the throughput explanation.
3. **TCP acknowledgment packets are outbound.** Watch mode only steers a device's outbound traffic,
   but that includes every ACK for a connection whose actual data is flowing *inbound* — a download's
   data never goes near Shepherd, but the steady stream of tiny ACK packets telling the sender "keep
   going" does. Measured relayed-byte totals during the slow runs were far too small to explain the
   speed drop by volume alone (tens of megabytes over two minutes, not the gigabytes a saturated link
   implies), which is consistent with a *packet-rate*, not *byte-volume*, bottleneck: a great many
   small ACKs, each one adding latency on its way through the relay, throttling the sender's own
   congestion window the normal way TCP responds to a slow or lossy path — even though the download
   itself never touched Shepherd.

The packet-rate cost that matters most turned out to be inside the relay's own send path, not the
raw syscalls: every relayed frame went through `sendWithTimeout`'s goroutine-and-timer wrapper (a
fresh goroutine and a fresh `time.After` timer, per packet), there to bound a `Sender.Send` call that
might hang forever. For the real `rawSender`, it cannot: its socket now carries a kernel-enforced
`SO_SNDTIMEO`, set once when the socket opens, so `Sendto` itself is already bounded. `rawSender`
reports this (the `selfBounded` interface in `sender.go`), and `sendWithTimeout` skips its wrapper
entirely for a Sender that reports it — a direct call, with only a cheap `defer`/`recover` for a
genuine panic, instead of a goroutine and a timer allocation on every single packet. `FakeSender`
does not report `selfBounded`, so every existing safety test (a deliberately wedged Sender, a
panicking one) still exercises the slow, fully defensive path unchanged.

That `sendWithTimeout` fix, like `ParallelRelay` before it, was re-measured live and **did not fix
the drop**: with both fixes in place, a real device still fell from ~1.1 Gbps to roughly 300 Mbps
while steered — the same slowdown as before either fix. Two more candidates were ruled out the same
way, live, against the real device:

4. **Tailscale on the test device.** Disabled entirely during a trial: same slowdown. Not the cause.
5. **Something upstream of all of this.** A live packet capture taken during a slow run showed the
   same SYN and QUIC "initial" packets being retransmitted abnormally fast — microseconds apart, not
   the seconds-scale backoff any normal TCP/QUIC stack uses — with a large directional asymmetry:
   thousands of packets out to one destination, only hundreds back. This was never root-caused before
   the investigation paused. Two hypotheses were raised and left open: (a) the device's own
   connections are retrying pathologically because something about the path looks broken to them, or
   (b) frames are being duplicated somewhere — possibly Shepherd's own capture path, possibly the
   eero's own Wi-Fi/bridging behavior reacting to the ARP change.

### A later code audit: no duplication found in Shepherd's own path, but a real avoidable cost found

Hypothesis (b) above — duplication inside Shepherd itself — had only ever been reasoned about
informally, never actually audited against the code. A line-by-line pass of `capture_linux.go`,
`open_linux.go`, `relay.go`, `controller.go`, and `spoofer.go` did that audit. Everything in this
subsection is a code-review finding, **not** re-measured against a real device — the honest
re-measurement is the first item in the "what to test live next" list below.

**`Relay.HandleFrame`'s destination-MAC filter is correct**, and was checked explicitly rather than
assumed. `HandleFrame` rewrites only the destination MAC when relaying (`relay.go`); the source MAC,
always the steered device's own, is left untouched. Neither the Relay's own relayed frames (addressed
to `GatewayMAC`) nor the Spoofer's claim/corrective frames (addressed to the device's own real MAC)
are ever addressed to `ShepherdMAC`, so the `dst != r.ShepherdMAC` check at the top of `HandleFrame`
discards every one of them before any lookup or send — correctly, in every case, not just the common
one. No path was found where a frame Shepherd itself transmitted could be re-relayed, double-sent, or
mistaken for new device traffic. **No frame duplication was found anywhere in this package.**

**But that correct filter runs after an avoidable capture.** The capture socket in
`openCaptureGroup` is a plain `AF_PACKET`/`ETH_P_ALL` socket with no promiscuous mode set (confirmed:
nothing in this package ever asks for it). Without `PACKET_IGNORE_OUTGOING`, a non-promiscuous
`AF_PACKET` socket bound to an interface still receives a loopback copy of every frame *this host*
transmits on that interface — standard Linux behavior, the same reason `tcpdump` shows your own
outgoing packets without asking for promiscuous mode. Concretely: every single frame the Relay
retransmits, and every periodic ARP claim/corrective the Spoofer sends, loops straight back into
Shepherd's own capture socket, gets parsed, fails the destination-MAC check, and is thrown away. At
the relay's real packet rate (the ACK-storm scale discussed above — tens of thousands of frames per
second during a sustained transfer), that is a second full parse-and-discard for every frame actually
relayed: real, avoidable CPU work, on the exact hot path already under suspicion, that nothing before
this audit had identified or measured.

**Fix:** `openCaptureGroup` now sets `PACKET_IGNORE_OUTGOING` (`golang.org/x/sys/unix`, value `0x17`,
Linux 4.20+) on each capture socket, asking the kernel to not deliver a host's own outgoing frames to
it at all. This is purely a cost removal, not a correctness change — the destination-MAC filter
already made the old behavior safe, it just paid for it. The call's error is deliberately ignored: on
a pre-4.20 kernel it fails with `ENOPROTOOPT` and capture keeps working exactly as it did before,
just without this saving, rather than failing the whole capture group over a missing optimization.
**This has not been measured live.** It removes real, confirmed-avoidable work, but there is no
measurement yet of how much of the 1.1→0.3 Gbps drop (if any) it accounts for — it may be a
meaningful fraction of the packet-rate cost, or it may be a rounding error next to whatever is
actually gating throughput. Treat it the same as the `ParallelRelay` and `sendWithTimeout` fixes
before it: plausible, shipped, unverified against real hardware.

**The Spoofer's claim interval and frame content were also reviewed against hypothesis (a)** (the
device itself retrying pathologically). `Spoofer.sendClaim`/`sendCorrective` send one **unicast** ARP
reply (`arp.NewReply`, addressed directly to the target device's real MAC) every `DefaultSpoofInterval`
(2 seconds) — not a broadcast gratuitous ARP flood, not a burst, not malformed content: standard
unsolicited-ARP-reply spoofing, same shape most ARP tools use, at a frequency far below any normal
device's ARP cache TTL (which is minutes, not seconds). **Nothing found here looks unusual or
wrong.** This review does not rule out hypothesis (a) — the device, or the eero's bridging of a
one-sided ARP change, could still be reacting badly to being steered at all — it only rules out the
Spoofer's own timing or content as the mechanism, since there is nothing about either that departs
from how ARP spoofing normally looks on the wire.

**Batched I/O (`recvmmsg`/`sendmmsg`) was considered and deliberately not attempted.** It would cut
per-packet syscall overhead further, but it adds real `unsafe.Pointer`-adjacent buffer-management
code to the single most safety-reviewed package in this repo, and this package's raw-socket code is
already, by design, untestable without `CAP_NET_RAW` (see the comments in `open_linux.go` and
`capture_linux.go`) — there is no way to give it the same test coverage as everything else here
without live hardware to validate against. Shipping that complexity now, unverified, on the strength
of a suspected-but-unconfirmed throughput problem is a worse trade than leaving it for a future change
made *after* the `PACKET_IGNORE_OUTGOING` fix above has been measured live and shown to still leave a
syscall-bound gap worth chasing.

**New diagnostics, added so the next live trial does not need a fresh packet capture to see this.**
`Controller.Stats()` is a new cumulative counter snapshot (frames/bytes examined, frames discarded for
not being addressed to Shepherd, frames/bytes actually relayed), fed lock-free from every `Relay`
sharing a `Controller`'s state — the `ParallelRelay` workers included. `SteeredDevice` (from `Status()`)
now also reports `PacketsRelayed`, not just bytes. `cmd/intercept-trial` samples `Stats()` every 2
seconds alongside `Status()` and logs a `rate:` line — packets/sec and bytes/sec actually relayed, the
raw examined rate, and `not_for_shepherd` (frames seen whose destination wasn't Shepherd's MAC, almost
all of which are the self-capture loopback described above). A live trial with this build will show,
without any separate `tcpdump`, whether packet rate itself is spiking abnormally during a slow run, and
roughly how much of the capture socket's work was ever the self-loopback `PACKET_IGNORE_OUTGOING` now
asks the kernel to stop delivering.

### Live result: `PACKET_IGNORE_OUTGOING` measured, does not fix it — and a new, more specific lead

Re-measured live (2-minute trial, real phone, real eero, `-workers` default, `PACKET_IGNORE_OUTGOING`
active alongside the existing `ParallelRelay` and `sendWithTimeout` fixes): **300–400 Mbps while
steered**, the same range as every earlier measurement, down from the ~1.1 Gbps unsteered baseline.
All three fixes shipped so far are real, individually-justified improvements — none of them, alone or
combined, closes the gap. Self-capture overhead was not the dominant cost after all.

The new `rate:` log line (`examined`/`relayed` pps, `not_for_shepherd`), watched live for the first
time this trial, narrows the search meaningfully. During the two windows that line up with the
maintainer's own speed tests (roughly 22s and 18s long, `examined` spiking as high as 5,700 pkt/s),
**`relayed` never left the single digits — the entire trial, bursts included** — and total bytes
actually relayed over the full two minutes was ~226 KB, far too little to be the outbound side of a
sustained 300–400 Mbps transfer by itself (the ACK-storm theory from the first investigation). Almost
everything the capture socket saw during the bursts was `not_for_shepherd`: traffic that was never
addressed to Shepherd's MAC at all, not a duplicate of something Shepherd itself sent (that specific
case is exactly what `PACKET_IGNORE_OUTGOING` already removes, and it was active for this run).

That rules out the self-capture loopback as the burst's source and weakens the pure ACK-storm framing
(if outbound ACKs for the download were the whole story, they would show up as `relayed`, since they
are addressed to Shepherd by design once a device is steered). It does not yet say what the
`not_for_shepherd` burst traffic actually is. Two live-testable explanations remain open, not yet
distinguished:

1. **The eero's own bridging/MAC-learning reacts to the ARP change** in a way that sends Shepherd's
   switch port more traffic than it would otherwise see during a transfer — consistent with hypothesis
   (a) from the first investigation (the device or the network path "looking broken" to something), but
   now with a concrete signature to look for (a `not_for_shepherd` spike that tracks the transfer, not
   just a vague retransmission concern).
2. **Something about the capture itself amplifies under load** in a way this audit did not predict —
   less likely given the code-level audit above found no duplication, but not fully excluded without a
   fresh packet capture to identify what the burst frames actually are (source/destination MACs,
   whether they are the steered device's own frames at all).

**Next, in order**: a fresh `tcpdump` on Shepherd's own interface during exactly this kind of burst,
filtered to show source/destination MACs on the high-rate frames, to identify what `not_for_shepherd`
actually contains; then, only if the eero itself looks implicated, a capture on the eero's own uplink
(not just at Shepherd) during the same kind of burst, which this audit could not do since it only
covered Shepherd's own code. Batched I/O (`recvmmsg`/`sendmmsg`) stays deliberately not attempted —
this result does not point at a syscall-rate ceiling in Shepherd's own relay, it points away from it.

This is a software relay, not a hardware switch, so steering a device will never be perfectly free —
but a drop this large, confirmed unchanged across three real fixes, is not ordinary relay overhead.
(It was not: see "The cause the evidence points at" below, measured and closed.)

### A real, separate bug found via the planned `tcpdump` — not the throughput-ceiling cause, but fixed

The fresh capture called for above turned up something concrete, though not the burst's root cause:
`Relay.HandleFrame` rewrote the destination MAC and relayed *every* frame addressed to Shepherd's own
MAC from a steered device, with no check on where it was actually headed. A steered device's ARP entry
for the real gateway is spoofed to Shepherd's MAC, but its entry for Shepherd's *own* IP (a DNS query to
the resolver Shepherd itself runs, a connection to its portal) is never touched and already correctly
resolves to that same MAC — so at the Ethernet layer, traffic genuinely meant for Shepherd was
indistinguishable from traffic meant for the real gateway, and every single one of those locally-destined
packets got needlessly duplicated out to the gateway, which has no reason to do anything with a frame
addressed to its own MAC but a different IP and just drops it. Confirmed directly in the capture: the
same DNS query, from the steered device to Shepherd's resolver, visible twice — once answered normally
by Shepherd's own stack, once uselessly re-transmitted to the gateway with a rewritten destination MAC.

Not data loss (Shepherd's own stack still received and answered the original locally, independent of the
relay's duplicate), but real wasted relay-worker capacity on every locally-destined packet a steered
device sends — a plausible, if likely partial, contributor to the throughput ceiling, now closed. Fixed
by `Relay.ShepherdIPs`: `HandleFrame` now leaves a frame alone (lets Shepherd's own kernel handle it
normally) when its IPv4 destination is one of Shepherd's own addresses on the interface, instead of
blindly relaying anything addressed to its MAC. `cmd/intercept-trial` auto-detects these from the
interface and a new `for_shepherd_itself` count in the `rate:` log line shows how much of this was
happening on any future live trial. The eero-bridging-reaction and capture-amplification hypotheses
above remain open and still need that same `tcpdump`, since this fix does not, by itself, change the
Mbps ceiling's own suspected cause.

### The cause the evidence points at: the relay was teaching the switch the wrong port

Re-read together, the live results above describe packet *loss* on the device's **inbound** side,
not a slow relay: relayed traffic never left single digits per second during the slow runs (so the
relay's own speed could not have mattered), the slowdown looked exactly like TCP and QUIC reacting
to loss (abnormally fast retransmits, "thousands out, hundreds back"), and the `not_for_shepherd`
burst tracked the transfer. One thing in the relay's own design produces precisely that.

`Relay.HandleFrame` rewrote only the **destination** MAC and deliberately left the steered device's
own MAC as the **source** of every frame it retransmitted ("a pure Ethernet-layer relay"). Every
Ethernet switch, and every Wi-Fi/LAN bridge — a consumer mesh router like the eero is one — learns
which port a MAC lives behind from the source address of the frames it sees. So each relayed frame
taught the eero that the phone lives on Shepherd's wired port; the phone's next Wi-Fi frame taught
it the opposite. While the entry pointed at Shepherd's port, the phone's **inbound** traffic — the
download direction, the one that carries the bytes and the one Watch mode never even sees — was
delivered to Shepherd's port and dropped. A handful of relayed frames per second is enough to flap
the entry a handful of times per second, and a gigabit stream does not survive that.

It also explains the `not_for_shepherd` burst without any amplification inside Shepherd: those were
the misdirected inbound frames, addressed to the *phone's* MAC, arriving at Shepherd's port. A
non-promiscuous NIC would have dropped them silently in hardware, so their showing up at all says
the capturing NIC was in promiscuous mode for some other reason (a Docker `macvlan`, a VM bridge, a
running `tcpdump` all do that). And it explains why the relayed count stayed tiny: a modern phone's
speed test is likely to run over IPv6, which uses NDP, not ARP, and so never went near Shepherd —
but the flapping MAC-table entry is protocol-agnostic, so the IPv6 download was hurt all the same.

**The fix:** a relayed frame now leaves with *both* addresses rewritten — destination to the real
gateway's MAC, source to Shepherd's own. The device's MAC is then only ever seen on its own port and
Shepherd's only on Shepherd's; nothing flaps. The IP packet inside is still untouched (the gateway
sees the device's own source IP and answers to it through its own, never spoofed, ARP entry), so
this is still a pure Ethernet-layer relay with no NAT, and the one-sided scope is unchanged.

**Measured live, 2026-10-30, and it is the fix.** Same NAS (12-core x86_64, Debian 12, kernel 6.18),
same eero, same phone, 2-minute trial through `ParallelRelay` with this fix, the kernel-side capture
filter and the lock-free counters below: the maintainer reported *"no perceivable slow down, reaching
full 1 gig Wi-Fi speeds"*. The relay's own `rate:` line during the speed test peaked at **167,000
relayed frames/s and 207 MB/s (about 1.6 Gbit/s)** of the phone's outbound traffic — the upload
half of the test, every byte of which crossed the relay — with 5.39 GB relayed over the trial, zero
send errors, the device healthy on every tick, `not_for_shepherd` at zero throughout, and a clean
auto-revert with GRO restored. Against the ~300–400 Mbps that every earlier run measured on this
exact path, that closes the investigation: the ceiling was the switch's MAC table, not the relay.

Two more cost-only changes went in alongside it, both on the relay's per-frame path:

- **A kernel-side capture filter.** Each `PACKET_FANOUT` capture socket now carries a classic BPF
  program (`SO_ATTACH_FILTER`, built in `capture_filter.go` with `golang.org/x/net/bpf`) admitting
  only IPv4 frames whose destination MAC is Shepherd's, so the kernel drops everything the Relay
  would discard anyway — broadcast, multicast, a promiscuous NIC's traffic for other hosts, ARP,
  IPv6, our own loopback copies — before copying it to userspace. The filter is attached before the
  socket is bound (created with protocol 0, bound with `ETH_P_ALL`, the libpcap order), so no frame
  ever slips in ahead of it. It is unit-tested on every platform through x/net/bpf's interpreter,
  including a property test that it admits a frame if and only if `HandleFrame` would relay it.
  That test found a real hole: `HandleFrame` filtered by denylist (not ARP, not IPv6), which let a
  VLAN-tagged (`0x8100`) frame through — and whatever a VLAN tag wraps could be IPv6. `HandleFrame`
  now positively matches plain IPv4 and nothing else. In the trial harness's `rate:` line,
  `not_for_shepherd` should now read zero or nearly so: anything it counts got past the kernel
  filter, which only an old kernel that refused to attach it should ever allow.
- **No lock on the hot path.** Per-device counters (`BytesRelayed`, `PacketsRelayed`,
  `LastVerified`, `Healthy`) are atomics reached through the same lock-free snapshot `Lookup`
  already used, so the parallel workers no longer serialize on `Controller.mu` for every frame.

### Beyond userspace: the XDP relay

The userspace relay is bounded by two syscalls and one buffer copy per frame, which is fine for the
ACK stream of a multi-gigabit download but a real ceiling for a multi-gigabit upload on a small
NAS. `Controller.AttachXDP` (`xdp_linux.go`, program in `bpf/xdp_relay.c`) is the same relay as an
XDP program on the interface: for a steered device's IPv4 frame addressed to Shepherd's MAC it
rewrites both MACs, counts it, and bounces it straight back out the same interface (`XDP_TX`)
without the frame ever becoming an skb, let alone crossing into userspace. Everything else is
`XDP_PASS`, untouched, so with the program attached the kernel sees exactly what it would without
it, minus the frames that were going to be relayed. Nothing is ever dropped. It runs in native
(driver) mode where the NIC driver supports it and falls back to generic mode otherwise, which is
slower but still skips userspace entirely.

**Measured live, 2026-10-30, immediately after the userspace run above**, `-xdp auto` attached in
native mode on the NAS's NIC and relayed the same phone's speed test at a peak of **180,000 frames/s
and 221 MB/s (about 1.77 Gbit/s)**, 3.02 GB over the test, healthy throughout, with nothing but
one-second counter reads crossing into userspace; the maintainer again saw no perceivable slowdown
and about a gigabit, which is that phone's Wi-Fi maximum. One thing to know: the NIC driver took about eight
seconds after the native attach before the program saw its first frame (the ring is torn down and
rebuilt on attach), during which `examined` read zero; the device stayed inside `StartupGrace` and
relaying began on its own. Generic mode has no such gap.

Its decision rules are `HandleFrame`'s, plus one the Go relay gets for free from `AF_PACKET`'s
copy semantics and the XDP program must do itself: a frame whose destination IPv4 address is one of
Shepherd's own (a steered device's DNS query to Shepherd, a portal connection) is passed to the
stack, never relayed. A steered-device map (`steered`, keyed by MAC) is kept in sync with the
`Controller`'s own steered set at every `Steer`, `Unsteer` and `PanicStop`, so the safety model is
unchanged: the Controller is still the only authority on what is steered, the program only consults
it. Per-device packet and byte counters live in that map and are read back every second to feed
`Status()` and the health loop, so fail-open on silence works identically. The program is compiled
by `go generate` (`bpf2go`, needs a clang with the BPF backend; the generated objects are committed,
so an ordinary `go build` needs no clang) and loaded with `github.com/cilium/ebpf`. Attaching needs
`CAP_NET_ADMIN` and `CAP_BPF` (or `CAP_SYS_ADMIN` on kernels before 5.8) on top of `CAP_NET_RAW`
for the Spoofer's sends. `cmd/intercept-trial -xdp auto` uses it in place of `ParallelRelay`.

## IPv4 only, no exceptions

IPv6 and NDP are never touched anywhere in this package. This is a hard rule carried over from
[IPV6.md](IPV6.md): Thread border routers and Matter devices depend on IPv6 neighbor discovery and
RAs working undisturbed, and a second actor on the LAN sending RAs or spoofing NDP breaks them
silently. The `Relay` relays plain IPv4-ethertype frames and nothing else — a positive match, not a
denylist, so a VLAN tag cannot smuggle IPv6 past it — the kernel-side capture filter admits only
the same, and the `Spoofer` only ever builds plain IPv4-over-Ethernet ARP frames; all of it is
proven with a fuzz/property test that feeds random and adversarial bytes at them (`go test -fuzz
FuzzRelayHandleFrame`, the capture-filter agreement test, and the Spoofer's own frame-builder
property test). The XDP program checks the ethertype before anything else, for the same reason.

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

## The one-off trial harness

`cmd/intercept-trial` is exactly that first trial, made runnable: a standalone CLI (Linux-only,
build-tagged) that wires a `Controller` as above, relays through `ParallelRelay` (see "Throughput"
above), and steers exactly one device named twice on the command line (`-target-mac` and `-confirm`,
which must match byte for byte) for a mandatory, capped (5 minutes max) trial duration. It is **not**
built, run, or shipped by anything in `cmd/shepherd`; it is a separate binary the maintainer builds
and runs by hand, once, watching `Status()` scroll by, with Ctrl-C wired to `PanicStop` + `Close`.

It also disables GRO (generic-receive-offload) on the interface for the trial's duration and always
restores it on exit, including on a signal: GRO coalesces several inbound TCP segments into one
oversized frame before any socket sees them, and the Relay retransmits whatever it captures
unchanged, so a coalesced super-frame can fail a raw send with `EMSGSIZE` — which the health loop
correctly, safely treats as a fail-open signal and unsteers at once, but which is really a capture
artifact, not a real fault. Needs `CAP_NET_ADMIN` (for `ethtool`) alongside `CAP_NET_RAW`.

Run twice against a disposable, throwaway VM (clean both times, auto-revert on schedule) and twice
against the maintainer's own phone with the maintainer's explicit go-ahead, watching live: a 30s run
(clean, ~8.4 MB relayed) and a 2-minute run that caught exactly the GRO/`EMSGSIZE` case above and
self-reverted within about a second, before the GRO handling existed. Confirms the maintainer's eero
7 Max accepts one-sided ARP steering, which was an open question.

None of this is wired into `cmd/shepherd` or the portal yet. Doing so happens later, only
with the maintainer's explicit go-ahead.

## Package layout

- `sender.go` — the `Sender` interface (`Send(Frame) error`, the one-method mirror of
  `internal/arp`'s `Source.Next`), `FakeSender` for tests, and the bounded `sendWithTimeout` helper
  every send in this package goes through.
- `open_linux.go` *(build-tagged `linux`)* — the only code that touches a send socket: `AF_PACKET`
  `SOCK_RAW` senders, write-only, needing `CAP_NET_RAW`. `Open` returns one; `OpenMany` returns `n`
  independent ones (no shared fd, no shared mutex), for `ParallelRelay`. Thin by necessity and not
  exercised by this package's own tests, the same pattern `internal/arp/open_linux.go` already uses
  on the read side. `open_other.go` reports `ErrUnsupported` everywhere else.
- `capture_linux.go` *(build-tagged `linux`)* — the read side: `n` `AF_PACKET` sockets joined to one
  `PACKET_FANOUT` group (hashed by flow, so one connection never gets reordered across workers), each
  carrying the kernel-side capture filter, and `Controller.ParallelRelay`, which pairs each capture
  socket with one of `OpenMany`'s senders via `NewRelay` and runs each pair on its own goroutine.
  This is what makes the relay path use more than one core; see "Throughput" above.
  `capture_other.go` reports `ErrUnsupported` everywhere else.
- `capture_filter.go` — the classic BPF program those capture sockets carry (destination MAC is
  Shepherd's, ethertype is IPv4), built with `golang.org/x/net/bpf` and unit-tested through its
  interpreter on every platform, including a property test that it agrees with `Relay.HandleFrame`
  frame for frame.
- `bpf/xdp_relay.c`, `xdp_bpfel.go`/`xdp_bpfeb.go` *(generated)*, `xdp_linux.go` *(build-tagged
  `linux`)* — the XDP relay: the eBPF program, its `bpf2go`-generated loader, and
  `Controller.AttachXDP`, which attaches it and keeps its steered-device map and counters in step
  with the Controller. See "Beyond userspace" above.
- `clock.go` — the `Clock` interface and `FakeClock`, so the Spoofer's periodic resend and the
  Controller's health loop and trial timers are all tested with no real sleeps.
- `spoofer.go` — `Spoofer`: one device's periodic claim and its corrective revert on stop, panic, or
  context cancellation.
- `relay.go` — `Relay`: rewrites (both MACs) and retransmits a steered device's outbound frames;
  relays plain IPv4 only, so ARP, IPv6 and VLAN-tagged frames never get past it.
- `controller.go` — `Controller`: the safety-governed authority described above. `Steer`, `Unsteer`,
  `PanicStop`, `Rearm`, `Status`, `History`, `Close`, `HandleFrame`, and `NewRelay` (an additional
  `Relay` sharing this Controller's state but with its own `Sender`, which is all `ParallelRelay` is
  built from).

## Tests

`go test -race ./internal/intercept`: every scenario in this document, plus concurrent
`Steer`/`Unsteer`/`Status`, a fuzz test proving IPv6 is never relayed under any input, a property
test proving the Spoofer's frame builder never produces anything but a plain IPv4 ARP reply, and the
capture filter run through x/net/bpf's interpreter against the Go Relay frame for frame. No real
interface and no real network anywhere; `FakeSender` and `FakeClock` throughout. `open_linux.go`
needs `CAP_NET_RAW` and cannot run unprivileged, so it is the one file this package's coverage floor
excludes, same as `internal/arp`'s equivalent file.

The XDP relay is the exception to "no real kernel anywhere", because there is no other way to run an
eBPF program: `xdp_linux_test.go` loads the real program (so the kernel's verifier has to accept it)
and runs it through `BPF_PROG_TEST_RUN` on the same frames the Go Relay is tested with, insisting the
two agree; `xdp_attach_linux_test.go` goes end to end on a veth pair — attach, `Steer`, inject frames
on the peer, read the relayed frames back with both MACs rewritten, see the counters reach `Status()`
and `Stats()`, `Unsteer`, see relaying stop at once. Both need root (or `CAP_BPF`+`CAP_NET_ADMIN`)
and skip without it; `make test-xdp` runs them for real in a privileged Linux container (Docker
required, any host OS), which is also how they were run during development.
