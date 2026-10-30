# What Watch mode actually buys you

Shepherd protects a network two different ways today, and they are not the same feature with
different settings — they sit at different layers, with different costs. This page lays out
exactly what you get with just the baseline (DNS filtering, passive ARP, geo-block, policy
modes, alarms, the scanners) versus what Watch mode (one-sided ARP interception,
[INTERCEPT.md](INTERCEPT.md)) would add on top, once it ships. Nothing here is marketing copy —
every row reflects the real, current, honestly-documented state of the code, not an aspiration.

**Watch mode is not live today.** `internal/intercept` is a tested library, hand-run only through
`cmd/intercept-trial` for short, deliberate trials; nothing in `cmd/shepherd` or the portal wires
it in yet (see [ROADMAP.md](ROADMAP.md) step 11). The "with Watch mode" column below describes
what the library already does in a trial, not a feature you can turn on in the portal.

| Capability | Baseline (DNS filtering + passive monitoring) | With Watch mode (one-sided ARP interception) |
|---|---|---|
| How blocking works | DNS answers rewritten (null or NXDOMAIN) for names that match a block rule | Same DNS-level blocking, unchanged — Watch mode does not replace it |
| Blocks an app that hardcodes IPs or runs its own DNS-over-HTTPS resolver | No — if a query never goes through Shepherd's resolver, there is nothing to block | Partially — Shepherd can see and steer the device's outbound connection attempts even when its DNS was bypassed entirely, since steering doesn't depend on DNS at all |
| Visibility into what a device actually talks to | Only the DNS names it asked Shepherd to resolve | Direct outbound traffic (destination IPs, TLS/QUIC SNI, connection attempts) regardless of what resolver the device used |
| Learns devices and MAC addresses | Yes — the passive ARP monitor ([ARP.md](ARP.md)) listens only, transmits nothing | Same passive learning, plus active one-sided steering for whichever devices you choose to steer |
| Sees a device's download/return traffic | N/A — not a traffic-path feature either way | **No, even while steering.** One-sided ARP only touches outbound (device→internet) traffic; the gateway's ARP table is never touched, so inbound responses take the normal path and are invisible to Shepherd. A device's real traffic volume is always understated. |
| Isolates one LAN device from another | No | No — steering affects device↔gateway traffic only; LAN-to-LAN isolation still needs your router's own guest network or VLANs, same as today |
| Works against a device on a VPN | No — tunneled traffic is opaque to DNS-based filtering | No — tunneled traffic is opaque to this too, for the same reason |
| Network performance cost | None — Shepherd never sits in the data path | **Real and currently unresolved.** A live test measured a steered device drop from ~1.1 Gbps to roughly 300 Mbps during a sustained transfer, confirmed across multiple independent fixes that did not close the gap (see INTERCEPT.md's "Throughput" section for the full investigation). Only the steered device is affected — everyone else on the network is unaffected. |
| Setup | Point your network's DNS at Shepherd. Nothing else. | Needs `CAP_NET_RAW` (and `CAP_NET_ADMIN` for the GRO workaround); today it's a hand-run CLI (`cmd/intercept-trial`) for a capped, confirmed, one-device-at-a-time trial — not a portal toggle |
| Recommended today | Always on — this is the default, zero-overhead protection every install gets | Short, deliberate trials only, with the throughput cost in mind, until the investigation above actually resolves it |

## The bottom line

DNS filtering plus passive monitoring is free, has zero network cost, and already catches the
overwhelming majority of real home-network traffic, because most apps and devices still do
ordinary DNS lookups through whatever resolver the network hands them. Watch mode's entire value
add, once it's safe to leave on, is closing the gap DNS-based filtering can never close by
definition: a device that deliberately avoids using your DNS resolver. That is a real gap, worth
closing — but it is a narrower, more specialized win than "better blocking," and it currently
costs real throughput on the one device being steered. Until the throughput investigation in
[INTERCEPT.md](INTERCEPT.md) resolves, Watch mode stays what it is today: a trial tool for
confirming the technique works, not a feature to run continuously.
