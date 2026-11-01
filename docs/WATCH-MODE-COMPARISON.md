# What Watch mode actually buys you

Shepherd protects a network two different ways today, and they are not the same feature with
different settings — they sit at different layers, with different costs. This page lays out
exactly what you get with just the baseline (DNS filtering, passive ARP, geo-block, policy
modes, alarms, the scanners) versus what Watch mode (one-sided ARP interception,
[INTERCEPT.md](INTERCEPT.md)) would add on top, once it ships. Nothing here is marketing copy —
every row reflects the real, current, honestly-documented state of the code, not an aspiration.

**Watch mode is live, and on by default** (2026-10-30), after the throughput ceiling that held it
back was root-caused and fixed and the relay was measured at full gigabit on real hardware. It
runs inside `cmd/shepherd` (`internal/watch`), is managed from the portal's Watch screen, and has
a per-device switch; see [WATCH.md](WATCH.md). The "with Watch mode" column below is what you
get today.

| Capability | Baseline (DNS filtering + passive monitoring) | With Watch mode (one-sided ARP interception) |
|---|---|---|
| How blocking works | DNS answers rewritten (null or NXDOMAIN) for names that match a block rule | Same DNS-level blocking, unchanged — Watch mode does not replace it |
| Blocks an app that hardcodes IPs or runs its own DNS-over-HTTPS resolver | No — if a query never goes through Shepherd's resolver, there is nothing to block | Partially — Shepherd can see and steer the device's outbound connection attempts even when its DNS was bypassed entirely, since steering doesn't depend on DNS at all |
| Visibility into what a device actually talks to | Only the DNS names it asked Shepherd to resolve | Direct outbound traffic (destination IPs, TLS/QUIC SNI, connection attempts) regardless of what resolver the device used |
| Learns devices and MAC addresses | Yes — the passive ARP monitor ([ARP.md](ARP.md)) listens only, transmits nothing | Same passive learning, plus active one-sided steering for whichever devices you choose to steer |
| Steers IPv6 as well | N/A | Optionally (`watch.ipv6`, off by default), by unicast Neighbor Advertisements, and only on a network with a global IPv6 route. Never for smart-home, Thread or Matter gear, and Shepherd never sends Router Advertisements. See [IPV6-WATCH.md](IPV6-WATCH.md) |
| Sees a device's download/return traffic | N/A — not a traffic-path feature either way | **No, even while steering.** One-sided ARP only touches outbound (device→internet) traffic; the gateway's ARP table is never touched, so inbound responses take the normal path and are invisible to Shepherd. A device's real traffic volume is always understated. |
| Isolates one LAN device from another | No | No — steering affects device↔gateway traffic only; LAN-to-LAN isolation still needs your router's own guest network or VLANs, same as today |
| Works against a device on a VPN | No — tunneled traffic is opaque to DNS-based filtering | No — tunneled traffic is opaque to this too, for the same reason |
| Network performance cost | None — Shepherd never sits in the data path | **Measured, and no longer the blocker it was.** A steered device held full gigabit Wi-Fi with no perceivable slowdown on real hardware; the relay peaked at 1.6 Gbit/s in userspace and 1.77 Gbit/s under XDP. The ~300 Mbps ceiling every earlier run hit was a real bug (the relay taught the switch the wrong port for the device), found and fixed on 2026-10-30 — see INTERCEPT.md. Only steered devices are in any path at all; everyone else is untouched. |
| Setup | Point your network's DNS at Shepherd. Nothing else. | Nothing: on by default on a Linux host with `CAP_NET_RAW`, `CAP_NET_ADMIN` and `CAP_BPF`. Opt out per device in the portal, or entirely with `watch.enabled = false`. Anywhere it cannot run it says so and stays out of the way |
| Recommended today | Always on — this is the default, zero-overhead protection every install gets | On, which is the default. It is the only way to see a device that bypasses your DNS, and it costs a measured nothing on hardware with headroom; the kill switch is one button if you disagree |

## The bottom line

DNS filtering plus passive monitoring is free, has zero network cost, and already catches the
overwhelming majority of real home-network traffic, because most apps and devices still do
ordinary DNS lookups through whatever resolver the network hands them. Watch mode's entire value
add is closing the gap DNS-based filtering can never close by definition: a device that
deliberately avoids using your DNS resolver. That is a real gap, and now that steering costs a
measured nothing on hardware with headroom it is worth having on by default — but keep it in
proportion. It is a narrower, more specialized win than "better blocking", it still sees only the
outbound half of a device's traffic, and it blocks nothing on its own. DNS filtering is still
what does the work on almost every device, almost all of the time.
