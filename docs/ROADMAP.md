# Roadmap

Each wave ends with something you can deploy and test on a real network.

| Wave | Theme | You can test |
|---|---|---|
| **1** | Validate on the real network (Docker testbed) | DNS through the router, per-device attribution, Tailscale migrated in, Thread/IPv6 unaffected |
| **2** | **Shepherd core (Go, one native binary)** | Own DNS engine (guarded list updates, upstream probing with automatic failover, per-client logs), portal v0, single config file, cross-compiled binary. Replaces the AdGuard container. Embedded Tailscale (`tsnet`) for portal access follows in the same wave |
| **3** | Devices and alarms | Persistent local store (SQLite, sync-ready records), query history, passive ARP/mDNS/DHCP discovery, device registry and groups, alarm engine v1 (dedupe, severity, mute/snooze, batch actions, ntfy), new-device and ARP-spoof alarms |
| **4** | Mesh v0 | Dataset sync across instances (rules, devices, alarms, history; convergent, encrypted, opt-in history), active-active DNS, cold-to-warm standby promotion |
| **5** | Self-maintenance | Signed self-update with rollback, retention budgets, digests, speed tests, uptime monitoring |
| **6** | Watch mode (ARP interception) | On by default for every device with per-device opt-out and automatic exclusion of infrastructure. Linux first, macOS second, Windows research. Rust data plane for packet inspection. Flows, bandwidth, pause, geo-blocking, DNS-bypass enforcement, warm-standby takeover with fencing |
| **7** | Portal: map and inspector | The HUD: interactive globe with live traffic arcs weighted by bytes, replay with a timeline scrubber, click-to-control, domain inspector (Whois/RDAP) |
| **8** | Scans and threat feeds | Scheduled scans, keyless threat intel, optional external Zeek/Suricata adapters |
| **9** | Local AI | Baselines, anomaly triage, explanations, expiring auto-blocks |
| **10** | Packaging | macOS and Windows installers, a setup wizard that turns protection on for the whole network, release channels, optional Docker image |

Research items (not scheduled): passive IPv6 observation, in-path IPv6, Gateway profile, NAT state sync for seamless failover.
