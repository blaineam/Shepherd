# Design

## Goals

A Firewalla-style guardian for people who already have a capable router and a NAS or server:
protection, visibility and control without replacing the router and without ongoing babysitting.

## Placement

Shepherd sits inside the LAN on a wired port. It is not the gateway. Capabilities depend on how
much traffic reaches it:

| Profile | How | Capabilities | Risk if Shepherd is down |
|---|---|---|---|
| **Guard** (default) | Router hands out Shepherd as DNS | DNS filtering, categories, allow/block lists, Tailscale-wide protection, remote access, uptime and speed tests | DNS fallback only; no path risk |
| **Watch** (on by default once enabled, opt out per device) | Shepherd steers chosen devices' IPv4 traffic through itself (see methods below) | Flows, per-device bandwidth, geo-blocking, real pause, IDS on selected devices | Selected devices lose IPv4 internet until they recover |
| **Gateway** (future, optional) | Shepherd as router | Everything | Total outage |

Watch mode is IPv4 only. See [IPV6.md](IPV6.md).

### Watch interception methods

Watch mode has one interface and swappable methods, tried in this order:

1. **ARP (first).** Shepherd tells a chosen device that the gateway's MAC is Shepherd's. It forwards
   and masquerades the traffic to the real router, so only the client side needs steering and the
   router's ARP table is never touched. No router configuration changes. On shutdown or failure
   Shepherd sends corrective ARP replies, and the device recovers on its own within minutes
   even if Shepherd dies. Firewalla documents ARP compatibility problems with some mesh routers
   and does not list eero 7, so this must be tested per router before relying on it.
2. **DHCP takeover (if ARP proves flaky).** Shepherd serves DHCP and hands chosen devices itself as gateway. Needs the router's DHCP pool shrunk and reserved (see the Firewalla eero workaround).
3. **Bridge or router with dual NICs (if the first two aren't enough).** A second NIC (for example Thunderbolt 10G) puts Shepherd physically inline.

ARP and DHCP only affect IPv4. Shepherd never spoofs NDP or touches RAs.

## Principles

- **Free and keyless.** Defaults use only keyless data sources. Paid or keyed services are optional plugins.
- **Self-maintaining.** List updates are guarded (size-change limits, top-sites allowlist). Image updates are staged, health-checked and rolled back on failure. Storage has budgets and downsampling. Notifications are digests, not floods.
- **Few moving parts.** A small core: AdGuard Home, the DHCP/forwarding layer, and one agent that handles ingest, rules and the portal API. State in SQLite/DuckDB.
- **Protected by default, reversible by design.** Once set up, every protection is on and each one is switched off per device, group or feature: opt-out, never opt-in. Guard rails (below) are what make default-on safe.
- **Private.** Local-only, no telemetry, each household owns its own instance.
- **Honest claims.** Shepherd reduces risk and adds visibility. It guarantees nothing.

## Data sources (keyless)

| Need | Source |
|---|---|
| Ads, trackers, categories | Hagezi, OISD, UT1, StevenBlack |
| Threat intel | abuse.ch (URLhaus, Feodo, ThreatFox), Spamhaus DROP, FireHOL |
| GeoIP / ASN | DB-IP Lite, iptoasn |
| Whois | local `whois` + RDAP (IANA bootstrap) |
| Map | MapLibre + bundled Natural Earth or self-hosted PMTiles |
| AI | local Ollama |
| Notifications | self-hosted ntfy |

## Device identity

MAC address is the primary key. Devices roll up into user-defined groups; every metric, rule and
alert can be scoped to a device, a group, or the whole network.

## Local AI

Triage and explanation, not enforcement. Classical per-device baselines detect; the LLM explains
and recommends. Auto-block only for high-confidence signals, with automatic expiry and a
notification. Two-week learning mode before any automatic action.

## Distribution

Planned for family and friends: guided setup wizard, signed releases, staged channels
(dogfood, family, public), debug-report button, optional time-limited remote help over Tailscale.
The setup wizard turns on Guard and, where the router path allows it, Watch for every device, excluding infrastructure automatically. People opt out, not in.

## Architecture direction (decided 2026-10-29)

Shepherd is a native application, not a bundle of containers. Wave 1's Docker stack is a testbed
for learning how real networks behave; Wave 2 replaces it.

- **One binary, installed like an app.** Linux (systemd, .deb/.rpm or static binary), macOS (launchd, signed .pkg) and Windows (service, MSI). Docker stays an optional packaging target for NAS users, never a requirement.
- **All control and monitoring in Shepherd's own portal.** No third-party dashboards to maintain. Underlying engines are embedded, bound to loopback, or absent.
- **Own the resolver.** An embedded DNS engine built on miekg/dns (BSD-3). Under AGPL, Shepherd may embed permissive, LGPL, GPLv3 and AGPL code (for example nDPI or AdGuard's DNS libraries). GPLv2-only tools such as Suricata stay separate programs that Shepherd orchestrates.
- **Tailscale: embedded for Shepherd's own node, system install for routing.** Shepherd embeds `tsnet` so the portal is reachable on your tailnet with automatic HTTPS and Tailscale identity as the login, with no extra software. Exit-node and subnet-router duty stays with the OS's `tailscaled` until a spike proves the embedded node can do it (it runs in userspace and may not forward like a kernel node). Tailscale's own Rust library (tailscale-rs, preview as of April 2026) is a future option for a single-language stack.
- **Languages: Go control plane, Rust data plane.** The control plane (DNS, portal, alarms, mesh, config, Tailscale) is Go: fast to build, memory-safe, cross-compiles to a static binary for Linux, macOS and Windows, and the only language with Tailscale's first-class embeddable `tsnet`. The data plane (high-rate packet inspection: flow tracking, TLS/QUIC server-name and fingerprint extraction, XDP/eBPF accounting) is Rust, introduced in Wave 6 as a separate component behind a narrow local interface, so the Go core never needs rewriting. **Storage:** SQLite. **Portal:** single-page app embedded in the binary.
- **Packet work** (ARP, forwarding, flows) is Linux-first (nftables, conntrack). macOS (pf) is second. Windows is possible through Npcap but needs a prototype (see the platform matrix). DNS protection and passive ARP monitoring work on all three.

### Platform matrix

| Capability | Linux | macOS | Windows |
|---|---|---|---|
| Guard (DNS, Tailscale, portal, alarms) | yes | yes | yes |
| Passive ARP/mDNS/DHCP monitoring (inventory, spoof detection) | yes | yes | yes (Npcap) |
| Watch: ARP interception + forwarding | first | second (pf, ip forwarding) | research (Npcap, WinNAT/ICS) |

Raw ARP frames work everywhere. The hard part is forwarding and NAT after interception, which is
fast and mature on Linux, workable on macOS, and fiddly on Windows. Npcap is free only for
personal use and can't be bundled without a license, so Windows installs would link to its installer.

### Mesh and cold standby

Multiple Shepherd instances on one network (or one tailnet) form a mesh. Config, lists, rules and
device groups replicate between them, with Tailscale and local mDNS as the transport.

- **DNS: active-active, not strict primary/secondary.** Operating systems don't honor "primary then secondary" reliably, so the router hands out both instances and both serve identical, replicated config. A cold instance is one that is stopped but holds a recent snapshot; promoting it is one click.
- **ARP/Watch mode: exactly one active interceptor.** A lease with heartbeats, deterministic election and fencing prevents two boxes spoofing at once. A graceful handover sends corrective ARP replies first.
- **Households stay separate.** A mesh never spans households by default; visibility across a family's boxes is opt-in.

## Lessons from the first deployment

- **DoH can be reset on a real network.** Encrypted upstreams to Quad9 connected but never answered, which stalled all DNS. The resolver must probe upstreams continuously, fail over automatically, and keep plain fallbacks until an encrypted one proves reachable.
- **Health checks must use uncached names.** The container reported healthy while resolution was failing, because the test name was cached.
- **Don't bind a dynamic IPv6 address.** Binding a SLAAC address by name risks losing DNS if it changes. The core must track addresses at runtime.

## What ARP interception adds beyond DNS

- **Closes DNS bypass.** Devices with hardcoded resolvers, DoH or DoT skip DNS filtering. In-path, Shepherd can see and redirect them.
- **Volume and destinations.** Per-device bytes, connections, countries and ASNs. DNS can't show any of this, and it feeds the live map.
- **Hostnames without DNS.** TLS SNI and QUIC SNI, plus TLS fingerprints (JA3/JA4) to identify apps and spot malware.
- **Real controls.** Per-device pause, quarantine of a compromised device, rate limits, IP/ASN/geo blocking, parental schedules.
- **Threat detection.** Beaconing to command-and-control servers, port scans, unusual uploads, IDS on selected devices.

**Passive ARP monitoring is a separate, zero-risk feature** (Wave 3, all operating systems): a live device
inventory, new-device alarms, MAC/IP change detection, IP conflict detection, and detection of
anyone else spoofing ARP on the LAN.

Limits: IPv6 bypasses interception (see IPV6.md), LAN-to-LAN traffic isn't seen unless peers are
also steered, and payloads stay encrypted.

## Standby ladder

- **Cold:** stopped, holds a recent config snapshot. Promote with one click.
- **Warm (ARP mode):** running and monitoring passively, heartbeating with the active box over the LAN and tailnet. If the active box stops forwarding (checked with data-path probes, not just a heartbeat), the standby takes over with gratuitous ARP within seconds. Elections use a lease and fencing to prevent two interceptors at once.
- **Hot (DNS):** both instances serve identical replicated config at all times.

Expect a few seconds of disruption on failover. In-flight connections reset unless NAT state is synced (conntrackd on Linux) or the design avoids NAT.

## Alarm system

Every feature emits alarms through one engine, so this is core, not an add-on.

- **Model:** type, severity, device/group, evidence, and a state (new, acknowledged, muted, resolved).
- **Dedupe and grouping:** repeats collapse into one alarm with a count; storms of similar alarms become one bundle.
- **Muting:** by device, group, rule, domain, or time window, with snooze presets (1h, tonight, forever) and quiet hours. Muted alarms are still recorded.
- **Batch management:** select by filter or checkbox, then acknowledge, mute, resolve, block, or turn the selection into a rule.
- **Learning mode:** suppresses automatic alarms while baselines form.
- **Delivery:** in-portal, self-hosted ntfy, and web push; digests for low severity, immediate for high.
- **Audit log:** every mute, block and rule change is recorded and replicated across the mesh.

## Portal HUD: the globe, flights and replay

The portal is a live heads-up display, not a table of logs.

- **Globe.** An interactive 3D globe (WebGL, bundled offline: no map tile services, no API keys) with arcs
  from each device to the places it talks to. Arcs wrap around the globe like trajectories.
- **Weight shows volume.** Arc thickness, brightness and glow scale with bytes transferred, so a large
  upload or download is unmistakable next to a tiny lookup. Color shows state: allowed, blocked, suspicious.
- **Honest data per profile.** In **Guard** (DNS only) arcs come from the addresses in DNS answers,
  placed with a keyless GeoIP database (DB-IP Lite), and weight reflects query volume. Real byte counts
  need **Watch** mode, which sees the flows. The HUD says which one you are looking at.
- **Control from the picture.** Click an arc, a device or a country to block, allow, pause, rate-limit or
  quarantine in real time, with an undo.
- **Replay.** Every flow and query is stored in a local time series, with a scrubber and speed control to
  replay any earlier period on the globe. Retention budgets keep storage bounded.
- **Scopes.** Everything filters by device, group or the whole network.

Rendering uses a bundled WebGL library, no remote assets, so the portal works offline and leaks nothing.

## Mesh dataset sync

Instances in a household replicate their dataset, not just their config.

- **What syncs.** Rules, policies, lists, device registry and groups, alarms and their state (acknowledged, muted), and the flow and query history.
- **How.** Every record carries a hybrid logical clock timestamp, the node that wrote it, and a tombstone flag. Mutable records (rules, devices, alarm state) merge last-writer-wins per field. Append-only records (queries, flows, alarms raised) merge by union and de-duplicate by ID. Any two replicas that have seen the same writes converge to the same state, in any order.
- **Transport.** Mutually authenticated and end-to-end encrypted, over the tailnet or the LAN. Replicas exchange only what the other is missing, by comparing per-node high-water marks.
- **Privacy scopes.** Configuration always syncs. Traffic history syncs only if you opt in per node, so a warm standby can resume with context while a less trusted node never sees your history.
- **Failure.** Nodes keep working offline and reconcile when they meet again. A promoted standby already holds the dataset.
- **Built sync-ready.** The Wave 3 storage layer uses these record shapes from day one, so mesh sync is an addition, not a migration. The convergence property is tested with generated operations applied in different orders.

## Testing strategy

Test-first development with a coverage floor that only rises (see [TESTING.md](TESTING.md)). Network code is tested against
fakes on loopback, never a real network. Sync is tested for convergence. The leak guard has its own self-test.

## Protected by default

Protection is on for the whole network as soon as setup finishes, and you opt out per device, group or
feature. A tool that protects only what you remembered to enable protects very little, and the devices
nobody thinks about (a TV, a camera, a guest's phone) are the ones that matter most.

Default-on touches real traffic, so it ships with guard rails:

- **Observe first.** A new install watches for a short learning period before it enforces anything in the data path, so it can see what normal looks like and pick what to exclude.
- **Automatic exclusions.** The gateway, Thread border routers and other infrastructure (discovered from the network), other Shepherds, and anything you mark are never steered. IPv6, Thread, Matter and mDNS are never touched.
- **Health-gated.** In-path protection is only active while Shepherd has verified that it forwards correctly, and a fail-open watchdog hands devices back to the router within seconds if it stops.
- **Breakage detection.** If a protected device's connections start failing, Shepherd raises an alarm and offers a one-click exclusion (or applies a temporary one), instead of leaving the device broken.
- **Visible and reversible.** The first-run summary lists what is protected and what was excluded and why. A global pause and a per-device pause (with timers) are always one click away.

Defaults that exist today: a blocklist is active out of the box, and Apple iCloud Private Relay is blocked
(devices see a notice that it is unavailable on this network; set `block_private_relay = false` or use the
portal switch to allow it). Both can be opted out of in `shepherd.toml` or the portal.

## Access: reverse proxy, certificates and tunnels

Planned, all managed from the portal (this replaces a hand-maintained proxy manager).

- **Friendly names for private services.** Map a service that only exists on your Tailscale network, such as `nas.home.example.com`, to its address. Shepherd's resolver answers that name with the proxy's tailnet address for devices on the tailnet and the LAN, so nothing about it is public.
- **Valid HTTPS everywhere.** Wildcard certificates from Let's Encrypt using the DNS challenge on Cloudflare DNS, so a private service gets a real certificate without being reachable from the internet. Certificates renew themselves. The Cloudflare API token is stored encrypted with the same key machinery as the history.
- **Reverse proxy built in.** One in-process proxy with per-host routes, WebSocket support and an access log, instead of a separate proxy manager to maintain. Existing proxy-manager hosts can be imported.
- **Public access through Cloudflare Tunnel.** Expose chosen services without opening a port: Shepherd configures and supervises the tunnel connector, and every request that arrives through it passes through the same proxy, so it is logged, rate limited and can be blocked by country or reputation.

## Ports and exposure

Planned: see what is open on your network. Scheduled, polite TCP scans of known devices (by device, group or the whole network), results kept per device with history, and alarms when a new port opens or a risky service appears. The router's own forwarded ports are listed too (through UPnP or NAT-PMP where the router supports them), with one-click removal. The host Shepherd runs on reports its own listening ports.

## Inbound traffic: what can be seen and protected

Shepherd sits inside the network, and a home router drops unsolicited inbound connections at the edge, so most internet scans never reach it. What it can do, honestly:

- **Everything that enters through Shepherd's own front doors.** Requests arriving through the reverse proxy, a Cloudflare Tunnel or Tailscale are fully visible and controllable: logged per request, rate limited, blocked by country, network or reputation, and shown on the globe as inbound arcs.
- **Exposure monitoring.** Alarms when a new port forward appears on the router, when a device starts listening on a new port, or when a service is reachable that should not be. This is the most useful protection, because a closed port is the best defence.
- **Watch mode.** Connections to a steered device that arrive through a port forward can be seen and filtered. Seeing the router-to-device direction needs two-sided interception or Gateway mode; the one-sided ARP method only steers a device's outgoing traffic.
- **The host itself.** Inbound connections to the machine running Shepherd can be tracked at the host level on Linux.
- **What it cannot see.** Scans and attacks the router drops before they reach the LAN, unless the router exposes logs.

## Encrypted history

Past queries can be kept, searchable, after the fact. See [HISTORY.md](HISTORY.md). The default stays in memory only; encrypted persistence is a setting, and the setup wizard will offer it.

## Where home is

The globe's "home" point is worked out automatically from the network's public address with a DNS "who am I" query to well-known public resolvers (no web service), placed with the local GeoIP database. Only the resulting place is kept, never the address. Choosing your own home in the portal always wins, and then nothing is looked up. Turn it off with `map.auto_home = false`.

## Decision log

- **2026-10-30:** Persistence, the globe HUD, device naming and groups, scoped app and category blocking, configurable upstreams with DoH, the reverse proxy with certificates and tunnels, port management and inbound protection were all pulled into the near roadmap. Work proceeds in tested increments that are deployed to the NAS as they land.
- **2026-10-30:** Protection is opt-out, not opt-in. Defaults are on (blocklist, Private Relay policy), and Watch mode will be default-on after setup with automatic exclusions, health gating and a fail-open watchdog. This replaces the earlier "everything in the data path is opt-in" stance.
- **2026-10-29:** Licensed AGPL-3.0-or-later (after weighing MIT and MIT/Apache-2.0). Self-hosted network software is exactly what closed hosted or appliance forks would target, and AGPL requires those to share their changes. Keeping copyright with the author preserves the option to relicense or dual-license later. A Rust-only core was replaced by a Go control plane plus a Rust data plane, so Tailscale's `tsnet` can be embedded while the speed-critical packet work still gets Rust. The Wave 1 claim that Rust's safety edge mattered for the whole core was overstated: Go is memory-safe too, and the control plane is not on the packet fast path.
