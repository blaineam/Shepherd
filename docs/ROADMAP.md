# Roadmap

Work ships in tested increments that are deployed to a real network as they land.

| Step | Theme | State |
|---|---|---|
| 1 | Docker testbed, preflight, Tailscale migration | done |
| 2 | **Core:** DNS engine, self-healing upstreams, guarded lists, portal, Private Relay policy | done, live on the NAS |
| 3 | **History, map and stream:** encrypted searchable history, geolocated destinations, live event stream, automatic home | done, live on the NAS |
| 4 | **Policy:** a catalog of lists, apps and categories, custom lists, scopes (network, group, device) | done, live on the NAS |
| 5 | **Upstreams:** plain, DoT and DoH with bootstrap, presets, test before adding | done, live on the NAS |
| 6 | **Devices:** registry, names from mDNS and the neighbor table, vendors, groups, search, bulk edit, automatic classification (DNS/vendor/ASN), wandering mode (unfiltered + watched) | done, live on the NAS |
| 7 | **Portal:** the globe HUD (arcs weighted by volume, replay, click to control) and the Devices/Blocking/Upstreams/History management screens | done, live on the NAS |
| 8 | **Device quarantine:** new devices land in a reserved group with their own rules until moved; LAN isolation is out of Shepherd's reach today (see the Watch mode note below) | done, live on the NAS |
| 9 | **Alarms:** engine with dedupe, severity, mute and snooze, batch actions, Web Push and ntfy fallback | built (library only); wiring into `cmd/shepherd` + portal API/UI in progress |
| 10 | **Passive ARP:** a read-only monitor that learns MAC addresses and raises spoofing/exposure alarms | built; wiring into `cmd/shepherd` and the alarm engine in progress |
| 11 | **Watch mode (ARP interception):** one-sided relay of a device's outbound traffic, with exclusion, health-checked fail-open, trial mode and panic stop | library built and live-trialed, with the maintainer's explicit go-ahead, against a disposable VM and the maintainer's own phone (multiple runs; see docs/INTERCEPT.md). **A real, significant throughput cost while a device is steered is confirmed and still not understood** — not GRO, not single-threaded relay, not per-packet overhead, not Tailscale; a packet capture points at the device's own connections retrying abnormally fast while steered. Investigation paused, not abandoned. Treated as a known limitation, not a blocker: DNS-only protection and passive ARP cost the network nothing and ship regardless. Not wired into `cmd/shepherd` or the portal yet. |
| 12 | **Router importers:** eero (unofficial API, unverified against a live account) and CSV, to bring in existing device names and groups | built (not yet wired into the portal) |
| 13 | **Scheduled access and allowlist mode:** time windows on a policy rule or switch at network, group or device scope (block or allow a category, app or list only during chosen hours/days); and an allowlist mode, settable at the same three scopes, that inverts the default to block everything except what is explicitly allowed, instead of today's block-list default | planned, next up (one design, one worktree — both change the same policy evaluation path) |
| 14 | **Ports and exposure:** scheduled scans, per-device open ports, router port forwards, change alarms | planned, next up |
| 15 | **Access:** reverse proxy, wildcard certificates on Cloudflare DNS, private service names, Cloudflare Tunnel; migrating off the current reverse-proxy manager | planned; higher-risk (touches live service reachability), designed carefully before any implementation touches the real NPM setup |
| 15 | **Portal locking:** demo data until unlocked, idle auto-lock (configurable, including never), PIN bound to a trusted browser, passkeys once the portal has HTTPS | designed, not built |
| 16 | **Inbound protection:** logging, rate limits and blocking at the proxy and tunnel, exposure alarms, host-level inbound tracking | planned |
| 17 | **Mesh:** dataset sync, active-active DNS, standbys | planned |
| 18 | **Self-maintenance:** signed self-update with rollback, retention budgets, digests | planned |
| 19 | **Threat feeds and local AI** | planned |
| 20 | **Packaging:** installers, setup wizard, release channels | planned |

## Stated future direction: Shepherd as a dual-NIC router

The maintainer wants to eventually run Shepherd as the actual router (a "Gateway" profile), on
hardware with two 10 Gb NICs, demoting the current Wi-Fi router to a bridge/access-point role. This is
real intent, not a research idea, but it is a large undertaking that only makes sense once Watch mode
is proven reliable, and it changes Shepherd's risk profile fundamentally (a router outage is a full
outage). See [DESIGN.md](DESIGN.md#gateway-shepherd-as-a-dual-nic-router-future-stated-goal). Not scheduled.

Other research items: passive IPv6 observation, in-path IPv6, NAT state sync for seamless failover,
and full two-sided (peer) ARP isolation for quarantine/LAN-isolation beyond what one-sided Watch mode
can offer.
