# Roadmap

Work ships in tested increments that are deployed to a real network as they land.

| Step | Theme | State |
|---|---|---|
| 1 | Docker testbed, preflight, Tailscale migration | done |
| 2 | **Core:** DNS engine, self-healing upstreams, guarded lists, portal, Private Relay policy | done, live on the NAS |
| 3 | **History, map and stream:** encrypted searchable history, geolocated destinations, live event stream, automatic home | built and tested, deploying |
| 4 | **Policy:** a catalog of lists, apps and categories, custom lists, scopes (network, group, device) | built (API wired, not yet deployed) |
| 5 | **Upstreams:** plain, DoT and DoH with bootstrap, presets, test before adding | built (API wired, not yet deployed) |
| 6 | **Devices:** registry, names from mDNS and the neighbor table, vendors, groups, search, bulk edit | built (API wired, not yet deployed) |
| 7 | **Portal:** the globe HUD (arcs weighted by volume, replay, click to control) and management screens for the above | in progress |
| 8 | **Alarms:** engine with dedupe, severity, mute and snooze, batch actions, ntfy | next |
| 9 | **Ports and exposure:** scheduled scans, per-device open ports, router port forwards, change alarms | planned |
| 10 | **Access:** reverse proxy, wildcard certificates on Cloudflare DNS, private service names, Cloudflare Tunnel | planned |
| 11 | **Watch mode:** ARP interception, flows and bytes, per-device pause, geo-blocking, inbound visibility, warm standby | planned |
| 12 | **Inbound protection:** logging, rate limits and blocking at the proxy and tunnel, exposure alarms, host-level inbound tracking | planned |
| 13 | **Mesh:** dataset sync, active-active DNS, standbys | planned |
| 14 | **Self-maintenance:** signed self-update with rollback, retention budgets, digests | planned |
| 15 | **Threat feeds and local AI** | planned |
| 16 | **Packaging:** installers, setup wizard, release channels | planned |

Research items: passive IPv6 observation, in-path IPv6, a Gateway profile, NAT state sync for seamless failover.
