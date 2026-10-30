# Ports and exposure

Shepherd scans the devices it already knows about (the [registry](DEVICES.md)) for open TCP ports, so
you can see exposure you did not expect: a camera that opened Telnet, a NAS with SMB reachable from the
LAN, a laptop with RDP turned on. The package is `internal/portscan`; this page is its reference.

## What this is, and what it is not

This is **awareness of your own network**, not a security scanner and not a penetration-testing tool. It
is built to be gentle and unmistakably non-aggressive, even to your own router or any IDS watching the LAN:

- **Plain TCP connect scans only.** Shepherd opens a normal TCP connection and closes it. No OS or service
  fingerprinting, no banner grabbing, no UDP, no SYN-stealth or other scan types associated with attack
  tools.
- **A short, fixed, documented port list** (below), not a sweep of the full 1-65535 range.
- **Bounded concurrency and a short per-connection timeout**, so a scan never floods a device or the LAN
  with connection attempts, and only one scan (scheduled or manual) ever runs at a time.
- **Your own known devices only.** A device has to already be in the registry (seen by DNS, mDNS, the
  neighbor table, or reverse DNS) before it is ever scanned.

### What it does not do (yet)

Not built: no vulnerability scanning (see [VULNSCAN.md](VULNSCAN.md), which deepens this feature's own
findings), no credential checking, no service version detection. A device reported as having port 23 open
just means something answered a TCP connection on port 23. Shepherd does not try to find out what.

## The port list

`portscan.DefaultPorts`, checked on every device, every scan:

| Ports | Why |
|---|---|
| 21, 22, 23 | FTP, SSH, Telnet: remote access |
| 25, 465, 587 | SMTP and submission: mail |
| 53 | DNS |
| 80, 443, 3000, 5000, 8000, 8080, 8443, 8888 | HTTP(S) and the common ports a router, camera, NAS or smart-home hub puts its own admin page on |
| 110, 143, 993, 995 | POP3/IMAP (plain and TLS): mail retrieval |
| 111, 2049 | rpcbind, NFS: legacy Unix file sharing |
| 135, 139, 445 | Windows RPC, NetBIOS, SMB: Windows file sharing |
| 389 | LDAP |
| 515, 631, 9100 | LPD, IPP, raw/JetDirect: printing |
| 548 | AFP: old Apple file sharing |
| 554 | RTSP: cameras and media servers |
| 873 | rsync |
| 1433, 3306, 5432, 6379 | MSSQL, MySQL, PostgreSQL, Redis: databases, which should almost never be reachable from the whole LAN |
| 1723 | PPTP: a broken, deprecated VPN protocol |
| 1883 | MQTT: smart-home message brokers |
| 2375, 2376 | Docker's API, unencrypted and TLS |
| 3389 | RDP: Windows Remote Desktop |
| 5900 | VNC: remote screen control |

That is roughly 40 ports, chosen for what actually matters on a home network, not completeness. A port
nobody in a household is likely to open on purpose is left off on purpose, to keep the list short and the
scan quick.

### Risky ports

A subset, `portscan.RiskyPorts`, is flagged **every time it is found open**, not only when newly opened,
because these are specifically worth a second look on a home network:

| Port | Why it is flagged |
|---|---|
| 21 (FTP) | often unencrypted, with weak or default credentials |
| 23 (Telnet) | unencrypted remote login, a classic IoT-botnet target |
| 111 (rpcbind) | legacy RPC portmapper, frequently exploited |
| 139 (NetBIOS) | legacy Windows file sharing |
| 445 (SMB) | Windows file sharing, a common ransomware and worm target |
| 1723 (PPTP) | a broken, deprecated VPN protocol |
| 2375 (Docker, no TLS) | can grant full control of the host |
| 3389 (RDP) | a frequent target for credential attacks |
| 5900 (VNC) | remote screen control, often reachable with no authentication at all |

Every risky port is also in the scanned list above (checked by a test): a port that is never scanned could
never be flagged.

## How a scan works

`internal/portscan.Scanner` dials each configured port on each known device's current address (its IPv4
address when it has one, otherwise whatever address the registry has) through an injectable dial function,
bounded to a handful of connection attempts in flight at once (10 by default) with a short per-connection
timeout (750ms by default). This is what makes it fully unit-testable with no real sockets, and what keeps
it gentle in production.

Per device, per port, Shepherd keeps:

- whether it is open as of the last scan;
- when it was first ever found open, and when it was last found open;
- whether it was newly opened **this scan** (closed or unseen last time, open now — never set on a
  device's very first scan, since there is nothing yet to compare against);
- whether it is on the risky list, and why;
- its WAN exposure, when `[portscan.wan_exposure]` is enabled (below).

A port that has never been found open has no record at all: history only grows for what is actually there.
A port that closes again keeps its record (open: false, with its first/last-seen times) rather than being
forgotten, so "this was open for a while and is now closed" stays visible.

## WAN exposure

Knowing what the scanner finds on the LAN is only half the exposure picture. The other half, and the far
more dangerous one, is whether the internet can reach that same port: an exposed Telnet or Docker API on
the LAN is bad; the same thing reachable from the WAN is much worse. `internal/upnpigd` is a small,
read-only client for one real, standard signal for this: **UPnP IGD** (Internet Gateway Device), the
protocol a huge range of home routers already speak on the LAN, and the same one game consoles, torrent
clients and VoIP apps already use to ask "what's forwarded right now." It:

1. discovers the router's IGD over SSDP (a UDP multicast `M-SEARCH` to the standard SSDP address, `239.255.255.250:1900` — the same on every network, not a detail of any one install); <!-- leakcheck:allow -->
2. fetches and parses its device description to find the `WANIPConnection` or `WANPPPConnection` control URL;
3. calls that service's `GetGenericPortMappingEntry` SOAP action repeatedly to enumerate the router's whole
   NAT port-mapping table.

It never calls `AddPortMapping` or `DeletePortMapping`. Shepherd only ever asks what is already forwarded;
it never changes it.

For every port a scan finds open, `internal/portscan.PortRecord.Exposure` is then set to one of:

| Value | Meaning |
|---|---|
| `lan_only` | The router's NAT table was read successfully and this exact LAN IP:port is not in it. |
| `wan_forwarded` | The router's NAT table has an enabled mapping forwarding this exact LAN IP:port from the WAN. |
| `unknown` | The check could not be made this round. See below. |

The field is simply **absent** (not `unknown`) for a port on a device when `[portscan.wan_exposure]` is
disabled: absence always means "not checked," never "safe."

### Why "unknown" will show up, and what it does not mean

This is a best-effort signal with two real limits, stated as plainly as the rest of this page:

- **UPnP IGD can only ever report what was forwarded *through it*.** A port made reachable from the WAN by
  any other means — a manual NAT rule configured outside UPnP, a DMZ host, a device with its own direct
  public address — is invisible to this check, and indistinguishable here from a port that genuinely is not
  exposed at all. `lan_only` means "not forwarded via UPnP," not "not reachable from the internet."
- **Not every router answers UPnP IGD discovery from a LAN client at all.** Some disable it by default;
  some consumer mesh systems (eero, among others) are known not to implement the classic IGD control
  surface the way a traditional router does, or restrict it. When nothing answers SSDP, or discovery
  succeeds but the device description has no `WANIPConnection`/`WANPPPConnection` service, or a SOAP call
  fails, every port gets `unknown` — not a guess at `lan_only` or `wan_forwarded`. For a household on one of
  those routers, **every port will show `unknown`, every time, forever**, and that is the honest answer,
  not a bug. This feature was not verified against the maintainer's own router hardware; the realistic
  expectation, going in, is that a meaningful fraction of installs will see `unknown` across the board.

A failed check never falls back to a previously cached table, either: once a refresh fails, every lookup
reports `unknown` until a refresh succeeds again, so exposure is never shown stale (see "Caching," below).
The first time the router stops answering, Shepherd logs it once ("log once, never spam," the same
convention `cmd/shepherd/geoblock.go` uses for its own always-on dependency check); it does not repeat that
log line on every later failure.

### Caching

A UPnP discovery-and-enumerate round trip is slower and far more fragile than internal/portscan's own TCP
connect probes, so it is not repeated on every scan or every port. `internal/upnpigd.Checker` queries the
router's whole NAT table at once and caches it for `refresh_interval_seconds` (10 minutes by default);
every `Exposure` lookup for every open port on every device, in between, is answered from that cache at no
network cost. Enumerating the whole table once per refresh, rather than looking up each open port
individually, is also the cheaper approach once more than one device has open ports to check, since it is
one router round trip no matter how many ports or devices a scan cycle covers.

## Should this be on by default?

**Yes, `[portscan].enabled` defaults to `true`.** This needed an explicit decision, because it is a
different kind of default than the rest of Shepherd. Everything else that is on by default (the device
registry, the neighbor-table poll, mDNS listening, automatic classification) only **listens**; this
feature actively opens connections to every device Shepherd knows about. That is a real, if small,
behavioral difference, and it deserved a decision instead of silently inheriting the "on by default"
convention.

The reasoning: the entire value of this feature is the owner finding out about exposure they did not know
about, and a feature that defaults off is a feature most owners never discover and never turn on, which
defeats that purpose. Given how deliberately gentle the scan is engineered to be (plain connect scans, a
short port list, a real rate limit), the risk of leaving it on is low enough that withholding the awareness
benefit by default is the worse trade. You can turn it off in `[portscan]` if you would rather it never ran
automatically; a manual scan from the portal still works even then.

**`[portscan.wan_exposure].enabled` also defaults to `true`, for the same reasoning, weighed again on its
own terms.** This sub-feature adds its own small amount of active LAN traffic — one SSDP multicast
discovery and, at most, a handful of SOAP calls per `refresh_interval_seconds`, never per scan and never per
port — on top of what `[portscan]` itself already does. That traffic is no more active on the network than
an owner's own UPnP-enabled game console, smart speaker or torrent client already is, and it talks only to
the router, never to another device. Given that, and that WAN-forwarded is specifically the more dangerous
half of the exposure picture this whole feature exists to surface, withholding it by default would repeat
the same mistake `[portscan]` itself already decided not to make. It needs `[portscan]` enabled: with no
open-port data to deepen, there is nothing for it to check.

## Configuration

```toml
[portscan]
enabled = true
interval_seconds = 21600   # 6 hours; the port list itself is built in, not configurable yet

[portscan.wan_exposure]
enabled = true
refresh_interval_seconds = 600   # 10 minutes; the router's NAT table is cached in between
```

`interval_seconds` must be at least 300 (5 minutes). `refresh_interval_seconds` must be at least 300 too,
when `wan_exposure` is enabled (a too-short value is accepted while it is disabled, since it then does
nothing). The port list is `portscan.DefaultPorts` and is not yet exposed in the configuration file.

## API

Under the portal token, `X-Shepherd: 1` on the scan trigger.

| Endpoint | Does |
|---|---|
| `GET /api/portscan` | `{enabled, ports, risky_ports}`: whether the scheduled scan is running, the configured port list, and the risky-port reasons |
| `GET /api/portscan/devices` | every device's last scan: `{devices: [{device_id, name, ip, last_scanned, ports: [{port, open, first_seen, last_seen, newly_opened, risky, risk_note, exposure}]}]}` |
| `GET /api/portscan/devices/{id}` | one device's last scan, in the same shape (empty `ports` and no `last_scanned` if it has never been scanned) |
| `POST /api/portscan/scan` | `{}` scans every known device now; `{"device_id": "..."}` scans just one. Returns the scanned devices in the same shape as the list endpoint |

`exposure` is one of `"lan_only"`, `"wan_forwarded"` or `"unknown"` (see "WAN exposure," above), and is
left out of a port's object entirely when `[portscan.wan_exposure]` is disabled.

A manual scan of **every** device can take up to roughly a minute depending on how many devices there are
and how many of their ports are silently dropped rather than actively refused (a refused connection answers
almost instantly; a silently filtered one waits out the full per-connection timeout). Scanning one device is
much faster. Only one scan runs at a time: a manual scan that arrives while the scheduled one is still
running waits for it, rather than piling more connection attempts onto the network.

History is kept at `<data_dir>/portscan.json` (mode 0600) and saved after every scan, scheduled or manual.
