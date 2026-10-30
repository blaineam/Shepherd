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

**Router port-forwarding discovery is not built.** Knowing what Shepherd's scanner finds on the LAN is
only half the exposure picture: the other half is what your router forwards from the internet to a LAN
device, which is a completely different question this feature does not answer. There is no reliable,
generic API across home routers for reading forwarding rules, so this was deliberately left out of this
pass rather than faked or guessed at from one specific router's unofficial API. It needs real router API
support, which does not exist yet; see the [roadmap](ROADMAP.md).

Also not built: no vulnerability scanning, no credential checking, no service version detection. A device
reported as having port 23 open just means something answered a TCP connection on port 23. Shepherd does
not try to find out what.

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
- whether it is on the risky list, and why.

A port that has never been found open has no record at all: history only grows for what is actually there.
A port that closes again keeps its record (open: false, with its first/last-seen times) rather than being
forgotten, so "this was open for a while and is now closed" stays visible.

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

## Configuration

```toml
[portscan]
enabled = true
interval_seconds = 21600   # 6 hours; the port list itself is built in, not configurable yet
```

`interval_seconds` must be at least 300 (5 minutes). The port list is `portscan.DefaultPorts` and is not
yet exposed in the configuration file.

## API

Under the portal token, `X-Shepherd: 1` on the scan trigger.

| Endpoint | Does |
|---|---|
| `GET /api/portscan` | `{enabled, ports, risky_ports}`: whether the scheduled scan is running, the configured port list, and the risky-port reasons |
| `GET /api/portscan/devices` | every device's last scan: `{devices: [{device_id, name, ip, last_scanned, ports: [{port, open, first_seen, last_seen, newly_opened, risky, risk_note}]}]}` |
| `GET /api/portscan/devices/{id}` | one device's last scan, in the same shape (empty `ports` and no `last_scanned` if it has never been scanned) |
| `POST /api/portscan/scan` | `{}` scans every known device now; `{"device_id": "..."}` scans just one. Returns the scanned devices in the same shape as the list endpoint |

A manual scan of **every** device can take up to roughly a minute depending on how many devices there are
and how many of their ports are silently dropped rather than actively refused (a refused connection answers
almost instantly; a silently filtered one waits out the full per-connection timeout). Scanning one device is
much faster. Only one scan runs at a time: a manual scan that arrives while the scheduled one is still
running waits for it, rather than piling more connection attempts onto the network.

History is kept at `<data_dir>/portscan.json` (mode 0600) and saved after every scan, scheduled or manual.
