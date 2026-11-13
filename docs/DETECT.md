# Detections and decoy ports

DNS filtering stops a device reaching a name on a list. It says nothing about a device that stops
asking, or one that is behaving strangely with names no list has heard of. `internal/detect` and
`internal/decoy` cover that ground, and they do it the way everything else in Shepherd's baseline
does: from data Shepherd already has, with nothing in the path of anyone's traffic.

Every finding raises an alarm naming the device. **Nothing here blocks anything.** The portal's
Alarms screen has a **Detections** tab with the checks' state, the decoy ports and the recent
findings.

## What it can and cannot see

Shepherd sits beside the network's traffic, not in it. These checks read two things: the DNS
queries Shepherd answers, and the per-device byte counts it reads from the router
([TRAFFIC.md](TRAFFIC.md)). So:

- A device that never asks Shepherd anything is invisible to the DNS checks. That is exactly what
  the silent-device check is for, and it needs byte counts to work.
- Nothing here sees where a connection goes, only what name was asked for first. A device that
  connects to an address it was built with is seen as bytes and nothing else.
- Traffic between two devices on the LAN never reaches Shepherd. The decoy ports are the one view
  of it: a probe of the neighbourhood reaches Shepherd's host like any other.
- Inbound traffic from the internet is the router's to stop. See [PORTSCAN.md](PORTSCAN.md) for the
  exposure checks.

This is detection of a device worth looking at, not a firewall and not an intrusion-prevention
system.

## The checks

| Alarm | What trips it | Needs |
|---|---|---|
| `encrypted-dns-lookup` | A device looks up one of the well-known public DNS-over-HTTPS or DNS-over-TLS resolvers. Once per device and resolver per day. | DNS only |
| `dns-bypass` | A device moved at least 200 MiB in 24 hours and not one lookup from it reached Shepherd. Once per device per week. | Bandwidth from the router |
| `dns-random-names` | One device asked for 20 different registrable domains that do not exist within 10 minutes, at least half of them machine-looking (long, high in entropy, short of vowels or salted with digits). | DNS only |
| `dns-tunnel` | One device asked for 40 different names under one domain within 10 minutes, each carrying at least 30 characters of subdomain. | DNS only |
| `dns-beacon` | One device looks up one name 21 times in a row at an even interval (under 10% variation, between 20 seconds and 2 hours), no other device asks for that domain, and the network first saw the domain after the learning period and within the last 7 days. | DNS only, after learning |
| `new-destination-country` | A lookup from a single-purpose device (TV, streaming box, speaker, camera, doorbell, printer, hub, plug, thermostat, e-reader) resolved to a country none of that device's lookups ever had. The device must have been watched for 7 days and made 200 lookups. Once per device and country. | The map ([GEOBLOCK.md](GEOBLOCK.md) uses the same database), after learning |
| `upload-spike` | A device uploaded at least 1 GiB in the last hour and that is three times its busiest hour in the last 15 days. A device with under a day of history needs 10 GiB. Once per device per six hours. | Bandwidth from the router |
| `decoy-touched` | Something connected to a decoy port. Once per source and port per hour. | A port Shepherd can bind |

### Learning

The beacon and new-country checks compare against the past, so for the first 7 days after
Shepherd first runs this version they only watch. What they learn is kept in
`<data_dir>/detect.json`: every registrable domain the network has looked up and when it first
did, and per device the countries its lookups have resolved to and when it last asked anything.
The file holds domains and country codes, never full query names, and it is how a restart does
not start the learning period again. Deleting it does.

The alarm engine's own learning mode ([ALARMS.md](ALARMS.md)) applies on top, per alarm type.

### Why each one is shaped the way it is

- **Random names** counts *registrable domains* that do not exist, not lookups, so one mistyped
  name retried a hundred times is one. Names Shepherd itself blocked do not count, nor do bare
  labels (a browser probes three random ones at start to detect a captive portal), reverse lookups
  or local-network suffixes. Requiring half to look machine-made keeps a list of dead bookmarks
  from tripping it.
- **Beaconing in DNS is what every connected device does**: a doorbell re-resolves its cloud
  endpoint every time the answer expires. So an even rhythm is not enough. The name must be new
  to the whole network, asked for by exactly one device, and still on its metronome 21 lookups
  later. A new app or a firmware update will occasionally meet all three, and the alarm says so.
- **Tunnelling** has honest false positives: some antivirus and telemetry products look up long
  encoded names by design. Mute the domain once ([ALARMS.md](ALARMS.md), mute rules).
- **New country** is limited to single-purpose devices because a laptop reaches a new country
  every week. The country is where the *answer* pointed, which for a name behind a content network
  is the nearest edge, not the owner.
- **Upload spike** uses the router's figures. On eero those are rates sampled over time, so totals
  are a floor rather than a measurement ([TRAFFIC.md](TRAFFIC.md)): a real spike can be under-read,
  never invented.
- **Silent device** cannot tell a device using its own resolver from one whose lookups arrive from
  an address Shepherd has not tied to it (an IPv6 address the registry has not learned, for
  example). The alarm says both. Shepherd's own host, the router and devices excluded from
  protection are left out.

## Encrypted DNS: two switches on the Blocking screen

Detection tells you a device looked for another resolver. Two built-in policy switches
([POLICY.md](POLICY.md)) do something about it:

- **Keep browsers on this resolver** (`doh-canary`, on by default). Answers NXDOMAIN for
  `use-application-dns.net`, the name a browser checks before switching itself to DNS over HTTPS.
  A negative answer is the documented signal that the network wants its resolver used. It breaks
  nothing; the name exists only to be asked about. An install that predates the switch gets it
  turned on the first time it runs this version, and it stays however you set it after that.
- **Block public encrypted-DNS resolvers** (`encrypted-dns`, off by default). Answers NXDOMAIN for
  the host names of the public resolvers a browser, a phone's private-DNS setting or an app
  actually ships with, so one configured by name cannot be found. Off by default because a phone
  whose owner set a private DNS provider in strict mode loses its lookups entirely until that
  setting is cleared, and that is the owner's call. It does nothing about a resolver reached by
  address; only a router's firewall can stop that.

Neither changes the detection: a lookup of a resolver name raises `encrypted-dns-lookup` whether it
was answered or refused.

## Decoy ports

`internal/decoy` listens on a few TCP ports and serves nothing from them. A connection is
accepted, its source recorded, and the connection closed without a byte sent. By default: 23 and
2323 (Telnet, what malware that spreads between cameras and routers tries first), 3389 (Windows
remote desktop) and 5900 (VNC screen sharing).

Nothing on a home network has a reason to connect to Telnet on the box running Shepherd. A device
scanning its neighbours does, and that scan comes to Shepherd without a mirror port.

- A port already in use on the host, or one Shepherd may not bind, is skipped and logged. Ports
  under 1024 need `CAP_NET_BIND_SERVICE` (the container images already have it for port 53) or
  root. A skipped decoy never stops Shepherd.
- Connections from this host's own addresses and from loopback are ignored, and Shepherd's own
  port scan ([PORTSCAN.md](PORTSCAN.md)) and vulnerability scan leave the decoys on this host out,
  so they are never reported as open ports or as a Telnet finding.
- **A network scanner you run yourself will trip them**, as will some routers' own device
  discovery. That is a true report; mute the source once.
- A decoy is a listening port. On a host that is directly reachable from the internet it will be
  touched constantly; set `decoy_ports = []` there.

## Configuration

```toml
[detect]
enabled = true
decoy_ports = [23, 2323, 3389, 5900]   # [] turns the decoys off and keeps the checks
```

The thresholds are not configurable yet; they are `detect.DefaultLimits`.

## Cost

Per DNS query: a handful of map lookups under one mutex, and one public-suffix lookup. Every five
minutes: one pass over the per-device byte totals. Memory is bounded everywhere (200,000 domains,
5,000 devices, 512 names per device per window, 200 recent findings). `detect.json` is written at
most every five minutes, only when something changed.

## API

`GET /api/detect` returns `enabled`, `status` (started, learning, learning_until, devices,
domains, traffic, findings), `findings` (newest first, at most 200 since start) and `decoy`
(`enabled`, `ports` with `listening` and `error`, `touches`).

## What is verified

Every check, the persistence and the decoy listeners are covered by unit tests with a controlled
clock (`internal/detect`, `internal/decoy`), and the wiring by `cmd/shepherd/detect_test.go`. The
thresholds are reasoned, not tuned: they have not yet run for a learning period against a real
network, so expect them to move.
