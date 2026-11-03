# Bandwidth

How much each device, each group and the whole network moves over the wire, live and over time.
The portal's **Bandwidth** screen shows it and `internal/traffic` keeps the history. There are two
ways to get the numbers, and the screen says plainly which one is in effect:

- **[Reading your router](#reading-them-from-your-router)** (`internal/routerusage`) — **the way
  to do this.** It asks the router you already have what each device has moved. Nothing is put in
  the path of your traffic, both directions are covered, and it works on networks where steering
  cannot; what you get depends on what your router will tell you, which is why eero's figures are
  a floor and UniFi's are exact. eero and UniFi are supported today.
- **[Watch mode](WATCH.md)** — **deprecated**, off by default, no new features. It relays each
  device's traffic and counts the bytes, which is exact for uploads, but it is an intervention, it
  only ever sees one direction (downloads are estimated from TCP acknowledgements), and on some
  networks it cannot be made to work at all.

Neither adds a byte to the network.

## Where the numbers come from

**Upload is measured exactly.** Watch mode relays everything a device sends (docs/WATCH.md), and
the relay counts the wire length of every frame per device. That has been there since Watch mode
shipped; this feature keeps it over time.

**Download is estimated from the device's own TCP acknowledgements.** The relay never sees a
download: the router answers the device directly (docs/WATCH.md, "What it does not see"). But
every TCP segment a device sends carries an acknowledgement number, which is the count of bytes
it has received so far on that connection. A download is a stream of inbound data the relay never
carries, answered by a stream of outbound ACKs it does, and each ACK's number has advanced by
exactly the bytes that arrived in between. Summing those advances per connection, and per device,
gives the download volume with no second interception, no promiscuous capture, no mirror port and
nothing new on the wire.

The rules, in `intercept.AckMeter` (`internal/intercept/ackmeter.go`) and, identically, in the
in-kernel relay (`meter_ack` in `internal/intercept/bpf/xdp_relay.c`):

| Segment | Effect |
|---|---|
| First ACK seen on a connection | A baseline, never a credit: a connection that was already running when steering began is not credited with everything it ever received |
| ACK that advances by less than 1 GiB | Credited in full, modulo 2^32 (wraparound is handled) |
| ACK that does not advance (duplicate ACK, window update, keepalive) | Nothing, which is right: a duplicate ACK means data did *not* arrive |
| ACK that advances by 1 GiB or more, or goes backwards | Not a download: a reused port pair or a badly reordered capture. It re-baselines |
| SYN without ACK | Ignored |
| FIN | Credits the final advance, then forgets the connection |
| RST | Forgets the connection |
| No segment for two minutes | Forgotten; the table holds 65,536 connections per relay worker |

The userspace relay keeps one meter per worker: `PACKET_FANOUT` hashes by flow, so every segment
of one connection reaches the same worker. The XDP relay keeps the connection table in an LRU
BPF map and the running estimate beside the relayed-byte counters, which the loader harvests
once a second. The two are held to agree frame for frame by `TestXDPMeterAgreesWithAckMeter`
(`make test-xdp`).

### What the estimate cannot see

It is TCP's bookkeeping, so it only sees TCP. **QUIC, every other UDP protocol and VPN tunnels show
as zero received.** QUIC carries most of YouTube and some other video and some app traffic; a
device that mostly does that will read far lower than it really is. The estimate can never
over-count: an acknowledgement number only ever covers bytes that genuinely arrived. The portal
says all of this wherever it shows a download figure, and never calls it anything but an estimate.

The gap is measurable. The host's own interface counters (what the loop brake already reads) give
the exact total both ways; the difference between that and the sum of the estimates is the share
this cannot see. Closing it needs the return path: a mirror port on a managed switch, two-sided
interception, or Gateway mode (docs/DESIGN.md).

## Reading them from your router

Not every network tolerates Watch mode. One-sided ARP steering depends on how the router switches
frames, and on at least one consumer mesh router it cannot be made to work: the router hands a
steered device's frames straight back, and the traffic dies. For those networks Shepherd can read
per-device bandwidth from the router instead, which touches nothing.

`internal/routerusage` is the shape of that. A `Source` is one router, and it declares which of
two things it can report:

| Kind | What the router gives | How Shepherd uses it | Accuracy |
|---|---|---|---|
| `KindCounters` | Bytes since the router booted | Differences consecutive reads | Exact apart from resets |
| `KindRates` | The rate right this moment | Integrates samples over time | An estimate |

The `Collector` normalizes both into the same per-device byte deltas `internal/traffic` already
stores, so the Bandwidth screen, the per-device chart and the history work the same either way. It
polls every 30 seconds, ignores a device the registry has never seen, refuses a counter that went
backwards or a figure too large to be real, and leaves a gap empty rather than interpolating
across a missed poll. A device Watch mode is already steering is skipped, so the two measurements
are never added together.

### eero

eero is the first source, and the only one today. eero publishes **no API** for this; the client
talks to the undocumented one its own app uses, the way well-known open-source clients do, so it
is unofficial and can stop working without notice.

eero reports only the rate right now (`down_mbps`, `up_mbps` per device), so it is a `KindRates`
source and its figures are **estimates**: traffic between two polls is interpolated, and a burst
that starts and ends between them is missed entirely. The portal never shows those numbers as
measured.

**How far off, measured.** On the maintainer's network, downloading about 300 MB in roughly a
minute was recorded as 45 MB -- a sixth of it. Thirty seconds is a long time next to a file
transfer, and both the sampling and eero's own reporting lag. So the per-device totals from this
source are a **floor, not a measurement**: they are good for "which devices are busy, and roughly
in what proportion", and poor for "how much has this device used this month". A shorter interval
narrows the gap at the cost of more requests to eero. A `KindCounters` source does not have this
problem at all, which is the argument for one.

**Connecting one.** On the Bandwidth screen, under "Read from your router", enter the eero
account's email or phone, type the code eero sends, and pick the network. The session token is
kept in `secrets.json` (`internal/secrets`, mode 0600, the same protection as every other stored
credential) and never leaves the server: it goes from the eero client straight into the store, and
no API call returns it. Switching the reader off keeps the sign-in, so turning it back on needs no
new code; **Disconnect** forgets it entirely.

**When the session expires**, the reader says so and the screen offers a sign-in rather than
showing a stuck collector. The network already chosen is kept.

### Device names

The kept sign-in is good for more than bandwidth. eero already knows what the household calls each
device, and `internal/importers` already maps those names to Shepherd aliases and eero's profiles
to groups -- that was the one-time import. With a session kept, the same thing can be run whenever
the owner adds a device, with no new verification code, from **Device names** in the same section.

It always previews first, and says exactly what would change before anything is written.
**The owner's own names win:** a device they have named in Shepherd is left alone unless they tick
"Also replace names I have set myself", which is asked for per sync and is never the default and
never automatic. Running it twice changes nothing the second time.

`POST /api/routerusage/names` takes `dry_run` and `overwrite_names` and returns the same report the
import does.

### UniFi

A UniFi Network controller keeps **real byte counters** per client, so it is a `KindCounters`
source: differencing consecutive reads is exact, and none of eero's sampling error applies. If you
have the choice, this is the one to use.

Connecting one is a single form -- a controller address, an account on it and the site -- because
unlike eero there is no verification code. **A read-only account is enough**; Shepherd only reads.
The credentials are checked against the controller before they are stored, so a typo is a message
on the screen rather than a collector that never works, and the password is kept in `secrets.json`
and never returned by any endpoint.

Two shapes of controller exist and both work. A UniFi OS console (a Dream Machine, a Cloud
Gateway, a UDR) answers under `/proxy/network` and wants a CSRF token; a self-hosted Network
Application answers directly. Which one is in front is discovered at login rather than configured.

The counters come from `stat/sta`, the endpoint the controller's own web interface uses:
Ubiquiti's documented API lists clients but does not expose their traffic. **Mind the direction** --
the controller reports from its own point of view, so its `tx_bytes` is what it sent *to* the
client, which is that device's download.

Controllers ship with a self-signed certificate, so a LAN address usually needs **Accept its
self-signed certificate**. It is off unless the owner turns it on.

When both a controller and an eero are connected, the controller wins: its numbers are
measurements and eero's are estimates.

### Adding another router

A new source is one type with three methods -- `Name`, `Kind` and `Poll` -- plus a constructor.
Everything else is shared. Routers that keep real byte counters (UniFi, OpenWrt) are the better
case: `KindCounters` is exact and needs no integration.

## History

`internal/traffic.Store` keeps one series per device at three resolutions and folds data from one
into the next as it ages, so months of history fit in a few megabytes. Bytes are additive, so
unlike [nethealth](NETHEALTH.md)'s averaged rollups every fold is exact.

| Resolution | Kept | Then |
|---|---|---|
| Per minute | 48 hours | folded into hours |
| Per hour | 90 days | folded into days |
| Per day | forever | capped at 8 MiB on disk; the oldest days go first |

A `[retention] max_mb` budget in shepherd.toml can lower that cap (docs/UPDATE.md "Retention").

Watch mode's engine hands the store each device's bytes once a second, keyed by registry device
ID (a device merged from several MACs is one row). A device that moved nothing leaves no trace. The
store saves itself to `<data_dir>/traffic.json` (mode 0600) at most once a minute while something
changes, and restores it at start. Nothing here is encrypted: these are byte counts per device, not
what the device looked up; the query history that *is* sensitive lives in
[HISTORY.md](HISTORY.md)'s encrypted store.

**Groups and the network are sums over devices**, computed when asked from the registry's current
membership. Moving a device between groups moves its history with it; there is no per-group
series to go stale.

A query at a resolution folds everything finer up into it, so a week at hourly resolution includes
the last two days that are still held per minute. The reverse is impossible, so a minute-level
query reaching further back than 48 hours finds nothing there; the API picks the resolution from
the span when the caller does not.

## In the portal

The **Bandwidth** screen, under Monitor:

- **Right now:** download and upload rates for the network, totals since Watch mode started, and
  every watched device with its own rates and totals, busiest first. Polls every two seconds while
  the screen is open.
- **Over time:** a chart of download and upload as average rates per bucket, for the whole
  network, one group or one device, over the last hour, day, week, month or 90 days, with the
  totals for the range.
- **Who used the most:** devices and groups ranked by bytes moved in the range, with each one's
  share of the network's total.

The Bandwidth screen's live tiles and each device's drawer show the live download estimate too.

## API

Under the portal token.

| Endpoint | Does |
|---|---|
| `GET /api/traffic` | `enabled` (Watch mode is on), `measuring` (running and armed), the retention windows, `live` network rates and totals, and `devices`: every watched device's `up_bytes_per_second`, `down_bytes_per_second`, `bytes_relayed`, `bytes_received_est` and `groups`, busiest first |
| `GET /api/traffic/series?from=&to=&bucket=&scope=` | `points` of `{time, up, down}` bytes per bucket over `[from, to]` (RFC 3339; default the last 24 hours). `bucket` is `minute`, `hour` or `day` (default from the span: minutes up to a day, hours to 60 days, days beyond). `scope` is `network` (default), `device:<id>` or `group:<id>`; an unknown one is 404 |
| `GET /api/traffic/top?from=&to=&limit=` | The `network` total, `devices` and `groups` ranked by bytes moved in the range. A device no longer in the registry still appears by ID so the total is never silently short |

## What it cannot see at all

History accrues only while Watch mode is running and steering (docs/WATCH.md): nothing is measured
for a device that is not steered, and a device with connections opened before it was steered can
keep sending those to the real router, so its numbers are partial until those connections end.

## Configuration

None yet. The retention windows and the save interval are constants
(`traffic.DefaultRetention`), and the feature is on whenever Watch mode is.
