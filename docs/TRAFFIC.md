# Bandwidth

How much each device, each group and the whole network moves over the wire, live and over time.
The portal's **Bandwidth** screen shows it; `internal/traffic` keeps the history; the numbers come
from [Watch mode](WATCH.md). Nothing here adds a byte to the network: the relay already carries
every steered device's outbound frames, and this is bookkeeping on frames that are passing through
anyway.

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

## History

`internal/traffic.Store` keeps one series per device at three resolutions and folds data from one
into the next as it ages, so months of history fit in a few megabytes. Bytes are additive, so
unlike [nethealth](NETHEALTH.md)'s averaged rollups every fold is exact.

| Resolution | Kept | Then |
|---|---|---|
| Per minute | 48 hours | folded into hours |
| Per hour | 90 days | folded into days |
| Per day | forever | capped at 8 MiB on disk; the oldest days go first |

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

The Watch screen's traffic tiles and each device's drawer show the live download estimate too.

## API

Under the portal token.

| Endpoint | Does |
|---|---|
| `GET /api/traffic` | `enabled` (Watch mode is on), `measuring` (running and armed), the retention windows, `live` network rates and totals, and `devices`: every watched device's `up_bytes_per_second`, `down_bytes_per_second`, `bytes_relayed`, `bytes_received_est` and `groups`, busiest first |
| `GET /api/traffic/series?from=&to=&bucket=&scope=` | `points` of `{time, up, down}` bytes per bucket over `[from, to]` (RFC 3339; default the last 24 hours). `bucket` is `minute`, `hour` or `day` (default from the span: minutes up to a day, hours to 60 days, days beyond). `scope` is `network` (default), `device:<id>` or `group:<id>`; an unknown one is 404 |
| `GET /api/traffic/top?from=&to=&limit=` | The `network` total, `devices` and `groups` ranked by bytes moved in the range. A device no longer in the registry still appears by ID so the total is never silently short |

## Configuration

None yet. The retention windows and the save interval are constants
(`traffic.DefaultRetention`), and the feature is on whenever Watch mode is.
