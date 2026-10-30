# Network health history

Everything else in Shepherd that checks on the network's own health (the upstream DNS pool, the ARP
layer) answers "is it up right now". This feature, `internal/nethealth`, exists to answer a different
question: **is my network reliable over the last few months, not just this instant.** It probes
latency, jitter, packet loss and reachability on a short interval, runs an occasional, deliberately
bounded bufferbloat check, and — unlike the gentle, mostly-stateless checks in
[PORTSCAN.md](PORTSCAN.md) and [VULNSCAN.md](VULNSCAN.md) — keeps real history, rolled up over time so
disk usage never grows without bound.

## What this measures, and how

### Latency, jitter, packet loss, reachability

These four are really one probe cycle: `internal/nethealth.Prober` sends a small burst of probes (5 by
default) to each target and derives all four from the results.

**The probe itself is a plain TCP connect to port 53, timed from dial to connection, not an ICMP echo.**
This was a deliberate choice, not a shortcut taken for lack of effort:

- ICMP echo needs a raw socket, which needs `CAP_NET_RAW` — the same capability
  [`internal/arp`](ARP.md) needs, and the same one [Watch mode](INTERCEPT.md) needs. Getting a raw
  ICMP implementation *right* (correct checksums, correct handling of a system that already has its own
  ping socket semantics, correct behavior when the capability is missing) is genuinely fiddly, and this
  change was written and tested without live hardware to verify any of it end-to-end against a real
  network. Shipping an unverified raw-socket implementation that silently does the wrong thing on someone
  else's router felt like a worse outcome than not having ICMP at all.
- Every target this package ever probes (the configured DNS upstreams, plus one or two well-known public
  resolvers — see "Targets" below) is, by definition, a DNS server, and every DNS server answers TCP
  connections on port 53 (TCP is a mandatory fallback in the DNS protocol itself, used whenever a UDP
  reply would be truncated). A bare TCP SYN/SYN-ACK round trip is a faithful, unprivileged stand-in for
  ICMP echo timing: it measures the same thing (one round trip to a live host), it needs no special
  capability, and — critically for this project's TDD discipline — it is exactly as unit-testable as
  `internal/portscan`'s own connect-scan probes, through the same injectable `DialFunc` seam, with zero
  real sockets touched in tests.
- The tradeoff: this measures TCP's handshake latency, not ICMP's. In practice these are extremely close
  (both are one round trip, and a SYN is not meaningfully heavier to process than an echo request for any
  real DNS server), but it is not literally the same packet type a dedicated `ping` sends, and a path that
  specifically filters ICMP while allowing TCP (or vice versa) would read differently here than it would
  in `ping`. This is called out plainly rather than letting "latency" quietly mean something slightly
  different from what the name implies.

**Targets** (`DefaultTargets` in `targets.go`): every host in `cfg.DNS.Upstreams`, stripped of its scheme
and port (`tls://dns.quad9.net:853` probes `dns.quad9.net`, not port 853), plus two well-known public
anycast resolvers, Cloudflare's `1.1.1.1` and Google's `8.8.8.8`, so a reading still means something on a
network with only one upstream configured, and so an outage of the configured upstreams specifically is
distinguishable from an outage of the network's path to the internet generally. Duplicates are dropped.

**Per target, per cycle:** `Successes`/`Probes` (packet loss for that target), `AvgLatencyMS` (mean of
that target's own successful round trips) and `JitterMS` (the **population standard deviation** of that
target's own successful round trips this cycle — deliberately *not* pooled across different targets,
since targets sit at different distances and pooling would read distance differences as jitter).

**The overall `Sample`** reported each cycle is the mean across targets: `LatencyMS` and `JitterMS` are
the mean of each *reachable* target's own average/jitter; `LossPct` is the mean loss percentage across
*every* target, reachable or not, so a target that is completely down pulls the number down rather than
being silently excluded from the average. `ReachableTargets`/`TotalTargets` give reachability directly;
`AllUnreachable()` is true when not one target answered (a total outage of the network's own path out,
not just one resolver).

### Bufferbloat

Bufferbloat is latency added under load: your connection may ping fine at idle and still turn a video call
choppy the moment someone starts a large download, because a saturated link's buffers queue packets for
seconds before anything gets through. Measuring it needs to actually create that load, if only briefly —
there is no way to observe bufferbloat passively.

`Prober.Bufferbloat` does three things in order: a short idle ping burst against one target, then a
**bounded** traffic burst (`LoadFunc`) with a second ping burst running alongside it, then the comparison
(`IncreaseMS = LoadedMS - IdleMS`, never negative). It is bounded twice over, deliberately, because this
is the one part of this feature that generates real traffic against the maintainer's own uplink and
getting the bound wrong would mean hammering their own network:

1. **Time bound:** the whole load burst runs under a context with `BufferbloatOptions.Duration` (default
   5 seconds) — whatever the load function is doing, it is cancelled at that point, full stop.
2. **Byte bound:** the default `LoadFunc` (`DefaultLoadFunc`, in `load.go`) additionally caps itself at
   `maxLoadBytes` (20 MiB) independent of the context, as a second line of defense in case a server or
   proxy somewhere along the path does not honor cancellation promptly.

The default load generator downloads from `https://speed.cloudflare.com/__down?bytes=...` — Cloudflare's
own public, no-auth, no-API-key speed-test endpoint, published for exactly this purpose (the same one
`speed.cloudflare.com` itself uses in the browser). This is the one place in `internal/nethealth` that
talks to anything other than the configured DNS upstreams and the two public resolvers above, and it is
called out here plainly: **this endpoint's real behavior is unverified in this project's test
environment**, which has no live network to confirm an actual download against it end to end. Everything
around it (the bounding, the idle/loaded comparison, the grading) is unit-tested with a fake `LoadFunc`
that never touches a socket; the production default itself has not been run against a real network. See
"What is verified, and what is not" below.

**Grading** (`gradeBufferbloat`): A under 30ms added latency, B under 60ms, C under 200ms, D under 400ms,
F otherwise (or when the load burst itself failed to run at all, which is reported separately as
`load_error` rather than guessed at). These bands are Shepherd's own reasonable approximation of the idea
popularized by the Waveform/DSLReports bufferbloat tests — their exact cutoffs are not published as a
spec to reproduce, so these are not a claim of matching them exactly.

### Reachability

Folded into the same probe cycle above (`ReachableTargets`/`TotalTargets`/`AllUnreachable()`) rather than
a separate check — reachability *is* "did any probe to this target succeed", which the latency/loss burst
already answers for every configured target.

**Default gateway**, specifically, is not part of the configurable target list: `cmd/shepherd`'s wiring
adds it automatically when it can be determined (Linux, via the same `/proc/net/route` helper
[`internal/arp`](ARP.md) already uses — `arp.DefaultGatewayFunc`), on the same "degrade gracefully, never
fatal" terms as everything else that needs platform-specific information. On a platform or a route table
where the gateway cannot be determined, it is simply left out of the target list; nothing else about the
feature is affected.

### Traceroute: deferred

**Not implemented in this pass**, for the same reason `internal/portscan` deferred router port-forwarding
discovery (see docs/PORTSCAN.md): getting a TTL-incrementing traceroute genuinely right — correctly
distinguishing "this hop didn't answer" from "this hop filters the probe type", handling the raw-socket or
ICMP-time-exceeded plumbing across platforms, and doing all of that without flooding intermediate routers
— is real, fiddly work that deserves to be verified against a real multi-hop path before it ships. This
project has no live hardware to do that verification against in the environment this feature was built
in. Shipping a traceroute implementation that has only ever run against a fake `DialFunc` in a unit test,
with no real router ever having answered it, was judged too risky for a feature whose only job is
*telling the maintainer the truth about their network* — a traceroute that quietly gets hop attribution
wrong would be worse than no traceroute. This is tracked as deferred, not abandoned; see
[ROADMAP.md](ROADMAP.md) step 15.

## Retention: raw, hourly, daily

The entire point of this feature, unlike `internal/portscan` and `internal/vulnscan`, is trend data over
months, which means it cannot just keep "the latest snapshot" the way those two gentle, mostly-stateless
checks do. At the same time, probing every couple of minutes for months would make a naive "keep every
sample forever" store grow without bound. `internal/nethealth.Store` borrows the
*thinking* behind [`internal/history`](HISTORY.md)'s own age/size retention (not its code — this data
needs no encryption, and the volume is tiny by comparison) and rolls samples up through three
resolutions as they age:

| Resolution | Default kept | What's in it |
|---|---|---|
| Raw | 3 days | every completed probe cycle, full detail (every target's own numbers) |
| Hourly | 60 days | one point per hour: count-weighted mean latency/jitter/loss/reachability, plus the min/max latency actually observed that hour |
| Daily | forever by default, capped by size | one point per day, same shape as hourly |

A sample older than the raw window is folded into its hour's aggregate (weighted by how many raw samples
are already behind that hour, so repeated folding stays exact rather than drifting toward an unweighted
average of averages); an hourly bucket older than the hourly window is folded into its day the same way.
The daily series has no age limit by default — "is this getting worse over the year" should always have
an answer — but is capped at 8 MiB on disk (`Retention.MaxBytes`): once the store would exceed that, the
*oldest* daily points are dropped first, since raw and hourly are already small and bounded by their own
age limits. 8 MiB holds tens of thousands of daily points, far more than any real install will ever
accumulate, so this cap is a safety net, not an expected limit.

Bufferbloat checks are kept as their own, much sparser series (no rollup — a check every hour or so for
a year is still a small list) and pruned by the same daily retention window.

History is persisted to `<data_dir>/nethealth.json` (mode 0600) and saved after every probe cycle and
every bufferbloat check, scheduled or manual, the same convention `internal/portscan` and
`internal/vulnscan` use for their own history files.

## Scheduling

Two independent schedules, because they have very different costs:

- **Latency/jitter/loss/reachability** is cheap — a handful of TCP connects per cycle, nothing more than
  `internal/portscan` already does per device per scan — so it runs often enough to actually produce a
  trend worth looking at: **every 2 minutes by default** (`interval_seconds`, minimum 60). This is
  minutes, not the hours `internal/portscan`/`internal/vulnscan` use, because the whole point of this
  feature is a dense enough trend line to see a blip, not just a daily snapshot.
- **Bufferbloat** generates real traffic against the maintainer's own uplink, so it runs far less often:
  **once an hour by default** (`bufferbloat_interval_seconds`, minimum 600 when enabled). A bounded 5-second
  download burst once an hour is a negligible fraction of any plan's data allowance and an even smaller
  fraction of any uplink's actual capacity over time, while still building a meaningful trend over weeks.

## Should this be on by default?

**The latency/jitter/loss/reachability probe defaults to `enabled = true`.** It costs essentially nothing
(a handful of TCP connects every couple of minutes, against servers that already exist specifically to
answer connection attempts), and, as with `internal/portscan`'s own default-on reasoning, a feature whose
entire value is "the owner can see a trend they could not see before" is a feature almost nobody turns on
by hand if it starts off.

**Bufferbloat defaults to `bufferbloat_enabled = false`**, and this one *did* need the opposite default,
for reasons specific to it rather than inherited automatically from portscan/vulnscan's own reasoning:

- Unlike every other probe in Shepherd — a bare TCP connect-and-close, a banner read — a bufferbloat
  check **actually uses meaningful bandwidth** on purpose, by design, every time it runs. That is real
  data use on a metered or capped connection, not a negligible side effect.
- The production load generator (`DefaultLoadFunc`, against Cloudflare's public speed-test endpoint) is,
  as noted above, unverified end to end in this project's own test environment. Defaulting a feature on
  that reaches an external endpoint this project has never actually watched behave in practice, on every
  Shepherd install everywhere, is a materially bigger leap than defaulting on a feature (portscan,
  vulnscan) that only ever talks to the maintainer's own already-known devices.
- Turning it on is one line in `[nethealth]`, and the portal exposes a "run bufferbloat test now" action
  either way, so nothing about the feature is hidden from an owner who wants it — it just is not forced
  on someone who has not made that choice.

## Alerting

A new builtin alarm type, `alarms.TypeNetworkDegraded`, raised when the network has been in a **sustained**
bad state, not a single blip. `internal/nethealth.DegradationTracker` (a pure, no-I/O state machine, fully
unit-tested without any real network) decides this from the Sample stream alone:

- A sample counts as "bad" when it is a total outage (`AllUnreachable()`), or mean loss is at or above
  20%, or mean latency (among reachable targets) is at or above 150ms.
- The alarm is raised only after **3 consecutive bad cycles in a row** (with the default 2-minute
  interval, roughly 6 minutes of sustained badness) — the same "don't cry wolf" discipline
  `cmd/shepherd/alarms.go`'s `wireUpstreamAlarms` already applies to upstream DNS health (requiring every
  upstream to be down, not just one, before raising `upstream-down`). One slow or lossy cycle is noise (a
  Wi-Fi retry, a loaded CPU delaying a goroutine for a moment); three in a row is a real finding.
- Recovery is immediate: the very next healthy sample after a raised alarm resolves it. Good news does
  not need the same "wait and see" discipline bad news does — this mirrors `internal/vulnscan`'s own
  resolve-the-moment-it-clears behavior, and `wireUpstreamAlarms`'s own instant `upstream-recovered` alarm.
- Unlike `vulnerability-found`, `network-degraded` **is** suppressed during the install learning period
  (`LearningSuppresses: true`): a freshly installed Shepherd, still learning what "normal" looks like on
  this specific network, raising a degradation alarm in its first hour would be exactly the noise learning
  mode exists to prevent — there is no equivalent to a vulnerability finding's "this is worth knowing about
  even on day one" urgency here, since a slow or lossy network on day one is far more likely to just be
  what this network's baseline already looks like.
- There is deliberately no separate "network recovered" alarm type, for the same reason
  [VULNSCAN.md](VULNSCAN.md) gives for not adding a "vulnerability resolved" type: `internal/alarms`
  already has the right primitive (`Resolve`), and a second type would just be two ways of saying the same
  thing.

Bufferbloat readings are not currently wired into the alarm engine at all — they are recorded and charted,
but a bad bufferbloat grade does not page anyone in this pass. This was a deliberate scope decision, not an
oversight: bufferbloat is inherently noisier (it depends on what else is using the connection at the
moment the check happens to run) and deciding a sensible "don't cry wolf" threshold for it deserves its own
dedicated look rather than being bolted onto the latency/loss alarm's threshold logic. Left for later; see
[ROADMAP.md](ROADMAP.md).

## Configuration

```toml
[nethealth]
enabled = true
interval_seconds = 120               # 2 minutes; minimum 60
bufferbloat_enabled = false
bufferbloat_interval_seconds = 3600  # 1 hour; minimum 600 when bufferbloat_enabled
```

The target list (configured upstreams plus the two public resolvers), probe burst size, per-probe
timeout, and the retention windows are all built-in constants, not yet exposed in the configuration file
— the same "built in, not configurable yet" convention `[portscan]`'s port list and `[vulnscan]`'s
signature list already use.

## API

Under the portal token, `X-Shepherd: 1` on the two state-changing endpoints, the same convention as every
other portal endpoint that triggers real work.

| Endpoint | Does |
|---|---|
| `GET /api/nethealth` | `{enabled, bufferbloat_enabled, targets, current, degraded}`: whether the scheduled probe and bufferbloat check are running, the current target list, the most recent `Sample`, and whether the degradation alarm is currently open |
| `GET /api/nethealth/series?from=&to=&bucket=` | `{bucket, points: [...]}` — the stored history over `[from, to]` (RFC 3339 timestamps) at `bucket` resolution (`raw`, `hour` or `day`; a range is rejected if it does not parse) |
| `GET /api/nethealth/bufferbloat?from=&to=` | `{points: [...]}` — every stored bufferbloat check in range |
| `POST /api/nethealth/probe` | runs one latency/jitter/loss/reachability cycle now and returns it, the same "scan now" convention `internal/portscan`/`internal/vulnscan` use |
| `POST /api/nethealth/bufferbloat/run` | runs one bufferbloat check now (even if the scheduled check is disabled) and returns it |

A manual probe or bufferbloat check reuses whatever target list the most recent *scheduled* cycle
used — the portal does not itself own the configured upstream list (`cmd/shepherd` computes it once at
startup, including the default gateway when available), so both manual endpoints answer 400 until the
first scheduled cycle has actually run at least once. In practice this is a non-issue: the scheduled
probe's own first cycle runs immediately on startup, before its interval ticker ever fires.

The default load generator for a manual bufferbloat run is whatever `cmd/shepherd` configured the
`Prober` with at construction (`nethealth.Options.Load`/`BufferbloatDuration`, defaulting to
`DefaultLoadFunc` against `DefaultLoadURL` and a 5 second bound) — the same generator the scheduled check
uses, not a separate one the portal would have no way to configure safely on its own.

## What is verified, and what is not

Being explicit about this matters more for a feature like this than almost anywhere else in Shepherd,
because the whole point is the maintainer trusting the trend line:

**Verified by unit tests, with a fake `DialFunc`/`LoadFunc`, zero real sockets:** the probe burst and its
aggregation (latency/jitter/loss/reachability math, including the all-targets-down and single-target-down
cases), the rollup/retention logic (raw → hourly → daily folding, the weighted-average math staying exact
across repeated folds, age-based pruning, the size cap dropping the oldest daily points), the degradation
tracker's "don't cry wolf" state machine (sustained vs. transient badness, immediate recovery), the
bufferbloat comparison and grading, and the portal API's request/response shapes.

**Not verified against real hardware or a real network, because none was available in this project's test
environment:**

- Whether TCP-connect timing to port 53 against real DNS upstreams and `1.1.1.1`/`8.8.8.8` actually
  behaves the way this document claims — a real resolver might answer TCP:53 more slowly than it answers
  UDP, behind a load balancer, in a way that would read as consistently higher latency than a true ICMP
  ping would show.
- Whether `DefaultLoadFunc` against `speed.cloudflare.com` actually downloads the requested byte count in
  practice, how its real RTT compares to the configured `Duration`, and whether the maintainer's own
  uplink shows a visible bufferbloat delta when this runs against it.
- Whether the default gateway, once genuinely determined from a real `/proc/net/route` on real hardware,
  behaves as a sensible reachability target (some consumer routers rate-limit or deprioritize traffic to
  themselves).
- The overall "does this feel like a trustworthy trend line" verdict, which can only come from watching it
  run for real, over real days, against a real network.

This should be treated as a real, working implementation that is ready for exactly that live check, not as
something already confirmed end to end.
