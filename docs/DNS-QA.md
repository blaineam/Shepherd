# DNS QA and the built-in self-test

Two pieces keep DNS failures from going unnoticed. The **QA suite** proves in CI that the resolver behaves.
The **self-test** checks, once a minute inside a running Shepherd, that the resolver on *this* network is
behaving right now. Both exist because of failures that were silent: Shepherd listening only on a NAS's
Wi-Fi address while devices used the wired one (a PS5 got "host not found"), an upstream failing a fifth of
its queries, list refreshes failing for hours.

## The self-test

On by default (`[selftest]` in `shepherd.toml`, `enabled = true`). Every `interval_seconds` (60) it:

| Check | What it asks | Fails when |
|---|---|---|
| **listener** | A known-good name, of every address Shepherd listens on, over UDP and over TCP. A wildcard listener (`0.0.0.0`) is asked on loopback and on each LAN address. | nothing answers. Critical: this is the "an address devices use has no listener" failure. |
| **resolve** | The same question, for the answer. | the name does not resolve (SERVFAIL, NXDOMAIN, no address). |
| **block** | A known-blocked name, on every address and protocol. By default a synthetic name the engine always blocks (`blocked.selftest.shepherd.invalid`), so it holds whatever lists you chose and honors `dns.block_mode`. Set `blocked_name` to a name on one of your lists to test the lists themselves. | the name is neither NXDOMAIN nor `0.0.0.0`/`::`. |
| **upstream** | Each upstream's last `window_minutes` (15) of real traffic and probes. | error rate above `max_error_percent` (5) with at least 10 queries, or a p95 latency more than 4 times its peers' median p95 and above 250 ms. |
| **lan** | Every private IPv4 address on this host's up, non-virtual interfaces (Docker bridges, tunnels, VPN interfaces are skipped). | the address is not covered by `dns.listen` (a wildcard covers all) and is not listed in `not_served`. A warning, not a failure. |

`good_name` is `example.com`. List an address in `not_served` when it deliberately has no DNS listener, so
it stops warning. Addresses Shepherd could not bind at startup (an interface that lost its cable) are shown
as *skipped* and are not reported as dead listeners.

The canary queries never appear in the query log or statistics and never teach the device list who is
asking (`Engine.Quiet`).

**Results:** the **Upstreams** screen has a *DNS self-test* card with a *Run now* button.
`GET /api/selftest` returns the latest report (`{"enabled": true, "report": {...}}`, `status` is `ok`,
`warn` or `fail`); `POST /api/selftest/run` runs a round and returns it.

**Alarms:** a finding must fail two rounds in a row before it raises an alarm, and the same finding does not
raise again for `alarm_cooldown_minutes` (30), however long it lasts or however often it flaps. Types:
`dns-listener-down` (critical), `dns-canary-failed` (high), `dns-lan-uncovered` (medium) and
`dns-upstream-degraded` (medium); see [ALARMS.md](ALARMS.md).

## The QA suite

```
scripts/dns-qa          # run it (race detector on)
scripts/dns-qa -v       # show every test
scripts/dns-qa --count 5
```

CI runs it as its own step. Every test is named `TestQA_...`; the harness is
`internal/dnsengine/qa_harness_test.go`: a fake resolver (`qaResolver`) that listens on one loopback port over
UDP and TCP and can answer, SERVFAIL, NXDOMAIN, stall, drop everything, or truncate over UDP; and `qaEngine`,
which serves a real `Engine` on real sockets in front of a pool of them. Tests query it as a device would and
assert both what the device saw and what the upstreams saw. DoH and DoT upstreams use the existing TLS
fakes.

What it covers:

- **Failover and hedging:** a SERVFAILing upstream, every upstream failing (SERVFAIL, not a hang), a stalled
  upstream costing only the ~150 ms hedge delay, no hedge when the first is fast, a blackholed upstream
  marked unhealthy by the prober (and then no longer costing the delay), recovery, DoH and DoT upstreams.
- **Truncation:** an upstream's truncated UDP answer retried over TCP; a large answer truncated for UDP
  clients and whole over TCP; UDP and TCP serving the same answers.
- **AAAA filtering:** `dns.filter_aaaa` answers empty without asking upstream, strips `ipv6hint` from HTTPS
  records while keeping `ipv4hint` and `alpn`, leaves the cache untouched, and the IPv6 probe turning it on
  after two failed rounds and off after one success.
- **Filtering:** blocklist matching (subdomains yes, look-alike names no), sinkhole answers per type, NXDOMAIN
  block mode, allowlist precedence over lists and policies, Private Relay hostnames NXDOMAIN with the policy
  on and resolving with it off.
- **Cache:** TTL honored and counted down, expiry, NXDOMAIN cached, SERVFAIL and TTL 0 not cached, A and AAAA
  separate.
- **Listener coverage** (`internal/selftest/qa_test.go`, real sockets on loopback aliases `127.0.0.2` and
  `127.0.0.3` standing in for a NAS's two addresses): every served address answers over both protocols, an
  address with no listener is caught for UDP and TCP, a blocked name on a list is checked, a LAN address with
  no listener warns. Linux has those aliases; on macOS run
  `sudo ifconfig lo0 alias 127.0.0.2 && sudo ifconfig lo0 alias 127.0.0.3` or the tests skip (the script
  says so).

To add a case, add a `TestQA_` function: make a `newQAResolver`, set its mode, build a `qaPool` and `qaEngine`,
and `qaQuery` it. Use reserved names and `192.0.2.x` addresses only (the leak guard enforces this).
