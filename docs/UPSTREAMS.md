# Upstream resolvers

Shepherd answers what it can (blocked names, its cache) and forwards the rest to one or more **upstream** resolvers. It probes them
all the time, uses the fastest healthy one first and fails over at once when one stops answering.

## Address forms

| You write | It means |
|---|---|
| `9.9.9.10` | plain DNS over UDP (retried over TCP when an answer is truncated), port 53 |
| `9.9.9.10:5353`, `[2001:db8::1]:53` | the same on another port; IPv6 needs brackets with a port |
| `tcp://192.0.2.1` | plain DNS over TCP only |
| `tls://dns.example` or `tls://dns.example:853` | **DNS over TLS** (DoT) |
| `https://dns.example/dns-query` | **DNS over HTTPS** (DoH), RFC 8484 |
| `https://192.0.2.1/dns-query` | DoH to an IP address (the certificate must be valid for that IP) |

Plain upstreams must be IP addresses, never names: Shepherd is the resolver, it must not depend on resolving the name of its own resolver.

### Bootstrap

A `tls://` or `https://` upstream is named by a hostname, which has to be looked up once. Shepherd does that over plain DNS using a short
list of **bootstrap resolvers** (IP addresses), never the system resolver. The default is two well-known public resolvers; change it with
`dns.bootstrap` in the config or in the portal. The answers are cached until they expire and refreshed in the background, and a stale address is
kept if a refresh fails, so a bootstrap outage does not take encrypted upstreams down.

## Presets

The portal lists verified public resolvers (Cloudflare, Cloudflare malware and family, Quad9, Google, AdGuard, Mullvad) with their IPs,
DoH and DoT addresses, what they filter on their own and a note on their privacy statement. A preset adds the form you pick. A resolver that
filters (malware, ads, family) blocks on its own side in addition to Shepherd's lists; the unfiltered ones leave everything to Shepherd.

## Test before you add

`POST /api/upstreams/test` sends the same probe the health checker uses (a unique name that cannot be cached) and reports the result
without adding anything: whether it answered, how long it took, and the response code or the error. Use it before adding, particularly for
encrypted upstreams.

## Editing at runtime

Add, remove, reorder (the order is the tie-breaker among equally fast upstreams) and replace the list in the portal. The last upstream cannot
be removed. Probing starts immediately after each change.

The configuration file only **seeds** the list. The first change you make writes `<data_dir>/upstreams.json` (mode 0600) holding the upstream list and
bootstrap resolvers; from then on that file wins over `dns.upstreams` and `dns.bootstrap`. If the file is ever invalid (hand edited, truncated) it is
ignored with a log message and the configuration is used. To go back to the configuration, delete the file.

## A lesson about encrypted upstreams

Encrypted upstreams are not always better for a home. On some networks a router, firewall or carrier resets or silently drops DoT (port 853) or
DoH connections: the connection opens, then nothing comes back. A resolver that connects but never answers can stall every device on the network
for as long as it is first in line. Shepherd therefore probes encrypted upstreams with real queries (not just a connection), marks one that does not
answer unhealthy, and fails over, but you should still:

- keep at least one **plain** upstream in the list as a fallback, listed after the encrypted ones;
- **test** an encrypted upstream from the network it will run on, not from your laptop on another network;
- remember that a plain upstream exposes your queries to your ISP and anyone on the path; encrypted ones only to the resolver you chose.

## Configuration

```toml
[dns]
upstreams = ["9.9.9.10", "149.112.112.10", "1.1.1.1"]
bootstrap = ["9.9.9.9", "1.1.1.1"]
```

## API

Under the portal token, `X-Shepherd: 1` on every change. All return the current list in the same shape: `{upstreams, presets, bootstrap}`.

| Endpoint | Does |
|---|---|
| `GET /api/upstreams` | the list with health (`healthy`, `rtt_ms`, `consecutive_failures`, `last_error`, `queries`, `errors`), the presets and the bootstrap |
| `POST /api/upstreams/test` | `{addr}` probes without adding: `{ok, rtt_ms, rcode, error}` |
| `POST /api/upstreams` | `{addr}` adds one (409 if it is already there) |
| `DELETE /api/upstreams?addr=` | removes one (404 if unknown, 409 for the last) |
| `PUT /api/upstreams` | `{addrs}` replaces and reorders |
| `PUT /api/upstreams/bootstrap` | `{servers}` replaces the bootstrap resolvers |
