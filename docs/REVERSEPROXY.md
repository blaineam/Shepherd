# Reverse proxy: other services, through Shepherd

`[reverseproxy]` lets Shepherd do the job a separate reverse-proxy manager does today: own an HTTPS
listener, terminate TLS for every configured hostname with a real certificate, and forward each request
(WebSockets included) to the backend set for that name. It is the main piece of
[ROADMAP.md](ROADMAP.md) step 18 ("Access") after [TLS.md](TLS.md), and like that step it is additive and
off by default. The package is `internal/reverseproxy`; the wiring is `cmd/shepherd/reverseproxy.go`.

This page is also meant to be read **before** a live cutover. The section
[Before you point real traffic at this](#before-you-point-real-traffic-at-this) is the checklist.

## What it does

- **One listener, many names.** A request arriving on `reverseproxy.listen` is matched by its `Host`
  header (any case, with or without a port or trailing dot) against the proxy hosts configured in the
  portal, and forwarded to that host's `target_scheme://target_host:target_port`. Path, query, method,
  body and headers are passed through untouched.
- **A name nobody configured gets a plain 404** from the proxy itself, as does a host that is switched
  off. It never falls through to the portal or anything else, so a typo or a removed host cannot expose
  Shepherd's own admin page under another name. The portal is not served on this listener at all; if you
  want it here too, add a host pointing at `portal.listen` like any other backend.
- **Backends may be `http` or `https`.** Some services terminate TLS themselves and only listen for HTTPS;
  a reverse-proxy manager supports both, so this does too.
- **WebSockets work**, and are tested end to end (see [WebSockets](#websockets-and-how-they-were-verified)).
- **Streaming is not buffered.** Server-sent events, long polls and chunked responses are flushed as they
  arrive; video ranges and large uploads stream through without size limits or timeouts.
- **Edits take effect on the next request.** Adding, changing, disabling or removing a host in the portal
  needs no restart.

### Headers a backend sees

| Header | Value | Why |
|---|---|---|
| `Host` | the public name the client asked for | what a reverse-proxy manager passes too, and what apps use to build their own links and check `Origin` |
| `X-Forwarded-For`, `X-Real-IP` | the client's own address | set, never appended to: this listener is the edge, so a client-supplied chain is not trusted |
| `X-Forwarded-Proto` | `https` | the client's connection was TLS |
| `X-Forwarded-Host` | the public name | |
| `X-Shepherd-Proxy` | a random marker for this process | detects a host pointed back at the proxy itself (answered with 508 instead of forwarding forever) |

Any `X-Forwarded-*` header the client sent is dropped before these are set.

## Configuration

```toml
[reverseproxy]
enabled = false
listen = ":8443"                # binding 443 is your call, not a default
domain = ""                     # e.g. "example.com" -> certificate for *.example.com
email = ""                      # optional; Let's Encrypt expiry-notice contact
cloudflare_api_token = ""
cloudflare_api_token_file = ""  # e.g. "/etc/shepherd/cloudflare-api-token"
```

- **`listen`** defaults to `:8443`, deliberately not 443. Taking port 443 over from the proxy you run
  today is a cutover you make on purpose (and binding a port below 1024 needs root or
  `CAP_NET_BIND_SERVICE` on Linux; a container port mapping such as `443:8443` is another way). If the
  address is already taken, Shepherd refuses to start with a clear `reverseproxy:` error rather than
  half-starting. It must differ from `tls.listen` when both are on.
- **`domain`** is the zone the certificate covers: `example.com` (or `*.example.com`, the same thing)
  gets a certificate for `*.example.com`. Required when enabled.
- **The Cloudflare token** follows `[tls]`'s rules exactly: set it directly or point
  `cloudflare_api_token_file` at a 0600 file, never both. Both sections may use the same token, scoped to
  **Zone → DNS → Edit** on the one zone, nothing broader (see [TLS.md](TLS.md)).

**The hosts are not in this file.** They are added, edited, switched off and removed in the portal's
**Proxy** tab (or over the API below) and persisted to `<data_dir>/reverseproxy.json` (mode 0600). This
follows the `geoblock.json` precedent rather than `upstreams.json`'s: nothing is seeded from
`shepherd.toml`, and nothing is written until the first edit. The hosts are live deployment details, the
kind of thing a config file that may end up in a repository should never carry, and the portal is the
place the project wants all of this managed from. The host list can be edited whether or not the
listener is on, so every host can be lined up before `enabled` is flipped.

A `reverseproxy.json` that cannot be read or validated stops startup instead of being replaced with an
empty list, so a later edit can never silently overwrite the hosts that were there.

### Portal API

All behind the portal token, every change needs `X-Shepherd: 1`:

| Route | Does |
|---|---|
| `GET /api/reverseproxy` | `{enabled, listen, wildcard, certificate: {names, not_after} \| null}` |
| `GET /api/reverseproxy/hosts` | `{hosts: [...]}`, sorted by domain |
| `POST /api/reverseproxy/hosts` | add `{domain, target_scheme, target_host, target_port, skip_tls_verify, enabled}`; `enabled` defaults to true, the id is assigned |
| `PUT /api/reverseproxy/hosts/{id}` | replace a host's fields; leaving `enabled` out keeps its current value |
| `DELETE /api/reverseproxy/hosts/{id}` | remove it; its name answers 404 from the next request on |

400 for an invalid definition, 409 for a domain another host already uses, 404 for an unknown id, 500
when the file could not be saved (and nothing changed).

## Why one wildcard certificate

Three designs were possible:

1. **A certificate per host**, issued and renewed separately. Every new host would mean a new ACME order,
   a new DNS-01 round trip, its own renewal schedule and its own failure mode, and the listener would
   need SNI-based selection across a changing set of certificates. That is most of the moving parts a
   reverse-proxy manager has, for no benefit on a zone you control.
2. **A small set of certificates chosen by SNI.** More general (it could mix zones), but it still needs
   per-certificate lifecycle management and a UI for it.
3. **One wildcard certificate, `*.<domain>`.** One order, one renewal loop, one file, and it covers every
   current and future host under the domain with zero per-host certificate work. Let's Encrypt only
   issues wildcards over DNS-01, which is exactly the flow `internal/tlscert` already runs against
   Cloudflare for `[tls]`.

This uses (3). `tlscert.Obtainer` already handled a wildcard order; a test now proves the CSR and the
challenge for `*.example.com` (the challenge TXT record goes at `_acme-challenge.example.com`, and the
code also drops a stray `*.` if a CA ever echoes one back). The certificate, its key and its own ACME
account key live in `<data_dir>/reverseproxy/tls/`, separate from `[tls]`'s `<data_dir>/tls/`, so neither
feature can overwrite the other. Renewal, caching and the "never block startup on Let's Encrypt or
Cloudflare" behavior are `[tls]`'s, shared through `startCertManager`; see [TLS.md](TLS.md#renewal).
`[tls]` itself is unchanged.

**What a wildcard does not cover**, and the portal flags with a badge:

- **Exactly one label.** `*.example.com` is valid for `jellyfin.example.com` but **not** for
  `a.b.example.com`. If your hosts are all `name.home.example.com`, set `domain = "home.example.com"`.
- **Not the bare domain.** `example.com` itself is not covered.
- **One zone.** Hosts under two different domains cannot share one wildcard; that would need design (2).

## Backend certificates

A request to an `https` backend verifies the backend's certificate by default, against the system roots
and the backend's address as written (`target_host`). Backends on loopback or the LAN rarely have a
certificate that passes that (self-signed, or issued for a name rather than `127.0.0.1`), so each host has
an explicit **"Accept any backend certificate"** switch (`skip_tls_verify`). A typical reverse-proxy
manager never verified backends at all; here the trade-off is per host and visible (the row is badged
"Backend not verified"). A host with verification on and an untrustworthy backend certificate fails
closed with a 502.

## WebSockets, and how they were verified

Forwarding uses `net/http/httputil.ReverseProxy`, which since Go 1.12 handles `Upgrade` requests by
completing the handshake with the backend, hijacking both connections and copying bytes in each
direction. Rather than take that on faith, `internal/reverseproxy/websocket_test.go` proves it with
nothing but the standard library (no WebSocket module added to `go.mod`): a backend that hand-implements
the RFC 6455 handshake and framing on a hijacked connection, behind the proxy served over real TLS with
HTTP/2 offered, and a raw TLS client that negotiates `http/1.1` the way a browser does for a WebSocket.
Each test checks:

- the `101 Switching Protocols` handshake, including a correct `Sec-WebSocket-Accept`;
- a message the backend pushes **first, unprompted** (backend to client with nothing to reply to, the way
  Jellyfin and Immich push live updates);
- several echoed text frames and one 70 KB binary frame each way (the 64-bit length form);
- that client frames arrive at the backend still masked (passed through untouched);
- the close handshake, and the backend hanging up reaching the client as end-of-stream;
- that the backend saw the public `Host`, `Origin`, `X-Forwarded-Proto: https` and the client address.

This runs against both an `http` and an `https` backend, and `cmd/shepherd`'s tests repeat a handshake
and echo through the real listener started by `run()`, with the host added over the portal API. Removing
the `Upgrade` header in the proxy's rewrite makes these tests fail, so they test what they claim.

Two details that matter for WebSockets: the transport to backends speaks **HTTP/1.1 only** (an HTTP/2
connection cannot carry a classic upgrade), and the listener does **not** advertise HTTP/2's extended
CONNECT, so browsers open WebSockets over HTTP/1.1 while ordinary requests still use HTTP/2. Go keeps
extended CONNECT off by default; do not run Shepherd with `GODEBUG=http2xconnect=1`.

## Limits: what this does not do yet

A straight migration from a reverse-proxy manager **may lose per-host features that manager had**. This
proxies a name to one backend, and that is all. Not built:

- **No access control of any kind per host**: no access lists, IP allowlists or denylists, HTTP basic
  auth, client-certificate auth, or single sign-on. Anyone who can reach the listener can reach every
  enabled host.
- **No custom per-host configuration**: no extra headers, no custom locations (sending one path to a
  different backend), no rewrites, no "advanced" free-form server config, no caching, no "block common
  exploits"-style filtering, no per-host body size limits or timeouts.
- **No plain-HTTP listener and no HTTP-to-HTTPS redirect.** If clients reach your services on port 80
  today (or rely on a "force SSL" redirect), something else must answer port 80 after a cutover.
- **No HSTS** or other security headers added to responses.
- **No per-host certificates, no custom (uploaded) certificates, no second zone.**
- **No TCP/UDP stream forwarding, redirection hosts or dead-host pages**: HTTP(S) proxy hosts only.
- **No access log.** Backend failures are logged by host name only (never the path or query, which can
  carry tokens); successful requests are not logged.
- **No import from an existing proxy manager.** Hosts are entered by hand in the Proxy tab (the backend
  field accepts the `http://127.0.0.1:8096` form such managers display).
- **Enabling still means editing `shepherd.toml`**: `enabled`, `domain`, `listen` and the token are config,
  as for `[tls]`. Only the hosts are portal-managed today.
- **No upstream proxy trust.** `X-Forwarded-For` is the direct client. If something is ever put in front
  of this listener (a tunnel, another proxy), backends will see that hop's address, not the real client.
- **Shutdown does not wait for WebSockets.** A Shepherd restart drops every open socket (clients
  reconnect) and briefly interrupts every proxied service.

## Before you point real traffic at this

Read this before moving DNS or port 443 over. It is the honest list.

1. **Inventory every host in the proxy you run today**, including anything beyond "name → scheme, host,
   port": access lists, auth, custom locations, advanced config, per-host certificates, forced-SSL or HSTS
   toggles, streams. Each of those is listed under [Limits](#limits-what-this-does-not-do-yet) and will
   **not** carry over. Decide per host whether losing it is acceptable before moving that host.
2. **Check every name fits the wildcard**: one label directly under `domain`. The Proxy tab badges any that
   do not; Shepherd also logs them at startup.
3. **Add the hosts in the Proxy tab** while the listener is off or still on `:8443`, and turn on "Accept any
   backend certificate" for `https` backends that use a self-signed certificate (the old proxy almost
   certainly never verified them; with verification on they will answer 502).
4. **Enable `[reverseproxy]` on a spare port first** (`:8443`), restart, and confirm the certificate
   arrives: the log says `reverseproxy: certificate for *.<domain> is valid until ...` and the Proxy tab's
   listener card turns green. This is the first time a **wildcard** is requested from the real Let's
   Encrypt and Cloudflare; see [What is verified](#what-is-verified-and-what-is-not).
5. **Test every service on the spare port** without touching DNS, for example
   `curl --resolve jellyfin.example.com:8443:<shepherd-address> https://jellyfin.example.com:8443/`, or a
   hosts-file entry and a browser. For each one: sign in, use the live-updating parts (WebSockets), upload
   something large, seek in a video, and watch for 502s in the Shepherd log.
6. **Update backends that trust their proxy by address.** Apps that read `X-Forwarded-For` only from known
   proxies (Home Assistant's `trusted_proxies`, Jellyfin's known proxies, and similar) must list the
   address Shepherd connects to them from. If the old proxy ran on the same host and connected over
   loopback, that may already match; check, do not assume.
7. **Decide what answers port 80** (see Limits), and whether anything relied on a redirect.
8. **Cut over with a rollback ready.** Stop the old proxy (freeing 443), set `listen = ":443"` (with the
   privilege to bind it), restart Shepherd. Leave the old proxy's configuration and certificates in place:
   rolling back is setting `listen` back, restarting Shepherd and starting the old proxy again.
9. **Remember what changes operationally.** Shepherd becomes the single point of failure for every proxied
   service, and every Shepherd restart or upgrade interrupts all of them for a moment. Watch the
   certificate's renewal (it starts 30 days before expiry; the Proxy tab warns when fewer days remain).

## What is verified, and what is not

**Verified by tests (no real network beyond loopback):** host matching and normalization; routing,
404s for unknown and disabled hosts, and transport choice per host; path, query, body, `Host` and
`X-Forwarded-*` handling against a real `httptest` backend through a real TLS front door with HTTP/2
offered; https backends with verification passing, failing closed, and skipped; 502 for a dead backend;
loop detection; unbuffered streaming; WebSockets end to end as described above; wildcard CSR and
challenge naming against a fake ACME client; `cmd/shepherd` starting the listener with a fake ACME client
and DNS-01 provider, failing fast on a taken port, never blocking on an unreachable CA, and carrying a
WebSocket through `run()` with the host added over the portal API; the portal API's CRUD and error
mapping; the Proxy tab's pure logic. The Proxy tab was also exercised by hand in a browser against a
loopback-only development instance, at phone and desktop widths.

**Not verified:** a real wildcard issuance against Let's Encrypt and Cloudflare (`[tls]`'s single-name
flow has had live trial runs; a wildcard has never been requested from a real CA); real Jellyfin, Immich, Home Assistant or other application
traffic, and real browsers' WebSocket clients, through Shepherd; throughput or latency under real load
compared to the proxy it would replace; and any real backend's self-signed certificate. Those belong to
the supervised steps in the checklist above, not to this change.
