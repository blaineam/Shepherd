# TLS: a real certificate for the portal

The portal is plain HTTP only by default, reached by IP on your LAN or tailnet. `[tls]` gives it a
real certificate for a real hostname, over real HTTPS, issued the same way a reverse-proxy manager
would get one: the ACME protocol's **DNS-01 challenge against Cloudflare DNS**. This is the first,
additive step of [ROADMAP.md](ROADMAP.md) item 18 ("Access") — it does not touch anything else.

## What this is, and is not

- **Additive, not a replacement.** Enabling `[tls]` adds a *second* listener, on its own address
  (`tls.listen`) and its own hostname (`tls.hostname`). The existing plain-HTTP listener on
  `portal.listen` keeps working exactly as it does today, byte for byte, whether or not `[tls]` is
  configured at all. Nothing here can make Shepherd require TLS; `enabled = false` (the default)
  changes nothing.
- **Shepherd's own portal only.** This gives `cmd/shepherd` a certificate for its own hostname. It
  does not reverse-proxy, or change DNS for, anything else. If you already run a reverse-proxy
  manager in front of other self-hosted services on the same DNS zone, this does not touch it, its
  configuration, or any of its certificates or DNS records.
- **Step one of a longer plan, not the whole thing.** The maintainer's eventual goal is for Shepherd
  to take over reverse-proxying for other services too, migrating off that separate manager one
  service at a time. That full migration — reverse proxy, private service names, Cloudflare Tunnel —
  is tracked separately as [ROADMAP.md](ROADMAP.md) item 18 and is deliberately out of scope here.
  This change is the first, safe, low-risk slice: the portal gets a real certificate, nothing else
  changes, and nothing here assumes or depends on the rest of that plan landing.
  Reverse-proxying other services has since landed separately as `[reverseproxy]`
  ([REVERSEPROXY.md](REVERSEPROXY.md)), which reuses this page's DNS-01 machinery for a wildcard
  certificate kept in its own directory; `[tls]` itself is unchanged by it.

## Why Cloudflare DNS-01

Let's Encrypt (or any ACME CA) can issue a certificate for a hostname it cannot reach at all, as long
as you can prove you control its DNS: the CA asks you to publish a specific TXT record under
`_acme-challenge.<hostname>`, and once it sees that record it issues the certificate. This matters
for a setup like the maintainer's own: a DNS zone that is public, but whose records resolve to a
tailnet-only address — nothing outside the tailnet can actually reach the host, yet DNS-01 still
works, because it only ever needs a DNS record, never a connection to the host itself. It is also
exactly how the maintainer already gets real certificates for other services on the same network
today, via Cloudflare's own DNS API, driven by a separate reverse-proxy manager. Reusing the same
mechanism for Shepherd's own portal adds no new moving part to that story: one more hostname under
the same zone, the same kind of API token, the same CA.

The alternative, HTTP-01 or TLS-ALPN-01, would need the CA to make an inbound connection to the host
on port 80 or 443 — impossible for a tailnet-only address, and undesirable even where it would work
(it would mean opening the portal to the internet just to prove ownership of it).

## Choice of ACME library: `golang.org/x/crypto/acme`, not `go-acme/lego`

`go-acme/lego` is the most widely used Go ACME client and does include a built-in Cloudflare DNS
provider, so it was the obvious first candidate. It was not chosen because of what importing it
costs: `lego` is a single Go module whose `go.mod` lists dependencies for every one of its ~100+ DNS
providers' cloud SDKs (AWS, Azure, Google Cloud, and so on), not just Cloudflare — even though Go's
compiler only links in the packages actually imported, `go.sum` and the module graph would still
carry all of it. That is a heavy addition for one feature in a project that has, so far, pulled in
exactly three focused dependencies beyond the standard library and `golang.org/x/*` packages
(`github.com/BurntSushi/toml`, `github.com/miekg/dns`, and the GeoIP libraries for the map).

`golang.org/x/crypto/acme` is a complete RFC 8555 (ACME v2) client — nonce handling, account key
management, order and challenge polling, certificate parsing — maintained by the Go team and already
a transitive part of this project's existing `golang.org/x/crypto` dependency (already in `go.mod`
directly, for other reasons). It is also what `golang.org/x/crypto/acme/autocert` is built on, so it
is a production-proven implementation of exactly this protocol. Choosing it adds **zero new module
dependencies**. The one thing it does not do — publishing the DNS-01 challenge at a specific
provider — is this project's own `internal/tlscert.CloudflareProvider`, a small, direct translation
of three Cloudflare API v4 calls (find the zone, create the TXT record, delete it again).

## Package shape (`internal/tlscert`)

Following the shape `internal/portscan` and `internal/vulnscan` already establish:

- **`ACMEClient`** is the small interface of `*acme.Client` methods the issuance flow needs.
  `*acme.Client` itself satisfies it with no wrapper (a compile-time assertion in `obtain.go` checks
  this), so production code has nothing extra to maintain; tests inject a fake implementing the same
  interface, so the full register → authorize → satisfy-challenge → finalize flow is exercised
  without ever making a real network call to Let's Encrypt.
- **`DNS01Provider`** is the interface `CloudflareProvider` (`cloudflare.go`) implements: `Present`
  creates the challenge TXT record and returns an id, `CleanUp` removes it again. Its one
  implementation talks to Cloudflare's API v4 over a configurable base URL, so tests run it against
  a local `httptest.Server` standing in for Cloudflare — never the real API.
- **`Obtainer`** (`obtain.go`) drives one full DNS-01 issuance for a hostname: register the account
  (a no-op if it is already registered), authorize an order, publish and clean up the challenge
  record for every authorization, wait for validation, and finalize into a certificate with its
  `Leaf` already parsed.
- **`Manager`** (`manager.go`) holds the currently active certificate behind an `atomic.Pointer`,
  exposes it through `GetCertificate` for `crypto/tls.Config`, and runs the scheduled renewal loop.
- **`LoadOrCreateAccountKey`** / **`SaveCertificate`** / **`LoadCertificate`** (`account.go`,
  `store.go`) persist the ACME account key and the obtained certificate and key to disk.

## Configuration

```toml
[tls]
enabled = false
hostname = ""                   # e.g. "shepherd.example.com"
listen = ""                     # e.g. "0.0.0.0:8443"; separate from portal.listen
email = ""                      # optional; Let's Encrypt expiry-notice contact
cloudflare_api_token = ""       # read-once seed: the token lives in the portal (see below)
cloudflare_api_token_file = ""  # e.g. "/etc/shepherd/cloudflare-api-token"
```

- **`hostname`** is the certificate's subject — the real DNS name you want to reach the portal at
  (e.g. `shepherd.<your-zone>`). It needs an existing DNS record in Cloudflare (A, AAAA, or even one
  that only resolves on your own tailnet) before Let's Encrypt will issue for it; DNS-01 never
  connects to the address that record points at, it only needs the zone's DNS to be editable through
  the API token below.
- **`listen`** is where the HTTPS listener binds. This is deliberately a separate setting from
  `portal.listen` (which stays loopback-only by this project's own convention): the hostname above
  typically resolves to an address other than loopback, so the HTTPS listener needs to bind
  somewhere that address actually reaches — `0.0.0.0:8443`, or the specific LAN/tailnet address, not
  `127.0.0.1`.
- **The Cloudflare API token is set in the portal, not here.** It is the one "DNS provider" token on the
  **Proxy** tab, shared with `[reverseproxy]` (one zone, one credential) and kept in
  `<data_dir>/secrets.json` (mode 0600, the same honest "file permissions are the whole protection" limit
  as every other secret this project persists). The portal checks a token with Cloudflare before saving it
  (a read-only zone lookup for `hostname`, nothing is created or changed), and certificate issuance reads
  it fresh at every attempt, so saving or rotating it needs no restart: a save also makes the renewal loop
  check at once, so a first certificate that was waiting on a token arrives within seconds. Enabling
  `[tls]` with no token anywhere is not an error: Shepherd starts, logs that a token is needed, and the
  HTTPS listener fails its handshakes until one is set. See [REVERSEPROXY.md](REVERSEPROXY.md#the-dns-provider-token).
- **`cloudflare_api_token`** / **`cloudflare_api_token_file`** are now **read-once seeds** for that portal
  token, the same precedent `[[lists]]` sets: the first time Shepherd starts without a portal-managed
  token, whatever is set here (directly, or the trimmed contents of a 0600 file; setting both is still a
  configuration error) is imported, and from then on the portal's value is used and these are ignored. A
  deployment that already uses `cloudflare_api_token_file` therefore keeps working across the upgrade with
  nothing re-entered; afterwards, rotating the token means saving it in the Proxy tab — editing the file
  no longer changes anything (a startup line says so when the file differs). If `[tls]` and
  `[reverseproxy]` hold different tokens at the import, `[tls]`'s wins and the conflict is logged by
  setting name. A token file that cannot be read at that moment is retried at the next start, never lost.

  **Recommended minimum token scope:** create a Cloudflare API token scoped to **Zone → DNS → Edit**
  on the one zone your hostname lives in, nothing broader. It never needs account-level access, never
  needs any other zone, and never needs any permission beyond editing DNS records (it only ever
  creates and deletes one TXT record at a time, under `_acme-challenge.<hostname>`).

Leaving `[tls]` out entirely, or `enabled = false`, is always safe and is the default: Shepherd
behaves exactly as it does today, plain HTTP only.

## Renewal

Let's Encrypt certificates are valid 90 days. `Manager` renews **30 days before expiry**
(`tlscert.DefaultRenewBefore`), checking every 12 hours (`tlscert.DefaultCheckInterval`) whether the
currently active certificate still clears that threshold — a check that touches only the in-memory
certificate's own expiry, never the network, so almost every check does nothing at all. 30 days is
deliberately generous: if Cloudflare or Let's Encrypt are unreachable for a while (an outage, a
token that was rotated or revoked, a changed DNS record), the still-valid certificate keeps serving
the whole time, Manager just keeps retrying on every scheduled check, and there remains a full 30
days of headroom before that certificate would actually expire and HTTPS would stop working — easily
enough time to notice and fix a stuck renewal from the server log before it matters.

On startup, `cmd/shepherd/tls.go`'s `startTLS` loads whatever certificate is already cached in
`<data_dir>/tls` (fast, local disk only — no network) and starts the renewal loop in the background.
**Obtaining or renewing a certificate never blocks Shepherd's startup**, the same "never block on
something outside Shepherd's control" convention `startARP` and `startGeoBlock` already follow: if
there is no cached certificate yet and Cloudflare or Let's Encrypt cannot be reached right away, this
logs a clear warning, the DNS engine and the plain-HTTP portal start normally, and the HTTPS listener
simply fails its TLS handshake until the background loop succeeds — which it keeps trying to do, on
the same schedule, with no need to restart Shepherd.

## What is persisted

- `<data_dir>/tls/account.key` — the ACME account's own key (ECDSA P-256, PEM, mode 0600). This
  identifies the Let's Encrypt account, not any certificate, and is generated once, the first time
  `[tls]` is enabled.
- `<data_dir>/secrets.json` — the shared DNS provider token (mode 0600), with the accountability mail
  relay; see [REVERSEPROXY.md](REVERSEPROXY.md#the-dns-provider-token).
- `<data_dir>/tls/cert.pem` and `<data_dir>/tls/key.pem` — the obtained certificate's full chain and
  its private key (mode 0600 each), the same honest "0600 is the whole protection" convention every
  other secret this project persists already uses (see `docs/DEVICES.md`, `docs/HISTORY.md`).

## What is still unverified

Everything above is tested against fakes: a fake Cloudflare API (`httptest.Server`) and a fake
`ACMEClient` implementing the exact interface `*acme.Client` does, so the full
register → authorize → publish-and-clean-up-the-TXT-record → finalize lifecycle is exercised with
zero real network calls, in both `internal/tlscert`'s own tests and `cmd/shepherd`'s wiring tests
(including an end-to-end test that makes a real HTTPS request against the running portal and gets a
real TLS handshake back). What this cannot verify, and has not been run against, is a **real**
Cloudflare account and a **real** Let's Encrypt server together: whether a real scoped API token
actually has the right permissions, whether Cloudflare's real zone-lookup response shape matches
what the fake assumes in every edge case, and whether a real first issuance against the maintainer's
real `fort.*` zone actually succeeds end to end. That first live run is a deliberate, supervised next
step, done with a real token the maintainer provides directly — not part of this change.
