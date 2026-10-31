# Changelog

All notable changes to Shepherd are documented here.

The format follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) and the project
follows [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html). Before 1.0.0, a minor
version may include breaking changes; they are always listed under **Changed** or **Removed**.

Every push to `main` publishes one rolling beta (`X.Y.Z-beta.N`) and deletes the previous beta,
so only the newest beta exists. Stable releases are tagged `vX.Y.Z` and their notes come from this
file. See [docs/RELEASING.md](docs/RELEASING.md).

## [Unreleased]

### Added
- **Secrets managed in the portal (`internal/secrets`):** the two credentials Shepherd cannot generate for
  itself — the DNS provider token ACME DNS-01 needs, and the accountability SMTP relay — no longer mean
  hand-editing `shepherd.toml` and restarting. Both live in `<data_dir>/secrets.json`, the same JSON, atomic
  save (temp file, fsync, rename), mode 0600, nothing-written-until-there-is-something shape as
  `reverseproxy.json` and `devices.json`, and the same honest security model as every other secret this
  project persists: 0600 is the whole protection, no encryption at rest. Both are **write-only** through the
  API (only "set or not", where it came from and when it changed ever come back; the types also redact
  themselves under `%v` so a stray log line cannot leak one), and both are **checked before they are saved**
  with a real, side-effect-free call, so a bad credential is refused now (422, nothing stored) instead of
  surfacing hours later as a failed renewal or a digest that never went out: the Cloudflare token with the
  read-only zone lookup issuance already makes (`tlscert.CloudflareProvider.Verify`, never a record write),
  for the names `[tls]` and `[reverseproxy]` will actually issue for; the relay with a real connect,
  TLS/STARTTLS and AUTH that quits before `MAIL FROM` (`accountability.SMTPSender.Verify`, nothing is ever
  sent). **One DNS provider token, shared:** `[tls]` and `[reverseproxy]` each had their own Cloudflare token
  fields for what is one credential on one zone; now both read the same portal-managed entry, set from the
  **Proxy** tab, and the record carries a `provider` field (only `cloudflare` exists) so another provider can
  be added without a format change. **The SMTP relay** (host, port, username, password, From, TLS mode) is set
  from the **Accountability** tab. **Neither needs a restart:** certificate issuance reads the token fresh on
  every attempt, and a save kicks each certificate manager to check at once (`tlscert.Manager.Kick`), so a
  first certificate that was waiting on a token arrives within seconds; the accountability engine now sends
  through an `accountability.RelaySender` a newly saved relay is swapped into live. The engine is also now
  built whenever `[accountability]` is enabled (the default), relay or not, so the Accountability tab no
  longer 404s on every call when no relay is set — the confusing "looks broken" state it showed before —
  and a saved relay's password is only ever reused for the same host and username (a changed host must have
  its password typed again, so a saved one can never be redirected to another server). A default install
  still pays nothing on the DNS hot path for it: a new `dnsengine.Engine.OnAccessWanted` gate skips even the
  item lookup while no relay is set, and no access is queued or persisted without one.
  **Upgrading keeps what `shepherd.toml` already has:** `[tls]`/`[reverseproxy]`'s
  `cloudflare_api_token`/`cloudflare_api_token_file` and the whole `[accountability.smtp]` section
  (`password_file` included) become read-once seeds, the `[[lists]]` precedent applied per secret — imported
  the first time Shepherd starts without a portal-managed value, and ignored from then on (a startup line says
  so when the file's value differs). If both sections hold different tokens at import, `[tls]`'s wins and the
  conflict is logged by setting name; a seed that cannot be read yet (a missing token file) is logged and
  retried at the next start rather than lost; clearing a secret in the portal is remembered, so the file never
  brings it back. Neither token field is required by `[tls]`/`[reverseproxy]` any more; enabling either with
  no token anywhere starts normally and says in the log (and the Proxy tab) that a token is needed. New API:
  `GET/PUT/DELETE /api/dns-provider` and `GET/PUT/DELETE /api/accountability/smtp`. Not done: encryption at
  rest, other DNS providers, a "send a test email" button, and turning `[accountability]`, `[tls]` or
  `[reverseproxy]` themselves on or off from the portal (those switches, and hostnames, are still config).
- **Passkey unlock (`internal/passkeys`):** the portal can now be unlocked with a passkey — Face ID, Touch
  ID, Windows Hello, a phone, or a hardware security key — alongside the token and the PIN, never instead
  of them. The step docs/LOCKING.md had designed and deliberately deferred until the portal had a real
  HTTPS name, which `[tls]` now gives it. **The WebAuthn protocol is `github.com/go-webauthn/webauthn`
  v0.18.2, not hand-rolled** — the one deliberate new dependency of tonight's work, because challenge,
  origin and RP ID binding, attestation and COSE key parsing and signature checks are exactly what a
  well-vetted library is for; it brings in CBOR, TPM-attestation, JWT and msgpack modules
  (docs/THIRD-PARTY.md). The relying party is `[tls].hostname`, its origin `https://<hostname>:<port of
  tls.listen>` (plus the same name on 443, for a container publishing 443 onto the listener); a passkey
  registered there works only there, never at the LAN IP, another name, or plain HTTP; each passkey records
  the hostname it was made for, so after a `[tls].hostname` change the old ones stay listed (flagged, to be
  removed) but are never offered at sign-in. **Every ceremony is
  refused before it starts when it could not work**: with `[tls]` off the Locking screen says passkeys need
  it, and from any page that is not the HTTPS listener at that name (the plain-HTTP LAN address, or the
  HTTPS listener reached by IP) it names both where you are and where to go, instead of a WebAuthn error in
  the console. Passkeys can only be *added* from an already-unlocked session (token or PIN), never used to
  gain first access; registration and login require user verification (a biometric or device PIN, since a
  passkey stands in for a PIN plus a trusted browser), ask for no attestation, prefer but do not require
  discoverable credentials so hardware keys without resident-key storage still work, and refuse a
  signature counter that goes backwards (a possible clone) without saving it (and never lower the stored counter
  when two sign-ins race). Ceremonies are single use
  (a finish attempt consumes one, right or wrong), expire after 5 minutes, are tied to the browser that
  began them by an `HttpOnly`/`Secure`/`SameSite=Strict` cookie holding only a random id (the challenge
  stays on the server), and are capped at 32 pending. A successful passkey login opens exactly the session
  a token or PIN login does — the same `shepherd_session`, idle lock and 30-day cap — and revoking that
  passkey ends the sessions it opened. Up to 20 passkeys, each named, renamable and revocable from a new
  **Passkeys** card on the Locking screen; the lock screen gains **Sign in with a passkey**, shown only on
  the HTTPS listener and only once one is registered (the unauthenticated check reveals neither the
  hostname nor how many exist). Stored in `<data_dir>/passkeys.json` (0600, atomic; public keys only — a
  passkey's private key never leaves its authenticator), wiped when the portal token rotates like the PIN
  and trusted browsers; a file that cannot be read disables passkeys alone (503, file untouched) while the
  token and PIN keep working. New API: `GET /api/login/passkey`, `POST /api/login/passkey/begin|finish`,
  `GET /api/passkeys`, `POST /api/passkeys/register/begin|finish`, `PATCH`/`DELETE /api/passkeys/{id}`.
  **Tested against a software authenticator, not a real one:** `internal/passkeys/passkeystest` builds and
  signs real ES256 WebAuthn payloads the way the library tests itself, and every tampered response (wrong
  origin, localhost, wrong RP ID, wrong challenge or ceremony type, no user verification, someone else's
  user handle, a wrong key, a replay, a revoked or unknown credential, a backwards counter) is checked to
  fail the specific check it targets, through the real HTTP API over a real TLS listener. No real browser,
  platform authenticator or security key has been tried yet; see docs/PASSKEYS.md, including its "Before
  you rely on this" checklist.
- **2D map fallback for the HUD:** browsers without WebGL, notably Safari in Lockdown Mode, now get a
  flat canvas map (`js/flatmap.js`) with the same arcs, comets, pulses, picking, Set home and panning and
  zooming, plus day/night shading, instead of a "needs WebGL" notice. `?nogl=1` forces it.
- **Reverse proxy (`[reverseproxy]`, `internal/reverseproxy`):** the main remaining piece of
  [ROADMAP.md](docs/ROADMAP.md) step 18 ("Access") — Shepherd can now do what a separate reverse-proxy
  manager does: own an HTTPS listener, terminate TLS for every configured hostname, and forward each
  request by its `Host` header to that host's `http://` or `https://` backend, path, query, body and
  headers untouched, with `X-Forwarded-For`/`X-Real-IP` set to the client's own address (set, never
  appended to a client-supplied chain: this is the edge), `X-Forwarded-Proto`/`X-Forwarded-Host`, and the
  public `Host` passed through the way such managers do. A name with no enabled host gets a plain 404 from
  the proxy itself, never the portal; a host pointed back at the proxy is answered 508 instead of looping.
  Forwarding is `httputil.ReverseProxy`, and **WebSocket upgrades are proven end to end, not assumed**:
  `internal/reverseproxy/websocket_test.go` hand-rolls RFC 6455 on both sides with only the standard
  library (zero new module dependencies) — a hijacking backend that pushes a message first and echoes, and
  a raw TLS client negotiating `http/1.1` like a browser — and checks the 101 handshake, the unprompted
  backend-to-client frame, echoes, a 70 KB frame each way and the close handshake, for both `http` and
  `https` backends; `cmd/shepherd`'s tests repeat it through the real listener started by `run()`.
  **One wildcard certificate** (`*.<domain>`) covers every host, issued over the same Cloudflare DNS-01
  flow as `[tls]` (now shared as `startCertManager`; `[tls]` behaves exactly as before) but kept in its
  own `<data_dir>/reverseproxy/tls/`; `tlscert.Obtainer` was already wildcard-capable and a test now
  proves the CSR and challenge naming. The same order also asks for the bare base domain itself
  (`Obtainer.ExtraHostnames`, a general "more names on the same certificate" seam): a pure wildcard never
  covers `example.com` on its own, only `*.example.com`, which the first live cutover hit directly (a
  host at the bare apex domain). A plain-HTTP listener (`redirect_listen`, off by default like `listen`
  itself never defaulting to `:443` — binding a port below 1024 needs a capability a fresh install does
  not have) answers every request with a 302 to the same host and path over https when set (e.g. `:80`),
  so a bookmarked or hardcoded `http://` link still gets there instead of failing to connect once
  nothing else owns port 80.
  Backend certificates are verified by default, with an explicit
  per-host "accept any backend certificate" switch for self-signed backends (a typical manager never
  verified them at all). Hosts live in `<data_dir>/reverseproxy.json` (0600), managed only from the
  portal — never seeded from `shepherd.toml`, nothing written until the first edit, editable while the
  listener is off so everything can be lined up first — over `GET/POST /api/reverseproxy/hosts`,
  `PUT/DELETE /api/reverseproxy/hosts/{id}` and `GET /api/reverseproxy` (listener and certificate state),
  and a new **Proxy** tab (`js/reverseproxyview.js`, pure logic in `js/reverseproxy.js` with its own
  tests) that badges any name the wildcard cannot cover and any backend left unverified. New config:
  `[reverseproxy]`'s `enabled` (**false by default**), `listen` (`:8443` by default, never 443: moving
  the standard port over is the owner's deliberate cutover), `domain`, `email` and
  `cloudflare_api_token`/`cloudflare_api_token_file` (same rules as `[tls]`), and `redirect_listen`
  (empty/off by default). A taken listen port (either one) stops startup with a clear error; obtaining the
  certificate never blocks it. Not yet: per-host access control of any kind, custom per-host config, an
  access log, or import from an existing manager — a straight migration can lose per-host features a
  manager had. Every automated test runs against fakes and loopback, but this has also now been run for
  real: a real wildcard certificate issued against a live Cloudflare zone, a dozen real services imported
  from an existing reverse-proxy manager and verified one by one (including a real WebSocket handshake
  against a live backend), and a real cutover of port 443 itself. See docs/REVERSEPROXY.md, including its
  "Before you point real traffic at this" checklist.
- **Marketing site (`site/`):** a public, vanilla-HTML/CSS/JS landing page — hero, the real shipped feature
  set (DNS filtering and the 95-list catalog, devices, the globe HUD, alarms, port and vulnerability
  scanning, geo-block, portal locking, self-healing upstreams and more), an honest "what's coming" section
  that calls out Watch mode's current trial-only state by name, and a Raspberry Pi section. The
  centerpiece is `site/demo/`: the portal's real compiled frontend (`internal/portal/web/`), forced
  permanently into its own built-in demo mode for a static host with zero backend — the real globe HUD and
  Devices/Blocking/Alarms screens, populated with synthetic data generated in the browser, not screenshots
  or a video. `site/demo/js/demomgmt.js` additionally gives the Alarms screen synthetic data (the shipped
  demo fake never covered `/api/alarms`; alarmsview.js already shows a clean "not available" card for that
  case, so this is additive, local to the site build, and does not touch
  `internal/portal/web/js/demomgmt.js`, the file `cmd/shepherd` actually embeds). Mirrored to
  `blaineam.github.io/apps/shepherd/` by the portfolio repo's `mirror-app-docs.yml`.
  New `.github/workflows/notify-portfolio.yml`, modeled on Haven's, dispatches that mirror on every push to
  `site/**` (needs a `PORTFOLIO_DISPATCH_TOKEN` repo secret to actually fire; skips cleanly without one, same
  as Haven's).
- **Alarm archiving:** the Alarms view had no way to dismiss a handled alarm from the default list short
  of resolving it (which means "this is fixed," a different claim) or waiting for retention's age/count
  pruning to remove it outright. A new `Archived bool`/`ArchivedAt time.Time` on `alarms.Alarm`,
  independent of `State` (an alarm in any state, including New, can be archived without claiming anything
  was fixed), plumbed through as one more `Filter` dimension (`IncludeArchived`, excluded by default the
  same way storm-bundle members need `IncludeChildren`) and two new batch verbs, `Engine.Archive`/
  `Unarchive`, following the exact `selectLocked`/mutate/`emitBatch`/undo-handle pattern every other batch
  verb already uses. An escalating repeat (a dedupe fold with a higher severity) clears `Archived`, since a
  bigger version of a dismissed problem deserves to resurface. `GET /api/alarms` gets `include_archived`
  (off by default — the default view is actually quieter now, not just capable of being asked to be);
  `POST /api/alarms/bulk` gets `op: "archive"|"unarchive"` (a single alarm archives through this too,
  `{"ids":["id"],"op":"archive"}`, rather than a dedicated route); `GET /api/alarms/summary` excludes
  archived alarms from every count. The Alarms tab gets a "Show archived" toggle, a bulk Archive/Unarchive
  button, and a per-row archive action next to acknowledge/resolve/mute/delete. See docs/ALARMS.md
  ("Archiving") for the Option A vs. Option B design reasoning.
- **Real TLS for the portal (`[tls]`, `internal/tlscert`):** the first, additive step of
  [ROADMAP.md](docs/ROADMAP.md) step 18 ("Access") — the portal can now get a real Let's Encrypt
  certificate for its own hostname, issued over ACME's DNS-01 challenge against Cloudflare DNS, the
  same mechanism the maintainer's existing reverse-proxy manager already uses for other services on
  the same Cloudflare zone. The ACME protocol itself (nonces, account keys, order/challenge polling,
  certificate parsing) is handled by `golang.org/x/crypto/acme` — already a transitive part of this
  project's existing `golang.org/x/crypto` dependency, so this adds zero new module dependencies
  (see docs/TLS.md for why that was chosen over `go-acme/lego`). `internal/tlscert` supplies the one
  piece that library does not (creating/removing the DNS-01 challenge's TXT record through
  Cloudflare's API, `CloudflareProvider`) plus the scheduling, persistence and hot-swap wiring:
  `Manager` renews 30 days before the certificate's real 90-day expiry, checking every 12 hours
  without ever touching the network while the current certificate is still comfortably valid, and
  never blocks `cmd/shepherd`'s startup — the same "never block on something outside Shepherd's
  control" convention `startARP` and `startGeoBlock` already follow. Wired into `cmd/shepherd`
  (`cmd/shepherd/tls.go`'s `startTLS`) as a second, additive HTTPS listener (`tls.listen`) alongside
  the existing plain-HTTP one on `portal.listen`, which is completely unchanged; `[tls].enabled =
  false` (the default) leaves Shepherd behaving exactly as it did before this landed. New config:
  `[tls]`'s `enabled`, `hostname`, `listen`, `email`, and `cloudflare_api_token` /
  `cloudflare_api_token_file` (mutually exclusive, following `[accountability.smtp]`'s own
  `password`/`password_file` convention exactly). The certificate, its key, and the ACME account key
  are persisted under `<data_dir>/tls/`, mode 0600 like every other secret this project persists.
  Every test (`internal/tlscert`'s own, and `cmd/shepherd`'s wiring tests, including an end-to-end
  test that makes a real HTTPS request against the running portal) runs against fakes — a fake
  Cloudflare API and a fake ACME client implementing the exact interface `*acme.Client` does — never
  a real network call to Cloudflare or Let's Encrypt, staging or otherwise. See docs/TLS.md,
  including the honest note on what a real live first issuance (a real Cloudflare account and
  token, done separately and deliberately) would still need to confirm.
- [docs/WATCH-MODE-COMPARISON.md](docs/WATCH-MODE-COMPARISON.md): a row-by-row, honest comparison of
  what the DNS-only baseline already covers versus what Watch mode (one-sided ARP interception, still
  a hand-run trial library, not wired into `cmd/shepherd` or the portal) would add once it ships —
  written for the maintainer to point to when deciding how to present the two, not aspirational copy.
- **Portal UX overhaul: a dedicated Vulnerabilities page, mobile reflow, and several maintainer-reported
  rough edges.** `internal/vulnscan`'s full API had no page of its own, only a panel inside each device's
  drawer; a new Vulnerabilities tab (`internal/portal/web/js/vulnscanview.js`) lists every finding across
  every scanned device, worst severity first, filterable, with a "Scan all" action, and clicking a row
  opens that device's drawer rather than duplicating the finding detail a second time — the drawer panel
  stays as the quick per-device summary. The Devices screen gained a "Needs attention" panel above the
  main list (`internal/portal/web/js/attention.js`): newly quarantined, wandering and excluded devices
  pulled to the top instead of mixed into 91 otherwise near-identical rows. Mobile: the Alarms table (a
  fixed 7-column grid with a >700px minimum width) now reflows into stacked cards below 760px, the same
  technique Devices and History already used; the HUD's Legend panel no longer force-displays on mobile,
  only behind a small "i" toggle; the top nav collapses behind a hamburger button into a vertical dropdown
  once its tabs stop fitting in one row; pinch-to-zoom is pinned off and every text input kept at an
  effective 16px so iOS Safari never force-zooms on focus; a duplicate "Wandering" badge next to a
  device's name in the Devices list was removed (the Mode column's own badge, which carries the
  countdown, already said it). The HUD inspector now shows "Blocked by" for a blocked query
  (`dnsengine.Entry.Reason`), and a blocked History row offers a one-click, domain-specific "Allow"
  (`POST /api/rules`, the same mechanism the HUD inspector's own block/allow buttons use). The Details
  view now states plainly that Watch mode is a planned feature, not available in this build yet, instead
  of leaving its absence to read as a bug (confirmed unwired: `cmd/shepherd` never imports
  `internal/intercept`; see docs/ROADMAP.md step 11). See docs/PORTAL.md, docs/VULNSCAN.md,
  docs/DEVICES.md and docs/HISTORY.md.
- **WAN exposure for open ports (`internal/upnpigd`):** `internal/portscan` now tells you not just that a
  port is open on the LAN, but whether your router also forwards it from the internet — the far more
  dangerous case for the same open port. A new, read-only UPnP IGD client discovers the router over SSDP,
  finds its WANIPConnection/WANPPPConnection control URL, and enumerates its NAT port-mapping table (never
  calling AddPortMapping or DeletePortMapping), cached for 10 minutes by default so a slower, more fragile
  router round trip never runs on every scan. Every open `PortRecord` gains `Exposure`: `"lan_only"`,
  `"wan_forwarded"` or `"unknown"` — `"unknown"`, never a guess, whenever the router does not cooperate
  (UPnP IGD disabled, or not implemented the same way by some consumer mesh systems), and the field is left
  out entirely when the new `[portscan.wan_exposure]` config is disabled. Enabled by default, alongside
  `[portscan]` itself (see docs/PORTSCAN.md's "Should this be on by default?" for the reasoning). The
  portal's `GET /api/portscan*` endpoints and each device's Ports panel now surface it, with a small "WAN"
  badge on a forwarded port's chip. See docs/PORTSCAN.md's new "WAN exposure" section for the full
  limits — in particular, that this is best-effort and will read `unknown` for every port on any router
  that does not answer UPnP IGD discovery at all.
- **Network health history (`internal/nethealth`):** latency, jitter, packet loss and reachability,
  probed every 2 minutes once enabled against the configured DNS upstreams plus `1.1.1.1`/`8.8.8.8`, and an
  occasional, tightly bounded bufferbloat check (idle vs. loaded latency against a bounded download
  burst). Both the probe and bufferbloat default **off** — unlike `[portscan]`/`[vulnscan]`, which only
  ever contact devices already on your own LAN, this probes fixed public internet addresses on a timer,
  which is a real behavioral difference worth an owner's explicit opt-in rather than inheriting
  portscan/vulnscan's default-on reasoning (see docs/NETHEALTH.md for the full reasoning, including a
  concrete hermetic-testing problem the default-on version of this caused in this project's own test
  suite before the default was flipped). Unlike `internal/portscan`/`internal/vulnscan`'s
  gentle, mostly-stateless checks, this keeps real history: raw samples for 3 days, hourly rollups for 60
  days, daily rollups indefinitely (capped at 8 MiB), so months of trend data stay available without disk
  usage growing without bound. Latency is timed as a plain, unprivileged TCP connect to port 53 rather
  than an ICMP raw socket (no `CAP_NET_RAW`, fully unit-testable with an injected dial function, the same
  seam `internal/portscan.Scanner` uses) — see docs/NETHEALTH.md for the full reasoning. A new
  `alarms.TypeNetworkDegraded` alarm raises after 3 consecutive bad probe cycles (not a single blip — the
  same "don't cry wolf" discipline `wireUpstreamAlarms` already applies to upstream DNS health) and
  resolves on the next healthy sample. Wired into `cmd/shepherd` (`[nethealth]`, both off by default) and
  the portal (`GET /api/nethealth`, `GET /api/nethealth/series`,
  `GET /api/nethealth/bufferbloat`, `POST /api/nethealth/probe`, `POST /api/nethealth/bufferbloat/run`),
  with a new top-level Network tab (current status plus latency/jitter/loss time-series charts). The
  default gateway is added to the probe targets automatically when it can be determined (reusing
  `internal/arp`'s `/proc/net/route` helper). Traceroute is deferred, for the same reason
  `internal/portscan` deferred router port-forwarding discovery: it needs real router/path verification
  this project's test environment cannot provide. See docs/NETHEALTH.md's "What is verified, and what is
  not" section for exactly what was and was not checked against a real network.
- **Vulnerability scanning (`internal/vulnscan`):** a real vulnerability-detection layer on top of
  `internal/portscan`'s open-port findings — not "port 23 is open" but "Telnet is open" or "this OpenSSH
  build is missing a specific named fix." A small, curated, built-in signature table (no external CVE API,
  matching this project's no-paid-API convention) covers SSH protocol 1 and outdated OpenSSH, unencrypted/
  anonymous FTP and the vsftpd 2.3.4 backdoor, outdated Apache/nginx/lighttpd banners, an unauthenticated
  Docker API and SMBv1 still being enabled. Every signature needs a gentle, protocol-appropriate probe to
  actually confirm exposure (a banner read, one HTTP request, one well-known anonymous FTP login, one raw
  SMBv1 negotiate packet) through the same injectable-dial-function seam `internal/portscan.Scanner`
  already uses, so tests touch zero real sockets. Wired into `cmd/shepherd` (`[vulnscan]`, enabled by
  default, needs `[portscan]` enabled too — see docs/VULNSCAN.md for why), a new `alarms.TypeVulnerabilityFound`
  alarm type (raised once per newly-found vulnerability per device, never suppressed by learning mode —
  this feature's whole point is telling the owner about exposure found on day one; a finding that clears
  resolves the alarm rather than leaving it to linger), and the portal (`GET /api/vulnscan`, `GET
  /api/vulnscan/devices[/{id}]`, `POST /api/vulnscan/scan`), with a Vulnerabilities panel in each device's
  drawer (reusing the Ports panel's layout and a scan-now button) showing active findings with a severity
  badge, description and evidence, plus a collapsed "N resolved" history. See docs/VULNSCAN.md.
- **`internal/vulnscan`: TLS probing and a UPnP-exposure signature, six new signatures in all.** A real
  TLS handshake (over an injectable `TLSConnectFunc` seam, the TLS analog of `DialFunc`, so tests still
  touch zero real sockets or certificates) now runs against 443, 8443, 465, 993, 995 and 2376 — offering
  every protocol version down to TLS 1.0 and every cipher suite Go's own `crypto/tls` implements,
  including the ones its standard library marks insecure, so a weak server reveals itself by what it
  actually negotiates. New signatures: `tls-weak-protocol` (TLS 1.0/1.1 negotiated), `tls-weak-cipher-
  suite` (RC4, 3DES, or a padding-oracle-prone CBC suite negotiated), `tls-cert-expired` and `tls-cert-
  not-yet-valid` (the certificate's own dates, nothing else), and `docker-tls-unauthenticated-api` (2375's
  own check, now also over Docker's TLS port). Certificate verification itself is skipped on purpose
  (`InsecureSkipVerify`): a self-signed or hostname-mismatched certificate is routine on a home LAN and
  deliberately never a finding — only a certificate's dates are judged. 443 and 8443 additionally get the
  same plaintext-shaped HTTP probe as the other HTTP ports, now over the decrypted channel, so the
  existing Apache/nginx/lighttpd signatures (and the new `upnp-exposed` one, below) fire over HTTPS too
  with no new signature code. Also new: `upnp-exposed` (medium) flags a `Server:` header naming UPnP on
  any HTTP port already probed — a deliberately narrow, banner-only check, not SSDP/IGD discovery (a
  separate, lower-level feature). Along the way, 465/993/995 were reclassified from `bannerPorts` (reading
  a plaintext greeting) to the new TLS path, fixing a latent, harmless-but-wrong read of raw TLS handshake
  bytes as a banner on those three implicit-TLS ports. Threat feeds (roadmap step 23) stay explicitly out
  of scope — a different, larger feature that needs to hook into traffic observation, not a per-port
  probe. See docs/VULNSCAN.md for the full signature table and the self-signed/hostname-mismatch judgment
  call.
- **Import wired into the portal:** the Devices screen's new "Import" modal drives `internal/importers`
  end to end — CSV upload or eero login (phone/email, then the code eero sends, then a network), a
  dry-run preview of what would be created or changed, and an apply step, matching the Devices tab's
  look. New endpoints under `/api/import/eero/{start,verify,preview,apply,cancel}` and
  `/api/import/csv/{preview,apply}`. The multi-step eero login needs a session between requests; it is
  kept server-side, in memory only, under a random `session_id` the browser holds instead of eero's own
  token, and is discarded on apply, on cancel, or automatically 15 minutes after it was last touched —
  it is never written to disk. See docs/IMPORT.md.
- **ARP monitoring wired into `cmd/shepherd`:** new `[arp]` config section (`enabled`, `interface`, auto-detected from the default route when empty); `cmd/shepherd/arp.go`'s `startARP` opens the real Linux socket, runs the monitor for the life of the process, and feeds the device registry, the same lifecycle as the classifier and device sources. `arp.Event`s go through a plain `func(arp.Event)` callback that, for now, just logs each one — nothing downstream consumes them yet (an alarm engine wiring will supply a real callback later). ARP monitoring never blocks startup: off by default, on the wrong platform, or without `CAP_NET_RAW`, it logs a clear warning and Shepherd starts normally. `GET /api/arp/stats` exposes the monitor's counters (`{"enabled":false}` when it is not running). See docs/ARP.md.
- [docs/RASPBERRY-PI.md](docs/RASPBERRY-PI.md): Shepherd already cross-compiles to `linux/arm64` in CI, so a Raspberry Pi 3 or newer (or similar cheap ARM64 hardware) is a real, documented place to run DNS-only protection and the passive ARP monitor today, with an honest note that Watch mode's software relay needs more headroom than the baseline does.
- **Alarms wired into `cmd/shepherd` and the portal:** the alarm engine (previously a library only) now
  runs for real. `[alarms]` config (`shepherd.example.toml`) turns it on and configures ntfy, the one
  delivery channel wired in (`[alarms.ntfy]`: server, topic, token or basic auth). A new, minimal
  `dnsengine.Pool.OnHealthChange` hook, in the same plain-callback style as `Engine.Observe`, raises
  `upstream-down` when every configured upstream has gone unhealthy (a true total outage, not one flaky
  resolver) and `upstream-recovered` per resolver as it comes back. Portal API under `/api/alarms`: list
  with filters, get one, acknowledge/resolve/delete (single and batch via a `Selector`), mute (single
  snooze or batch by alarm/type/device/domain/key), undo, a summary and mute-rule CRUD. A new Alarms tab
  matches the Devices tab's structure: severity/state filters, search, single and bulk actions with a
  bulkbar and undo toasts, and a Rules sub-view. **Web Push is explicitly deferred, not forgotten:** it
  needs a secure context (HTTPS), which the portal does not have yet; wiring it up today would be
  unreachable code. See docs/ALARMS.md ("Wiring into `cmd/shepherd` and the portal", "Not built yet").
- **Ports and exposure (`internal/portscan`):** scheduled, gentle TCP connect scans of every known device's
  common ports (roughly 40, chosen for home-network relevance, not completeness), with per-port history
  (open/closed, first/last seen), flags for a newly-opened port and for a short built-in list of
  specifically risky ports (Telnet, RDP, SMB, VNC, rpcbind, NetBIOS, unauthenticated Docker, PPTP, FTP)
  whenever they are found open at all. Plain connect scans only — no OS/service fingerprinting, no UDP, no
  stealth scan types — with bounded concurrency and a short per-connection timeout, fully unit-testable
  through an injectable dial function with zero real sockets in tests. Wired into `cmd/shepherd`
  (`[portscan]`, enabled by default — see docs/PORTSCAN.md for why) and the portal (`GET /api/portscan`,
  `GET /api/portscan/devices[/{id}]`, `POST /api/portscan/scan` for a manual scan of one or every device),
  with a Ports panel in each device's drawer showing its open ports, risky and newly-opened flags, last
  scan time and a "Scan now" button. Router port-forwarding discovery (what the internet can reach) is
  explicitly not built: there is no reliable, generic router API for it.
- **Allowlist mode and scheduled access (`internal/dnsengine`, `internal/portal`):** two additions to the policy engine, built together since they touch the same evaluation path. Every scope (network, group or device) now has a **Mode**, `"block"` (the existing, unchanged default) or `"allow"`; effective Mode resolves the same most-specific-wins way as everything else (device, else group, else network). In allow mode, a scope's switched-on catalog or custom item is its allowlist instead of its blocklist — the same picker, just inverted — and a name nothing decides is blocked by default instead of allowed; built-in policy switches always block in both modes, and there are deliberately no automatic infrastructure exceptions (NTP, OS checks, captive portal), so switching to allow mode can break basic device functionality until you explicitly allow what it needs. The existing block-vs-allow precedence (an allow at the same or a more specific scope beats a block from a less specific one; a block at a more specific scope beats an allow from a less specific one) is unchanged and reused exactly for allow mode, not reinvented. Separately, any allow or block rule can now carry an optional **schedule** (days of week plus a start/end minute-of-day, server-local time, no midnight-spanning in v1 — use two schedules) that makes the rule apply only inside that window; outside it the rule is inert, as if unconfigured, and evaluation falls through normally. `POST /api/policy/mode` sets or clears a scope's Mode; `POST /api/policy/rules` takes an optional `schedule`; `GET /api/policy` reports both per scope. The Blocking screen gains a Blocklist/Allowlist segmented toggle at the scope selector and a day-of-week/time schedule picker on the rule-add form, with a schedule badge on existing rules; the demo-data mock API supports both. See docs/POLICY.md's "Allowlist mode" and "Scheduled access".
- **Portal locking:** the portal shows synthetic demo data by default until it is unlocked with the token or a PIN, reusing the existing `?demo=1` code path for the locked view itself. Signing in creates a random, in-memory, server-side session (`shepherd_session`, `HttpOnly`/`SameSite=Strict`, never carrying the token); it idle-locks after `portal.idle_lock_minutes` (default 10, 0 = never) of real activity — the frontend's own background status/query polling and the live stream deliberately do not count as activity, or idle locking would never trigger while a tab merely sat open — and never outlives 30 days or a server restart regardless. A PIN, set from the new **Locking** settings screen after the first token unlock, only works paired with a random per-browser trusted-device cookie (up to 20 registered at once); PINs are 6-12 letters/digits, rejecting obvious ones, hashed with Argon2id at the same cost `internal/history` already uses for passphrases; 5 wrong attempts in a row lock a browser out for 15 minutes with growing delays, and attempts during the lockout still count toward an outright revoke at 10. The Locking screen lists and revokes trusted browsers and sets the idle timeout or turns it off; rotating the portal token (detected by its hash no longer matching across a restart) wipes the PIN and every trusted browser. Passkeys (WebAuthn) are designed for but explicitly not built here — they need HTTPS, which the portal does not have yet (a separate roadmap item) — see docs/LOCKING.md.
- **Country blocking (geo-block):** a Firewalla-style, per-scope (network, group or device) list of ISO country codes whose DNS answers get blocked, built as an additive check layered outside the Filter's own rule evaluation — it runs only after a query would otherwise be allowed, reusing the engine's already-geolocated answer destinations and the existing sinkhole/`block_mode` mechanism, the same hook shape Apple Private Relay blocking and the classifier's `Observe` already use (`Engine.CountryBlock`). State persists to its own `geoblock.json`, separate from `policy.json`. Depends on `[map]`'s GeoIP database; degrades silently (never blocks, never errors, logs once) when the map is off or not loaded yet. Blocked queries show `reason: "geo"` and `geo_country` in the live stream and history. Portal API (`GET`/`POST /api/geoblock`) and a Countries tab on the Blocking screen's existing scope picker. See docs/GEOBLOCK.md for the honest DNS-answer-only limitation (same caveat the rest of the DNS-based filtering carries).
- **`cmd/intercept-trial`:** a standalone, Linux-only, hand-run CLI for a one-off controlled trial of Watch mode's ARP interception engine against exactly one named device, for a mandatory, capped trial duration, with Ctrl-C wired to a panic stop; disables GRO on the interface for the trial and always restores it on exit (a GRO-coalesced frame can be larger than the wire allows, which the health loop correctly fails open on but which is a capture artifact, not a real fault), needing `CAP_NET_ADMIN` alongside `CAP_NET_RAW`. Not part of `cmd/shepherd`; not run automatically. Run clean against a disposable VM and, with the maintainer's explicit go-ahead, against the maintainer's own phone (confirming the maintainer's eero 7 Max accepts one-sided ARP steering). See docs/INTERCEPT.md.
- **`Controller.ParallelRelay` and `NewRelay` (`internal/intercept`):** a real, measured throughput problem — a single capture-and-relay goroutine cut a steered device's throughput to roughly a third in a live test — addressed by splitting capture across several `PACKET_FANOUT` workers (`OpenMany` for independent per-worker senders, `NewRelay` for additional `Relay`s sharing one `Controller`'s state), each on its own goroutine. `cmd/intercept-trial` uses it by default (`-workers`). See docs/INTERCEPT.md's "Throughput" section — this alone did not fix the slowdown.
- **`rawSender`'s kernel-level `SO_SNDTIMEO` and the `selfBounded` fast path (`internal/intercept`):** the real packet-rate cost turned out to be `sendWithTimeout`'s per-packet goroutine and `time.After` timer, there to bound a `Sender.Send` that might hang — unnecessary once the real socket enforces its own send timeout at the kernel level. `sendWithTimeout` now skips its defensive wrapper entirely for a Sender that reports itself `selfBounded`, taking a direct call (still panic-recovered) instead; `FakeSender` does not report it, so every existing wedged/panicking-Sender safety test is unchanged. Root cause found by live-testing each hypothesis in turn (parallelism, GRO, then this) rather than assuming the first one. See docs/INTERCEPT.md.
- **Accountability-partner email alerts:** `internal/accountability` lets someone invite a trusted contact to be emailed when a device in a group they chose accesses a category they chose — a self-hosted, free equivalent of Covenant Eyes or Accountable2You, built for someone who wants this visibility shared with a person they trust. Summary detail (no domain names) and digest delivery (daily by default) are the defaults; detailed and immediate are opt-in, and even immediate mode coalesces a burst into one email. Matching is decoupled from blocking: an "any" trigger (the default) is disclosure, not enforcement, so an access that was never blocked is reported neutrally, not as a violation. Contacts and subscriptions persist as atomic JSON (mode 0600); email is composed from two reviewable `text/template` strings and sent through a minimal, standard-library-only SMTP client (STARTTLS/implicit TLS, bring-your-own relay, no paid API) with classified send outcomes. Now wired up end to end: `dnsengine.Engine.OnAccess` fires for every completed query, blocked or allowed, that matches a watched catalog or custom list item (unlike `Observe`, which exists for the automatic classifier and skips blocked queries on purpose); `cmd/shepherd`'s `startAccountability` resolves each access's device and groups from the device registry and feeds `Engine.Record` through a small worker queue so a subscriber's digest write never holds up a DNS response; a new `[accountability]` / `[accountability.smtp]` config section (enabled by default, inert until an SMTP relay is actually configured, with a `password` or `password_file` choice for the SMTP secret); and a portal `/api/accountability/...` API plus an Accountability screen for managing contacts and subscriptions (scope, watched items, detail, mode, trigger). See docs/ACCOUNTABILITY.md, which no longer lists any of this as future work.
- **`PACKET_IGNORE_OUTGOING` on every capture socket, `Controller.Stats()`, and a `rate:` log line in `cmd/intercept-trial` (`internal/intercept`):** a code audit of the capture/relay/spoof path, prompted by a live packet capture showing an unexplained retransmission storm, found no frame duplication anywhere in this package (`Relay.HandleFrame`'s destination-MAC filter is correct in every case checked) but did find a real, avoidable cost: without `PACKET_IGNORE_OUTGOING`, the non-promiscuous capture socket also receives a loopback copy of every frame Shepherd itself just transmitted, which is then parsed and discarded — a second parse-and-discard for every relayed frame, at the same hot path already under suspicion. Capture sockets now set it (Linux 4.20+; ignored, not fatal, on an older kernel). `Controller.Stats()` and the new `SteeredDevice.PacketsRelayed` give `cmd/intercept-trial` enough to log packets/bytes-per-second and the self-capture rate every 2 seconds, so the next live trial does not need a fresh packet capture to see this. **Now measured live** (a 2-minute trial, real phone, real eero, with the maintainer's explicit go-ahead): still 300–400 Mbps while steered, the same range as every earlier measurement — this fix, like the two before it, is real but did not close the gap. The `rate:` line watched live for the first time narrows the search: `relayed` stayed in the single digits through two ~20-second bursts that spiked `examined` to thousands of packets/sec, which rules out the self-capture loopback (already removed by this fix) and weakens the pure ACK-storm theory, pointing instead at the eero's own bridging behavior during the ARP change as the more likely remaining cause. See docs/INTERCEPT.md's "Throughput" section for the full, updated writeup and what to test live next.
- **Device quarantine:** a newly discovered device lands in a reserved Quarantine group automatically and stays there until it is moved to a real group (or explicitly released), so nothing new gets the run of the network before you have looked at it. Quarantine is a group like any other for policy, so its rules are set the same way (Blocking → A group → Quarantine). It cannot be deleted; `devices.quarantine_new_devices = false` turns off automatic assignment. Shepherd cannot stop a quarantined device from reaching other LAN devices directly (that needs your router's guest network); see docs/DEVICES.md.
- **Shepherd core (Wave 2):** one native binary with an embedded DNS filtering resolver and web portal. It cross-compiles, with no CGO, to Linux, macOS and Windows.
- **DNS engine:** blocklists in hosts, plain-domain and adblock formats; allow and block rules that match subdomains, with allow winning over every block source; a TTL cache; UDP and TCP serving with truncation handled correctly; both IPv4 and IPv6 answers.
- **Upstream health:** continuous probing with uncached names, automatic failover, fastest-healthy-first ordering, and TCP and TLS upstreams. Learned from a real outage where an encrypted upstream was reset on the network and stalled all DNS.
- **List guardrails:** a list update is rejected if it is empty, blocks a protected domain, or changes size drastically, and the previous list stays active. Lists are cached so filtering works offline at startup.
- **Apple iCloud Private Relay blocking:** a built-in policy answers NXDOMAIN for the relay hostnames, as Apple documents for networks, switchable from the portal. Relay attempts are logged by device.
- **Portal:** live query list with per-row allow and block, upstream and list health, rules, policy switches, top devices and top blocked domains. Token authentication, strict cookies, a CSRF header on every change, and a strict content security policy.
- **Configuration:** a single TOML file (`shepherd.example.toml`), validated at startup with clear errors.
- **Public-development safety:** `scripts/leakcheck` keeps private addresses, MAC addresses, tailnet names, keys, personal paths and email addresses out of commits and commit messages (git hook and CI), with a private `.leakcheck.local` for your own identifiers.
- **Documentation travels with code:** `scripts/doccheck` fails a commit that changes code without changing docs.
- **Testing:** 97% statement coverage with the race detector, and a coverage floor in CI that only goes up.
- **Releases:** rolling beta builds and tagged stable releases through GitHub Actions, SemVer throughout.
- Wave 1 Docker testbed (AdGuard Home, Tailscale, Uptime Kuma), `shepherd-doctor` preflight (hardened against a real UGOS host) and a guide for migrating an existing Tailscale container.
- Design, roadmap, IPv6/Thread rules, Contributor Covenant code of conduct, security policy, contributing guide and issue templates.
- Icon: the black sheep, reused from the Lamdi app.

- Optional Docker packaging in `deploy/docker/` (Dockerfile and compose file) that runs the same static binary under a restart policy with a read-only filesystem and minimal capabilities, plus docs for supervising Shepherd and cutting over from another resolver.

- **Encrypted history (opt-in):** a searchable record of past queries on disk, sealed with AES-256-GCM in immutable, individually keyed segments with an encrypted index, retention by age and size, tamper detection, and a key file or passphrase (Argon2id) unlock. In-memory only remains the default. See docs/HISTORY.md.
- **Live event stream and history API:** `GET /api/stream` (Server-Sent Events with resume), `GET /api/history`, `POST /api/history/unlock`.
- **Geolocated destinations:** query entries carry the places their answers point to, using a free GeoIP database (DB-IP Lite, CC BY 4.0) downloaded monthly, validated before use and kept if an update fails.
- **Automatic home:** the globe's home point is found from the network's public address with a DNS "who am I" query and placed with the local database; only the place is stored. Choose your own home and it always wins, with reset and re-detect. Turn off with `map.auto_home = false`.
- Settings API (`GET /api/settings`, `POST/DELETE /api/settings/home`, `POST /api/settings/home/detect`).
- `[history]` and `[map]` configuration sections, including a database mirror URL.
- Roadmap and design for the reverse proxy with wildcard certificates and tunnels, port and exposure management, and inbound monitoring and protection.

- **The globe HUD** is the portal's new home view: a dot-matrix 3D globe with traffic arcs from home to every destination, weighted so heavy lanes are visibly thicker and brighter, color coded by allowed, cached, blocked and error, with blocked queries pulsing a shield at home. Click an arc to inspect it and block or allow the domain with undo, filter by device, action or domain, set home by clicking the globe, and replay any retained period with a timeline scrubber and speed control. It runs from the live stream, falls back to polling, works offline (the globe library and land outlines are bundled), respects reduced motion and falls back to the Details view without WebGL. `?demo=1` shows synthetic data with no API calls. The earlier dashboard lives on in the Details tab.
- Front-end unit tests (94, `node --test`), run in CI.
- `docs/PORTAL.md` and `docs/THIRD-PARTY.md`.

- **Blocking policy with a catalog (steps 4 to 6 wired in):** a catalog of 95 lists, apps and categories (Instagram, Discord, YouTube, Steam, Social, Gaming, Adult, Gambling and more) you can switch on for the whole network, a group of devices or one device, plus custom lists from a URL or pasted text. Blocks add up across the scopes that apply to a device; an allow at a more specific scope beats a block from a less specific one. See docs/POLICY.md. Endpoints: `/api/catalog`, `/api/policy` and `/api/policy/items|rules|switches|custom-lists|refresh`.
- **Devices that have names:** a registry of the machines on the network, learned passively from DNS clients, the neighbor table (ARP and NDP), mDNS announcements, reverse DNS (asked of your router) and a built-in MAC vendor table. Display names follow alias, then self-announced name, then reverse DNS, then vendor and type, then the IP address, and appear in the live stream, the query ring and the encrypted history (`device` and `device_id` on every entry). Search with filters (`group:`, `vendor:`, `type:`, `ip:`, `seen:`, `tag:`, `excluded:`, `unnamed:`), groups, bulk edit and merge. Saved to `<data_dir>/devices.json` (0600). New `[devices]` config section; see docs/DEVICES.md. Endpoints: `/api/devices`, `/api/devices/{id}`, `/api/devices/bulk`, `/api/devices/merge`, `/api/groups`.
- **Configurable upstreams:** plain, TCP, DNS over TLS and DNS over HTTPS upstreams (by IP or name), bootstrap resolvers (`dns.bootstrap`), verified presets, test before adding, add, remove and reorder in the portal. Runtime edits persist to `<data_dir>/upstreams.json` and win over `dns.upstreams` once it exists. See docs/UPSTREAMS.md. Endpoints under `/api/upstreams`.
- `/api/status` reports `device_count`, `group_count`, `catalog_count`, `custom_list_count` and `network_item_count`.
- **Excluded devices** are answered without blocking (log reason `excluded`); in Watch mode they will also never be steered through Shepherd.
- Catalog list licenses and data sources in docs/THIRD-PARTY.md.

- **Wandering mode:** a per-device mode that stops all filtering while still watching every request. Optional timer (15 minutes to 30 days, or until turned off) that the DNS engine honours at query time, a `shadow` field recording what filtering would have blocked, `wandering` flags in the stream and history, a `wandering:true` search filter, and a bulk `set_wandering` operation. It is distinct from Excluded, which leaves a device alone.
- **Automatic device classification:** devices are guessed as a phone, camera, TV, speaker and more from their DNS lookups (the strongest signal), MAC vendor, and, when `[map]` is enabled, the networks they talk to (ASN, from a second free DB-IP database downloaded and guarded the same way as the city one). A type you set yourself always wins and is never overwritten. Guesses appear in the existing `type`/`type_reason` fields, plus new `type_auto` and `type_confidence`. New `[classify]` config section. See docs/CLASSIFY.md.
- Passive ARP monitoring (`internal/arp`): a read-only listener that learns real MAC addresses for the device registry and raises events for a new MAC, an IP moving to a different MAC, and a changed gateway MAC (the classic spoofing signature). It never transmits anything. See docs/ARP.md. Deployed in `cmd/shepherd` (above); not yet wired into the alarm engine.
- **Watch mode's ARP interception engine (library, not yet wired up):** `internal/intercept` implements one-sided ARP steering of a chosen device on top of `internal/arp`'s codec — a `Spoofer` that claims the gateway's MAC and reverts on stop, a `Relay` that rewrites and retransmits a steered device's outbound frames, and a `Controller` that is the only thing allowed to start or stop steering: it enforces exclusions (the gateway, an `Excluder`-backed device list) at the call, verifies real relayed traffic on a health loop and fails a device open the instant something looks wrong, supports a trial mode with an automatic revert after a fixed duration, and has a `PanicStop` that unsteers everything immediately even if the sender is wedged. IPv4 only; IPv6 is never touched, proven with a fuzz test. Outbound-direction visibility only — the gateway's own ARP table is never touched, so inbound traffic bypasses Shepherd by design. See docs/INTERCEPT.md. Nothing calls this automatically yet; wiring a trial UI or API, and running it against a real network, needs the maintainer's explicit go-ahead.
- Router importers (`internal/importers`): a one-time, optional import of device names and groups from eero's unofficial API or a generic CSV, with a dry-run preview before anything changes. See docs/IMPORT.md. Not yet wired into the portal.
- Alarm engine (`internal/alarms`) with Web Push (`internal/webpush`) and ntfy (`internal/ntfy`) delivery: severities, dedupe, storm control, mute rules and quiet hours, batch actions, and a digest for low-severity alarms. See docs/ALARMS.md. Not yet wired into Shepherd or the portal.
- Design and roadmap entries for device quarantine (a reserved group new devices land in until moved), portal locking (demo data until unlocked, configurable auto-lock, PIN, passkeys), and running Shepherd as a dual-NIC router someday (a stated, unscheduled future direction).

### Fixed
- Passkeys' `Serves`/`RequestOrigin` checked `r.TLS != nil` to decide whether a request reached the
  portal over HTTPS, which is only ever true when `[tls]`'s own listener terminated the connection
  directly. Reaching the portal through `[reverseproxy]` on the same hostname instead — a real cutover
  hit this directly, right after setting both features up the same night — terminates TLS at the proxy
  and forwards as plain HTTP, so `r.TLS` is nil even though the browser's own connection genuinely was
  HTTPS, and passkeys refused with "this page is http://..." on a page that was, from the browser's own
  address bar, unmistakably `https://`. Fixed by also trusting `X-Forwarded-Proto: https`, which
  `internal/reverseproxy.Proxy` always sets and always overwrites (never passes through from a client) —
  this gate is an availability check, not the actual WebAuthn trust boundary, which the library enforces
  independently against the browser-signed origin regardless of this header. See docs/PASSKEYS.md.
- `internal/intercept.Relay` relayed *every* frame a steered device addressed to Shepherd's own MAC to
  the real gateway, including frames genuinely destined for Shepherd itself (a DNS query to the resolver
  Shepherd runs, a connection to its portal) — because a steered device's ARP entry for the real gateway
  is spoofed to Shepherd's MAC, but its entry for Shepherd's own IP is never touched and already
  correctly resolves to that same MAC, making the two indistinguishable at the Ethernet layer alone. A
  live packet capture confirmed it directly: the same DNS query visible twice, once answered normally by
  Shepherd's own stack, once uselessly re-transmitted to the gateway with a rewritten destination MAC —
  wasted relay-worker capacity on every locally-destined packet, not data loss (Shepherd's own stack
  still answered the original), but a real, avoidable cost under load. Fixed with `Relay.ShepherdIPs`:
  a frame whose IPv4 destination is one of Shepherd's own addresses on the interface is now left
  completely alone instead of relayed. `cmd/intercept-trial` auto-detects these addresses and reports
  how often this was happening via a new `for_shepherd_itself` count in its `rate:` log line. See
  docs/INTERCEPT.md.
- `internal/dnsengine.Engine` wrote every DNS response to the client before recording the matching
  query-log entry, in all four response paths (blocked, geo-blocked, error, allowed/cached). Nothing
  synchronizes "the client's goroutine woke up because it got a UDP packet" with "this goroutine's next
  few lines of Go code have run," so a client (or test) that reacts to its answer immediately can
  observe the log before that entry exists. Caught CI-only (never locally, lower scheduling pressure
  made the window far less likely) as a panic in `TestEngineUsesClientScopes`: `entries[len(entries)-1]`
  on a still-empty log. Fixed by recording the entry before writing the response in every path, so the
  ordering is actually guaranteed rather than merely likely.
- `cmd/shepherd`'s DNS-01 propagation check (`dnsLookupTXT`) used `net.DefaultResolver`, which honors
  the host's own system resolver — and on a typical Shepherd deployment, the host's system resolver
  points at Shepherd itself (that is the point of running it). So the propagation check could end up
  routing its own lookup back through Shepherd's own DNS engine and cache instead of checking what the
  public internet (and so Let's Encrypt) actually sees. A live DNS-01 attempt against a real
  Cloudflare-hosted zone hit this directly: a public resolver had the fresh challenge TXT record within
  seconds while Shepherd's own DNS server never returned it at all, so the propagation check could never
  succeed — the same "a resolver that depends on itself for DNS would deadlock the network" problem
  `internal/dnsengine`'s own bootstrap resolver exists to avoid for `tls://`/`https://` upstream
  hostnames. Fixed by looking the TXT record up directly against `dns.bootstrap`'s plain resolvers over
  UDP, the same way and for the same reason `internal/dnsengine` already resolves upstream hostnames
  without the system resolver.
- `tlscert.DefaultObtainTimeout` (2 minutes) left no real headroom beyond `cmd/shepherd`'s own DNS-01
  propagation-wait timeout (also 2 minutes): both clocks start at nearly the same moment inside one
  `Obtain` call, so once propagation actually finished there was next to no budget left for the
  ACME Accept/WaitAuthorization/WaitOrder/CreateCertFromOrder calls that still had to run, or for
  cleaning up the challenge TXT record afterward. A live DNS-01 attempt against a real Cloudflare zone
  surfaced this directly: the TXT record published and propagated fine, then the obtain failed right
  after with `context deadline exceeded`, and the deferred `CleanUp` failed the same way for the same
  reason. Raised to 5 minutes, giving the propagation wait's own worst case plus real room for
  everything that has to happen after it.
- `Controller`'s trial-expiry watcher (`internal/intercept`) could fire a second, spurious unsteer after
  a device had already been unsteered manually and then re-steered: its goroutine blocks on
  `select { case <-spoofCtx.Done(): ...; case <-trialTimer: ... }`, and Go's `select` does not prefer
  one ready case over another when both are ready at once — a `FakeClock.Advance` landing around the
  same moment a manual `Unsteer` cancelled `spoofCtx` could still pick the `trialTimer` branch, calling
  `unsteer` against whatever now holds that MAC (a legitimate second `Steer` call, since `unsteer`'s own
  presence check has no way to tell the two apart). Caught by `TestTrialCancelledByManualUnsteerDoesNotDoubleFire`
  failing intermittently in CI, never locally (lower scheduling pressure made the race far less likely to
  manifest). Fixed by re-checking `spoofCtx.Done()` with a non-blocking `select` immediately before
  acting on the timer branch, which is safe regardless of which way the outer `select` resolved: once
  cancelled, `spoofCtx.Done()` stays ready, so the re-check is not itself timing-sensitive.
- `scripts/coverage`'s floor check counted `cmd/intercept-trial` against the whole-repo total, but that
  package is a hand-run, Linux-only CLI most of whose logic needs `CAP_NET_RAW`/`CAP_NET_ADMIN` and live
  hardware to exercise — the same reason `internal/intercept`'s own raw-socket code is untestable
  without it. On a non-Linux dev machine the package's Linux-build-tagged files never even compile, so a
  local coverage run never saw this gap; CI's `ubuntu-latest` runner does, and the mismatch (a local
  97.4% against CI's real 95.7%) sat below a floor that had just been raised assuming the two numbers
  agreed. The floor calculation now excludes that one package's statements (its own tests still run,
  same as before); only the floor check ignores them.
- The Accountability screen showed a generic "update the server" message when nothing was
  configured (no SMTP relay set), which reads as broken rather than as a setup step — that copy is
  meant for a genuinely older server missing the API entirely, not a current one where the feature
  exists but isn't configured. The screen now shows the specific reason the server already returns
  (`api_accountability.go`: "accountability is not configured on this server") instead.
- **PIN login only ever worked from one trusted browser at a time.** docs/LOCKING.md has always said the PIN is shared across up to 20 trusted browsers, but the only way a second browser could ever join was by calling the same endpoint that *sets* the PIN (`POST /api/pin`), which always overwrote the shared PIN with whatever was typed — so registering browser #2 silently (and usually accidentally, since the field was just labeled "New PIN") locked out browser #1 and every other already-trusted browser unless the exact same digits were retyped. Split into three real cases: the very first PIN setup (unchanged), joining with an already-set PIN from a new browser (new `POST /api/pin/trust`: verifies the *existing* PIN via the same Argon2id check `loginPIN` uses and registers the browser, without ever touching the stored PIN — a wrong guess gets a flat 400ms delay rather than a per-device lockout, since there is deliberately no trusted-device record yet to hang one on), and changing the PIN for everyone (still `POST /api/pin`, but now refused with `403` from a browser that is not already trusted, instead of silently reinterpreting "change" as "set my own"). `GET /api/settings`'s `locking` object gained `this_device_trusted` so the frontend knows which of the two situations applies. The Locking screen's PIN card now shows "Set PIN", "Trust this browser" (asking for the *existing* PIN, not a new one) or "Change PIN" (now behind a confirmation dialog that spells out the blast radius) depending on which case actually applies, instead of one "Change PIN" button that meant different things depending on whether the browser was already trusted.
- The globe's land dot-matrix (`internal/portal/web/js/topo.js`) showed false rings of "land" dots across open ocean at a few specific latitudes, most visibly a band south of the equator and several near the north pole. Cause: `ringContains`'s ray-casting test read a polygon edge that crosses the antimeridian (raw longitude jumping from near +180 to near -180, as Russia's coastline does) as a huge jump instead of a short hop, misreading it as a crossing for nearly every longitude in that edge's latitude band. `coastSegments` already special-cased this for coastline rendering; the same case was missing from the point-in-polygon test the dot matrix depends on. Fixed by unwrapping a ring's longitudes into one continuous range before testing, trying the candidate point at its own longitude and +-360 of it. The first version of this fix tried all three branches for every ring, wrapping or not, which made the HUD's cold load noticeably slower (`sampleLandPoints` calls this on every candidate point against every nearby polygon); now the extra branches are only tried for a ring that actually needs unwrapping, same as before the fix existed for every other ring.
- CI was failing on every push and nobody had noticed. `TestUnreadableDeviceFileIsMovedAsideNotOverwritten` left a deliberately un-renameable directory behind; `t.TempDir()`'s own cleanup couldn't remove it on Linux, and `cmd/shepherd`'s `run()` starts background goroutines (the list manager, the upstream probe) before `startDevices` even runs, so one of them can still be writing into the data directory, after the deferred `cancel()` fires but before it takes effect, when the test's own cleanup runs — a first fix that cleaned up only the one anticipated path still missed that race. Now the whole data directory is removed, retried briefly to tolerate it.
  `internal/alarms`'s `TestWorkerTickSweepsAndSaves` had two real, unrelated races, not just a slow poll: `Engine.New` started the worker goroutine before that goroutine had necessarily reached its own `clock.NewTicker` call, so a `FakeClock.Advance` immediately after `New` returned could fire before the ticker was even registered, permanently missing the one tick a test relies on rather than merely running it late; and the test's own `afterTick` hook was being assigned directly onto the already-running engine, an unsynchronized write racing the worker's unsynchronized read of the same field. Fixed both structurally: `New` now creates the ticker itself, synchronously, before spawning the worker, and `afterTick` is threaded through `Options` (unexported, so nothing outside this package can set it) and set once before the worker starts. The test no longer needs a generous timeout to paper over either race.
  Two `cmd/shepherd` e2e tests (`TestExcludedDeviceIsNotFiltered`, `TestWanderingDeviceIsWatchedButNotFiltered`) read `/api/queries` immediately after a `resolve()` round trip, with no guarantee the log entry (written after the DNS response, see `dnsengine.Engine.done`) had landed yet; both now poll briefly via the existing `waitUntil` helper instead of assuming it already has.
  `cmd/shepherd/alarms.go`'s `startAlarms` ran the alarm Router's delivery loop (`rt.Run(ctx)`) on `run()`'s own shared `ctx`, with no way for the caller to know it had actually stopped: `run()`'s own defer order closes the alarm engine before that shared `ctx` is cancelled, so waiting on the Router's goroutine there would have deadlocked, and not waiting at all left its final `Router.Save` racing a test's `TempDir` cleanup on early failure (`TestBadHistoryKeyFileStopsStartup`, intermittently, once a real test exercised that path). `startAlarms` now returns a `stop` func that cancels the Router's own independently-cancelable context and waits for its goroutine to exit before closing the engine, so shutdown order no longer matters. The existing `TestStartAlarmsBuildsAWorkingEngine` had already papered over the same race with a hardcoded sleep; it now uses `stop` instead and needs no sleep.
- `POST /api/lists/refresh` started the refresh with the request's context, which ends as soon as the response is written, so a refresh from the portal could be cancelled immediately. It now runs to completion in the background.
- The command tests took about 50 seconds because each test's DNS warm-up query went to an unreachable upstream and shutdown waited for it; they now take a few seconds. Passphrase tests also use a cheap Argon2id cost (production keeps the strong defaults).
- The portal kept polling the API every second while signed out, flooding the console with 401 errors. It now stops until you sign in.
- The example config's blocklist URL returned HTTP 404. It now points at a working list, and a weekly CI job (`scripts/check-list-urls`) fails if any example blocklist URL stops resolving.
- Four `internal/alarms` tests polled a background worker with a 3-second real-wall-clock deadline against a fake-clock-advanced tick; under load (the full suite running concurrently) that was occasionally too tight and failed even though the worker itself was fine (instant in isolation). Widened to 10 seconds.

### Changed
- The optional Docker packaging (`deploy/docker/compose.yaml`) now also grants `NET_RAW`, alongside the existing `NET_BIND_SERVICE`, so the passive ARP monitor (read-only) can actually run in the container; `cap_drop: [ALL]` otherwise, unchanged.
- **Policy lives in `<data_dir>/policy.json`.** On the first start after upgrading, `rules.json` (allow, block, policy switches) and `[[lists]]` are migrated into it with nothing lost and the same blocking; a catalog entry with the same URL replaces the old list, anything else becomes a custom list. An install that already existed does **not** gain the recommended catalog lists; a new install does. After that `rules.json`, `[[lists]]` and `no_default_lists` are no longer read (they only seed a first run) and the portal owns the policy. The old rule, policy and list endpoints now act on the network scope.
- **Protection is on by default; you opt out, not in.** A fresh install now ships with a blocklist and blocks Apple iCloud Private Relay (devices see a notice that it is unavailable on the network). Opt out with `block_private_relay = false` or `no_default_lists = true`, or from the portal. Lists you define always replace the built-in one. Watch mode will follow the same rule (default-on with automatic exclusions and a fail-open watchdog); see the design doc.
- Licensed AGPL-3.0-or-later.
- The in-memory query log now keeps 20,000 entries by default (was 5,000) so replay reaches further back.
- Direction: a native single binary with a Go control plane and a Rust data plane (Wave 6), instead of containers.
- `shepherd.example.toml`'s `[dns].listen` comment now says explicitly that one address per interface can
  be listed at once (a wired LAN address, a separate Wi-Fi NIC's address, a Tailscale address, and so on),
  not just a single choice — a real deployment hit this directly wanting all three reachable together.
