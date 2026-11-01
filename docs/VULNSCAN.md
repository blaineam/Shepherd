# Vulnerability scanning

[Ports and exposure](PORTSCAN.md) tells you *that* a port is open. This feature, `internal/vulnscan`,
tries to tell you *what is actually running on it* and whether that specific thing is a known problem:
not "port 23 is open" but "Telnet is open, and that is a classic IoT-botnet target" or "this is OpenSSH
7.2, missing the fix for a 2018 username-enumeration bug." It schedules its own scan, keeps its own
per-device finding history, and raises alarms the same way every other Shepherd feature does.

## What this is, and what it is not

This is a **much lighter, self-hosted sibling** of what a tool like Nessus or Firewalla does for a home
network — not an enterprise vulnerability scanner, not a penetration-testing tool:

- **A reviewed built-in table, plus a signature feed Shepherd publishes itself.** The built-in list
  (`vulnscan.BuiltinSignatures`) is a small, curated Go table, checked into the repository and reviewed
  like any other code. On top of it, a running Shepherd fetches **one JSON document** — this repository's
  own `feeds/vulnscan.json`, rebuilt daily from the NVD and CISA's Known Exploited Vulnerabilities
  catalog — so a signature for a newly exploited bug reaches every install the same day it is published,
  with no Shepherd release in between. The feed is **data, never code**: a signature can only say "this
  product, in these version ranges" or "this text in a banner", over information the probes below already
  collect. It cannot make Shepherd probe anything new. See "Signature feed" below for exactly how it is
  built and what it covers. This is one more of the few things this project reaches the internet for on
  its own (the others: blocklist downloads and the optional monthly GeoIP database, see
  [DESIGN.md](DESIGN.md)); there is still no paid API anywhere, and `feed_url = ""` turns it off entirely.
- **No authenticated scanning, no credential guessing, no deep protocol fuzzing.** Every signature fires
  on a single, gentle, protocol-appropriate exchange: read a banner, send one minimal HTTP request, try
  exactly one well-known anonymous FTP login, send one SMBv1 negotiate packet. Nothing here tries a list
  of passwords, nothing here sends malformed input to see what breaks.
- **It deepens `internal/portscan`, it does not duplicate it.** This package never decides a port is
  open on its own — it only probes ports `internal/portscan` already found open on a device
  (`TargetsFromPortscan`), so the two features never both open a connection just to answer "is this port
  reachable at all." If portscan is disabled, this feature has nothing to probe and does not start (see
  "Configuration" below).

### What it detects

Two sources, one mechanism. Every built-in signature is in `vulnscan.BuiltinSignatures()`
(`internal/vulnscan/signature.go`), a plain Go slice of `Signature` values (ID, name, severity,
description, which ports it applies to, and a pure `Match` function over already-collected data — no I/O
happens inside `Match` itself). Feed signatures (`internal/vulnscan/feed.go`) are compiled into the very
same `Signature` shape from declarative JSON, and `Scanner.Signatures()` is the merged set a scan actually
evaluates: the built-ins in table order, then the feed's, with a feed signature of the **same ID replacing
the built-in** so the published feed can correct a built-in's version range without a release. The built-in
table as of this writing:

| Signature | Port(s) | Severity | What it needs to see |
|---|---|---|---|
| `telnet-exposed` | 23 | high | the connection succeeds at all |
| `ssh-protocol-1` | 22 | critical | an SSH banner advertising protocol major version 1 |
| `ssh-missing-roaming-fix` | 22 | critical | an OpenSSH banner older than 7.1 (CVE-2016-0777, CVE-2016-0778) |
| `ssh-outdated-openssh` | 22 | high | an OpenSSH banner from 7.1 up to (not including) 7.8 (CVE-2018-15473) |
| `ftp-unencrypted` | 21 | medium | a banner that actually looks like FTP (a "220" greeting) |
| `ftp-anonymous-login` | 21 | high | `USER anonymous` followed by a password ends in a 230 (login accepted) |
| `ftp-vsftpd-234-backdoor` | 21 | critical | a banner naming vsftpd 2.3.4, a tampered, backdoored build (CVE-2011-2523) |
| `apache-path-traversal-2021` | any HTTP port probed | critical | an `Apache/2.4.49` or `Apache/2.4.50` Server header (CVE-2021-41773, CVE-2021-42013) |
| `apache-eol-2.2` | any HTTP port probed | high | an `Apache/2.2.x` Server header (end of life since 2018) |
| `apache-outdated` | any HTTP port probed | low | an `Apache/2.4.x` Server header older than 2.4.49 |
| `nginx-resolver-cve` | any HTTP port probed | medium | an `nginx` Server header older than 1.20.1 (CVE-2021-23017) |
| `lighttpd-outdated` | any HTTP port probed | low | a `lighttpd` Server header older than 1.4.50 (no specific CVE cited — see below) |
| `docker-unauthenticated-api` | 2375 | critical | an unauthenticated `GET /version` answers with Docker's own API shape |
| `docker-tls-unauthenticated-api` | 2376 | critical | the same, over TLS — the handshake completes with no client certificate, then `GET /version` still answers |
| `smb1-enabled` | 445 | critical | a raw SMBv1 Negotiate Protocol request gets an SMBv1 reply that *selects* the offered dialect (a reply with DialectIndex `0xFFFF`, which is how a server with SMBv1 disabled refuses, does not count) |
| `tls-weak-protocol` | 443, 8443, 465, 993, 995, 2376 | high | a TLS handshake offering down to TLS 1.0 actually negotiates TLS 1.0 or 1.1 |
| `tls-weak-cipher-suite` | 443, 8443, 465, 993, 995, 2376 | high | the negotiated cipher suite is one Go's own standard library documents as insecure (RC4, 3DES, or a CBC-mode suite with a padding-oracle weakness) |
| `tls-cert-expired` | 443, 8443, 465, 993, 995, 2376 | medium | the presented certificate's `NotAfter` is in the past |
| `tls-cert-not-yet-valid` | 443, 8443, 465, 993, 995, 2376 | low | the presented certificate's `NotBefore` is in the future |
| `upnp-exposed` | any HTTP port probed | medium | the HTTP `Server:` header contains "UPnP" |

"Any HTTP port probed" means 80, 3000, 5000, 8000, 8080 and 8888 over plain HTTP, plus 443 and 8443 over
TLS (see "How a scan works" below) — the Apache/nginx/lighttpd and `upnp-exposed` signatures all key off
the `Server:` header itself, not the port it arrived on, so they fire identically either way.

Every one of these needs a **positive, confirmed signal** before it fires. A port that is open but gives
no useful banner, a connection that is refused, or a read that times out, produces no finding at all —
"could not learn anything" is handled by learning nothing, never by guessing.

### Not detected (on purpose, and why)

Being honest about the gap matters more here than anywhere else in Shepherd, because this feature's whole
job is telling you about exposure — a false sense of "nothing was found, so it's fine" would be worse than
not having the feature:

- **Only the products Shepherd can fingerprint, and only what the NVD files under them.** The feed
  covers exactly the fourteen products a banner or `Server:` header names with a version (see "Signature
  feed"); a device whose service hides its version, or runs anything else, gets nothing from the feed. A
  distribution that backports a fix without bumping the version string (Debian's OpenSSH, Ubuntu's
  Apache) will match a range it has actually patched — the aggregate signatures say so in their text, and
  the CVE identifiers in the evidence are there precisely so you can check what your vendor shipped.
  There is still no OS-level or authenticated CVE assessment: a device can have real, serious
  vulnerabilities this feature says nothing about.
- **No IP/domain threat-intelligence feeds** (the signature feed above is about software versions, not addresses). A locally bundled list of known-malicious IPs/domains to flag
  against observed traffic is a real, different feature (step 23 on [the roadmap](ROADMAP.md), paired
  with "local AI") — it would need to hook into traffic observation (`internal/dnsengine`/history), not a
  per-port probe, and was out of scope for this pass. Not started, not half-built.
- **No self-signed-certificate or hostname-mismatch findings, by deliberate judgment call.** TLS probing
  (below) inspects every certificate it is handed, but a home LAN device presenting a self-signed
  certificate, or one whose name does not match how you actually reach it (a router at its LAN IP, a
  NAS's mDNS name, a camera's default cert), is the **normal, expected case**, not a sign of anything
  wrong — flagging it on every scan would train people to ignore real findings. This package only judges
  a certificate's actual dates (`tls-cert-expired`, `tls-cert-not-yet-valid`), which are objectively wrong
  regardless of who issued the certificate or what name is on it.
- **No SSLv3 detection.** Go's `crypto/tls` dropped SSLv3 support outright years ago (there is no way to
  even offer it from a Go TLS client), so `tls-weak-protocol` can only ever detect TLS 1.0/1.1 — a real
  gap if a device still answers SSLv3 at all, which would need a different TLS implementation to confirm.
- **TLS probing is limited to six ports.** 443, 8443 (with the same Apache/nginx/lighttpd signatures also
  checked over the decrypted channel), 2376 (Docker's TLS port, checked the same way 2375 is), and the
  three implicit-TLS mail ports (465 SMTPS, 993 IMAPS, 995 POP3S — certificate/protocol/cipher only, no
  mail-protocol-specific signature exists yet). 587 (SMTP submission) is deliberately left as a plaintext
  banner port: its TLS is explicit (STARTTLS, negotiated after a plaintext greeting), which this package
  does not attempt to upgrade into.
- **No UPnP device discovery.** `upnp-exposed` only recognizes a UPnP stack that happens to answer one of
  the plain HTTP ports this package already probes (80, 3000, 5000, 8000, 8080, 8888) with "UPnP" in its
  `Server:` header — the same kind of banner match every other HTTP signature here uses, no new wire
  protocol involved. It is **not** SSDP/IGD discovery (UDP multicast on port 1900, locating a device's
  real control URL, which can be anywhere): that is a separate, lower-level capability a different
  feature (LAN-vs-WAN port-exposure discovery via UPnP IGD queries) owns. A UPnP stack that only answers
  on a port outside the list above, or one whose `Server:` header does not mention UPnP at all, is missed.
- **No generic default-credential detection.** Beyond the one specific, well-documented case that is
  detectable purely from a banner (the vsftpd 2.3.4 backdoor), this does not try to recognize "this banner
  looks like a device with default credentials": that would mean guessing at vendor-specific banners or
  actually trying credentials, both of which this project's no-authenticated-scanning rule rules out.
- **Docker's own unauthenticated `/version` confirms exposure, over plain HTTP and over TLS alike.**
  `internal/portscan` already flags 2375 and 2376 as risky ports purely from being open; this package
  goes one step further for both — 2375 over plain HTTP, 2376 by completing a TLS handshake first (with
  no client certificate offered) and then making the same unauthenticated request over it.
- **Only one OpenSSH version-history signature family.** Non-OpenSSH SSH servers (Dropbear, libssh, ...)
  are not matched against any version-specific signature — only the protocol-version-1 check, which looks
  at the banner's own protocol field rather than a specific vendor's version history, applies to them.
- **`lighttpd-outdated` cites no specific CVE.** Unlike the Apache and nginx signatures, the built-in does
  not assert a specific CVE number for old lighttpd versions, to avoid stating something not actually
  verified; the finding is a generic "this is old, check lighttpd's own release notes" rather than a named
  vulnerability. The feed's `nvd-*-lighttpd` signatures carry the actual CVE identifiers.

## Signature feed

`feeds/vulnscan.json` in this repository is the feed every Shepherd fetches by default
(`[vulnscan].feed_url`, `vulnscan.DefaultFeedURL`: the file on the `main` branch via
`raw.githubusercontent.com`). It is **built by `cmd/vulnfeed`** (`internal/vulnfeed`), which the
`vulnfeed` GitHub Actions workflow runs every day and commits when the data changed, from two public,
keyless sources:

- **The NVD CVE API 2.0**, queried once per product CPE (`cpe:2.3:a:openbsd:openssh`, ...) for every CVE
  filed under it, with its CVSS metrics and its affected-configuration version ranges.
- **CISA's Known Exploited Vulnerabilities (KEV) catalog**, the list of CVEs with confirmed exploitation in
  the wild.

**What gets in.** A CVE becomes part of the feed when it is **in KEV** (whatever its score), or when the
NVD's own CVSS 3.x assessment says it is **reachable over the network with no credentials** and rated
**critical (9.0+)**, or **high (7.0–8.9) with no user interaction either**. Everything else — local bugs,
ones that need an account, medium and low scores, rejected entries, and any entry whose affected
configuration is an unbounded wildcard ("every version ever", which is never what a CVE means) — is left
out on purpose. A home-network scanner that lit up on every medium CVE in an old PHP would train people to
ignore it; the whole point of the thresholds is that a feed finding is worth a look.

**What it produces.** Three kinds of signature:

| ID | One per | Severity | Fires when |
|---|---|---|---|
| `kev-cve-YYYY-NNNN` | KEV CVE | critical | the product's version is in that CVE's affected range; the description is the NVD's text plus the date CISA added it |
| `nvd-critical-<product>` | product | critical | the version is in the affected range of **any** critical, network-exploitable CVE for that product; the evidence names which (`OpenSSH_8.9p1 — CVE-2023-38408, CVE-2024-6387 (2 CVEs)`) |
| `nvd-high-<product>` | product | high | the same for the high tier |

The aggregates exist so an old build produces one row that names its CVEs, not fifty rows. Each version
range inside an aggregate carries the CVE it came from, which is how the evidence can be specific.

**Products.** The feed can only name what `internal/vulnscan` can fingerprint
(`vulnscan.KnownProducts()`, pinned by `internal/vulnfeed`'s own test so the two can never drift): from an
SSH/FTP/SMTP banner — OpenSSH, Dropbear, vsftpd, ProFTPD, Exim; from an HTTP `Server:` header, every
`Product/version` token — Apache httpd, nginx, lighttpd, OpenSSL, PHP, Boa, mini_httpd, GoAhead and
Microsoft IIS (`Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f PHP/7.4.3` yields three fingerprints). A feed that
names a product this build does not know (a newer feed on an older Shepherd) simply has that signature
skipped, counted in the feed status, never an error.

**The format** (`vulnscan.Feed`, schema 1) is deliberately small:

```json
{
  "schema": 1,
  "generated_at": "2026-11-01T05:41:00Z",
  "signatures": [
    {
      "id": "kev-cve-2024-6387", "name": "OpenSSH: CVE-2024-6387 (actively exploited)",
      "severity": "critical", "description": "...", "cves": ["CVE-2024-6387"],
      "match": {"product": "openssh", "versions": [{"gte": "8.5", "lt": "9.8"}]}
    },
    {
      "id": "nvd-high-openssl", "name": "OpenSSL with known high-severity CVEs", "severity": "high",
      "description": "...",
      "match": {"product": "openssl", "versions": [{"lt": "1.1.1l", "cve": "CVE-2021-3711"}, {"gte": "3.0.0", "lt": "3.0.7", "cve": "CVE-2022-3602"}]}
    }
  ]
}
```

A `match` is either `product` + `versions` (ranges with any of `gte`, `gt`, `lte`, `lt`, `eq`; an empty
list means any version of the product) or `contains` (a case-insensitive substring of the banner or
`Server:` header). Versions are dotted numbers; a single trailing letter orders releases
(OpenSSL's `1.1.1f` < `1.1.1l`), any longer suffix (`7.4p1`, `0.94.14rc21`) is ignored. `ParseFeed`
rejects anything else — a wrong schema, a duplicate or missing ID, an unknown severity, a matcher that
says both or neither — and a rejected feed never replaces the one in use.

**How a running Shepherd uses it** (`vulnscan.FeedUpdater`, wired in `cmd/shepherd/vulnscan.go`):

- At start, the last good copy is restored from `<data_dir>/vulnscan-feed.json` (mode 0600), so an install
  with no internet still has its signatures, then the published feed is fetched.
- Every `feed_refresh_seconds` (6 hours by default) it is fetched again — conditionally, with the ETag,
  so an unchanged feed is one small 304 — and a **genuinely new feed re-scans every device right away**
  rather than waiting for the daily scan. That is the point of the feature: a signature published for
  a bug exploited this week is applied within hours, not whenever `interval_seconds` next comes around.
  The cached copy restored at start does not trigger a scan (nothing new was learned).
- A download that fails, or a document that does not parse, is recorded as the feed's `last_error` (the
  portal shows it) and the previous signatures stay in force.
- Feed findings alert exactly like built-in ones (see "Alerting"), with the feed signature's own severity,
  and resolve the same way when a later scan — or a later feed that no longer lists the range — stops
  matching.

**Trust.** The feed is fetched over HTTPS from this repository, it is validated before use, and it can
only ever add or change *recognition* of versions in data the fixed set of probes already collects —
never what is probed, how, or how often. If you would rather not fetch it, `feed_url = ""`; if you want to
pin a copy you reviewed, `feed_url = "file:///path/to/vulnscan.json"` works the same way. The workflow
commits with `[skip ci]`, so a feed refresh never triggers a beta build on its own.

## How a scan works

`internal/vulnscan.Scanner` takes `Target` values — a device ID, an address, and the exact ports
`internal/portscan` found open on it (`TargetsFromPortscan` builds these from
`portscan.Scanner.Results()`) — and, for each port it actually knows how to interpret (see the table
above; a port like MySQL's 3306, with no signature at all, is never even dialed), runs one gentle,
protocol-appropriate exchange through an injectable dial function (the same `DialFunc` seam
`internal/portscan.Scanner` uses), bounded by a per-probe timeout, with a handful of probes in flight at
once. This is what makes it fully unit-testable with zero real sockets in tests, and what keeps production
scans gentle.

The defaults are gentler than `internal/portscan`'s own (10 connections at once, 750ms each): 5 at once,
2 seconds each. Each probe here does more real work than a bare connect-and-close — a banner read, or a
short write/read exchange for FTP, Docker and SMB1 — so it deserves a little more time and a little less
concurrency.

**TLS probing.** For the six TLS-wrapped ports (443, 8443, 465, 993, 995, 2376), the probe runs a real
TLS handshake over an injectable `TLSConnectFunc` seam (the TLS analog of `DialFunc`, so tests still touch
zero real sockets or certificates) that deliberately offers down to TLS 1.0 and every cipher suite Go's
`crypto/tls` still implements, including the ones Go's own standard library documents as insecure. A
server that only speaks an old protocol version or a weak cipher reveals that by what it actually
negotiates when offered the choice, rather than the handshake simply failing against Go's modern,
safe-by-default client settings. Certificate verification itself is skipped (`InsecureSkipVerify`): this
package only judges the certificate's own dates, never who issued it or what name is on it (see "Not
detected" above for why). For 443 and 8443, a successful handshake is followed by the same minimal
HTTP/1.0 request the plaintext HTTP ports get, over the now-decrypted channel — the Apache/nginx/lighttpd
and `upnp-exposed` signatures fire identically either way, since they only ever look at the `Server:`
header. For 2376, a successful handshake is followed by the same unauthenticated `GET /version` 2375 gets.
465, 993 and 995 get the handshake and nothing more: there is no mail-protocol-specific signature yet to
act on their decrypted content.

Per device, per (signature, port) pair, Shepherd keeps a `Finding`: whether it is currently active, when
it was first and most recently seen, and, mirroring `internal/portscan.PortRecord`'s own philosophy, it
is **kept, not discarded, once it stops matching** — `Active` flips to `false` and `ResolvedAt` is set,
so "this device was exposed for a while and the problem is now fixed" stays visible instead of silently
disappearing. `NewlyFound` marks a finding that just went from inactive-or-unseen to active — **including
on a device's very first scan**, which is the one deliberate difference from `PortRecord.NewlyOpened`
(never set on a first scan, since everything would look "new" with no baseline yet). A vulnerability that
already existed before Shepherd ever looked is still exactly the thing this feature exists to tell you
about, so it is never held back just because it was found on day one.

## Should this be on by default?

**Yes, `[vulnscan].enabled` defaults to `true`, for the same reasoning docs/PORTSCAN.md gives for its own
default**, carried one step further: the entire value of this feature is the owner learning about real,
named exposure they did not know they had, and a feature that defaults off is a feature almost nobody ever
turns on, which defeats the point entirely.

This one does strictly more active probing than portscan (a banner read, and for a few protocols a short
write/read exchange — a login attempt with a well-known anonymous account, one HTTP request, one SMBv1
negotiate packet), so that tradeoff deserved to be weighed honestly rather than inherited automatically:

- Every exchange is the kind of thing a normal client of that protocol already does on day one (an FTP
  client logging in, a browser's first HTTP request, a Windows box negotiating SMB) — nothing here sends
  anything a legitimate client of that service would not also send.
- The anonymous-FTP login uses the actual well-known "anonymous" account by design — that is the
  well-known account advertised by the protocol itself, not a guess, and a server that rejects it (as a
  correctly configured one should) is left completely alone.
- It only ever runs against a port `internal/portscan` already found open and already recorded as part
  of its own default-on scan, so it adds no new category of device contact, only a deeper look at
  contact Shepherd was already making.
- A dangerous finding discovered the moment Shepherd is installed is exactly the case this feature exists
  for, which is also why its alarm type (below) is **not** suppressed during the install learning period,
  unlike most of Shepherd's other "on by default" alarms.

You can turn it off in `[vulnscan]` if you would rather it never ran automatically; a manual scan from the
portal still works even then, as long as `[portscan]` is enabled (see below).

## Configuration

```toml
[portscan]
enabled = true

[vulnscan]
enabled = true
interval_seconds = 86400          # once a day
feed_url = "https://raw.githubusercontent.com/blaineam/shepherd/main/feeds/vulnscan.json"
feed_refresh_seconds = 21600      # 6 hours; "" for feed_url disables the feed entirely
```

`interval_seconds` must be at least 300 (5 minutes), the same floor `[portscan]` uses, though a daily
schedule is the sane default: this is a deeper, slower probe than portscan's own connect scan, and there
is no reason to repeat it constantly. `feed_refresh_seconds` has the same floor and only matters while
`feed_url` is set; the built-in signature table itself is not configurable.

**`[vulnscan]` needs `[portscan]` enabled.** This feature deepens portscan's own open-port findings
rather than scanning for open ports itself (see "What this is, and what it is not"); with portscan
disabled there is nothing for it to probe. `cmd/shepherd` logs a clear warning and does not start the
scheduled vulnerability scan in that case, rather than silently doing nothing or scanning everything
itself and duplicating portscan's work.

## Alerting

A newly active finding (`NewlyFound`) raises `alarms.TypeVulnerabilityFound` once, with the finding's own
severity (critical findings like `smb1-enabled` or `docker-unauthenticated-api` really do mean critical,
not the type's own default). The dedupe key is `vulnerability-found|<device>|<signature>|<port>`, so a
finding that keeps matching scan after scan folds into the same alarm (per `internal/alarms`'s existing
dedupe window) instead of paging you every time the schedule runs.

Unlike most of Shepherd's "on by default" alarm types, `vulnerability-found` is **not** suppressed during
the install learning period. Learning mode exists so that a burst of normal, expected noise while Shepherd
first maps a network (new devices, a blocked-query baseline forming) does not page anyone; a real,
concrete vulnerability discovered on day one is not that kind of noise — it is precisely the thing this
feature is for, so it is never dampened just because it was found early.

**Resolution.** When a finding flips from active to inactive, `cmd/shepherd`'s wiring
(`cmd/shepherd/vulnscan.go`) logs it and resolves the matching open alarm (`alarms.Engine.Resolve`) rather
than leaving it to linger as "new" or "acknowledged" after the underlying problem is actually gone. There
is deliberately no separate "vulnerability resolved" alarm type: `internal/alarms` already has exactly the
right primitive for this (`Resolve` closes an alarm of any open state, and the same key simply raises a
fresh alarm the next time it is seen), so adding a second type would just be two ways of saying the same
thing. Every transition — new or resolved — is also logged with `log.Printf` regardless of whether the
alarm engine is enabled, so there is always a plain server-log record even with `[alarms]` turned off.

## API

Under the portal token, `X-Shepherd: 1` on the scan trigger — the same convention as every other
state-changing portal endpoint.

| Endpoint | Does |
|---|---|
| `GET /api/vulnscan` | `{enabled, signatures: [{id, name, severity, description, ports, cves, source}], builtin_signatures, feed_signatures, feed}` — `signatures` is the merged set a scan evaluates (`source` is `builtin` or `feed`); `feed` is `{url, signatures, skipped, generated_at, last_checked, last_updated, last_error}` or `null` when the feed is disabled |
| `GET /api/vulnscan/devices` | every device's last scan: `{devices: [{device_id, name, ip, last_scanned, findings: [...]}]}` |
| `GET /api/vulnscan/devices/{id}` | one device's last scan, same shape (empty `findings` and no `last_scanned` if never scanned) |
| `POST /api/vulnscan/scan` | `{}` re-probes every device portscan currently has open ports for; `{"device_id": "..."}` scans just one. Returns the scanned devices in the same shape as the list endpoint |
| `POST /api/vulnscan/feed/refresh` | fetches the signature feed now, outside its schedule: `{changed, feed}`; a changed feed re-scans in the background. 400 when the feed is disabled, 502 (with the error as the body) when the fetch failed |

A manual scan re-probes whatever `internal/portscan` currently knows is open — it does not itself trigger
a fresh port scan first, so it stays fast (bounded by a handful of short banner/protocol reads, not a
sweep of ~40 ports). Run a portscan "scan now" first if you want the very latest open-port picture before
a manual vulnerability scan.

History is kept at `<data_dir>/vulnscan.json` (mode 0600) and saved after every scan, scheduled or manual.

## Portal

A dedicated **Vulnerabilities** tab lists every finding across every scanned device in one place, worst
severity first, filterable by minimum severity, active/resolved and free text, with a "Scan all" button
(`POST /api/vulnscan/scan` with no `device_id`). One line under the controls says what the scanner is
matching against — how many signatures are built in and how many the feed supplies, when the feed was
built upstream and last checked, in amber when the last check failed — with an "Update feed" button
(`POST /api/vulnscan/feed/refresh`). Clicking a row opens that device's drawer rather than
repeating the finding detail a second time. The device drawer itself (Devices screen) still has its own
smaller Vulnerabilities panel — a quick, per-device summary with its own "Scan now" — for when you are
already looking at one device and do not need the cross-network view. See
`internal/portal/web/js/vulnscanview.js`.
