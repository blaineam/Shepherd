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

### Fixed
- The portal kept polling the API every second while signed out, flooding the console with 401 errors. It now stops until you sign in.
- The example config's blocklist URL returned HTTP 404. It now points at a working list, and a weekly CI job (`scripts/check-list-urls`) fails if any example blocklist URL stops resolving.

### Changed
- **Protection is on by default; you opt out, not in.** A fresh install now ships with a blocklist and blocks Apple iCloud Private Relay (devices see a notice that it is unavailable on the network). Opt out with `block_private_relay = false` or `no_default_lists = true`, or from the portal. Lists you define always replace the built-in one. Watch mode will follow the same rule (default-on with automatic exclusions and a fail-open watchdog); see the design doc.
- Licensed AGPL-3.0-or-later.
- The in-memory query log now keeps 20,000 entries by default (was 5,000) so replay reaches further back.
- Direction: a native single binary with a Go control plane and a Rust data plane (Wave 6), instead of containers.
