# Third-party software and data

Shepherd is AGPL-3.0-or-later. It includes or uses the following, under their own licenses.

| What | Used for | License |
|---|---|---|
| [three.js](https://threejs.org) 0.186.1 (bundled, `internal/portal/web/vendor/`) | the globe | MIT |
| [world-atlas](https://github.com/topojson/world-atlas) 2.0.2 `land-110m` with [Natural Earth](https://www.naturalearthdata.com) data | land outlines | ISC (package), public domain (data) |
| [DB-IP](https://db-ip.com) IP to City Lite database (downloaded at runtime, never bundled) | placing destinations and home on the globe | CC BY 4.0, attribution shown in the portal |
| [miekg/dns](https://github.com/miekg/dns) | the DNS server and client | BSD-3-Clause |
| [BurntSushi/toml](https://github.com/BurntSushi/toml) | configuration | MIT |
| [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) | Argon2id key derivation | BSD-3-Clause |
| [oschwald/maxminddb-golang](https://github.com/oschwald/maxminddb-golang) | reading the GeoIP database | ISC |
| [maxmind/mmdbwriter](https://github.com/maxmind/mmdbwriter) | building small GeoIP databases for tests only | Apache-2.0 |
| [golang.org/x/net](https://pkg.go.dev/golang.org/x/net), [golang.org/x/sys](https://pkg.go.dev/golang.org/x/sys) | multicast sockets for the passive mDNS listener | BSD-3-Clause |
| IEEE Registration Authority MA-L ("OUI") registry, prefixes and normalized vendor names only (bundled, `internal/devices/oui_data.gz`; see `internal/devices/README.md`) | the manufacturer of a device from its MAC address | published by the IEEE for public lookup; factual assignment data, see [IEEE terms](https://standards.ieee.org/products-programs/regauth/) |
| Blocklists in the catalog (downloaded at runtime by your own Shepherd from the publishers, never bundled; the catalog only references their URLs) | filtering | each list's own license, below and shown beside the entry in the portal |

### Catalog lists

The catalog (`internal/dnsengine/catalog.json`) names these sources. Shepherd redistributes none of their data: it downloads a list only when you
switch it on, from the publisher, and caches it on your machine.

| Source | Entries that use it | License |
|---|---|---|
| [HaGeZi DNS Blocklists](https://github.com/hagezi/dns-blocklists) | the `hagezi-*` lists (ads, trackers, threat intelligence, popups, gambling, piracy, native tracker lists, and more) | GPL-3.0 |
| [The Block List Project](https://github.com/blocklistproject/Lists) | the `blp-*` lists, Adobe, and the Facebook, WhatsApp, TikTok, X, YouTube and Fortnite app lists | Unlicense (public domain) |
| [NextDNS services lists](https://github.com/nextdns/services) | most app entries (Instagram, Messenger, Discord, Snapchat, Reddit, streaming, gaming, messaging and other services) | MIT, (c) NextDNS |
| [StevenBlack/hosts](https://github.com/StevenBlack/hosts) | `stevenblack-unified` | MIT |
| [AdGuard DNS filter](https://github.com/AdguardTeam/AdGuardSDNSFilter) | `adguard-dns` | GPL-3.0 |

Each entry's `license` field in the catalog is authoritative for that entry. The names of apps and services are used only to say what a list blocks.

Exact bundled versions and checksums of the front-end libraries are in `internal/portal/web/vendor/VENDOR.md`.
