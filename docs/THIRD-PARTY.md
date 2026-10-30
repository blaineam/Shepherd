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
| Blocklists (downloaded at runtime from their publishers, never bundled) | filtering | each list's own license, shown in the catalog |

Exact bundled versions and checksums of the front-end libraries are in `internal/portal/web/vendor/VENDOR.md`.
