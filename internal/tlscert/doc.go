// SPDX-License-Identifier: AGPL-3.0-or-later

// Package tlscert obtains and renews a real TLS certificate for Shepherd's
// own portal, using the ACME protocol's DNS-01 challenge against Cloudflare
// DNS (docs/TLS.md). This is the first, additive slice of roadmap step 18
// ("Access"): it gives the portal a real hostname and a real certificate,
// matching the maintainer's existing reverse-proxy setup (Cloudflare DNS-01,
// driven today by a separate reverse-proxy manager this does not touch or
// replace). It never does anything beyond that: no reverse proxying of other
// services, no change to any other DNS record, no change to the portal's
// existing plain-HTTP listener.
//
// The ACME wire protocol itself (nonces, account keys, order and challenge
// polling, certificate parsing) is handled by golang.org/x/crypto/acme,
// already a transitive part of this project's dependency on
// golang.org/x/crypto — not a new module dependency, and a package the Go
// team maintains specifically for this (it is also what
// golang.org/x/crypto/acme/autocert is built on). This package supplies the
// one piece that library does not: creating and removing the DNS-01
// challenge's TXT record through Cloudflare's API (CloudflareProvider), and
// the scheduling, persistence and hot-swap wiring cmd/shepherd needs
// (Manager). See ACMEClient and DNS01Provider for the seams every test here
// uses instead of a real network call.
package tlscert
