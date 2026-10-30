// SPDX-License-Identifier: AGPL-3.0-or-later

// Package tlscert obtains and renews a real TLS certificate using the ACME
// protocol's DNS-01 challenge against Cloudflare DNS (docs/TLS.md). It
// backs two independent listeners: [tls], the portal's own certificate for
// its own hostname, and [reverseproxy], which asks for a wildcard
// ("*.example.com") so one certificate covers every proxied hostname
// (docs/REVERSEPROXY.md). Nothing here changes any DNS record beyond the
// short-lived challenge TXT record, and neither use touches the portal's
// plain-HTTP listener.
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
