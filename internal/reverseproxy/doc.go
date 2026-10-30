// SPDX-License-Identifier: AGPL-3.0-or-later

// Package reverseproxy routes HTTPS requests for other self-hosted services
// through Shepherd by their Host header, so Shepherd can take over from a
// separate reverse-proxy manager (docs/REVERSEPROXY.md, roadmap step 18).
//
// The list of proxied hosts lives in a Store the portal edits, persisted to
// <data_dir>/reverseproxy.json; Proxy is the http.Handler that looks each
// request up in it and forwards it with net/http/httputil.ReverseProxy,
// WebSocket upgrades included. Certificates are not this package's concern:
// cmd/shepherd serves Proxy behind a wildcard certificate from
// internal/tlscert, so one certificate covers every host in the Store.
package reverseproxy
