// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ntfy is a small client for publishing notifications to an ntfy
// server, using only the Go standard library.
//
// ntfy is Shepherd's fallback delivery channel. Web Push is silently dropped
// when an iPhone is in Lockdown Mode, and it needs a home-screen web app that
// not every household sets up; the ntfy app needs neither. A self-hosted
// server (reachable on the LAN or the tailnet) keeps the alarm text inside the
// household.
//
// A message is published with a plain POST to {server}/{topic}: the message is
// the request body, and Title, Priority, Tags, Click and Actions are headers.
// Credentials go in the Authorization header as a bearer token or as basic
// auth. Every value that becomes a header is checked for CR and LF (header
// injection) and non-ASCII text is sent RFC 2047 encoded, which ntfy decodes.
//
// The server URL is operator configuration, not attacker input, so unlike
// internal/webpush this package does not refuse private addresses: a self-hosted
// ntfy normally lives on one.
package ntfy
