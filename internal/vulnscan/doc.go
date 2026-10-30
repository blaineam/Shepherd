// SPDX-License-Identifier: AGPL-3.0-or-later

// Package vulnscan turns internal/portscan's open-port findings into named,
// concrete vulnerability findings: a lightweight banner/protocol probe per
// open port, matched against a small, curated, local signature list. See
// docs/VULNSCAN.md for exactly what is and is not detected, and why.
//
// This package never scans a port on its own: internal/portscan already
// owns deciding which ports are open on which devices (docs/PORTSCAN.md).
// TargetsFromPortscan turns its results into vulnscan.Target values, so the
// two packages never both open a TCP connection just to learn "is this port
// open" — only this package's own deeper, protocol-appropriate probe adds a
// new connection, and only for ports it knows how to interpret.
package vulnscan
