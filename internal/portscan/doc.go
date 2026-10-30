// SPDX-License-Identifier: AGPL-3.0-or-later

// Package portscan scans Shepherd's own known devices (from internal/devices)
// for open TCP ports, so an owner can see exposure they did not expect: a
// camera that opened Telnet, a NAS with SMB reachable, a laptop with RDP on.
//
// This is deliberately gentle, for awareness of your own network, never for
// probing anyone else's:
//
//   - plain TCP connect scans only. No OS or service fingerprinting, no UDP,
//     no SYN-stealth or other scan types that look like an attack tool;
//   - a short, fixed, documented list of well-known ports (DefaultPorts), not
//     a sweep of the full 1-65535 range;
//   - bounded concurrency and a short per-connection timeout, so a scan never
//     floods a device or the LAN with connection attempts.
//
// It knows nothing about router port forwarding (what the internet can reach
// from outside): there is no reliable, generic router API for that today. See
// docs/PORTSCAN.md.
package portscan
