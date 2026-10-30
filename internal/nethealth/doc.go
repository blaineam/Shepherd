// SPDX-License-Identifier: AGPL-3.0-or-later

// Package nethealth measures the reliability of the network connection
// itself, not any one device on it: latency, jitter, packet loss and
// reachability against a small set of well-known targets, plus an
// occasional, deliberately bounded bufferbloat check. Unlike
// internal/portscan and internal/vulnscan, which answer "is my network
// exposed right now", this package exists to answer "is my network
// reliable over the last few months", so it keeps history, not just the
// latest reading (see Store).
//
// Measurement is unprivileged by design: rather than an ICMP raw socket
// (which needs CAP_NET_RAW, like internal/arp, and cannot be verified
// end-to-end without live hardware), latency is timed as a plain TCP
// connect against port 53 on each target — every target here already runs
// a DNS resolver, so a bare SYN/SYN-ACK round trip is a faithful stand-in
// for ICMP echo timing without any extra privilege. See docs/NETHEALTH.md
// for the full reasoning and what was deferred (traceroute).
package nethealth
