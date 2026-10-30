// SPDX-License-Identifier: AGPL-3.0-or-later

// Package arp is Shepherd's passive ARP monitor.
//
// It listens to ARP frames that are already broadcast on the local network
// and turns them into device observations (real MAC and IP pairs for the
// device registry) and into security events about the ARP layer itself
// (IP conflicts, a changed gateway MAC, spoofing signatures).
//
// The package is strictly passive. The Source interface has no send method,
// the Monitor never writes anywhere but to its Sink and event callback, and
// the Linux raw socket is opened read-only without promiscuous mode. The
// frame builders in this package exist for tests and for the future Watch
// mode interceptor; nothing here transmits a frame. IPv6 is ignored
// entirely (docs/IPV6.md).
//
// See docs/ARP.md for the event rules, thresholds and deployment notes.
package arp
