// SPDX-License-Identifier: AGPL-3.0-or-later

// Package devices is Shepherd's device registry: the identity layer that turns
// client IPs into named, searchable, groupable devices.
//
// Evidence arrives as Observations from passive sources (neighbor table, mDNS,
// reverse DNS, DNS queries) and, later, from ARP interception: every source
// feeds the same Registry through the Sink interface. A device is keyed by MAC
// when known, else by IP, and merges when a MAC is learned later. Randomized
// (locally administered) MACs are folded into the device that already holds
// the IP or hostname instead of multiplying the device count.
//
// Every record carries a hybrid logical clock stamp, the writing node and a
// tombstone flag so the registry replicates by last-writer-wins per record
// (see docs/DESIGN.md, "Mesh dataset sync").
//
// IPv6 follows docs/IPV6.md: nothing here sends or spoofs ND, RA or mDNS
// traffic; mDNS and the neighbor table are only listened to.
package devices
