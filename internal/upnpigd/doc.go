// SPDX-License-Identifier: AGPL-3.0-or-later

// Package upnpigd is a best-effort, read-only client for a home router's
// UPnP Internet Gateway Device (IGD) control service. It exists for one
// question internal/portscan cannot otherwise answer: of the ports found
// open on the LAN, which ones does the router also forward from the
// internet (the far more dangerous case for the same open port)?
//
// It works by:
//
//   - discovering the IGD over SSDP (a UDP multicast M-SEARCH to the
//     standard SSDP address, 239.255.255.250:1900, the same everywhere (leakcheck:allow), not
//     a detail of this project's own — the same mechanism game consoles,
//     torrent clients and VoIP apps already use to ask "what's forwarded
//     right now");
//   - fetching and parsing its device description to find the
//     WANIPConnection or WANPPPConnection control URL;
//   - calling that service's GetGenericPortMappingEntry SOAP action
//     repeatedly to enumerate the router's whole NAT port-mapping table.
//
// This is read-only: nothing here ever calls AddPortMapping or
// DeletePortMapping. Shepherd only ever asks what is already forwarded; it
// never changes it.
//
// # What this cannot tell you
//
// UPnP IGD can only ever report what was forwarded *through it*. A port
// reachable from the WAN by some other means — a manual NAT rule made
// outside UPnP, a DMZ host, a device with its own direct public address —
// is invisible to this package, and indistinguishable from a port that
// genuinely is not exposed at all. It also depends entirely on the router
// actually speaking UPnP IGD to LAN clients: many do, but some disable it
// by default, and some consumer mesh systems are known not to implement
// the classic IGD control surface the way a traditional router does. When
// discovery or a query fails for any reason, every caller gets Unknown,
// never a guess — see internal/portscan's Exposure type and
// docs/PORTSCAN.md for what that means in practice.
package upnpigd
