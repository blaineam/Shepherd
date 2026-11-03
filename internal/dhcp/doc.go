// SPDX-License-Identifier: AGPL-3.0-or-later

// Package dhcp serves the LAN's DHCP and decides which devices are routed
// through Shepherd. It is docs/DHCP.md's implementation, and it is off by
// default.
//
// The one idea the package rests on: whether a device's traffic reaches
// Shepherd at all is a property of the lease it was handed, not of a packet
// rule. DHCP option 3 (router) is one address per lease, so putting the
// gateway's address there leaves a device on the path it has always used, and
// putting Shepherd's address there makes that device send everything
// off-segment to Shepherd — which forwards and masquerades it to the gateway.
// Nothing in this package touches a packet; the kernel forwards and
// translates, and Reconciler only configures it.
//
// Three modes, because a boolean cannot express the dangerous part:
//
//   - ModeOff opens no socket and changes nothing. The default.
//   - ModeObserve opens a listener with no send path at all. It reads the
//     segment's DHCP traffic, feeds the device registry, and runs the
//     allocator in dry run so the portal can show what Shepherd would have
//     answered. It cannot transmit: Server refuses to construct a writable
//     connection in this mode, so an observe-mode bug cannot put a frame on
//     the wire.
//   - ModeServe answers. It is gated on a typed portal confirmation and on
//     Peers reporting that no other DHCP server has answered recently,
//     because two servers on one segment is a non-deterministic split of the
//     household that one forgotten checkbox can cause.
//
// The failure behaviour is deliberately the opposite of docs/GATEWAY.md's
// fail-closed decision, and the reason is in docs/DHCP.md: here the dangerous
// direction is cutting devices off, so an unhealthy Shepherd hands out the
// gateway's address instead of its own and every routed device drifts back to
// the gateway by itself within one renewal interval. Nothing has to be
// working for that to happen, which is why the default lease time is short.
//
// Wire format comes from github.com/insomniacslk/dhcp/dhcpv4: encode, decode
// and the typed option accessors, which is the part where someone else's
// production mileage with odd clients is worth more than this project's
// reading of RFC 2132. The socket, the serve loop and every decision are
// Shepherd's, because observe mode's no-send-path guarantee, the rogue-server
// interlock and the routing policy all need to see traffic that a
// request-dispatching server loop would have filtered away.
package dhcp
