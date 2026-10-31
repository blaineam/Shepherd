// SPDX-License-Identifier: AGPL-3.0-or-later

package intercept

import (
	"encoding/binary"
	"net/netip"
	"time"

	"shepherd/internal/arp"
)

const (
	ethHeaderLen  = 14
	etherTypeARP  = 0x0806
	etherTypeIPv4 = 0x0800
	etherTypeIPv6 = 0x86dd

	// ipv4DstOffset is the destination address field's offset within an
	// IPv4 header (bytes 16-19), and ipv4HeaderMinLen is that header's
	// length with no options — the only shape destinedForShepherd needs
	// to read, since the destination address sits before where any
	// options would start.
	ipv4DstOffset    = 16
	ipv4HeaderMinLen = 20

	// ipv6DstOffset is the destination address field's offset within an
	// IPv6 header (bytes 24-39), and ipv6HeaderLen is the fixed base
	// header length. Unlike IPv4 the base header has no options, so the
	// destination always sits at this one offset.
	ipv6DstOffset = 24
	ipv6HeaderLen = 40
)

// Family is the set of address families a device is steered for. Watch
// mode steers IPv4 and IPv6 independently (docs/IPV6-WATCH.md): a device
// can be steered for one, the other, or both, and a frame of a family the
// device is not steered for is passed through untouched. The zero value
// steers nothing.
type Family uint8

const (
	// SteerV4 steers the device's outbound IPv4 traffic (the original,
	// always-available Watch mode).
	SteerV4 Family = 1 << iota
	// SteerV6 steers the device's outbound IPv6 traffic. Off unless
	// explicitly enabled; see docs/IPV6-WATCH.md for the rules that gate
	// it (global IPv6 route present, smart-home devices excluded, master
	// switch on).
	SteerV6
)

// Has reports whether f includes family g.
func (f Family) Has(g Family) bool { return f&g != 0 }

// String renders the families as "v4", "v6", "v4+v6" or "none".
func (f Family) String() string {
	switch {
	case f.Has(SteerV4) && f.Has(SteerV6):
		return "v4+v6"
	case f.Has(SteerV4):
		return "v4"
	case f.Has(SteerV6):
		return "v6"
	}
	return "none"
}

// Relay rewrites and retransmits the outbound frames a steered device
// sends to Shepherd's MAC, so they reach the real gateway instead of
// Shepherd. It never touches a frame it does not own: ARP (the Spoofer's
// and the passive arp.Monitor's job) is always filtered out, and a frame
// is relayed only if its source-MAC device is steered for that frame's
// family (SteerV4 for IPv4, SteerV6 for IPv6). IPv6 is therefore relayed
// only for a device explicitly steered for IPv6 and is otherwise passed
// through untouched — docs/IPV6.md's hard rule, enforced per device. So
// Shepherd can run this against a mixed, unfiltered capture and trust it
// to leave everything else alone.
//
// A relayed frame leaves with BOTH Ethernet addresses rewritten: the
// destination to the real gateway's MAC (so it gets there) and the source
// to Shepherd's own MAC (so the switches in between stay sane). The second
// rewrite is not cosmetic. Every Ethernet switch and every Wi-Fi/LAN bridge
// (a consumer mesh router is one) learns which port a MAC lives behind from
// the source address of the frames it sees. Retransmitting a device's frame
// with the device's own source MAC teaches the switch that the device lives
// on Shepherd's port; the device's next Wi-Fi frame teaches it the opposite.
// Every relayed frame flips that entry, and while it points at Shepherd,
// the device's inbound traffic (the download direction Watch mode never
// even sees) is delivered to Shepherd's port and lost. That is packet
// loss, in bursts, on the one direction that carries the bytes, and TCP
// and QUIC respond to it exactly as they should: by slowing down.
// docs/INTERCEPT.md's "Throughput" section has the live evidence. With
// Shepherd's MAC as the source, the device's MAC is only ever seen on
// its own port and Shepherd's only on Shepherd's; nothing flaps.
//
// The IP packet inside is still untouched, so this is still a pure
// Ethernet-layer relay with no NAT: the gateway sees the device's own
// source IP, answers to it through its own (never spoofed) ARP entry, and
// the reply goes straight to the device, same as before. One-sided scope
// is unchanged.
type Relay struct {
	Sender      Sender
	ShepherdMAC arp.MAC
	GatewayMAC  arp.MAC
	SendTimeout time.Duration // default DefaultSendTimeout

	// ShepherdIPs are this host's own IPv4 addresses on the interface
	// Relay runs on. A steered device's ARP entry for the real gateway is
	// spoofed to ShepherdMAC, but its entry for Shepherd's own IP (e.g. a
	// DNS query to the resolver Shepherd itself runs, or a connection to
	// its portal) is never touched and already correctly resolves to the
	// same ShepherdMAC — so at the Ethernet layer, traffic genuinely meant
	// for Shepherd is indistinguishable from traffic meant for the real
	// gateway; only the IPv4 destination address tells them apart.
	// HandleFrame leaves a frame destined for one of these addresses
	// completely alone (Shepherd's own kernel already receives and
	// answers it normally): relaying it to the real gateway as well would
	// not just waste a relay worker's capacity on every single locally-
	// destined packet, the gateway has no reason to do anything with a
	// frame addressed to its own MAC but a different IP, and silently
	// drops it. Empty (the default) skips this check entirely, so a
	// caller that has not supplied it gets today's behavior unchanged.
	ShepherdIPs []netip.Addr

	// ShepherdIPs6 is the IPv6 counterpart of ShepherdIPs: this host's own
	// IPv6 addresses on the interface (link-local, ULA, any global). A
	// steered device's IPv6 frame to one of these is for Shepherd itself
	// (its resolver's IPv6 address, its portal over IPv6) and is left
	// alone, exactly as the IPv4 case. Empty skips the check.
	ShepherdIPs6 []netip.Addr

	// Lookup reports whether mac is a currently steered device, its
	// registered IP, and which address families it is steered for. This is
	// the hot-path check: keep it cheap (a map read, no allocation). A nil
	// Lookup makes HandleFrame a no-op. A device whose Family does not
	// include the frame's family is treated as not steered for that frame.
	Lookup func(mac arp.MAC) (ip netip.Addr, fam Family, ok bool)

	// OnRelayed is called after a frame is successfully retransmitted,
	// with the device's MAC, the family relayed (SteerV4 or SteerV6), the
	// frame's wire length, and the time. The family lets a caller keep
	// per-family health (docs/IPV6-WATCH.md: IPv6 idle is normal and must
	// not flap IPv4). Optional.
	OnRelayed func(mac arp.MAC, fam Family, n int, now time.Time)
	// OnRelayError is called when a matched frame fails to send, with the
	// family it belonged to so a caller can fail that family open on its
	// own. Optional.
	OnRelayError func(mac arp.MAC, fam Family, err error)

	// OnFrameExamined, when set, is called once for every frame passed to
	// HandleFrame, before any filtering, with its wire length. It exists
	// purely for packet-rate diagnostics (bytes and frames per second,
	// independent of how many frames go on to match); nil, the default,
	// costs nothing. Optional.
	OnFrameExamined func(n int)
	// OnFrameNotForShepherd, when set, is called for every frame
	// HandleFrame discards because its destination MAC is not
	// ShepherdMAC's. A non-promiscuous capture socket otherwise only ever
	// sees frames addressed to this host, so in practice this is almost
	// always a loopback copy of a frame Shepherd itself just transmitted
	// on the same interface — see PACKET_IGNORE_OUTGOING in
	// capture_linux.go and docs/INTERCEPT.md's "Throughput" section.
	// Optional, diagnostic only.
	OnFrameNotForShepherd func(n int)
	// OnFrameForShepherdItself, when set, is called for every frame
	// HandleFrame leaves alone because its destination is one of Shepherd's
	// own addresses (ShepherdIPs for IPv4, ShepherdIPs6 for IPv6). Optional,
	// diagnostic only.
	OnFrameForShepherdItself func(n int)

	Now func() time.Time // default time.Now
}

func (r *Relay) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Relay) timeout() time.Duration {
	if r.SendTimeout > 0 {
		return r.SendTimeout
	}
	return DefaultSendTimeout
}

// HandleFrame processes one raw inbound Ethernet frame captured off the
// wire. It reports whether the frame was relayed.
//
// A frame that is too short to have an Ethernet header, not addressed to
// Shepherd's MAC, neither plain IPv4 nor plain IPv6 (so ARP, VLAN-tagged,
// anything else), whose Ethernet source MAC is not a device currently
// steered for that frame's family, or whose destination is one of
// Shepherd's own addresses is ignored (false, nil) and left completely
// untouched. Matching is by source MAC only — MAC is Shepherd's device
// identity key everywhere else (docs/DESIGN.md, "Device identity") — so a
// device that gets a new IP from DHCP (or a new IPv6 address, which
// happens constantly with privacy addressing) is still relayed without a
// gap.
//
// A matched frame has its destination MAC rewritten to the real gateway
// MAC and its source MAC rewritten to Shepherd's own (see the type
// comment for why that second rewrite matters); the IP packet inside,
// source IP and hop limit / TTL included, is untouched, so this is a pure
// Ethernet-layer relay, not NAT and not routing — unlike a real router it
// does not decrement the hop limit. The caller's buffer is never modified.
func (r *Relay) HandleFrame(raw []byte) (bool, error) {
	if r.OnFrameExamined != nil {
		r.OnFrameExamined(len(raw))
	}
	if len(raw) < ethHeaderLen {
		return false, nil
	}
	var dst, src arp.MAC
	copy(dst[:], raw[0:6])
	copy(src[:], raw[6:12])
	etherType := binary.BigEndian.Uint16(raw[12:14])

	if dst != r.ShepherdMAC {
		if r.OnFrameNotForShepherd != nil {
			r.OnFrameNotForShepherd(len(raw))
		}
		return false, nil
	}
	// Positive match on a known family, never a denylist of ARP: a
	// denylist let a VLAN-tagged (0x8100) frame through, and the ethertype
	// of what it wraps could be anything. IPv4 and IPv6 are the only two
	// things one-sided steering can deliver here on purpose, and the only
	// two the kernel-side capture filter (capture_filter.go) admits. The
	// per-frame family is matched against the device's steered families
	// below, so an IPv6 frame from a device steered only for IPv4 (and any
	// IPv6 frame at all while nothing is IPv6-steered) is passed through —
	// docs/IPV6.md's hard rule, enforced per device, not by a blanket drop.
	var family Family
	switch etherType {
	case etherTypeIPv4:
		family = SteerV4
	case etherTypeIPv6:
		family = SteerV6
	default:
		return false, nil
	}
	if r.Lookup == nil || r.Sender == nil {
		return false, nil
	}
	_, fam, ok := r.Lookup(src)
	if !ok || !fam.Has(family) {
		return false, nil
	}
	if r.destinedForShepherd(raw, etherType) {
		if r.OnFrameForShepherdItself != nil {
			r.OnFrameForShepherdItself(len(raw))
		}
		return false, nil
	}

	out := make([]byte, len(raw))
	copy(out, raw)
	copy(out[0:6], r.GatewayMAC[:])
	copy(out[6:12], r.ShepherdMAC[:])

	if err := sendWithTimeout(r.Sender, Frame(out), r.timeout()); err != nil {
		if r.OnRelayError != nil {
			r.OnRelayError(src, family, err)
		}
		return false, err
	}
	if r.OnRelayed != nil {
		r.OnRelayed(src, family, len(raw), r.now())
	}
	return true, nil
}

// destinedForShepherd reports whether raw's IP destination address is one
// of Shepherd's own (ShepherdIPs for IPv4, ShepherdIPs6 for IPv6). Called
// only once etherType is known to be IPv4 or IPv6 and raw has already
// passed the minimum Ethernet-header-length check in HandleFrame, so the
// only remaining bounds check is for the IP header itself; a frame too
// short to hold one is, by definition, not destined for any specific
// address Shepherd would recognize.
func (r *Relay) destinedForShepherd(raw []byte, etherType uint16) bool {
	if etherType == etherTypeIPv6 {
		if len(r.ShepherdIPs6) == 0 || len(raw) < ethHeaderLen+ipv6HeaderLen {
			return false
		}
		dst := netip.AddrFrom16([16]byte(raw[ethHeaderLen+ipv6DstOffset : ethHeaderLen+ipv6DstOffset+16]))
		for _, own := range r.ShepherdIPs6 {
			if own == dst {
				return true
			}
		}
		return false
	}
	if len(r.ShepherdIPs) == 0 || len(raw) < ethHeaderLen+ipv4HeaderMinLen {
		return false
	}
	var b [4]byte
	copy(b[:], raw[ethHeaderLen+ipv4DstOffset:ethHeaderLen+ipv4DstOffset+4])
	dst := netip.AddrFrom4(b)
	for _, own := range r.ShepherdIPs {
		if own.Unmap() == dst {
			return true
		}
	}
	return false
}
