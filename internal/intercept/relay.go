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
	etherTypeIPv4 = 0x0800
	etherTypeARP  = 0x0806
	etherTypeIPv6 = 0x86dd
)

// Relay rewrites and retransmits the outbound frames a steered device
// sends to Shepherd's MAC, so they reach the real gateway instead of
// Shepherd. It never touches a frame it does not own: ARP (the Spoofer's
// and the passive arp.Monitor's job) and IPv6 (docs/IPV6.md) are filtered
// out before anything else runs, regardless of what Lookup says, so
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

	// Lookup reports whether mac is a currently steered device and its
	// registered IP. This is the hot-path check: keep it cheap (a map
	// read, no allocation). A nil Lookup makes HandleFrame a no-op.
	Lookup func(mac arp.MAC) (ip netip.Addr, ok bool)

	// OnRelayed is called after a frame is successfully retransmitted,
	// with the device's MAC, the frame's wire length, and the time.
	// Optional.
	OnRelayed func(mac arp.MAC, n int, now time.Time)
	// OnRelayError is called when a matched frame fails to send. Optional.
	OnRelayError func(mac arp.MAC, err error)

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
// Shepherd's MAC, not plain IPv4 (so ARP, IPv6, VLAN-tagged, anything
// else), or whose Ethernet source MAC is not a currently steered device
// is ignored (false, nil) and left completely untouched. Matching is by source MAC only — MAC is Shepherd's device
// identity key everywhere else (docs/DESIGN.md, "Device identity") — so a
// device that gets a new IP from DHCP is still relayed without a gap.
//
// A matched frame has its destination MAC rewritten to the real gateway
// MAC and its source MAC rewritten to Shepherd's own (see the type
// comment for why that second rewrite matters); the IP packet inside,
// source IP included, is untouched, so this is a pure Ethernet-layer
// relay, not NAT. The caller's buffer is never modified.
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
	// Positive match on IPv4, not a denylist of ARP and IPv6: a denylist
	// let a VLAN-tagged (0x8100) frame through, and the ethertype of what
	// it wraps could be anything, IPv6 included — a hole in docs/IPV6.md's
	// hard rule. Plain IPv4-over-Ethernet is the only thing one-sided ARP
	// steering can ever deliver here on purpose, and the only thing the
	// kernel-side capture filter (capture_filter.go) admits.
	if etherType != etherTypeIPv4 {
		return false, nil
	}
	if r.Lookup == nil || r.Sender == nil {
		return false, nil
	}
	if _, ok := r.Lookup(src); !ok {
		return false, nil
	}

	out := make([]byte, len(raw))
	copy(out, raw)
	copy(out[0:6], r.GatewayMAC[:])
	copy(out[6:12], r.ShepherdMAC[:])

	if err := sendWithTimeout(r.Sender, Frame(out), r.timeout()); err != nil {
		if r.OnRelayError != nil {
			r.OnRelayError(src, err)
		}
		return false, err
	}
	if r.OnRelayed != nil {
		r.OnRelayed(src, len(raw), r.now())
	}
	return true, nil
}
