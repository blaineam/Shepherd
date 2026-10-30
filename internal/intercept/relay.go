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
	etherTypeIPv6 = 0x86dd
)

// Relay rewrites and retransmits the outbound frames a steered device
// sends to Shepherd's MAC, so they reach the real gateway instead of
// Shepherd. It never touches a frame it does not own: ARP (the Spoofer's
// and the passive arp.Monitor's job) and IPv6 (docs/IPV6.md) are filtered
// out before anything else runs, regardless of what Lookup says, so
// Shepherd can run this against a mixed, unfiltered capture and trust it
// to leave everything else alone.
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
// Shepherd's MAC, ARP, IPv6, or whose Ethernet source MAC is not a
// currently steered device is ignored (false, nil) and left completely
// untouched. Matching is by source MAC only — MAC is Shepherd's device
// identity key everywhere else (docs/DESIGN.md, "Device identity") — so a
// device that gets a new IP from DHCP is still relayed without a gap.
//
// A matched frame has its destination MAC rewritten to the real gateway
// MAC; the source MAC, the source IP, and everything else in the frame is
// untouched, so this is a pure Ethernet-layer relay, not NAT.
func (r *Relay) HandleFrame(raw []byte) (bool, error) {
	if len(raw) < ethHeaderLen {
		return false, nil
	}
	var dst, src arp.MAC
	copy(dst[:], raw[0:6])
	copy(src[:], raw[6:12])
	etherType := binary.BigEndian.Uint16(raw[12:14])

	if dst != r.ShepherdMAC {
		return false, nil
	}
	if etherType == etherTypeARP || etherType == etherTypeIPv6 {
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
