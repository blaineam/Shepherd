// SPDX-License-Identifier: AGPL-3.0-or-later

package ndp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"shepherd/internal/arp"
)

// Wire constants.
const (
	etherTypeIPv6 = 0x86dd
	etherHdrLen   = 14
	ipv6HdrLen    = 40
	nextHdrICMPv6 = 58
	hopLimitNDP   = 255 // RFC 4861: NDP packets MUST use 255; receivers reject anything else

	icmpTypeNS = 135 // Neighbor Solicitation
	icmpTypeNA = 136 // Neighbor Advertisement

	naHdrLen   = 24 // type, code, checksum, flags+reserved, target address
	nsHdrLen   = 24 // type, code, checksum, reserved, target address
	optTypeSLL = 1  // Source Link-Layer Address option
	optTypeTLL = 2  // Target Link-Layer Address option
	lenLLAOpt  = 8  // a 6-byte MAC option, length field 1 (in 8-byte units)

	// NA flag bits in the first byte of the NA flags/reserved word.
	naFlagRouter    = 0x80
	naFlagSolicited = 0x40
	naFlagOverride  = 0x20
)

// Errors returned by this package.
var (
	// ErrNotIPv6 marks a build or parse of something that is not IPv6 —
	// the hard rule (docs/IPV6.md): this package only ever touches IPv6.
	ErrNotIPv6 = errors.New("ndp: address is not a usable IPv6 address")
	// ErrMulticast marks an attempt to build a frame addressed to a
	// multicast group. Shepherd never sends multicast NDP (unicast-only
	// is the whole safety story; see docs/IPV6-WATCH.md), so Marshal
	// refuses it rather than trusting every caller to remember.
	ErrMulticast = errors.New("ndp: destination is multicast; Shepherd only sends unicast NDP")
	// ErrNotNS marks a frame that is not an ICMPv6 Neighbor Solicitation.
	ErrNotNS = errors.New("ndp: not a Neighbor Solicitation")
	// ErrMalformed marks a frame that claims to be what it is but is
	// truncated or inconsistent.
	ErrMalformed = errors.New("ndp: malformed frame")
)

// Flags are the three Neighbor Advertisement flag bits that matter.
//
// Router MUST be true whenever the advertised address is a router's (the
// steering case always is): clearing it tells the receiver to drop the
// address from its Default Router List, which would black-hole the
// device's IPv6 entirely instead of steering it (RFC 4861 §7.2.5).
//
// Override MUST be true to overwrite an existing cache entry; without it a
// receiver that already has the real router cached ignores the new
// link-layer address.
//
// Solicited is false for the periodic unsolicited claim and true only in
// a direct reply to a Neighbor Solicitation.
type Flags struct {
	Router    bool
	Solicited bool
	Override  bool
}

func (f Flags) byte() byte {
	var b byte
	if f.Router {
		b |= naFlagRouter
	}
	if f.Solicited {
		b |= naFlagSolicited
	}
	if f.Override {
		b |= naFlagOverride
	}
	return b
}

// Advertisement is a unicast Neighbor Advertisement to build. Every field
// is required. Target is the address being advertised (for steering, the
// gateway's link-local address); TargetLLA is the link-layer address the
// receiver should cache for it (for steering, Shepherd's MAC). SrcIP and
// DstIP are the IPv6 packet endpoints; EthSrc and EthDst the Ethernet
// ones. Nothing here is ever multicast — Marshal enforces it.
type Advertisement struct {
	EthSrc, EthDst arp.MAC
	SrcIP, DstIP   netip.Addr
	Target         netip.Addr
	TargetLLA      arp.MAC
	Flags          Flags
}

// usableV6 reports whether a is a concrete IPv6 address (not IPv4, not a
// 4-in-6 mapping, not the unspecified address).
func usableV6(a netip.Addr) bool {
	return a.Is6() && !a.Is4In6() && !a.IsUnspecified()
}

// Marshal builds the full Ethernet + IPv6 + ICMPv6 Neighbor Advertisement,
// computing the mandatory ICMPv6 checksum and fixing the hop limit at 255.
// It refuses to build anything that is not IPv6 (ErrNotIPv6) or that is
// addressed to a multicast group (ErrMulticast): those refusals are the
// enforcement, not merely the documentation, of the unicast-only,
// IPv6-only rules this package exists to keep.
func (a Advertisement) Marshal() ([]byte, error) {
	if !usableV6(a.SrcIP) || !usableV6(a.DstIP) || !usableV6(a.Target) {
		return nil, ErrNotIPv6
	}
	if a.DstIP.IsMulticast() || a.EthDst.IsMulticast() {
		return nil, ErrMulticast
	}

	// ICMPv6 message: NA header (24) + target link-layer address option (8).
	icmp := make([]byte, naHdrLen+lenLLAOpt)
	icmp[0] = icmpTypeNA
	icmp[1] = 0 // code
	// icmp[2:4] checksum, filled in below.
	icmp[4] = a.Flags.byte()
	// icmp[5:8] reserved, already zero.
	target := a.Target.As16()
	copy(icmp[8:24], target[:])
	icmp[24] = optTypeTLL
	icmp[25] = 1 // length in 8-byte units
	copy(icmp[26:32], a.TargetLLA[:])

	src := a.SrcIP.As16()
	dst := a.DstIP.As16()
	sum := icmpv6Checksum(src[:], dst[:], icmp)
	binary.BigEndian.PutUint16(icmp[2:4], sum)

	frame := make([]byte, etherHdrLen+ipv6HdrLen+len(icmp))
	copy(frame[0:6], a.EthDst[:])
	copy(frame[6:12], a.EthSrc[:])
	binary.BigEndian.PutUint16(frame[12:14], etherTypeIPv6)

	ip := frame[etherHdrLen:]
	ip[0] = 0x60 // version 6, traffic class 0
	// ip[1:4] flow label 0.
	binary.BigEndian.PutUint16(ip[4:6], uint16(len(icmp)))
	ip[6] = nextHdrICMPv6
	ip[7] = hopLimitNDP
	copy(ip[8:24], src[:])
	copy(ip[24:40], dst[:])

	copy(frame[etherHdrLen+ipv6HdrLen:], icmp)
	return frame, nil
}

// icmpv6Checksum is the 16-bit one's-complement checksum over the IPv6
// pseudo-header (src, dst, upper-layer length, next header) and the
// ICMPv6 message, with the message's own checksum field taken as zero
// (the caller has not yet written it).
func icmpv6Checksum(src, dst, icmp []byte) uint16 {
	var sum uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(b[i])<<8 | uint32(b[i+1])
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	add(src)
	add(dst)
	var pseudo [8]byte
	binary.BigEndian.PutUint32(pseudo[0:4], uint32(len(icmp)))
	pseudo[7] = nextHdrICMPv6
	add(pseudo[:])
	add(icmp)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// Solicitation is a parsed ICMPv6 Neighbor Solicitation: who sent it, for
// which target address, and (if present) the sender's own link-layer
// address option.
type Solicitation struct {
	EthSrc, EthDst arp.MAC
	SrcIP, DstIP   netip.Addr
	Target         netip.Addr
	SourceLLA      arp.MAC
	HasSourceLLA   bool
}

// ParseSolicitation decodes a raw Ethernet frame as an ICMPv6 Neighbor
// Solicitation. It never panics: every read is bounds-checked. A frame
// that is not IPv6/ICMPv6/NS returns ErrNotNS; one that is an NS but
// truncated or inconsistent returns ErrMalformed. The ICMPv6 checksum is
// not verified here — the kernel already does that for anything it
// delivers, and the steering layer only acts on an NS whose target is the
// gateway address it is already steering.
func ParseSolicitation(b []byte) (Solicitation, error) {
	var s Solicitation
	if len(b) < etherHdrLen+ipv6HdrLen+nsHdrLen {
		return s, fmt.Errorf("%w: %d bytes", ErrNotNS, len(b))
	}
	if binary.BigEndian.Uint16(b[12:14]) != etherTypeIPv6 {
		return s, ErrNotNS
	}
	ip := b[etherHdrLen:]
	if ip[0]>>4 != 6 {
		return s, ErrNotNS
	}
	if ip[6] != nextHdrICMPv6 {
		// An extension header before ICMPv6 is legal IPv6 but never used
		// for the on-link NS a steered device sends; not our case.
		return s, ErrNotNS
	}
	icmp := b[etherHdrLen+ipv6HdrLen:]
	if icmp[0] != icmpTypeNS {
		return s, ErrNotNS
	}
	if icmp[1] != 0 {
		return s, fmt.Errorf("%w: NS code %d", ErrMalformed, icmp[1])
	}
	copy(s.EthDst[:], b[0:6])
	copy(s.EthSrc[:], b[6:12])
	s.SrcIP = netip.AddrFrom16([16]byte(ip[8:24]))
	s.DstIP = netip.AddrFrom16([16]byte(ip[24:40]))
	s.Target = netip.AddrFrom16([16]byte(icmp[8:24]))

	// Options follow the 24-byte NS header; look for a Source Link-Layer
	// Address option (type 1). Each option is type(1) len(1, in 8-byte
	// units) value. A zero length is malformed (would loop forever).
	for off := nsHdrLen; off+2 <= len(icmp); {
		otype := icmp[off]
		olen := int(icmp[off+1]) * 8
		if olen == 0 || off+olen > len(icmp) {
			return s, fmt.Errorf("%w: bad NS option", ErrMalformed)
		}
		if otype == optTypeSLL && olen >= 8 {
			copy(s.SourceLLA[:], icmp[off+2:off+8])
			s.HasSourceLLA = true
		}
		off += olen
	}
	return s, nil
}
