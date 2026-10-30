// SPDX-License-Identifier: AGPL-3.0-or-later

package arp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// Wire constants.
const (
	etherTypeARP  = 0x0806
	etherTypeVLAN = 0x8100
	etherHdrLen   = 14
	arpBodyLen    = 28
	minFrameLen   = 60 // Ethernet minimum without FCS; builders pad to it
)

// ARP operations.
const (
	OpRequest uint16 = 1
	OpReply   uint16 = 2
)

// Errors returned by the codec and by sources.
var (
	// ErrMalformed marks a frame that claims to be ARP but is truncated or
	// inconsistent. Monitors count it and carry on.
	ErrMalformed = errors.New("arp: malformed frame")
	// ErrNotARP marks a frame that is not IPv4-over-Ethernet ARP (another
	// EtherType, a double-tagged frame, a non-IPv4 protocol address).
	ErrNotARP = errors.New("arp: not an IPv4 ARP frame")
	// ErrClosed is returned by a Source after Close or when it is drained.
	ErrClosed = errors.New("arp: source closed")
	// ErrUnsupported is returned where raw ARP capture is unavailable.
	ErrUnsupported = errors.New("arp: raw ARP capture is not supported on this platform")
)

// MAC is an Ethernet hardware address.
type MAC [6]byte

// Broadcast is the all-ones Ethernet address.
var Broadcast = MAC{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// String renders the lower-case colon form the device registry uses.
func (m MAC) String() string {
	const hex = "0123456789abcdef"
	var b [17]byte
	for i, v := range m {
		b[i*3] = hex[v>>4]
		b[i*3+1] = hex[v&15]
		if i < 5 {
			b[i*3+2] = ':'
		}
	}
	return string(b[:])
}

// IsZero reports 00:00:00:00:00:00.
func (m MAC) IsZero() bool { return m == MAC{} }

// IsMulticast reports the group bit, which includes broadcast.
func (m MAC) IsMulticast() bool { return m[0]&1 == 1 }

// IsLocallyAdministered reports the locally-administered bit: the signature
// of a randomized private Wi-Fi address.
func (m MAC) IsLocallyAdministered() bool { return m[0]&2 == 2 }

// usable reports whether m can identify a device.
func (m MAC) usable() bool { return !m.IsZero() && !m.IsMulticast() }

// ParseMAC parses the colon form ("02:00:5e:00:00:01").
func ParseMAC(s string) (MAC, error) {
	var m MAC
	if len(s) != 17 {
		return m, fmt.Errorf("arp: bad MAC %q", s)
	}
	for i := 0; i < 6; i++ {
		if i < 5 && s[i*3+2] != ':' {
			return MAC{}, fmt.Errorf("arp: bad MAC %q", s)
		}
		hi, ok1 := unhex(s[i*3])
		lo, ok2 := unhex(s[i*3+1])
		if !ok1 || !ok2 {
			return MAC{}, fmt.Errorf("arp: bad MAC %q", s)
		}
		m[i] = hi<<4 | lo
	}
	return m, nil
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// Kind classifies a frame.
type Kind int

// Frame kinds.
const (
	KindUnknown Kind = iota
	KindRequest
	KindReply
	// KindProbe is an RFC 5227 address probe: a request whose sender IP is 0.0.0.0.
	KindProbe
	// KindAnnounce is a gratuitous request: sender IP equals target IP.
	KindAnnounce
	// KindGratuitousReply is a reply whose sender IP equals its target IP.
	KindGratuitousReply
)

func (k Kind) String() string {
	switch k {
	case KindRequest:
		return "request"
	case KindReply:
		return "reply"
	case KindProbe:
		return "probe"
	case KindAnnounce:
		return "announce"
	case KindGratuitousReply:
		return "gratuitous-reply"
	}
	return "unknown"
}

// Frame is a parsed Ethernet + IPv4 ARP frame.
type Frame struct {
	DstMAC, SrcMAC MAC // Ethernet header

	Tagged bool   // 802.1Q tag present
	VLAN   uint16 // VLAN ID when Tagged

	Op        uint16
	SenderMAC MAC
	SenderIP  netip.Addr
	TargetMAC MAC
	TargetIP  netip.Addr

	Time time.Time // capture time; zero means "now" to the Monitor
}

// Kind classifies the frame.
func (f Frame) Kind() Kind {
	switch f.Op {
	case OpRequest:
		switch {
		case f.SenderIP.IsUnspecified():
			return KindProbe
		case f.SenderIP == f.TargetIP:
			return KindAnnounce
		}
		return KindRequest
	case OpReply:
		if f.SenderIP == f.TargetIP {
			return KindGratuitousReply
		}
		return KindReply
	}
	return KindUnknown
}

// IsGratuitous reports an announce or a gratuitous reply.
func (f Frame) IsGratuitous() bool {
	k := f.Kind()
	return k == KindAnnounce || k == KindGratuitousReply
}

// ParseFrame decodes a raw Ethernet frame. It never panics: every read is
// bounds checked. A single 802.1Q tag is accepted and recorded; anything
// else that is not IPv4-over-Ethernet ARP returns ErrNotARP, and a frame
// that is ARP but cut short or inconsistent returns ErrMalformed.
func ParseFrame(b []byte) (Frame, error) {
	var f Frame
	if len(b) < etherHdrLen {
		return f, fmt.Errorf("%w: %d bytes is shorter than an Ethernet header", ErrMalformed, len(b))
	}
	copy(f.DstMAC[:], b[0:6])
	copy(f.SrcMAC[:], b[6:12])
	et := binary.BigEndian.Uint16(b[12:14])
	off := etherHdrLen
	if et == etherTypeVLAN {
		if len(b) < etherHdrLen+4 {
			return f, fmt.Errorf("%w: truncated VLAN tag", ErrMalformed)
		}
		f.Tagged = true
		f.VLAN = binary.BigEndian.Uint16(b[14:16]) & 0x0fff
		et = binary.BigEndian.Uint16(b[16:18])
		off += 4
	}
	if et != etherTypeARP {
		return f, fmt.Errorf("%w: ethertype 0x%04x", ErrNotARP, et)
	}
	body := b[off:]
	if len(body) < arpBodyLen {
		return f, fmt.Errorf("%w: ARP body is %d bytes", ErrMalformed, len(body))
	}
	htype := binary.BigEndian.Uint16(body[0:2])
	ptype := binary.BigEndian.Uint16(body[2:4])
	hlen, plen := body[4], body[5]
	if htype != 1 || ptype != 0x0800 {
		return f, fmt.Errorf("%w: hardware 0x%04x protocol 0x%04x", ErrNotARP, htype, ptype)
	}
	if hlen != 6 || plen != 4 {
		return f, fmt.Errorf("%w: address lengths %d/%d", ErrMalformed, hlen, plen)
	}
	f.Op = binary.BigEndian.Uint16(body[6:8])
	if f.Op != OpRequest && f.Op != OpReply {
		return f, fmt.Errorf("%w: operation %d", ErrMalformed, f.Op)
	}
	copy(f.SenderMAC[:], body[8:14])
	f.SenderIP = netip.AddrFrom4([4]byte(body[14:18]))
	copy(f.TargetMAC[:], body[18:24])
	f.TargetIP = netip.AddrFrom4([4]byte(body[24:28]))
	return f, nil
}

// Marshal builds the wire bytes, padded to the 60-byte Ethernet minimum.
// It exists for tests and the future interceptor; the Monitor never calls
// it and nothing in this package sends the result anywhere.
func (f Frame) Marshal() ([]byte, error) {
	if !f.SenderIP.Is4() || !f.TargetIP.Is4() {
		return nil, fmt.Errorf("arp: Marshal needs IPv4 sender and target addresses")
	}
	if f.Op != OpRequest && f.Op != OpReply {
		return nil, fmt.Errorf("arp: Marshal needs operation 1 or 2, got %d", f.Op)
	}
	if f.Tagged && f.VLAN > 0x0fff {
		return nil, fmt.Errorf("arp: VLAN id %d out of range", f.VLAN)
	}
	n := etherHdrLen + arpBodyLen
	if f.Tagged {
		n += 4
	}
	if n < minFrameLen {
		n = minFrameLen
	}
	b := make([]byte, n)
	copy(b[0:6], f.DstMAC[:])
	copy(b[6:12], f.SrcMAC[:])
	off := 12
	if f.Tagged {
		binary.BigEndian.PutUint16(b[off:], etherTypeVLAN)
		binary.BigEndian.PutUint16(b[off+2:], f.VLAN)
		off += 4
	}
	binary.BigEndian.PutUint16(b[off:], etherTypeARP)
	off += 2
	binary.BigEndian.PutUint16(b[off:], 1)
	binary.BigEndian.PutUint16(b[off+2:], 0x0800)
	b[off+4], b[off+5] = 6, 4
	binary.BigEndian.PutUint16(b[off+6:], f.Op)
	copy(b[off+8:], f.SenderMAC[:])
	s4, t4 := f.SenderIP.As4(), f.TargetIP.As4()
	copy(b[off+14:], s4[:])
	copy(b[off+18:], f.TargetMAC[:])
	copy(b[off+24:], t4[:])
	return b, nil
}

// NewRequest is "who has target? tell sender".
func NewRequest(srcMAC MAC, srcIP, targetIP netip.Addr) Frame {
	return Frame{DstMAC: Broadcast, SrcMAC: srcMAC, Op: OpRequest,
		SenderMAC: srcMAC, SenderIP: srcIP, TargetIP: targetIP}
}

// NewReply is "sender is at senderMAC", addressed to target.
func NewReply(senderMAC MAC, senderIP netip.Addr, targetMAC MAC, targetIP netip.Addr) Frame {
	return Frame{DstMAC: targetMAC, SrcMAC: senderMAC, Op: OpReply,
		SenderMAC: senderMAC, SenderIP: senderIP, TargetMAC: targetMAC, TargetIP: targetIP}
}

// NewProbe is an RFC 5227 probe: a request with sender IP 0.0.0.0.
func NewProbe(srcMAC MAC, targetIP netip.Addr) Frame {
	return NewRequest(srcMAC, netip.IPv4Unspecified(), targetIP)
}

// NewAnnounce is an RFC 5227 announcement: a request whose sender and
// target IP are both the announced address.
func NewAnnounce(srcMAC MAC, ip netip.Addr) Frame {
	return NewRequest(srcMAC, ip, ip)
}

// NewGratuitousReply is a broadcast reply that announces mac as the owner of ip.
func NewGratuitousReply(mac MAC, ip netip.Addr) Frame {
	return Frame{DstMAC: Broadcast, SrcMAC: mac, Op: OpReply,
		SenderMAC: mac, SenderIP: ip, TargetMAC: Broadcast, TargetIP: ip}
}
