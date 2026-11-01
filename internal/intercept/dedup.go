// SPDX-License-Identifier: AGPL-3.0-or-later

package intercept

import (
	"encoding/binary"
	"sync"
	"time"
)

// Dedup is the duplicate brake for the userspace relay: the same mechanism
// the XDP program carries (bpf/xdp_relay.c, is_duplicate), so a loop is
// contained whichever relay is in effect and the Controller's duplicate
// counts mean the same thing under both.
//
// A relay loop is one frame arriving and being relayed over and over. The
// brake fingerprints each frame it relays -- the IPv4 identification field,
// the lengths, both addresses, the protocol and the first sixteen bytes of
// the transport header (for IPv6: traffic class and flow label, payload
// length, next header, both addresses and the same sixteen bytes) -- and
// refuses to relay the same frame twice inside Window. The window sits
// between two real numbers: a loop's round trip is microseconds, and the
// shortest TCP retransmission timeout Linux uses is 200 ms, so a frame
// going round is caught on its second pass and a genuine retransmission is
// never touched. A frame that really is a network-level duplicate is
// dropped, which is what should happen to it: the first copy already
// reached the gateway.
//
// One Dedup belongs to one Relay. ParallelRelay's capture sockets are
// hashed by flow, so a frame and its echo reach the same worker and the
// same table. Direct-mapped with Slots entries: a collision costs one
// suppressed frame, an eviction one more pass that the next catches.
type Dedup struct {
	Window time.Duration // default DefaultDedupWindow
	Slots  int           // default DefaultDedupSlots; a power of two is not required

	mu    sync.Mutex
	table []dedupEntry
}

type dedupEntry struct {
	fingerprint uint64
	at          time.Time
}

const (
	// DefaultDedupWindow matches DUP_WINDOW_NS in the XDP program.
	DefaultDedupWindow = 100 * time.Millisecond
	// DefaultDedupSlots matches DUP_SLOTS in the XDP program.
	DefaultDedupSlots = 8192

	fnvOffset = 1469598103934665603
	fnvPrime  = 1099511628211
)

// Seen reports whether raw, a frame about to be relayed, was already
// relayed inside the window, and records it either way. A frame that is
// not IPv4 or IPv6, or too short to fingerprint, is never a duplicate.
func (d *Dedup) Seen(raw []byte, now time.Time) bool {
	fp, ok := Fingerprint(raw)
	if !ok {
		return false
	}
	window := d.Window
	if window <= 0 {
		window = DefaultDedupWindow
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.table == nil {
		n := d.Slots
		if n <= 0 {
			n = DefaultDedupSlots
		}
		d.table = make([]dedupEntry, n)
	}
	e := &d.table[(fp>>16)%uint64(len(d.table))]
	dup := e.fingerprint == fp && !now.Before(e.at) && now.Sub(e.at) < window
	e.fingerprint, e.at = fp, now
	return dup
}

// Fingerprint identifies one frame well enough to recognise it coming
// round again, with the same fields as the XDP program's fingerprint and
// fingerprint6, so the two relays agree on what a duplicate is. ok is
// false for a frame that is neither IPv4 nor IPv6 or is too short.
func Fingerprint(raw []byte) (fp uint64, ok bool) {
	if len(raw) < ethHeaderLen {
		return 0, false
	}
	h := uint64(fnvOffset)
	mix := func(w uint32) {
		h ^= uint64(w)
		h *= fnvPrime
	}
	l4 := func(off int) [4]uint32 {
		var w [4]uint32
		if off+8 <= len(raw) {
			w[0] = binary.LittleEndian.Uint32(raw[off : off+4])
			w[1] = binary.LittleEndian.Uint32(raw[off+4 : off+8])
		}
		if off+16 <= len(raw) {
			w[2] = binary.LittleEndian.Uint32(raw[off+8 : off+12])
			w[3] = binary.LittleEndian.Uint32(raw[off+12 : off+16])
		}
		return w
	}
	switch binary.BigEndian.Uint16(raw[12:14]) {
	case etherTypeIPv4:
		ip := raw[ethHeaderLen:]
		if len(ip) < ipv4HeaderMinLen {
			return 0, false
		}
		ihl := int(ip[0]&0x0f) * 4
		mix(uint32(binary.LittleEndian.Uint16(ip[4:6]))<<16 | uint32(binary.LittleEndian.Uint16(ip[2:4])))
		mix(binary.LittleEndian.Uint32(ip[12:16]))
		mix(binary.LittleEndian.Uint32(ip[16:20]))
		mix(uint32(ip[9])<<16 | uint32(len(raw)&0xffff))
		w := l4(ethHeaderLen + ihl)
		for _, x := range w {
			mix(x)
		}
		mix(0)
	case etherTypeIPv6:
		ip := raw[ethHeaderLen:]
		if len(ip) < ipv6HeaderLen {
			return 0, false
		}
		mix(uint32(ip[1])<<16 | uint32(binary.LittleEndian.Uint16(ip[2:4])))
		mix(uint32(binary.LittleEndian.Uint16(ip[4:6]))<<16 | uint32(ip[6])<<8)
		mix(uint32(len(raw) & 0xffff))
		for i := 0; i < 8; i++ {
			mix(binary.LittleEndian.Uint32(ip[8+i*4 : 12+i*4]))
		}
		w := l4(ethHeaderLen + ipv6HeaderLen)
		mix(w[0])
		mix(w[1])
		mix(w[2] ^ w[3])
	default:
		return 0, false
	}
	return h | 1, true
}
