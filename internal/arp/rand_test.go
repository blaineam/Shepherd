// SPDX-License-Identifier: AGPL-3.0-or-later

package arp

import (
	"math/rand"
	"net/netip"
	"reflect"
	"time"
)

type rnger struct{ r *rand.Rand }

func newRand(seed int64) *rnger { return &rnger{rand.New(rand.NewSource(seed))} }
func (g *rnger) n(max int) int  { return g.r.Intn(max) }

func hasMethod(v any, name string) bool { return reflect.ValueOf(v).MethodByName(name).IsValid() }

// frame builds a random frame from a small pool so that collisions (and
// therefore every rule) are exercised, with a sprinkling of invalid fields.
func (g *rnger) frame(when time.Time) Frame {
	pickMAC := func() MAC {
		switch g.n(12) {
		case 0:
			return MAC{}
		case 1:
			return Broadcast
		}
		return MAC{byte(g.n(4)), 0, 0x5e, 0, 0, byte(g.n(12))}
	}
	pickIP := func() netip.Addr {
		switch g.n(14) {
		case 0:
			return netip.Addr{}
		case 1:
			return netip.IPv4Unspecified()
		case 2:
			return netip.MustParseAddr("2001:db8::1")
		}
		return netip.AddrFrom4([4]byte{192, 0, 2, byte(g.n(20))})
	}
	return Frame{
		DstMAC: pickMAC(), SrcMAC: pickMAC(), Op: uint16(g.n(4)),
		SenderMAC: pickMAC(), SenderIP: pickIP(), TargetMAC: pickMAC(), TargetIP: pickIP(),
		Tagged: g.n(2) == 0, VLAN: uint16(g.n(5000)), Time: when,
	}
}
