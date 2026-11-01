// SPDX-License-Identifier: AGPL-3.0-or-later

package intercept

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"shepherd/internal/arp"
)

// IPv6 test addresses built from byte arrays rather than text literals.
var (
	devIP6  = netip.AddrFrom16([16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10})
	shepIP6 = netip.AddrFrom16([16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02})
	// A documentation global address (2001:db8::/32) as an off-link dest.
	someV6 = netip.MustParseAddr("2001:db8::1234")
)

// ipv6Frame builds a raw Ethernet frame carrying a minimal IPv6 header
// with the given addresses and hop limit. Only the destination address
// and (for the hop-limit-untouched test) the hop-limit byte matter.
func ipv6Frame(dst, src arp.MAC, srcIP, dstIP netip.Addr, hopLimit byte, payload []byte) []byte {
	ipHdr := make([]byte, ipv6HeaderLen)
	ipHdr[0] = 0x60
	ipHdr[6] = 59 // next header: "no next header", arbitrary for the test
	ipHdr[7] = hopLimit
	s, d := srcIP.As16(), dstIP.As16()
	copy(ipHdr[8:24], s[:])
	copy(ipHdr[24:40], d[:])
	return ethFrame(dst, src, etherTypeIPv6, append(ipHdr, payload...))
}

func TestRelayPassesIPv6WhenNotV6Steered(t *testing.T) {
	sender := NewFakeSender()
	r := &Relay{
		Sender: sender, ShepherdMAC: shepherdMAC, GatewayMAC: gwMAC,
		Lookup: steeredLookupFam(devMAC, devIP, SteerV4), // IPv4 only
	}
	raw := ipv6Frame(shepherdMAC, devMAC, devIP6, someV6, 64, []byte("x"))
	ok, err := r.HandleFrame(raw)
	if ok || err != nil {
		t.Fatalf("IPv6 frame from a v4-only device: ok=%v err=%v, want not relayed", ok, err)
	}
	if len(sender.Frames()) != 0 {
		t.Fatal("nothing should have been sent")
	}
}

func TestRelayRelaysIPv6WhenV6Steered(t *testing.T) {
	sender := NewFakeSender()
	var gotFam Family
	r := &Relay{
		Sender: sender, ShepherdMAC: shepherdMAC, GatewayMAC: gwMAC,
		Lookup:    steeredLookupFam(devMAC, devIP, SteerV4|SteerV6),
		OnRelayed: func(_ arp.MAC, fam Family, _ int, _ time.Time) { gotFam = fam },
	}
	const hop = 42
	raw := ipv6Frame(shepherdMAC, devMAC, devIP6, someV6, hop, []byte("payload6"))
	ok, err := r.HandleFrame(raw)
	if !ok || err != nil {
		t.Fatalf("HandleFrame = %v, %v, want relayed", ok, err)
	}
	if gotFam != SteerV6 {
		t.Fatalf("OnRelayed family = %v, want SteerV6", gotFam)
	}
	sent := sender.Frames()[0]
	if arp.MAC(sent[0:6]) != gwMAC {
		t.Fatalf("dst MAC not rewritten to gateway: %v", arp.MAC(sent[0:6]))
	}
	if arp.MAC(sent[6:12]) != shepherdMAC {
		t.Fatalf("src MAC not rewritten to Shepherd: %v", arp.MAC(sent[6:12]))
	}
	if binary.BigEndian.Uint16(sent[12:14]) != etherTypeIPv6 {
		t.Fatal("ethertype changed")
	}
	// Hop limit must be untouched: a pure L2 relay does not decrement it.
	if sent[ethHeaderLen+7] != hop {
		t.Fatalf("hop limit = %d, want %d untouched (no decrement)", sent[ethHeaderLen+7], hop)
	}
}

func TestRelayIPv6ForShepherdItselfIsPassed(t *testing.T) {
	sender := NewFakeSender()
	var passed bool
	r := &Relay{
		Sender: sender, ShepherdMAC: shepherdMAC, GatewayMAC: gwMAC,
		ShepherdIPs6:             []netip.Addr{shepIP6},
		Lookup:                   steeredLookupFam(devMAC, devIP, SteerV4|SteerV6),
		OnFrameForShepherdItself: func(int) { passed = true },
	}
	raw := ipv6Frame(shepherdMAC, devMAC, devIP6, shepIP6, 64, []byte("dns"))
	ok, err := r.HandleFrame(raw)
	if ok || err != nil {
		t.Fatalf("frame for Shepherd's own IPv6: ok=%v err=%v, want passed through", ok, err)
	}
	if !passed {
		t.Fatal("OnFrameForShepherdItself should have fired")
	}
	if len(sender.Frames()) != 0 {
		t.Fatal("a locally-destined frame must not be relayed to the gateway")
	}
}

// FuzzRelayHandleFrameV6Only proves family gating is strict in the other
// direction too: a device steered for IPv6 only never has an IPv4 frame
// relayed, under any input, and HandleFrame never panics. Together with
// FuzzRelayHandleFrame (a v4-only device, no IPv6 ever relayed) this is
// the machine-checked form of "a frame is relayed only for a device
// steered for that frame's family."
func FuzzRelayHandleFrameV6Only(f *testing.F) {
	f.Add(ipv6Frame(shepherdMAC, devMAC, devIP6, someV6, 64, []byte{1, 2, 3, 4}))
	f.Add(ethFrame(shepherdMAC, devMAC, 0x0800, []byte{1, 2, 3, 4}))
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x00, 0x5e})

	f.Fuzz(func(t *testing.T, in []byte) {
		sender := NewFakeSender()
		r := &Relay{
			Sender: sender, ShepherdMAC: shepherdMAC, GatewayMAC: gwMAC,
			Lookup: steeredLookupFam(devMAC, devIP, SteerV6), // IPv6 only
		}
		ok, _ := r.HandleFrame(in) // must never panic
		if len(in) >= 14 && binary.BigEndian.Uint16(in[12:14]) == etherTypeIPv4 && ok {
			t.Fatalf("relayed an IPv4 frame for an IPv6-only device: % x", in)
		}
		for _, sent := range sender.Frames() {
			if len(sent) >= 14 && binary.BigEndian.Uint16(sent[12:14]) == etherTypeIPv4 {
				t.Fatalf("sent an IPv4 frame for an IPv6-only device: % x", sent)
			}
		}
	})
}
