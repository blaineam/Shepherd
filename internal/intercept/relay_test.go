// SPDX-License-Identifier: AGPL-3.0-or-later

package intercept

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"

	"shepherd/internal/arp"
)

func steeredLookup(mac arp.MAC, ip netip.Addr) func(arp.MAC) (netip.Addr, bool) {
	return func(m arp.MAC) (netip.Addr, bool) {
		if m == mac {
			return ip, true
		}
		return netip.Addr{}, false
	}
}

func TestRelayRewritesDestinationAndRelays(t *testing.T) {
	sender := NewFakeSender()
	var relayedMAC arp.MAC
	var relayedN int
	r := &Relay{
		Sender: sender, ShepherdMAC: shepherdMAC, GatewayMAC: gwMAC,
		Lookup:    steeredLookup(devMAC, devIP),
		OnRelayed: func(mac arp.MAC, n int, _ time.Time) { relayedMAC, relayedN = mac, n },
	}
	raw := ethFrame(shepherdMAC, devMAC, 0x0800, []byte("payload"))
	ok, err := r.HandleFrame(raw)
	if err != nil || !ok {
		t.Fatalf("HandleFrame = %v, %v", ok, err)
	}
	if relayedMAC != devMAC || relayedN != len(raw) {
		t.Fatalf("OnRelayed got mac=%v n=%d", relayedMAC, relayedN)
	}
	frames := sender.Frames()
	if len(frames) != 1 {
		t.Fatalf("want 1 sent frame, got %d", len(frames))
	}
	sent := frames[0]
	var gotDst, gotSrc arp.MAC
	copy(gotDst[:], sent[0:6])
	copy(gotSrc[:], sent[6:12])
	if gotDst != gwMAC {
		t.Fatalf("destination not rewritten to the gateway: %v", gotDst)
	}
	if gotSrc != shepherdMAC {
		// Not cosmetic: a relayed frame carrying the device's own source
		// MAC makes every switch between Shepherd and the device learn
		// the device on Shepherd's port and misdeliver its inbound
		// traffic there. See the Relay type comment and docs/INTERCEPT.md.
		t.Fatalf("source MAC must be rewritten to Shepherd's own, got %v", gotSrc)
	}
	if string(sent[14:]) != "payload" {
		t.Fatal("payload was altered")
	}
	// The original buffer must not have been mutated.
	if raw[0] != shepherdMAC[0] {
		t.Fatal("HandleFrame mutated the caller's buffer")
	}
}

// A relayed frame's own loopback copy (as a capture socket without
// PACKET_IGNORE_OUTGOING would deliver it) must never be relayed again:
// with the source now rewritten to Shepherd's MAC, the destination check
// still discards it, and so would the Lookup even if it did not, since
// Shepherd's own MAC is never a steered device.
func TestRelayNeverReRelaysItsOwnOutput(t *testing.T) {
	sender := NewFakeSender()
	r := &Relay{Sender: sender, ShepherdMAC: shepherdMAC, GatewayMAC: gwMAC, Lookup: steeredLookup(devMAC, devIP)}
	if ok, err := r.HandleFrame(ethFrame(shepherdMAC, devMAC, 0x0800, []byte("first"))); !ok || err != nil {
		t.Fatalf("first HandleFrame = %v, %v", ok, err)
	}
	loopedBack := append([]byte(nil), sender.Frames()[0]...)
	if ok, err := r.HandleFrame(loopedBack); ok || err != nil {
		t.Fatalf("re-relayed Shepherd's own output: %v, %v", ok, err)
	}
	if len(sender.Frames()) != 1 {
		t.Fatalf("want exactly 1 sent frame, got %d", len(sender.Frames()))
	}
}

func TestRelayIgnoresFramesNotAddressedToShepherd(t *testing.T) {
	sender := NewFakeSender()
	r := &Relay{Sender: sender, ShepherdMAC: shepherdMAC, GatewayMAC: gwMAC, Lookup: steeredLookup(devMAC, devIP)}
	raw := ethFrame(gwMAC, devMAC, 0x0800, []byte("x")) // addressed to the gateway, not Shepherd
	ok, err := r.HandleFrame(raw)
	if ok || err != nil {
		t.Fatalf("got %v, %v", ok, err)
	}
	if len(sender.Frames()) != 0 {
		t.Fatal("a frame not addressed to Shepherd must never be sent")
	}
}

func TestRelaySkipsFramesDestinedForShepherdItself(t *testing.T) {
	sender := NewFakeSender()
	var skippedN int
	r := &Relay{
		Sender: sender, ShepherdMAC: shepherdMAC, GatewayMAC: gwMAC,
		ShepherdIPs:              []netip.Addr{shepherdIP},
		Lookup:                   steeredLookup(devMAC, devIP),
		OnFrameForShepherdItself: func(n int) { skippedN = n },
	}
	raw := ipv4Frame(shepherdMAC, devMAC, devIP, shepherdIP, []byte("dns query"))
	ok, err := r.HandleFrame(raw)
	if ok || err != nil {
		t.Fatalf("got %v, %v", ok, err)
	}
	if len(sender.Frames()) != 0 {
		t.Fatal("a frame destined for Shepherd's own IP must never be relayed to the gateway")
	}
	if skippedN != len(raw) {
		t.Fatalf("OnFrameForShepherdItself got n=%d, want %d", skippedN, len(raw))
	}
}

func TestRelayStillRelaysFramesDestinedElsewhere(t *testing.T) {
	sender := NewFakeSender()
	skipped := false
	r := &Relay{
		Sender: sender, ShepherdMAC: shepherdMAC, GatewayMAC: gwMAC,
		ShepherdIPs:              []netip.Addr{shepherdIP},
		Lookup:                   steeredLookup(devMAC, devIP),
		OnFrameForShepherdItself: func(int) { skipped = true },
	}
	internet := ip(200)
	raw := ipv4Frame(shepherdMAC, devMAC, devIP, internet, []byte("https request"))
	ok, err := r.HandleFrame(raw)
	if err != nil || !ok {
		t.Fatalf("HandleFrame = %v, %v", ok, err)
	}
	if len(sender.Frames()) != 1 {
		t.Fatal("a frame destined elsewhere must still be relayed")
	}
	if skipped {
		t.Fatal("OnFrameForShepherdItself fired for a frame that was not destined for Shepherd")
	}
}

func TestRelayWithNoShepherdIPsConfiguredRelaysEverything(t *testing.T) {
	// ShepherdIPs left empty (the zero value) must behave exactly as it
	// did before this field existed: destinedForShepherd is never even
	// consulted, so a frame whose IP destination happens to equal
	// Shepherd's real IP is still relayed rather than silently dropped
	// by a caller that never set this up.
	sender := NewFakeSender()
	r := &Relay{Sender: sender, ShepherdMAC: shepherdMAC, GatewayMAC: gwMAC, Lookup: steeredLookup(devMAC, devIP)}
	raw := ipv4Frame(shepherdMAC, devMAC, devIP, shepherdIP, []byte("x"))
	ok, err := r.HandleFrame(raw)
	if err != nil || !ok {
		t.Fatalf("HandleFrame = %v, %v", ok, err)
	}
	if len(sender.Frames()) != 1 {
		t.Fatal("with ShepherdIPs unset, every matched frame must still be relayed")
	}
}

func TestRelayIgnoresARP(t *testing.T) {
	sender := NewFakeSender()
	r := &Relay{Sender: sender, ShepherdMAC: shepherdMAC, GatewayMAC: gwMAC, Lookup: steeredLookup(devMAC, devIP)}
	raw := ethFrame(shepherdMAC, devMAC, 0x0806, []byte("x"))
	ok, err := r.HandleFrame(raw)
	if ok || err != nil {
		t.Fatalf("got %v, %v", ok, err)
	}
}

func TestRelayIgnoresIPv6(t *testing.T) {
	sender := NewFakeSender()
	r := &Relay{Sender: sender, ShepherdMAC: shepherdMAC, GatewayMAC: gwMAC, Lookup: steeredLookup(devMAC, devIP)}
	raw := ethFrame(shepherdMAC, devMAC, 0x86dd, []byte("x"))
	ok, err := r.HandleFrame(raw)
	if ok || err != nil {
		t.Fatalf("got %v, %v", ok, err)
	}
	if len(sender.Frames()) != 0 {
		t.Fatal("IPv6 must never be relayed, docs/IPV6.md is a hard rule")
	}
}

// A VLAN tag (0x8100) hides the real ethertype one header further in;
// what it wraps could be IPv6. Only plain IPv4 is ever relayed.
func TestRelayIgnoresVLANTaggedAndOtherEthertypes(t *testing.T) {
	sender := NewFakeSender()
	r := &Relay{Sender: sender, ShepherdMAC: shepherdMAC, GatewayMAC: gwMAC, Lookup: steeredLookup(devMAC, devIP)}
	vlanIPv6 := ethFrame(shepherdMAC, devMAC, 0x8100, []byte{0x00, 0x01, 0x86, 0xdd, 0x60, 0, 0, 0})
	for _, f := range [][]byte{
		vlanIPv6,
		ethFrame(shepherdMAC, devMAC, 0x88cc, []byte("lldp")),
		ethFrame(shepherdMAC, devMAC, 0x8863, []byte("pppoe")),
	} {
		if ok, err := r.HandleFrame(f); ok || err != nil {
			t.Fatalf("ethertype %#04x: got %v, %v", binary.BigEndian.Uint16(f[12:14]), ok, err)
		}
	}
	if len(sender.Frames()) != 0 {
		t.Fatal("only plain IPv4 may ever be relayed")
	}
}

func TestRelayIgnoresUnmatchedDevice(t *testing.T) {
	sender := NewFakeSender()
	r := &Relay{Sender: sender, ShepherdMAC: shepherdMAC, GatewayMAC: gwMAC, Lookup: steeredLookup(devMAC, devIP)}
	other := rndMAC(99)
	raw := ethFrame(shepherdMAC, other, 0x0800, []byte("x"))
	ok, err := r.HandleFrame(raw)
	if ok || err != nil {
		t.Fatalf("got %v, %v", ok, err)
	}
	if len(sender.Frames()) != 0 {
		t.Fatal("a frame from a device that is not steered must never be sent")
	}
}

func TestRelayIgnoresTooShortFrames(t *testing.T) {
	r := &Relay{Sender: NewFakeSender(), ShepherdMAC: shepherdMAC, GatewayMAC: gwMAC, Lookup: steeredLookup(devMAC, devIP)}
	for n := 0; n < ethHeaderLen; n++ {
		ok, err := r.HandleFrame(make([]byte, n))
		if ok || err != nil {
			t.Fatalf("len %d: got %v, %v", n, ok, err)
		}
	}
}

func TestRelayNilLookupOrSenderIsANoOp(t *testing.T) {
	raw := ethFrame(shepherdMAC, devMAC, 0x0800, []byte("x"))
	r1 := &Relay{Sender: NewFakeSender(), ShepherdMAC: shepherdMAC, GatewayMAC: gwMAC}
	if ok, err := r1.HandleFrame(raw); ok || err != nil {
		t.Fatalf("nil Lookup: got %v, %v", ok, err)
	}
	r2 := &Relay{ShepherdMAC: shepherdMAC, GatewayMAC: gwMAC, Lookup: steeredLookup(devMAC, devIP)}
	if ok, err := r2.HandleFrame(raw); ok || err != nil {
		t.Fatalf("nil Sender: got %v, %v", ok, err)
	}
}

func TestRelayReportsSendErrorAndDoesNotCountAsRelayed(t *testing.T) {
	sender := NewFakeSender()
	sender.SetError(errors.New("boom"))
	relayedCalled := false
	var gotErrMAC arp.MAC
	r := &Relay{
		Sender: sender, ShepherdMAC: shepherdMAC, GatewayMAC: gwMAC,
		Lookup:       steeredLookup(devMAC, devIP),
		OnRelayed:    func(arp.MAC, int, time.Time) { relayedCalled = true },
		OnRelayError: func(mac arp.MAC, err error) { gotErrMAC = mac },
	}
	raw := ethFrame(shepherdMAC, devMAC, 0x0800, []byte("x"))
	ok, err := r.HandleFrame(raw)
	if ok || err == nil {
		t.Fatalf("got %v, %v", ok, err)
	}
	if relayedCalled {
		t.Fatal("OnRelayed must not fire on a failed send")
	}
	if gotErrMAC != devMAC {
		t.Fatalf("OnRelayError mac = %v", gotErrMAC)
	}
}

func TestRelayOnFrameExaminedFiresForEveryFrameRegardlessOfOutcome(t *testing.T) {
	sender := NewFakeSender()
	var examined []int
	r := &Relay{
		Sender: sender, ShepherdMAC: shepherdMAC, GatewayMAC: gwMAC,
		Lookup:          steeredLookup(devMAC, devIP),
		OnFrameExamined: func(n int) { examined = append(examined, n) },
	}
	matched := ethFrame(shepherdMAC, devMAC, 0x0800, []byte("x"))
	notShepherd := ethFrame(gwMAC, devMAC, 0x0800, []byte("yy"))
	tooShort := make([]byte, 3)

	for _, f := range [][]byte{matched, notShepherd, tooShort} {
		if _, err := r.HandleFrame(f); err != nil {
			t.Fatalf("HandleFrame: %v", err)
		}
	}
	want := []int{len(matched), len(notShepherd), len(tooShort)}
	if len(examined) != len(want) {
		t.Fatalf("OnFrameExamined fired %d times, want %d", len(examined), len(want))
	}
	for i, n := range want {
		if examined[i] != n {
			t.Fatalf("examined[%d] = %d, want %d", i, examined[i], n)
		}
	}
}

func TestRelayOnFrameNotForShepherdFiresOnlyForWrongDestination(t *testing.T) {
	sender := NewFakeSender()
	var notForShepherd int
	r := &Relay{
		Sender: sender, ShepherdMAC: shepherdMAC, GatewayMAC: gwMAC,
		Lookup:                steeredLookup(devMAC, devIP),
		OnFrameNotForShepherd: func(int) { notForShepherd++ },
	}
	// Addressed to Shepherd: must not count, no matter how it is then
	// filtered (ARP, unmatched device, or actually relayed).
	for _, f := range [][]byte{
		ethFrame(shepherdMAC, devMAC, 0x0800, []byte("relayed")),
		ethFrame(shepherdMAC, devMAC, 0x0806, []byte("arp")),
		ethFrame(shepherdMAC, rndMAC(77), 0x0800, []byte("unmatched")),
	} {
		if _, err := r.HandleFrame(f); err != nil {
			t.Fatal(err)
		}
	}
	if notForShepherd != 0 {
		t.Fatalf("OnFrameNotForShepherd fired %d times for Shepherd-addressed frames, want 0", notForShepherd)
	}

	// This is the case that matters: a loopback copy of a frame Shepherd
	// itself just relayed (dst rewritten to the gateway, src to Shepherd).
	if _, err := r.HandleFrame(ethFrame(gwMAC, shepherdMAC, 0x0800, []byte("looped back"))); err != nil {
		t.Fatal(err)
	}
	if notForShepherd != 1 {
		t.Fatalf("OnFrameNotForShepherd = %d, want 1", notForShepherd)
	}
	if len(sender.Frames()) != 1 {
		t.Fatal("only the one genuinely matched frame should ever be sent")
	}
}

// Fuzz/property test: no random or adversarial byte sequence ever gets
// relayed when its ethertype is IPv6, and HandleFrame never panics.
// Mirrors internal/arp's FuzzParseFrame pattern (seed corpus of valid and
// truncated input, then arbitrary bytes).
func FuzzRelayHandleFrame(f *testing.F) {
	good := ethFrame(shepherdMAC, devMAC, 0x0800, []byte{1, 2, 3, 4})
	ipv6 := ethFrame(shepherdMAC, devMAC, 0x86dd, []byte{1, 2, 3, 4})
	arpLike, _ := arp.NewRequest(devMAC, devIP, gwIP).Marshal()
	f.Add(good)
	f.Add(ipv6)
	f.Add(arpLike)
	f.Add([]byte{})
	f.Add(good[:10])

	f.Fuzz(func(t *testing.T, in []byte) {
		sender := NewFakeSender()
		r := &Relay{
			Sender: sender, ShepherdMAC: shepherdMAC, GatewayMAC: gwMAC,
			// Lookup always says "steered" so the only thing that can
			// stop a relay is the ethertype/destination checks: exactly
			// what this test wants to stress.
			Lookup: func(arp.MAC) (netip.Addr, bool) { return devIP, true },
		}
		ok, err := r.HandleFrame(in) // must never panic
		if len(in) >= 14 {
			et := binary.BigEndian.Uint16(in[12:14])
			if et == etherTypeIPv6 && ok {
				t.Fatalf("relayed an IPv6-ethertype frame: % x", in)
			}
		}
		_ = err
		for _, sent := range sender.Frames() {
			if len(sent) >= 14 && binary.BigEndian.Uint16(sent[12:14]) == etherTypeIPv6 {
				t.Fatalf("sent an IPv6-ethertype frame: % x", sent)
			}
		}
	})
}
