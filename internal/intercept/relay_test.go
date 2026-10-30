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
	if gotSrc != devMAC {
		t.Fatalf("source MAC must stay untouched: %v", gotSrc)
	}
	if string(sent[14:]) != "payload" {
		t.Fatal("payload was altered")
	}
	// The original buffer must not have been mutated.
	if raw[0] != shepherdMAC[0] {
		t.Fatal("HandleFrame mutated the caller's buffer")
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
