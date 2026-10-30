// SPDX-License-Identifier: AGPL-3.0-or-later

package intercept

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"shepherd/internal/arp"
)

var t0 = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

// Documentation-range addresses only (RFC 5737 / RFC 7042), same
// convention as internal/arp's test helpers: stable (globally
// administered) MACs for infrastructure, rnd (locally administered,
// 02:00:5e) for ordinary devices.
func stableMAC(n byte) arp.MAC { return arp.MAC{0x00, 0x00, 0x5e, 0x00, 0x53, n} }
func rndMAC(n byte) arp.MAC    { return arp.MAC{0x02, 0x00, 0x5e, 0x00, 0x00, n} }

func ip(n byte) netip.Addr { return netip.AddrFrom4([4]byte{192, 0, 2, n}) }

var (
	gwMAC       = stableMAC(1)
	gwIP        = ip(1)
	shepherdMAC = stableMAC(2)
	devMAC      = rndMAC(10)
	devIP       = ip(10)
)

func testConfig() ControllerConfig {
	return ControllerConfig{
		Sender:      NewFakeSender(),
		Clock:       NewFakeClock(t0),
		ShepherdMAC: shepherdMAC,
		GatewayIP:   gwIP,
		GatewayMAC:  gwMAC,
	}
}

func newTestController(t *testing.T, mod func(*ControllerConfig)) (*Controller, *FakeSender, *FakeClock) {
	t.Helper()
	cfg := testConfig()
	sender := cfg.Sender.(*FakeSender)
	clk := cfg.Clock.(*FakeClock)
	if mod != nil {
		mod(&cfg)
	}
	c, err := NewController(cfg)
	if err != nil {
		t.Fatalf("NewController: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c, sender, clk
}

// ethFrame builds a raw Ethernet frame with an arbitrary (non-ARP)
// ethertype and payload, for Relay tests. It never needs to be valid IP;
// the Relay only looks at the Ethernet header.
func ethFrame(dst, src arp.MAC, etherType uint16, payload []byte) []byte {
	b := make([]byte, ethHeaderLen+len(payload))
	copy(b[0:6], dst[:])
	copy(b[6:12], src[:])
	binary.BigEndian.PutUint16(b[12:14], etherType)
	copy(b[14:], payload)
	return b
}

// waitForFrame blocks until ch delivers a frame or timeout elapses, and
// fails the test on timeout. Synchronizing on a real channel send from a
// background goroutine (the Spoofer's or Relay's own send) is not the
// "real sleep" the test-authoring rules warn against — that rule is about
// not sleeping out a virtual duration instead of using the FakeClock.
func waitForFrame(t *testing.T, ch <-chan Frame, timeout time.Duration) Frame {
	t.Helper()
	select {
	case f := <-ch:
		return f
	case <-time.After(timeout):
		t.Fatal("timed out waiting for a sent frame")
		return nil
	}
}

// arpOf decodes a frame sent by the Spoofer or Relay's own ARP paths.
func arpOf(t *testing.T, f Frame) arp.Frame {
	t.Helper()
	parsed, err := arp.ParseFrame(f)
	if err != nil {
		t.Fatalf("not a parseable ARP frame: %v", err)
	}
	return parsed
}
