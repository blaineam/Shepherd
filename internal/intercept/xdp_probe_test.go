// SPDX-License-Identifier: AGPL-3.0-or-later

package intercept

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"shepherd/internal/arp"
)

// The self-test is only worth anything if the probe is a frame the relay
// would really relay and a frame that can do no harm if it escapes. The
// kernel test (xdp_linux_test.go) checks the first against the program
// itself; this checks the construction on every platform.
func TestTheProbeFrameIsWellFormedAndHarmless(t *testing.T) {
	shepherd := arp.MAC{0x02, 0x00, 0x5e, 0x00, 0x00, 0x20}
	f := probeFrame(shepherd)

	if len(f) != 60 {
		t.Fatalf("probe frame is %d bytes, want 60, the minimum on the wire: a padded frame is not the frame that was sent", len(f))
	}
	var dst, src arp.MAC
	copy(dst[:], f[0:6])
	copy(src[:], f[6:12])
	if dst != shepherd {
		t.Errorf("probe destination MAC = %v, want Shepherd's own %v, or the program's rule 2 passes it", dst, shepherd)
	}
	if src != probeMAC {
		t.Errorf("probe source MAC = %v, want the probe's %v", src, probeMAC)
	}
	// Locally administered and unicast, so no real device can hold it.
	if probeMAC[0]&0x02 == 0 {
		t.Errorf("probe MAC %v is not locally administered, so a real device could own it", probeMAC)
	}
	if probeMAC[0]&0x01 != 0 {
		t.Errorf("probe MAC %v is a multicast address", probeMAC)
	}
	if et := binary.BigEndian.Uint16(f[12:14]); et != 0x0800 {
		t.Errorf("probe ethertype = %#04x, want IPv4 0x0800", et)
	}

	ip := f[14 : 14+probeIPHeaderLen]
	if ip[0] != 0x45 {
		t.Errorf("probe IP version/IHL = %#02x, want 0x45", ip[0])
	}
	if got := binary.BigEndian.Uint16(ip[2:4]); got != uint16(len(f)-14) {
		t.Errorf("probe IP total length = %d, want %d", got, len(f)-14)
	}
	if ip[9] != 17 {
		t.Errorf("probe IP protocol = %d, want 17 (UDP)", ip[9])
	}
	if ip[8] == 0 {
		t.Error("probe TTL is zero, so the first hop would discard it")
	}
	if sum := ipChecksum(ip); sum != 0 {
		t.Errorf("probe IPv4 header checksum does not verify: %#04x over the whole header, want 0", sum)
	}

	// Inside TEST-NET-2, which is not routable and which nothing answers,
	// and deliberately clear of this package's own Shepherd address
	// (192.0.2.2): the program passes a frame addressed to one of
	// Shepherd's own addresses, which would make the test see nothing.
	srcIP := netip.AddrFrom4([4]byte(ip[12:16]))
	dstIP := netip.AddrFrom4([4]byte(ip[16:20]))
	testNet2 := netip.MustParsePrefix("198.51.100.0/24")
	for _, a := range []netip.Addr{srcIP, dstIP} {
		if !testNet2.Contains(a) {
			t.Errorf("probe address %v is outside %v, so it is not guaranteed to go nowhere", a, testNet2)
		}
	}

	udp := f[14+probeIPHeaderLen:]
	if sp, dp := binary.BigEndian.Uint16(udp[0:2]), binary.BigEndian.Uint16(udp[2:4]); sp != 9 || dp != 9 {
		t.Errorf("probe UDP ports = %d->%d, want 9->9 (discard)", sp, dp)
	}
	if got := binary.BigEndian.Uint16(udp[4:6]); got != uint16(len(udp)) {
		t.Errorf("probe UDP length = %d, want %d", got, len(udp))
	}

	// Two probes are identical, which matters: the verdict is "was this
	// exact frame seen coming back", not "was something like it seen".
	if string(probeFrame(shepherd)) != string(f) {
		t.Error("probeFrame is not deterministic")
	}
	// A healthy relay relays it zero times, so one pass is already a loop.
	if probeLoopThreshold != 1 {
		t.Errorf("probeLoopThreshold = %d, want 1: the program only sees received frames, so a probe it sees came back", probeLoopThreshold)
	}
}

func TestIPChecksumMatchesAKnownHeader(t *testing.T) {
	// RFC 1071's worked example header, checksum field zeroed.
	h := []byte{0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00,
		0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7}
	if got, want := ipChecksum(h), uint16(0xb861); got != want {
		t.Fatalf("ipChecksum = %#04x, want %#04x", got, want)
	}
	// Filled in, the same header checksums to zero.
	binary.BigEndian.PutUint16(h[10:12], 0xb861)
	if got := ipChecksum(h); got != 0 {
		t.Fatalf("a complete header must checksum to 0, got %#04x", got)
	}
}
