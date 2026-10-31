// SPDX-License-Identifier: AGPL-3.0-or-later

package ndp

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"shepherd/internal/arp"
)

// Test addresses are built from byte arrays rather than text literals, to
// keep link-local address literals out of the source. 02:… MACs are
// locally-administered, the documentation form.
var (
	shepherdMAC = arp.MAC{0x02, 0x00, 0x5e, 0x00, 0x00, 0x01}
	gatewayMAC  = arp.MAC{0x02, 0x00, 0x5e, 0x00, 0x00, 0xfe}
	deviceMAC   = arp.MAC{0x02, 0x00, 0x5e, 0x00, 0x00, 0x42}

	// gateway and device link-local addresses (…::1 and …::42).
	gatewayLL = netip.AddrFrom16([16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01})
	deviceLL  = netip.AddrFrom16([16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42})
)

// verifyChecksum recomputes the ICMPv6 checksum over the pseudo-header and
// message with the checksum field left in place; a correct checksum makes
// the result zero.
func verifyChecksum(t *testing.T, frame []byte) {
	t.Helper()
	if len(frame) < etherHdrLen+ipv6HdrLen {
		t.Fatalf("frame too short: %d", len(frame))
	}
	ip := frame[etherHdrLen:]
	src, dst := ip[8:24], ip[24:40]
	icmp := frame[etherHdrLen+ipv6HdrLen:]
	if got := icmpv6Checksum(src, dst, icmp); got != 0 {
		t.Fatalf("checksum does not verify: recomputed 0x%04x, want 0", got)
	}
}

func TestClaimLayout(t *testing.T) {
	frame, err := Claim(shepherdMAC, deviceMAC, gatewayLL, deviceLL)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if len(frame) != etherHdrLen+ipv6HdrLen+naHdrLen+lenLLAOpt {
		t.Fatalf("frame length %d", len(frame))
	}
	if got := arp.MAC(frame[0:6]); got != deviceMAC {
		t.Errorf("eth dst = %v, want device %v", got, deviceMAC)
	}
	if got := arp.MAC(frame[6:12]); got != shepherdMAC {
		t.Errorf("eth src = %v, want shepherd %v", got, shepherdMAC)
	}
	if et := binary.BigEndian.Uint16(frame[12:14]); et != etherTypeIPv6 {
		t.Errorf("ethertype = 0x%04x, want 0x86dd", et)
	}
	ip := frame[etherHdrLen:]
	if ip[0]>>4 != 6 {
		t.Errorf("IP version = %d, want 6", ip[0]>>4)
	}
	if ip[6] != nextHdrICMPv6 {
		t.Errorf("next header = %d, want 58", ip[6])
	}
	if ip[7] != hopLimitNDP {
		t.Errorf("hop limit = %d, want 255 (RFC 4861)", ip[7])
	}
	icmp := frame[etherHdrLen+ipv6HdrLen:]
	if icmp[0] != icmpTypeNA {
		t.Errorf("ICMPv6 type = %d, want 136 (NA)", icmp[0])
	}
	// Claim: Router + Override, not Solicited.
	if icmp[4] != naFlagRouter|naFlagOverride {
		t.Errorf("flags = 0x%02x, want R|O 0x%02x", icmp[4], naFlagRouter|naFlagOverride)
	}
	if got := netip.AddrFrom16([16]byte(icmp[8:24])); got != gatewayLL {
		t.Errorf("target = %v, want gateway link-local %v", got, gatewayLL)
	}
	if icmp[24] != optTypeTLL || icmp[25] != 1 {
		t.Errorf("option header = %d/%d, want 2/1 (TLLA)", icmp[24], icmp[25])
	}
	if got := arp.MAC(icmp[26:32]); got != shepherdMAC {
		t.Errorf("TLLA = %v, want shepherd %v", got, shepherdMAC)
	}
	verifyChecksum(t, frame)
}

func TestCorrectiveRestoresGateway(t *testing.T) {
	frame, err := Corrective(gatewayMAC, deviceMAC, gatewayLL, deviceLL)
	if err != nil {
		t.Fatalf("Corrective: %v", err)
	}
	if got := arp.MAC(frame[6:12]); got != gatewayMAC {
		t.Errorf("eth src = %v, want gateway %v", got, gatewayMAC)
	}
	icmp := frame[etherHdrLen+ipv6HdrLen:]
	if got := arp.MAC(icmp[26:32]); got != gatewayMAC {
		t.Errorf("TLLA = %v, want gateway's real MAC %v", got, gatewayMAC)
	}
	if icmp[4]&naFlagOverride == 0 {
		t.Error("corrective must set Override to overwrite Shepherd's claim")
	}
	if icmp[4]&naFlagRouter == 0 {
		t.Error("corrective must set Router, or the device drops its default route")
	}
	verifyChecksum(t, frame)
}

func TestSolicitedReplySetsSolicited(t *testing.T) {
	frame, err := SolicitedReply(shepherdMAC, deviceMAC, gatewayLL, deviceLL)
	if err != nil {
		t.Fatalf("SolicitedReply: %v", err)
	}
	icmp := frame[etherHdrLen+ipv6HdrLen:]
	want := naFlagRouter | naFlagSolicited | naFlagOverride
	if icmp[4] != byte(want) {
		t.Errorf("flags = 0x%02x, want R|S|O 0x%02x", icmp[4], want)
	}
	verifyChecksum(t, frame)
}

func TestMarshalRejectsIPv4(t *testing.T) {
	v4 := netip.MustParseAddr("192.0.2.1")
	_, err := Advertisement{
		EthSrc: shepherdMAC, EthDst: deviceMAC,
		SrcIP: gatewayLL, DstIP: v4, Target: gatewayLL, TargetLLA: shepherdMAC,
		Flags: steerFlags,
	}.Marshal()
	if err != ErrNotIPv6 {
		t.Fatalf("Marshal with IPv4 dst: err = %v, want ErrNotIPv6", err)
	}
}

func TestMarshalRejectsMulticast(t *testing.T) {
	// ff02::1 all-nodes: the one address that would reach every device on
	// the LAN, Thread/Matter gear included. Marshal must refuse it.
	allNodes := netip.AddrFrom16([16]byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01})
	_, err := Advertisement{
		EthSrc: shepherdMAC, EthDst: arp.MAC{0x33, 0x33, 0, 0, 0, 0x01},
		SrcIP: gatewayLL, DstIP: allNodes, Target: gatewayLL, TargetLLA: shepherdMAC,
		Flags: steerFlags,
	}.Marshal()
	if err != ErrMulticast {
		t.Fatalf("Marshal with multicast dst: err = %v, want ErrMulticast", err)
	}
}

// buildNS hand-builds a Neighbor Solicitation frame for the parse tests
// (this package deliberately has no NS builder of its own).
func buildNS(ethSrc, ethDst arp.MAC, srcIP, dstIP, target netip.Addr, withSLL bool) []byte {
	icmpLen := nsHdrLen
	if withSLL {
		icmpLen += lenLLAOpt
	}
	frame := make([]byte, etherHdrLen+ipv6HdrLen+icmpLen)
	copy(frame[0:6], ethDst[:])
	copy(frame[6:12], ethSrc[:])
	binary.BigEndian.PutUint16(frame[12:14], etherTypeIPv6)
	ip := frame[etherHdrLen:]
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], uint16(icmpLen))
	ip[6] = nextHdrICMPv6
	ip[7] = hopLimitNDP
	s16, d16 := srcIP.As16(), dstIP.As16()
	copy(ip[8:24], s16[:])
	copy(ip[24:40], d16[:])
	icmp := frame[etherHdrLen+ipv6HdrLen:]
	icmp[0] = icmpTypeNS
	tg := target.As16()
	copy(icmp[8:24], tg[:])
	if withSLL {
		icmp[24] = optTypeSLL
		icmp[25] = 1
		copy(icmp[26:32], ethSrc[:])
	}
	return frame
}

func TestParseSolicitation(t *testing.T) {
	frame := buildNS(deviceMAC, shepherdMAC, deviceLL, gatewayLL, gatewayLL, true)
	s, err := ParseSolicitation(frame)
	if err != nil {
		t.Fatalf("ParseSolicitation: %v", err)
	}
	if s.EthSrc != deviceMAC {
		t.Errorf("EthSrc = %v, want %v", s.EthSrc, deviceMAC)
	}
	if s.Target != gatewayLL {
		t.Errorf("Target = %v, want %v", s.Target, gatewayLL)
	}
	if !s.HasSourceLLA || s.SourceLLA != deviceMAC {
		t.Errorf("SourceLLA = %v/%v, want %v/true", s.SourceLLA, s.HasSourceLLA, deviceMAC)
	}
}

func TestParseSolicitationRejectsNonNS(t *testing.T) {
	// A Neighbor Advertisement is ICMPv6 but not an NS.
	na, _ := Claim(shepherdMAC, deviceMAC, gatewayLL, deviceLL)
	if _, err := ParseSolicitation(na); err != ErrNotNS {
		t.Fatalf("parsing an NA as NS: err = %v, want ErrNotNS", err)
	}
	if _, err := ParseSolicitation([]byte{1, 2, 3}); err == nil {
		t.Fatal("parsing 3 bytes: want an error")
	}
}

// FuzzParseSolicitation: no input ever panics, and anything parsed as an
// NS has a well-formed target address read back.
func FuzzParseSolicitation(f *testing.F) {
	f.Add(buildNS(deviceMAC, shepherdMAC, deviceLL, gatewayLL, gatewayLL, true))
	f.Add(buildNS(deviceMAC, shepherdMAC, deviceLL, gatewayLL, gatewayLL, false))
	na, _ := Claim(shepherdMAC, deviceMAC, gatewayLL, deviceLL)
	f.Add(na)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, in []byte) {
		s, err := ParseSolicitation(in) // must never panic
		if err == nil && !s.Target.Is6() {
			t.Fatalf("parsed NS with non-IPv6 target: % x", in)
		}
	})
}
