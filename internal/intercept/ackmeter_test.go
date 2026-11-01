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

// tcpSegment builds a 20-byte TCP header with the given ports, ack number
// and flags. Sequence number, window and checksum are zero: the meter
// never reads them.
func tcpSegment(sport, dport uint16, ack uint32, flags byte) []byte {
	b := make([]byte, tcpHeaderMin)
	binary.BigEndian.PutUint16(b[0:2], sport)
	binary.BigEndian.PutUint16(b[2:4], dport)
	binary.BigEndian.PutUint32(b[8:12], ack)
	b[12] = 5 << 4 // data offset: 5 words
	b[13] = flags
	return b
}

// tcpFrame4 is an outbound IPv4 TCP frame from the steered device to a
// remote, as the relay would capture it.
func tcpFrame4(srcIP, dstIP netip.Addr, sport, dport uint16, ack uint32, flags byte) []byte {
	f := ipv4Frame(shepherdMAC, devMAC, srcIP, dstIP, tcpSegment(sport, dport, ack, flags))
	f[ethHeaderLen+9] = ipProtoTCP
	return f
}

func tcpFrame6(srcIP, dstIP netip.Addr, sport, dport uint16, ack uint32, flags byte) []byte {
	f := ipv6Frame(shepherdMAC, devMAC, srcIP, dstIP, 64, tcpSegment(sport, dport, ack, flags))
	f[ethHeaderLen+6] = ipProtoTCP
	return f
}

var remoteIP = netip.AddrFrom4([4]byte{203, 0, 113, 7})

func TestAckMeterCreditsAdvancesAfterABaseline(t *testing.T) {
	m := &AckMeter{}
	now := t0
	// First ACK on an unknown connection: baseline only.
	if n := m.Observe(tcpFrame4(devIP, remoteIP, 50000, 443, 1000, tcpFlagACK), now); n != 0 {
		t.Fatalf("first ACK credited %d, want 0 (baseline)", n)
	}
	if n := m.Observe(tcpFrame4(devIP, remoteIP, 50000, 443, 1000+1460, tcpFlagACK), now); n != 1460 {
		t.Fatalf("advance credited %d, want 1460", n)
	}
	if n := m.Observe(tcpFrame4(devIP, remoteIP, 50000, 443, 1000+1460, tcpFlagACK), now); n != 0 {
		t.Fatalf("duplicate ACK credited %d, want 0", n)
	}
	if n := m.Observe(tcpFrame4(devIP, remoteIP, 50000, 443, 1000+1460*3, tcpFlagACK), now); n != 2920 {
		t.Fatalf("second advance credited %d, want 2920", n)
	}
	if m.Flows() != 1 {
		t.Fatalf("flows = %d, want 1", m.Flows())
	}
}

func TestAckMeterKeepsConnectionsApart(t *testing.T) {
	m := &AckMeter{}
	m.Observe(tcpFrame4(devIP, remoteIP, 50000, 443, 100, tcpFlagACK), t0)
	m.Observe(tcpFrame4(devIP, remoteIP, 50001, 443, 5000, tcpFlagACK), t0)
	if n := m.Observe(tcpFrame4(devIP, remoteIP, 50001, 443, 5000+10, tcpFlagACK), t0); n != 10 {
		t.Fatalf("second connection credited %d, want 10", n)
	}
	if n := m.Observe(tcpFrame4(devIP, remoteIP, 50000, 443, 100+7, tcpFlagACK), t0); n != 7 {
		t.Fatalf("first connection credited %d, want 7", n)
	}
	if m.Flows() != 2 {
		t.Fatalf("flows = %d, want 2", m.Flows())
	}
}

func TestAckMeterHandlesWraparound(t *testing.T) {
	m := &AckMeter{}
	m.Observe(tcpFrame4(devIP, remoteIP, 50000, 443, 0xffffff00, tcpFlagACK), t0)
	if n := m.Observe(tcpFrame4(devIP, remoteIP, 50000, 443, 0x00000100, tcpFlagACK), t0); n != 0x200 {
		t.Fatalf("wrapped advance credited %d, want %d", n, 0x200)
	}
}

func TestAckMeterRebaselinesOnAnImplausibleJump(t *testing.T) {
	m := &AckMeter{}
	m.Observe(tcpFrame4(devIP, remoteIP, 50000, 443, 1000, tcpFlagACK), t0)
	// A port pair reused by a brand-new connection with a random ISN.
	if n := m.Observe(tcpFrame4(devIP, remoteIP, 50000, 443, 1000+MaxAdvance, tcpFlagACK), t0); n != 0 {
		t.Fatalf("jump of MaxAdvance credited %d, want 0", n)
	}
	// ...and the new baseline is the jump's value.
	if n := m.Observe(tcpFrame4(devIP, remoteIP, 50000, 443, 1000+MaxAdvance+5, tcpFlagACK), t0); n != 5 {
		t.Fatalf("after re-baseline credited %d, want 5", n)
	}
	// A backwards ACK (an out-of-order capture) is a huge unsigned delta
	// too, so it re-baselines rather than crediting ~4 GiB.
	if n := m.Observe(tcpFrame4(devIP, remoteIP, 50000, 443, 1000+MaxAdvance, tcpFlagACK), t0); n != 0 {
		t.Fatalf("backwards ACK credited %d, want 0", n)
	}
}

func TestAckMeterIgnoresSYNAndForgetsOnRSTAndFIN(t *testing.T) {
	m := &AckMeter{}
	const syn = 0x02
	if n := m.Observe(tcpFrame4(devIP, remoteIP, 50000, 443, 0, syn), t0); n != 0 || m.Flows() != 0 {
		t.Fatalf("SYN: credit %d flows %d, want 0 and 0", n, m.Flows())
	}
	m.Observe(tcpFrame4(devIP, remoteIP, 50000, 443, 100, tcpFlagACK), t0)
	m.Observe(tcpFrame4(devIP, remoteIP, 50000, 443, 100, tcpFlagACK|tcpFlagRST), t0)
	if m.Flows() != 0 {
		t.Fatalf("RST left %d flows, want 0", m.Flows())
	}
	m.Observe(tcpFrame4(devIP, remoteIP, 50000, 443, 100, tcpFlagACK), t0)
	if n := m.Observe(tcpFrame4(devIP, remoteIP, 50000, 443, 160, tcpFlagACK|tcpFlagFIN), t0); n != 60 {
		t.Fatalf("FIN credited %d, want 60", n)
	}
	if m.Flows() != 0 {
		t.Fatalf("FIN left %d flows, want 0", m.Flows())
	}
}

func TestAckMeterIgnoresNonTCPAndMalformedFrames(t *testing.T) {
	m := &AckMeter{}
	udp := ipv4Frame(shepherdMAC, devMAC, devIP, remoteIP, tcpSegment(1, 2, 999, tcpFlagACK))
	udp[ethHeaderLen+9] = 17
	cases := map[string][]byte{
		"udp":           udp,
		"arp":           ethFrame(shepherdMAC, devMAC, etherTypeARP, make([]byte, 28)),
		"short eth":     []byte{1, 2, 3},
		"short ip":      ethFrame(shepherdMAC, devMAC, etherTypeIPv4, make([]byte, 10)),
		"truncated tcp": ipv4Frame(shepherdMAC, devMAC, devIP, remoteIP, []byte{6}),
		"later frag":    withFragOffset(tcpFrame4(devIP, remoteIP, 50000, 443, 5, tcpFlagACK), 185),
		"bad version":   withByte(tcpFrame4(devIP, remoteIP, 50000, 443, 5, tcpFlagACK), ethHeaderLen, 0x65),
		"ihl too small": withByte(tcpFrame4(devIP, remoteIP, 50000, 443, 5, tcpFlagACK), ethHeaderLen, 0x44),
		"v6 not tcp":    withByte(tcpFrame6(devIP6, someV6, 50000, 443, 5, tcpFlagACK), ethHeaderLen+6, 17),
		"v6 short":      ethFrame(shepherdMAC, devMAC, etherTypeIPv6, make([]byte, ipv6HeaderLen+4)),
		"v6 bad ver":    withByte(tcpFrame6(devIP6, someV6, 50000, 443, 5, tcpFlagACK), ethHeaderLen, 0x45),
	}
	for name, f := range cases {
		if n := m.Observe(f, t0); n != 0 {
			t.Errorf("%s: credited %d", name, n)
		}
		if n := m.Observe(f, t0); n != 0 {
			t.Errorf("%s (again): credited %d", name, n)
		}
	}
	if m.Flows() != 0 {
		t.Fatalf("flows = %d, want 0", m.Flows())
	}
}

func withByte(f []byte, i int, v byte) []byte {
	out := append([]byte(nil), f...)
	out[i] = v
	return out
}

func withFragOffset(f []byte, off uint16) []byte {
	out := append([]byte(nil), f...)
	binary.BigEndian.PutUint16(out[ethHeaderLen+6:ethHeaderLen+8], off)
	return out
}

func TestAckMeterReadsIPv4OptionsAndIPv6(t *testing.T) {
	m := &AckMeter{}
	// IPv4 with 8 bytes of options (IHL 7): the TCP header moves.
	opts := func(ack uint32) []byte {
		hdr := make([]byte, 28)
		hdr[0] = 0x47
		hdr[9] = ipProtoTCP
		s, d := devIP.As4(), remoteIP.As4()
		copy(hdr[12:16], s[:])
		copy(hdr[16:20], d[:])
		return ethFrame(shepherdMAC, devMAC, etherTypeIPv4, append(hdr, tcpSegment(40000, 80, ack, tcpFlagACK)...))
	}
	m.Observe(opts(10), t0)
	if n := m.Observe(opts(25), t0); n != 15 {
		t.Fatalf("IPv4 with options credited %d, want 15", n)
	}
	m.Observe(tcpFrame6(devIP6, someV6, 40000, 80, 10, tcpFlagACK), t0)
	if n := m.Observe(tcpFrame6(devIP6, someV6, 40000, 80, 110, tcpFlagACK), t0); n != 100 {
		t.Fatalf("IPv6 credited %d, want 100", n)
	}
	// An IPv4 and an IPv6 connection on the same ports are different flows.
	if m.Flows() != 2 {
		t.Fatalf("flows = %d, want 2", m.Flows())
	}
}

func TestAckMeterSweepsIdleFlowsAndRespectsTheCap(t *testing.T) {
	m := &AckMeter{MaxFlows: 2, IdleTimeout: time.Minute}
	m.Observe(tcpFrame4(devIP, remoteIP, 1, 443, 1, tcpFlagACK), t0)
	m.Observe(tcpFrame4(devIP, remoteIP, 2, 443, 1, tcpFlagACK), t0)
	// Full: a third connection is not admitted while the others are fresh.
	m.Observe(tcpFrame4(devIP, remoteIP, 3, 443, 1, tcpFlagACK), t0.Add(time.Second))
	if m.Flows() != 2 {
		t.Fatalf("flows = %d, want 2 (cap)", m.Flows())
	}
	if n := m.Observe(tcpFrame4(devIP, remoteIP, 3, 443, 50, tcpFlagACK), t0.Add(time.Second)); n != 0 {
		t.Fatalf("un-admitted connection credited %d", n)
	}
	// Still tracked connections keep metering.
	if n := m.Observe(tcpFrame4(devIP, remoteIP, 1, 443, 11, tcpFlagACK), t0.Add(2*time.Second)); n != 10 {
		t.Fatalf("tracked connection credited %d, want 10", n)
	}
	// Once the others go idle, the cap sweep frees room.
	later := t0.Add(5 * time.Minute)
	m.Observe(tcpFrame4(devIP, remoteIP, 3, 443, 1, tcpFlagACK), later)
	if m.Flows() != 1 {
		t.Fatalf("flows after idle sweep = %d, want 1", m.Flows())
	}
	// The periodic sweep runs without the cap being hit too.
	m.Observe(tcpFrame4(devIP, remoteIP, 4, 443, 1, tcpFlagACK), later.Add(sweepEvery+5*time.Minute))
	if m.Flows() != 1 {
		t.Fatalf("flows after periodic sweep = %d, want 1", m.Flows())
	}
}

func TestRelayFeedsTheAckMeterOnlyForRelayedFrames(t *testing.T) {
	sender := NewFakeSender()
	var got []uint64
	var gotMAC arp.MAC
	var gotFam Family
	r := &Relay{
		Sender: sender, ShepherdMAC: shepherdMAC, GatewayMAC: gwMAC,
		Lookup: steeredLookupFam(devMAC, devIP, SteerV4|SteerV6),
		Meter:  &AckMeter{},
		OnInferredRx: func(mac arp.MAC, fam Family, n uint64) {
			gotMAC, gotFam = mac, fam
			got = append(got, n)
		},
	}
	// A frame not for Shepherd never reaches the meter, so it is not a
	// baseline either: the next one still counts as the first.
	r.HandleFrame(tcpFrameTo(gwMAC, devIP, remoteIP, 50000, 443, 100))
	if ok, _ := r.HandleFrame(tcpFrame4(devIP, remoteIP, 50000, 443, 1000, tcpFlagACK)); !ok {
		t.Fatal("baseline frame not relayed")
	}
	if ok, _ := r.HandleFrame(tcpFrame4(devIP, remoteIP, 50000, 443, 1500, tcpFlagACK)); !ok {
		t.Fatal("advance frame not relayed")
	}
	if len(got) != 1 || got[0] != 500 || gotMAC != devMAC || gotFam != SteerV4 {
		t.Fatalf("OnInferredRx got %v mac=%v fam=%v, want one credit of 500 for the device over IPv4", got, gotMAC, gotFam)
	}
	r.HandleFrame(tcpFrame6(devIP6, someV6, 50000, 443, 10, tcpFlagACK))
	r.HandleFrame(tcpFrame6(devIP6, someV6, 50000, 443, 30, tcpFlagACK))
	if len(got) != 2 || got[1] != 20 || gotFam != SteerV6 {
		t.Fatalf("IPv6 credit: got %v fam=%v", got, gotFam)
	}
	// A send failure is not a relayed frame, so nothing is metered.
	sender.SetError(errors.New("send failed"))
	r.HandleFrame(tcpFrame4(devIP, remoteIP, 50000, 443, 9000, tcpFlagACK))
	if len(got) != 2 {
		t.Fatalf("a failed send was metered: %v", got)
	}
}

func tcpFrameTo(dst arp.MAC, srcIP, dstIP netip.Addr, sport, dport uint16, ack uint32) []byte {
	f := ipv4Frame(dst, devMAC, srcIP, dstIP, tcpSegment(sport, dport, ack, tcpFlagACK))
	f[ethHeaderLen+9] = ipProtoTCP
	return f
}

func TestRelayWithoutAMeterStillRelays(t *testing.T) {
	sender := NewFakeSender()
	called := false
	r := &Relay{
		Sender: sender, ShepherdMAC: shepherdMAC, GatewayMAC: gwMAC,
		Lookup:       steeredLookup(devMAC, devIP),
		OnInferredRx: func(arp.MAC, Family, uint64) { called = true },
	}
	r.HandleFrame(tcpFrame4(devIP, remoteIP, 50000, 443, 1000, tcpFlagACK))
	if ok, _ := r.HandleFrame(tcpFrame4(devIP, remoteIP, 50000, 443, 1500, tcpFlagACK)); !ok || called {
		t.Fatalf("relayed=%v metered=%v, want relayed and not metered", ok, called)
	}
}

func TestControllerSumsInferredDownloadsPerDeviceAndInTotal(t *testing.T) {
	c, _, _ := newTestController(t, nil)
	if err := c.Steer(DeviceRef{MAC: devMAC, IP: devIP}, SteerOptions{}); err != nil {
		t.Fatal(err)
	}
	// Two workers, as ParallelRelay would build them, each with its own
	// meter; the Controller adds them up.
	w1 := c.NewRelay(NewFakeSender())
	w2 := c.NewRelay(NewFakeSender())
	w1.HandleFrame(tcpFrame4(devIP, remoteIP, 50000, 443, 1000, tcpFlagACK))
	w1.HandleFrame(tcpFrame4(devIP, remoteIP, 50000, 443, 4000, tcpFlagACK))
	w2.HandleFrame(tcpFrame4(devIP, remoteIP, 50001, 443, 0, tcpFlagACK))
	w2.HandleFrame(tcpFrame4(devIP, remoteIP, 50001, 443, 250, tcpFlagACK))
	// The Controller's own relay has a meter too.
	c.HandleFrame(tcpFrame4(devIP, remoteIP, 50002, 443, 7, tcpFlagACK))
	c.HandleFrame(tcpFrame4(devIP, remoteIP, 50002, 443, 8, tcpFlagACK))

	st := c.Status()
	if len(st) != 1 || st[0].BytesReceivedEst != 3251 {
		t.Fatalf("Status BytesReceivedEst = %+v, want 3251", st)
	}
	if got := c.Stats().BytesReceivedEst; got != 3251 {
		t.Fatalf("Stats BytesReceivedEst = %d, want 3251", got)
	}
	// Relayed bytes are still the wire length, unaffected.
	if st[0].PacketsRelayed != 6 {
		t.Fatalf("PacketsRelayed = %d, want 6", st[0].PacketsRelayed)
	}
	// A batch credit (the XDP harvest path) lands in the same place.
	c.recordInferredRxBatch(devMAC, SteerV4, 49)
	if c.Status()[0].BytesReceivedEst != 3300 || c.Stats().BytesReceivedEst != 3300 {
		t.Fatalf("after batch: %d / %d, want 3300", c.Status()[0].BytesReceivedEst, c.Stats().BytesReceivedEst)
	}
	// A device that is not steered is counted in the total only.
	c.recordInferredRxBatch(rndMAC(99), SteerV4, 1)
	if c.Stats().BytesReceivedEst != 3301 {
		t.Fatalf("unsteered credit: total %d, want 3301", c.Stats().BytesReceivedEst)
	}
	c.recordInferredRxBatch(devMAC, SteerV4, 0)
}
