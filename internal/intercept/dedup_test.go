// SPDX-License-Identifier: AGPL-3.0-or-later

package intercept

import (
	"encoding/binary"
	"testing"
	"time"

	"shepherd/internal/arp"
)

func TestDedupDropsTheSameFrameInsideTheWindowOnly(t *testing.T) {
	d := &Dedup{}
	f := tcpFrame4(devIP, remoteIP, 50000, 443, 1000, tcpFlagACK)
	if d.Seen(f, t0) {
		t.Fatal("the first copy is never a duplicate")
	}
	if !d.Seen(f, t0.Add(50*time.Microsecond)) {
		t.Fatal("the same frame 50us later is the loop's second pass")
	}
	if !d.Seen(f, t0.Add(99*time.Millisecond)) {
		t.Fatal("still inside the window")
	}
	// A genuine retransmission comes no sooner than 200ms after the
	// previous copy; the window is well short of that.
	if d.Seen(f, t0.Add(99*time.Millisecond+DefaultDedupWindow)) {
		t.Fatal("a frame outside the window is not a duplicate")
	}
	// Time going backwards (a clock step) never counts as a duplicate.
	if d.Seen(f, t0) {
		t.Fatal("an earlier timestamp must not match")
	}
}

func TestDedupTellsDifferentFramesApart(t *testing.T) {
	d := &Dedup{}
	base := tcpFrame4(devIP, remoteIP, 50000, 443, 1000, tcpFlagACK)
	d.Seen(base, t0)
	variants := map[string][]byte{
		"ack advanced":   tcpFrame4(devIP, remoteIP, 50000, 443, 1001, tcpFlagACK),
		"other port":     tcpFrame4(devIP, remoteIP, 50001, 443, 1000, tcpFlagACK),
		"other remote":   tcpFrame4(devIP, ip(9), 50000, 443, 1000, tcpFlagACK),
		"other ip id":    withIPID(base, 7),
		"other length":   append(append([]byte(nil), base...), 0),
		"other protocol": withByte(base, ethHeaderLen+9, 17),
	}
	for name, v := range variants {
		if d.Seen(v, t0.Add(time.Microsecond)) {
			t.Errorf("%s was taken for a duplicate of the base frame", name)
		}
	}
	// Frames the brake cannot fingerprint are never duplicates.
	arpF := ethFrame(shepherdMAC, devMAC, etherTypeARP, make([]byte, 28))
	if d.Seen(arpF, t0) || d.Seen(arpF, t0) {
		t.Error("an ARP frame was taken for a duplicate")
	}
	if d.Seen([]byte{1, 2}, t0) || d.Seen(ethFrame(shepherdMAC, devMAC, etherTypeIPv4, []byte{1}), t0) {
		t.Error("a truncated frame was taken for a duplicate")
	}
	if _, ok := Fingerprint(ethFrame(shepherdMAC, devMAC, etherTypeIPv6, make([]byte, 10))); ok {
		t.Error("a truncated IPv6 frame was fingerprinted")
	}
}

func withIPID(f []byte, id uint16) []byte {
	out := append([]byte(nil), f...)
	binary.BigEndian.PutUint16(out[ethHeaderLen+4:ethHeaderLen+6], id)
	return out
}

func TestDedupCoversIPv6AndSmallTables(t *testing.T) {
	d := &Dedup{Slots: 2, Window: time.Second}
	f6 := tcpFrame6(devIP6, someV6, 40000, 80, 10, tcpFlagACK)
	if d.Seen(f6, t0) || !d.Seen(f6, t0.Add(time.Millisecond)) {
		t.Fatal("IPv6 duplicate not caught")
	}
	if d.Seen(tcpFrame6(devIP6, someV6, 40000, 80, 11, tcpFlagACK), t0) {
		t.Fatal("a different IPv6 segment was taken for a duplicate")
	}
	// Two slots: an eviction costs one unsuppressed pass, never a wrong
	// suppression.
	for i := uint16(0); i < 50; i++ {
		d.Seen(tcpFrame4(devIP, remoteIP, 50000+i, 443, 1, tcpFlagACK), t0)
	}
	if d.Seen(tcpFrame4(devIP, remoteIP, 1, 443, 1, tcpFlagACK), t0) {
		t.Fatal("a never-seen frame was suppressed")
	}
}

func TestRelayDropsADuplicateAndTheControllerCountsIt(t *testing.T) {
	c, _, _ := newTestController(t, nil)
	if err := c.Steer(DeviceRef{MAC: devMAC, IP: devIP}, SteerOptions{}); err != nil {
		t.Fatal(err)
	}
	w := c.NewRelay(NewFakeSender())
	f := tcpFrame4(devIP, remoteIP, 50000, 443, 1000, tcpFlagACK)
	if ok, _ := w.HandleFrame(f); !ok {
		t.Fatal("the first copy must be relayed")
	}
	for i := 0; i < 3; i++ {
		if ok, err := w.HandleFrame(f); ok || err != nil {
			t.Fatalf("copy %d: relayed=%v err=%v, want dropped", i+2, ok, err)
		}
	}
	// A different frame is still relayed.
	if ok, _ := w.HandleFrame(tcpFrame4(devIP, remoteIP, 50000, 443, 1500, tcpFlagACK)); !ok {
		t.Fatal("a different frame must be relayed")
	}
	if got := c.DuplicatesSuppressed(); got != 3 {
		t.Fatalf("DuplicatesSuppressed = %d, want 3", got)
	}
	if got := c.DuplicatesByDevice(); got[devMAC] != 3 {
		t.Fatalf("DuplicatesByDevice = %v, want 3 for the device", got)
	}
	st := c.Status()
	if st[0].PacketsRelayed != 2 || st[0].DuplicatesSuppressed != 3 {
		t.Fatalf("Status = %+v, want 2 relayed and 3 duplicates", st[0])
	}
	if c.Stats().DuplicatesSuppressed != 3 {
		t.Fatalf("Stats duplicates = %d", c.Stats().DuplicatesSuppressed)
	}
	// The Controller's own relay has the brake too.
	g := tcpFrame4(devIP, remoteIP, 50002, 443, 7, tcpFlagACK)
	c.HandleFrame(g)
	if ok, _ := c.HandleFrame(g); ok {
		t.Fatal("the Controller's own relay relayed a duplicate")
	}
	if c.DuplicatesSuppressed() != 4 {
		t.Fatalf("DuplicatesSuppressed = %d, want 4", c.DuplicatesSuppressed())
	}
	// A duplicate from a device that is no longer steered still counts in
	// the total, not against any device.
	if err := c.Unsteer(devMAC); err != nil {
		t.Fatal(err)
	}
	c.recordDuplicate(devMAC, SteerV4)
	if c.DuplicatesSuppressed() != 5 || len(c.DuplicatesByDevice()) != 0 {
		t.Fatalf("after unsteer: total %d by-device %v", c.DuplicatesSuppressed(), c.DuplicatesByDevice())
	}
	var _ arp.MAC = devMAC
}

func TestRelayWithoutADedupRelaysEverything(t *testing.T) {
	sender := NewFakeSender()
	r := &Relay{Sender: sender, ShepherdMAC: shepherdMAC, GatewayMAC: gwMAC, Lookup: steeredLookup(devMAC, devIP)}
	f := tcpFrame4(devIP, remoteIP, 50000, 443, 1000, tcpFlagACK)
	for i := 0; i < 3; i++ {
		if ok, _ := r.HandleFrame(f); !ok {
			t.Fatalf("copy %d not relayed without a brake", i+1)
		}
	}
}
