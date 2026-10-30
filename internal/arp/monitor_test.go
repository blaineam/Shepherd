// SPDX-License-Identifier: AGPL-3.0-or-later

package arp

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"shepherd/internal/devices"
)

func claimFrame(m MAC, a netip.Addr) Frame { return NewRequest(m, a, ip(1)) }

func TestScenarioDHCPThenARP(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Gateway = ip(1) })
	phone := rnd(0x20)
	// Router is known first.
	h.send(NewAnnounce(stable(1), ip(1)), 0)
	// DHCP client: probe, announce, then ordinary resolution.
	h.send(NewProbe(phone, ip(30)), 10*time.Second)
	h.send(NewAnnounce(phone, ip(30)), 11*time.Second)
	h.send(NewRequest(phone, ip(30), ip(1)), 12*time.Second)
	h.send(NewReply(stable(1), ip(1), phone, ip(30)), 12*time.Second) // solicited
	h.send(NewRequest(phone, ip(30), ip(1)), 20*time.Second)          // chatty repeat

	obs := h.sink.list()
	if len(obs) != 2 {
		t.Fatalf("observations = %+v", obs)
	}
	o := obs[1]
	if o.Source != devices.SourceARP || o.MAC != phone.String() || o.IP != "192.0.2.30" || !o.Time.Equal(at(11*time.Second)) {
		t.Fatalf("obs = %+v", o)
	}
	if h.count(EventNewMAC) != 2 || len(h.evs) != 2 {
		t.Fatalf("events = %+v", h.evs)
	}
	ev := h.find(EventNewMAC)
	if ev.Severity != SeverityInfo || !ev.Baseline || ev.Key != "arp:new-mac-seen:"+stable(1).String() {
		t.Fatalf("event %+v", ev)
	}
	if h.evs[1].Evidence["randomized"] != "true" {
		t.Fatalf("randomized evidence: %+v", h.evs[1])
	}
	st := h.m.Stats()
	if st.Frames != 6 || st.Probes != 1 || st.Gratuitous != 2 || st.Observations != 2 ||
		st.UnsolicitedReplies != 0 || st.Events[EventNewMAC] != 2 || st.TrackedMACs != 2 || st.TrackedIPs != 2 {
		t.Fatalf("stats %+v", st)
	}
	// After the interval the pair is observed again; after the learn period events are not baseline.
	h.send(claimFrame(phone, ip(30)), 6*time.Minute)
	if got := h.sink.list(); len(got) != 3 {
		t.Fatalf("expected refreshed observation, got %d", len(got))
	}
	h.send(claimFrame(stable(9), ip(40)), 7*time.Minute)
	if last := h.evs[len(h.evs)-1]; last.Baseline {
		t.Fatal("baseline flag after learning period")
	}
}

func TestDeviceChangesIP(t *testing.T) {
	h := newHarness(t, nil)
	d := stable(5)
	h.send(claimFrame(d, ip(40)), 0)
	h.send(claimFrame(d, ip(41)), time.Hour)
	if len(h.sink.list()) != 2 {
		t.Fatal("both addresses should be observed")
	}
	if h.count(EventIPMoved)+h.count(EventDuplicateIP) != 0 || h.count(EventNewMAC) != 1 {
		t.Fatalf("a device changing IP is not an event: %+v", h.evs)
	}
}

func TestRandomizationRotation(t *testing.T) {
	h := newHarness(t, nil)
	h.send(claimFrame(rnd(1), ip(50)), 0)
	h.send(claimFrame(rnd(2), ip(50)), 30*time.Minute) // old MAC long gone
	ev := h.find(EventIPMoved)
	if ev == nil || ev.Severity != SeverityInfo || ev.OtherMAC != rnd(1).String() || ev.Evidence["reason"] != "randomized address rotation" {
		t.Fatalf("event %+v", ev)
	}
	if h.find(EventSpoofingSuspected) != nil {
		t.Fatal("rotation must not feed the spoofing summary")
	}
}

func TestIPHandoverSeverities(t *testing.T) {
	h := newHarness(t, nil)
	h.send(claimFrame(stable(1), ip(60)), 0)
	h.send(claimFrame(stable(2), ip(60)), 30*time.Minute)
	if ev := h.find(EventIPMoved); ev == nil || ev.Severity != SeverityLow {
		t.Fatalf("quiet handover: %+v", ev)
	}
	// An owner still chatting elsewhere makes it medium.
	h2 := newHarness(t, nil)
	h2.send(claimFrame(stable(1), ip(60)), 0)
	h2.send(claimFrame(stable(1), ip(61)), 30*time.Second)
	h2.send(claimFrame(stable(2), ip(60)), time.Minute)
	if ev := h2.find(EventIPMoved); ev == nil || ev.Severity != SeverityMedium {
		t.Fatalf("active owner: %+v", ev)
	}
	// Evicted/unknown previous owner counts as quiet.
	h3 := newHarness(t, func(c *Config) { c.MaxTracked = 2 })
	h3.send(claimFrame(stable(1), ip(60)), 0)
	h3.send(claimFrame(stable(2), ip(61)), time.Second)
	h3.send(claimFrame(stable(3), ip(62)), 2*time.Second) // evicts stable(1)'s MAC record
	h3.send(claimFrame(stable(4), ip(60)), 3*time.Second)
	if h3.count(EventIPMoved) != 0 { // the IP record was evicted too, so it is just new
		t.Fatalf("events %+v", h3.evs)
	}
	if st := h3.m.Stats(); st.TrackedMACs > 2 || st.TrackedIPs > 2 {
		t.Fatalf("tables exceed cap: %+v", st)
	}
}

func TestGatewayMACChangeRaisedOnce(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Gateway = ip(1) })
	router, attacker := stable(1), stable(66)
	for i := 0; i < 5; i++ {
		h.send(NewAnnounce(router, ip(1)), time.Duration(i)*time.Minute)
	}
	if h.count(EventGatewayMACChanged) != 0 {
		t.Fatal("false positive on steady gateway")
	}
	for i := 0; i < 100; i++ {
		h.send(NewGratuitousReply(attacker, ip(1)), 10*time.Minute+time.Duration(i)*time.Second/10)
	}
	if n := h.count(EventGatewayMACChanged); n != 1 {
		t.Fatalf("gateway events = %d, want 1", n)
	}
	ev := h.find(EventGatewayMACChanged)
	if ev.Severity != SeverityHigh || ev.MAC != attacker.String() || ev.OtherMAC != router.String() || ev.IP != "192.0.2.1" ||
		ev.Evidence["expected_mac"] != router.String() || ev.Evidence["pinned"] != "false" {
		t.Fatalf("event %+v", ev)
	}
	if ev.Key != "arp:gateway-mac-changed:192.0.2.1:"+router.String()+":"+attacker.String() {
		t.Fatalf("key %s", ev.Key)
	}
	// The gateway IP changing hands is reported as the gateway event only.
	if h.count(EventIPMoved) != 0 {
		t.Fatal("duplicate ip-moved report for the gateway")
	}
	// The router answering again is one more transition (reverse key), then it stays quiet.
	for i := 0; i < 20; i++ {
		h.send(NewAnnounce(router, ip(1)), 11*time.Minute+time.Duration(i)*time.Second)
	}
	// A renewed fight inside the cooldown cannot raise either key again.
	for i := 0; i < 10; i++ {
		h.send(NewGratuitousReply(attacker, ip(1)), 12*time.Minute+time.Duration(i)*time.Second)
		h.send(NewAnnounce(router, ip(1)), 12*time.Minute+time.Duration(i)*time.Second+time.Millisecond)
	}
	if n := h.count(EventGatewayMACChanged); n != 2 {
		t.Fatalf("flapping produced %d gateway events, want 2", n)
	}
	if h.m.Stats().EventsSuppressed == 0 {
		t.Fatal("cooldown never suppressed")
	}
}

func TestGatewayPinned(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Gateway = ip(1); c.GatewayMAC = stable(1) })
	h.send(NewAnnounce(stable(66), ip(1)), 0) // first sighting already wrong
	if ev := h.find(EventGatewayMACChanged); ev == nil || ev.Evidence["pinned"] != "true" || ev.OtherMAC != stable(1).String() {
		t.Fatalf("pinned mismatch: %+v", h.evs)
	}
	h.send(NewAnnounce(stable(66), ip(1)), time.Second)
	if h.count(EventGatewayMACChanged) != 1 {
		t.Fatal("pinned repeat not deduped")
	}
	h.send(NewAnnounce(stable(1), ip(1)), 2*time.Second)
	if h.count(EventGatewayMACChanged) != 1 {
		t.Fatal("the pinned MAC is fine")
	}
}

func TestGatewayLearnedFromFunc(t *testing.T) {
	calls := 0
	gw := ip(1)
	var errs []error
	fail := false
	h := newHarness(t, func(c *Config) {
		c.GatewayFunc = func() (netip.Addr, error) {
			calls++
			if fail {
				return netip.Addr{}, errors.New("no route")
			}
			return gw, nil
		}
		c.OnError = func(err error) { errs = append(errs, err) }
	})
	h.send(NewAnnounce(stable(1), ip(1)), 0)
	h.send(NewAnnounce(stable(2), ip(1)), time.Second) // moved, and the gateway is known by now
	if calls != 1 || h.count(EventGatewayMACChanged) != 1 {
		t.Fatalf("calls=%d events=%+v", calls, h.evs)
	}
	// Refresh interval: lookup fails, error reported, old gateway kept.
	fail = true
	h.send(NewAnnounce(stable(2), ip(1)), 10*time.Minute)
	if calls != 2 || len(errs) != 1 || !strings.Contains(errs[0].Error(), "no route") {
		t.Fatalf("calls=%d errs=%v", calls, errs)
	}
	// The gateway moves to another address: baseline resets, no event.
	fail, gw = false, ip(254)
	h.send(NewAnnounce(stable(7), ip(254)), 20*time.Minute)
	h.send(NewAnnounce(stable(7), ip(254)), 20*time.Minute+time.Second)
	if h.count(EventGatewayMACChanged) != 1 {
		t.Fatalf("events %+v", h.evs)
	}
	// An unusable answer is ignored.
	gw = netip.MustParseAddr("0.0.0.0")
	h.send(NewAnnounce(stable(7), ip(254)), time.Hour)
	// A backwards clock re-reads rather than waiting forever.
	h.send(NewAnnounce(stable(7), ip(254)), -time.Hour)
}

func TestNoGatewayKnownMeansNoGatewayEvents(t *testing.T) {
	h := newHarness(t, nil)
	h.send(NewAnnounce(stable(1), ip(1)), 0)
	h.send(NewAnnounce(stable(2), ip(1)), time.Second)
	if h.count(EventGatewayMACChanged) != 0 || h.count(EventIPMoved) != 1 {
		t.Fatalf("%+v", h.evs)
	}
}

func TestSpoofingBurstRaisesSummaryOnce(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Gateway = ip(1) })
	router, atk := stable(1), stable(66)
	h.send(NewAnnounce(router, ip(1)), 0)
	h.send(claimFrame(stable(10), ip(10)), time.Second)
	// Attacker claims the gateway: HIGH gateway event, but one signal alone is not a summary.
	h.send(NewGratuitousReply(atk, ip(1)), time.Minute)
	if h.find(EventSpoofingSuspected) != nil {
		t.Fatal("one signal produced a summary")
	}
	// Then poisons a victim: replies nobody asked for.
	for i := 0; i < 10; i++ {
		h.send(NewReply(atk, ip(1), stable(10), ip(10)), time.Minute+time.Duration(i)*time.Second)
	}
	n := h.count(EventSpoofingSuspected)
	if n != 1 {
		t.Fatalf("summary events = %d, want 1 (gateway change + storm)", n)
	}
	ev := h.find(EventSpoofingSuspected)
	if ev.Severity != SeverityHigh || ev.MAC != atk.String() || !strings.Contains(ev.Evidence["signals"], "gateway-mac-changed") ||
		ev.Evidence["gateway_involved"] != "true" {
		t.Fatalf("summary %+v", ev)
	}
	if h.count(EventUnsolicitedStorm) != 1 || h.count(EventGatewayMACChanged) != 1 {
		t.Fatalf("events %+v", h.evs)
	}
	// More burst traffic does not repeat any of it.
	for i := 0; i < 50; i++ {
		h.send(NewReply(atk, ip(1), stable(10), ip(10)), 2*time.Minute+time.Duration(i)*time.Second)
	}
	if h.count(EventSpoofingSuspected) != 1 || h.count(EventUnsolicitedStorm) != 1 {
		t.Fatalf("repeats: %+v", h.m.Stats())
	}
}

func TestSpoofingNeedsThreeDistinctSignalsWithoutGateway(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.ManyIPsThreshold = 3; c.GratuitousLimit = 3; c.UnsolicitedLimit = 3 })
	m := stable(70)
	for i := 0; i < 3; i++ { // many IPs
		h.send(claimFrame(m, ip(byte(100+i))), time.Duration(i)*time.Second)
	}
	if h.find(EventManyIPs) == nil || h.find(EventSpoofingSuspected) != nil {
		t.Fatalf("%+v", h.evs)
	}
	for i := 0; i < 3; i++ { // gratuitous flood: second signal
		h.send(NewAnnounce(m, ip(100)), 10*time.Second+time.Duration(i)*time.Millisecond)
	}
	if h.find(EventGratuitousFlood) == nil || h.find(EventSpoofingSuspected) != nil {
		t.Fatalf("two signals must not be enough: %+v", h.evs)
	}
	for i := 0; i < 3; i++ { // unsolicited storm: third signal
		h.send(NewReply(m, ip(100), stable(9), ip(9)), 20*time.Second+time.Duration(i)*time.Millisecond)
	}
	if h.count(EventSpoofingSuspected) != 1 {
		t.Fatalf("%+v", h.evs)
	}
}

func TestSignalsExpire(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.ManyIPsThreshold = 2; c.GratuitousLimit = 2; c.UnsolicitedLimit = 2 })
	m := stable(70)
	for i := 0; i < 2; i++ {
		h.send(claimFrame(m, ip(byte(100+i))), time.Duration(i)*time.Second)
	}
	for i := 0; i < 2; i++ {
		h.send(NewAnnounce(m, ip(100)), time.Hour+time.Duration(i)*time.Millisecond)
	}
	for i := 0; i < 2; i++ {
		h.send(NewReply(m, ip(100), stable(9), ip(9)), 2*time.Hour+time.Duration(i)*time.Millisecond)
	}
	if h.find(EventSpoofingSuspected) != nil {
		t.Fatalf("stale signals combined: %+v", h.evs)
	}
}

func TestManyIPs(t *testing.T) {
	h := newHarness(t, nil)
	m := stable(80)
	for i := 0; i < 7; i++ {
		h.send(claimFrame(m, ip(byte(100+i))), time.Duration(i)*time.Second)
	}
	if h.find(EventManyIPs) != nil {
		t.Fatal("7 addresses is under the threshold")
	}
	h.send(claimFrame(m, ip(120)), 8*time.Second)
	ev := h.find(EventManyIPs)
	if ev == nil || ev.Severity != SeverityMedium || ev.Evidence["count"] != "8" || !strings.Contains(ev.Evidence["ips"], "192.0.2.100") {
		t.Fatalf("%+v", ev)
	}
	for i := 0; i < 20; i++ {
		h.send(claimFrame(m, ip(byte(130+i))), 9*time.Second+time.Duration(i)*time.Second)
	}
	if h.count(EventManyIPs) != 1 {
		t.Fatal("repeated")
	}
}

func TestManyIPsWindowAndExemptions(t *testing.T) {
	// Claims spread beyond the window do not accumulate.
	h := newHarness(t, nil)
	m := stable(80)
	for i := 0; i < 20; i++ {
		h.send(claimFrame(m, ip(byte(100+i))), time.Duration(i)*11*time.Minute)
	}
	if h.find(EventManyIPs) != nil {
		t.Fatal("slow claims flagged")
	}
	// Trusted MACs and the gateway MAC are exempt.
	h2 := newHarness(t, func(c *Config) { c.Gateway = ip(1); c.TrustedMACs = []MAC{stable(81)} })
	h2.send(NewAnnounce(stable(1), ip(1)), 0)
	for i := 0; i < 12; i++ {
		h2.send(claimFrame(stable(81), ip(byte(100+i))), time.Duration(i)*time.Second)
		h2.send(claimFrame(stable(1), ip(byte(150+i))), time.Duration(i)*time.Second)
	}
	if h2.find(EventManyIPs) != nil {
		t.Fatalf("exempt MACs flagged: %+v", h2.evs)
	}
}

func TestPerMACAddressSetIsBounded(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.TrustedMACs = []MAC{stable(1)} })
	for i := 0; i < 300; i++ {
		h.send(claimFrame(stable(1), netip.AddrFrom4([4]byte{192, 0, 2, byte(i)})), time.Duration(i)*time.Millisecond)
	}
	ms, _ := h.m.macs.peek(stable(1))
	if len(ms.ips) > maxIPsPerMAC {
		t.Fatalf("per-MAC set grew to %d", len(ms.ips))
	}
}

func TestDuplicateIPFlipping(t *testing.T) {
	h := newHarness(t, nil)
	a, b := stable(1), stable(2)
	for i := 0; i < 2; i++ {
		h.send(claimFrame(a, ip(70)), time.Duration(i*4)*time.Second)
		h.send(claimFrame(b, ip(70)), time.Duration(i*4+2)*time.Second)
	}
	// owner changes so far: a->b, b->a, a->b = 3 within 2 minutes
	if h.count(EventDuplicateIP) != 1 {
		t.Fatalf("duplicate events = %d: %+v", h.count(EventDuplicateIP), h.evs)
	}
	ev := h.find(EventDuplicateIP)
	if ev.Severity != SeverityMedium || ev.IP != "192.0.2.70" || ev.Key != "arp:duplicate-ip:192.0.2.70" {
		t.Fatalf("%+v", ev)
	}
	for i := 0; i < 20; i++ {
		h.send(claimFrame(a, ip(70)), 20*time.Second+time.Duration(i)*time.Second)
		h.send(claimFrame(b, ip(70)), 20*time.Second+time.Duration(i)*time.Second+time.Millisecond)
	}
	if h.count(EventDuplicateIP) != 1 {
		t.Fatal("duplicate repeated inside cooldown")
	}
}

func TestSlowIPChurnIsNotDuplicate(t *testing.T) {
	h := newHarness(t, nil)
	for i := 0; i < 6; i++ {
		h.send(claimFrame(stable(byte(1+i%2)), ip(70)), time.Duration(i)*10*time.Minute)
	}
	if h.count(EventDuplicateIP) != 0 {
		t.Fatalf("%+v", h.evs)
	}
}

func TestProbeConflict(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Gateway = ip(1) })
	h.send(NewAnnounce(stable(1), ip(1)), 0)
	h.send(claimFrame(stable(5), ip(70)), time.Second)
	h.send(NewProbe(stable(6), ip(70)), 2*time.Second)
	ev := h.find(EventDuplicateIP)
	if ev == nil || ev.Severity != SeverityLow || ev.MAC != stable(6).String() || ev.OtherMAC != stable(5).String() || ev.Evidence["via"] != "probe" {
		t.Fatalf("%+v", ev)
	}
	// Probing the gateway's address is more serious.
	h.send(NewProbe(stable(6), ip(1)), 3*time.Second)
	if n := h.count(EventDuplicateIP); n != 2 || h.evs[len(h.evs)-1].Severity != SeverityMedium {
		t.Fatalf("%+v", h.evs)
	}
	// Probing your own address, a stale owner, an unknown or unusable target: nothing.
	before := len(h.evs)
	h.send(NewProbe(stable(5), ip(70)), 4*time.Second)
	h.send(NewProbe(stable(6), ip(70)), time.Hour)
	h.send(NewProbe(stable(6), ip(99)), 5*time.Second)
	h.send(NewProbe(stable(6), netip.IPv4Unspecified()), 5*time.Second)
	h.send(NewProbe(stable(6), ip(70)), -time.Hour) // clock went backwards
	if len(h.evs) != before {
		t.Fatalf("unexpected events %+v", h.evs[before:])
	}
	if len(h.sink.list()) != 2 {
		t.Fatal("probes must not create observations")
	}
}

func TestGratuitousFlood(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Gateway = ip(1) })
	// A router/phone sending a handful is normal.
	for i := 0; i < 19; i++ {
		h.send(NewAnnounce(stable(5), ip(70)), time.Duration(i)*time.Second)
	}
	if h.find(EventGratuitousFlood) != nil {
		t.Fatal("19 gratuitous frames in a minute is normal")
	}
	h.send(NewAnnounce(stable(5), ip(70)), 19*time.Second)
	ev := h.find(EventGratuitousFlood)
	if ev == nil || ev.Severity != SeverityLow || ev.Evidence["count"] != "20" {
		t.Fatalf("%+v", ev)
	}
	// Spread over windows: no more flood; gateway flood is medium.
	for i := 0; i < 20; i++ {
		h.send(NewGratuitousReply(stable(6), ip(1)), time.Duration(i)*time.Second)
	}
	if got := h.evs[len(h.evs)-1]; got.Type != EventGratuitousFlood || got.Severity != SeverityMedium {
		t.Fatalf("%+v", h.evs)
	}
}

func TestUnsolicitedReplyStorm(t *testing.T) {
	h := newHarness(t, nil)
	srv := stable(5)
	// Replies to requests we saw are fine, however many.
	for i := 0; i < 30; i++ {
		d := time.Duration(i) * time.Second
		h.send(NewRequest(stable(9), ip(9), ip(70)), d)
		h.send(NewReply(srv, ip(70), stable(9), ip(9)), d+100*time.Millisecond)
	}
	if h.find(EventUnsolicitedStorm) != nil || h.m.Stats().UnsolicitedReplies != 0 {
		t.Fatalf("solicited replies flagged: %+v", h.evs)
	}
	// A late reply (request too old) and a never-asked one both count.
	for i := 0; i < 9; i++ {
		h.send(NewReply(srv, ip(70), stable(9), ip(9)), time.Hour+time.Duration(i)*time.Second)
	}
	if h.find(EventUnsolicitedStorm) != nil {
		t.Fatal("9 is under the limit")
	}
	h.send(NewReply(srv, ip(70), stable(9), ip(9)), time.Hour+9*time.Second)
	ev := h.find(EventUnsolicitedStorm)
	if ev == nil || ev.Severity != SeverityMedium || ev.MAC != srv.String() {
		t.Fatalf("%+v", ev)
	}
	// A reply that precedes its "request" in time is unsolicited too.
	h.send(NewRequest(stable(9), ip(9), ip(71)), 3*time.Hour)
	h.send(NewReply(srv, ip(71), stable(9), ip(9)), 2*time.Hour)
	if h.m.Stats().UnsolicitedReplies != 11 {
		t.Fatalf("%+v", h.m.Stats())
	}
}

func TestIgnoredFrames(t *testing.T) {
	h := newHarness(t, nil)
	bad := []Frame{
		NewRequest(Broadcast, ip(10), ip(1)),                   // broadcast sender MAC
		NewRequest(MAC{}, ip(10), ip(1)),                       // zero MAC
		NewRequest(MAC{0x01, 0, 0x5e, 0, 0, 1}, ip(10), ip(1)), // multicast MAC
		NewRequest(stable(1), netip.IPv4Unspecified(), ip(1)),  // probe: handled elsewhere
		NewRequest(stable(1), netip.MustParseAddr("224.0.0.1"), ip(1)),
		NewRequest(stable(1), netip.MustParseAddr("255.255.255.255"), ip(1)),
		NewRequest(stable(1), netip.MustParseAddr("127.0.0.1"), ip(1)),
		NewRequest(stable(1), netip.MustParseAddr("0.1.2.3"), ip(1)),
		{Op: 9, SenderIP: ip(1), TargetIP: ip(2), SenderMAC: stable(1)},
		{Op: OpRequest, SenderMAC: stable(1)},                                                                // no addresses
		{Op: OpRequest, SenderMAC: stable(1), SenderIP: netip.MustParseAddr("2001:db8::1"), TargetIP: ip(1)}, // IPv6 ignored
	}
	for _, f := range bad {
		h.send(f, 0)
	}
	if len(h.sink.list()) != 0 || len(h.evs) != 0 {
		t.Fatalf("obs=%v evs=%v", h.sink.list(), h.evs)
	}
	st := h.m.Stats()
	if st.Ignored != 10 || st.Probes != 1 || st.Frames != 11 || st.TrackedMACs != 0 {
		t.Fatalf("%+v", st)
	}
}

func TestSenderMismatchCounted(t *testing.T) {
	h := newHarness(t, nil)
	f := claimFrame(stable(1), ip(10))
	f.SrcMAC = stable(2)
	h.send(f, 0)
	if h.m.Stats().SenderMismatch != 1 || len(h.sink.list()) != 1 || h.sink.list()[0].MAC != stable(1).String() {
		t.Fatalf("%+v", h.m.Stats())
	}
}

func TestMemoryIsBounded(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.MaxTracked = 64 })
	for i := 0; i < 5000; i++ {
		m := MAC{0x02, 0, 0x5e, byte(i >> 16), byte(i >> 8), byte(i)}
		a := netip.AddrFrom4([4]byte{198, 51, byte(i >> 8), byte(i)})
		h.send(NewRequest(m, a, ip(1)), time.Duration(i)*time.Millisecond)
	}
	st := h.m.Stats()
	if st.TrackedMACs > 64 || st.TrackedIPs > 64 || h.m.pairs.len() > 64 || h.m.reqs.len() > 64 ||
		h.m.cool.len() > 64 || h.m.sigs.len() > 64 {
		t.Fatalf("tables exceed cap: %+v", st)
	}
}

func TestEventCooldownExpires(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Gateway = ip(1); c.EventCooldown = time.Minute })
	h.send(NewAnnounce(stable(1), ip(1)), 0)
	h.send(NewAnnounce(stable(2), ip(1)), time.Second)
	h.send(NewAnnounce(stable(1), ip(1)), 2*time.Second)
	h.send(NewAnnounce(stable(2), ip(1)), 3*time.Second)  // inside cooldown
	h.send(NewAnnounce(stable(1), ip(1)), 90*time.Second) // reverse key still cooling? it was 2s ago -> 88s later, expired
	h.send(NewAnnounce(stable(2), ip(1)), 91*time.Second) // key 1->2 raised at 1s, expired now
	if n := h.count(EventGatewayMACChanged); n != 4 {
		t.Fatalf("gateway events = %d", n)
	}
	// A clock that steps backwards cannot lock events out forever or crash.
	h.send(NewAnnounce(stable(1), ip(1)), -time.Hour)
}

func TestNilSinkAndCallbackAreFine(t *testing.T) {
	m := NewMonitor(NewFakeSource(), Config{})
	m.Handle(NewAnnounce(stable(1), ip(10))) // zero Time: uses Now
	m.Handle(NewAnnounce(stable(2), ip(10)))
	st := m.Stats()
	if st.Frames != 2 || st.Observations != 0 || st.Events[EventNewMAC] != 2 {
		t.Fatalf("%+v", st)
	}
	st.Events["tamper"] = 1 // snapshot must be a copy
	if _, ok := m.Stats().Events["tamper"]; ok {
		t.Fatal("Stats leaked internal map")
	}
}

func TestConfigDefaults(t *testing.T) {
	c := (Config{ManyIPsThreshold: 3}).withDefaults()
	d := DefaultConfig()
	if c.ManyIPsThreshold != 3 || c.MaxTracked != 16384 || c.GratuitousLimit != d.GratuitousLimit ||
		c.SpoofWindow != d.SpoofWindow || c.Now == nil {
		t.Fatalf("%+v", c)
	}
	if len(AllEventTypes()) != 8 {
		t.Fatal("event type list")
	}
}

func TestRunProcessesAndStopsWhenSourceCloses(t *testing.T) {
	src := NewFakeSource()
	h := &harness{t: t, sink: &recSink{}}
	cfg := DefaultConfig()
	cfg.Sink = h.sink
	m := NewMonitor(src, cfg)
	src.Push(timed(NewAnnounce(stable(1), ip(10)), 0))
	src.PushRaw([]byte{1, 2, 3})                       // malformed
	src.PushRaw(make([]byte, 60))                      // ethertype 0: not ARP
	src.Push(timed(NewAnnounce(stable(2), ip(11)), 0)) // still processed afterwards
	src.Finish()
	if err := m.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	st := m.Stats()
	if st.Frames != 4 || st.Malformed != 1 || st.NotARP != 1 || len(h.sink.list()) != 2 || !src.Closed() {
		t.Fatalf("%+v closed=%v", st, src.Closed())
	}
}

func TestRunStopsOnContextCancel(t *testing.T) {
	src := NewFakeSource()
	m := NewMonitor(src, Config{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.Run(ctx) }()
	src.Push(NewAnnounce(stable(1), ip(10)))
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop on cancel")
	}
	if !src.Closed() {
		t.Fatal("source not closed on shutdown")
	}
}

func TestRunReturnsCaptureErrors(t *testing.T) {
	src := NewFakeSource()
	boom := errors.New("socket on fire")
	src.PushErr(boom)
	err := NewMonitor(src, Config{}).Run(context.Background())
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if !src.Closed() {
		t.Fatal("source not closed after failure")
	}
}

func TestStatsAreSafeWhileRunning(t *testing.T) {
	src := NewFakeSource()
	m := NewMonitor(src, Config{Sink: &recSink{}, OnEvent: func(Event) {}})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	for i := 0; i < 500; i++ {
		src.Push(NewAnnounce(rnd(byte(i)), ip(byte(i%250+1))))
		m.Stats()
	}
	cancel()
	<-done
}

// Whatever arrives, the monitor must not panic and must stay bounded.
func TestHandleNeverPanicsOnRandomFrames(t *testing.T) {
	rng := newRand(7)
	m := NewMonitor(NewFakeSource(), Config{MaxTracked: 128, Gateway: ip(1), Sink: &recSink{}, OnEvent: func(Event) {}})
	for i := 0; i < 100000; i++ {
		m.Handle(rng.frame(t0.Add(time.Duration(rng.n(1000)-100) * time.Second)))
	}
	st := m.Stats()
	if st.TrackedMACs > 128 || st.TrackedIPs > 128 {
		t.Fatalf("%+v", st)
	}
}

func TestNeverTransmits(t *testing.T) {
	// The Source interface has no way to send. Assert that structurally:
	// the only methods are Next and Close.
	var s Source = NewFakeSource()
	type reader interface {
		Next(context.Context) (Frame, error)
		Close() error
	}
	if _, ok := s.(reader); !ok {
		t.Fatal("Source drifted")
	}
	for _, name := range []string{"Send", "Write", "Inject", "Transmit"} {
		if hasMethod(s, name) {
			t.Fatalf("Source implementation exposes %s", name)
		}
	}
}
