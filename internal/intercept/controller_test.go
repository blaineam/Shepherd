// SPDX-License-Identifier: AGPL-3.0-or-later

package intercept

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"shepherd/internal/arp"
)

// waitHealthTick synchronizes with the Controller's autonomous
// health-check loop without sleeping: it sets the package-private test
// hook (this file is in package intercept, so it can) and returns a
// function that blocks on a real channel receive until the next tick has
// fully run, bounded so a bug cannot hang the test suite.
func waitHealthTick(t *testing.T, c *Controller) func() {
	t.Helper()
	ch := make(chan struct{}, 8)
	c.afterHealthCheck = func(time.Time) {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	return func() {
		select {
		case <-ch:
		case <-time.After(5 * time.Second):
			t.Fatal("health tick never completed")
		}
	}
}

func waitUnsteer(t *testing.T, ch <-chan UnsteerRecord) UnsteerRecord {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for an unsteer event")
		return UnsteerRecord{}
	}
}

func onUnsteerChan() (func(UnsteerRecord), <-chan UnsteerRecord) {
	ch := make(chan UnsteerRecord, 16)
	return func(r UnsteerRecord) { ch <- r }, ch
}

// --- construction validation ---

func TestNewControllerRequiresSenderShepherdAndGateway(t *testing.T) {
	base := testConfig()
	cases := []struct {
		name string
		mod  func(*ControllerConfig)
		want error
	}{
		{"no sender", func(c *ControllerConfig) { c.Sender = nil }, ErrSenderRequired},
		{"no shepherd mac", func(c *ControllerConfig) { c.ShepherdMAC = arp.MAC{} }, ErrShepherdMACRequired},
		{"no gateway ip", func(c *ControllerConfig) { c.GatewayIP = netip.Addr{} }, ErrGatewayRequired},
		{"ipv6 gateway ip", func(c *ControllerConfig) { c.GatewayIP = netip.MustParseAddr("2001:db8::1") }, ErrGatewayRequired},
		{"no gateway mac", func(c *ControllerConfig) { c.GatewayMAC = arp.MAC{} }, ErrGatewayRequired},
	}
	for _, tc := range cases {
		cfg := base
		tc.mod(&cfg)
		if _, err := NewController(cfg); !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, err, tc.want)
		}
	}
}

func TestNewControllerDefaultsToRealClock(t *testing.T) {
	cfg := testConfig()
	cfg.Clock = nil
	c, err := NewController(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.cfg.Clock == nil {
		t.Fatal("Clock should default, not stay nil")
	}
	if _, ok := c.cfg.Clock.(realClock); !ok {
		t.Fatalf("got %T, want realClock", c.cfg.Clock)
	}
}

// --- Steer exclusion rules, enforced at the call, not just documented ---

func TestSteerRefusesTheGatewayItself(t *testing.T) {
	c, _, _ := newTestController(t, nil)
	if err := c.Steer(DeviceRef{MAC: gwMAC, IP: ip(55)}, SteerOptions{}); !errors.Is(err, ErrGatewayExcluded) {
		t.Errorf("gateway MAC: got %v", err)
	}
	if err := c.Steer(DeviceRef{MAC: rndMAC(77), IP: gwIP}, SteerOptions{}); !errors.Is(err, ErrGatewayExcluded) {
		t.Errorf("gateway IP: got %v", err)
	}
	if err := c.Steer(DeviceRef{MAC: shepherdMAC, IP: ip(66)}, SteerOptions{}); !errors.Is(err, ErrGatewayExcluded) {
		t.Errorf("shepherd's own MAC: got %v", err)
	}
}

func TestSteerRefusesStaticExclusionList(t *testing.T) {
	excluded := rndMAC(42)
	c, _, _ := newTestController(t, func(cfg *ControllerConfig) { cfg.ExcludedMACs = []arp.MAC{excluded} })
	if err := c.Steer(DeviceRef{MAC: excluded, IP: ip(42)}, SteerOptions{}); !errors.Is(err, ErrExcluded) {
		t.Errorf("got %v", err)
	}
}

type fakeExcluder struct{ excluded map[arp.MAC]bool }

func (f fakeExcluder) Excluded(mac arp.MAC) bool { return f.excluded[mac] }

func TestSteerRefusesExcluderEvenIfAsked(t *testing.T) {
	ex := fakeExcluder{excluded: map[arp.MAC]bool{devMAC: true}}
	c, _, _ := newTestController(t, func(cfg *ControllerConfig) { cfg.Excluder = ex })
	if err := c.Steer(DeviceRef{MAC: devMAC, IP: devIP}, SteerOptions{}); !errors.Is(err, ErrExcluded) {
		t.Errorf("got %v", err)
	}
	// A device the Excluder does not know about is unaffected.
	if err := c.Steer(DeviceRef{MAC: rndMAC(5), IP: ip(5)}, SteerOptions{}); err != nil {
		t.Errorf("unexpected: %v", err)
	}
}

func TestSteerRejectsInvalidOrIPv6Device(t *testing.T) {
	c, _, _ := newTestController(t, nil)
	cases := []DeviceRef{
		{MAC: arp.MAC{}, IP: devIP},
		{MAC: arp.Broadcast, IP: devIP},
		{MAC: devMAC, IP: netip.Addr{}},
		{MAC: devMAC, IP: netip.MustParseAddr("2001:db8::10")}, // hard rule: IPv4 only
		{MAC: devMAC, IP: netip.IPv4Unspecified()},
	}
	for i, d := range cases {
		if err := c.Steer(d, SteerOptions{}); !errors.Is(err, ErrInvalidDevice) {
			t.Errorf("case %d: got %v", i, err)
		}
	}
}

func TestSteerRejectsBadTrialDuration(t *testing.T) {
	c, _, _ := newTestController(t, nil)
	if err := c.Steer(DeviceRef{MAC: devMAC, IP: devIP}, SteerOptions{Trial: true, Duration: 0}); !errors.Is(err, ErrTrialDuration) {
		t.Errorf("got %v", err)
	}
}

func TestSteerRefusesAlreadySteered(t *testing.T) {
	c, _, _ := newTestController(t, nil)
	if err := c.Steer(DeviceRef{MAC: devMAC, IP: devIP}, SteerOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := c.Steer(DeviceRef{MAC: devMAC, IP: devIP}, SteerOptions{}); !errors.Is(err, ErrAlreadySteered) {
		t.Errorf("got %v", err)
	}
}

func TestUnsteerRefusesUnknownDevice(t *testing.T) {
	c, _, _ := newTestController(t, nil)
	if err := c.Unsteer(devMAC); !errors.Is(err, ErrNotSteered) {
		t.Errorf("got %v", err)
	}
}

// --- relay flow, bytes, health ---

func TestSteerRelayFlowIncreasesByteCountersAndStaysHealthy(t *testing.T) {
	onUnsteer, unsteerCh := onUnsteerChan()
	c, sender, _ := newTestController(t, func(cfg *ControllerConfig) { cfg.OnUnsteer = onUnsteer })
	watchCh, stopWatch := sender.Watch()
	if err := c.Steer(DeviceRef{MAC: devMAC, IP: devIP}, SteerOptions{}); err != nil {
		t.Fatal(err)
	}
	waitForFrame(t, watchCh, time.Second) // the initial spoof claim
	stopWatch()

	frame1 := ethFrame(shepherdMAC, devMAC, 0x0800, []byte("hello"))
	frame2 := ethFrame(shepherdMAC, devMAC, 0x0800, []byte("world!!"))
	if ok, err := c.HandleFrame(frame1); err != nil || !ok {
		t.Fatalf("HandleFrame 1: %v %v", ok, err)
	}
	if ok, err := c.HandleFrame(frame2); err != nil || !ok {
		t.Fatalf("HandleFrame 2: %v %v", ok, err)
	}

	st := c.Status()
	if len(st) != 1 {
		t.Fatalf("Status() = %v", st)
	}
	want := uint64(len(frame1) + len(frame2))
	if st[0].BytesRelayed != want {
		t.Fatalf("BytesRelayed = %d, want %d", st[0].BytesRelayed, want)
	}
	if st[0].PacketsRelayed != 2 {
		t.Fatalf("PacketsRelayed = %d, want 2", st[0].PacketsRelayed)
	}
	if !st[0].Healthy {
		t.Fatal("device should be healthy after relayed traffic")
	}
	if st[0].LastVerified.IsZero() {
		t.Fatal("LastVerified should be set")
	}

	select {
	case r := <-unsteerCh:
		t.Fatalf("device was unsteered unexpectedly: %+v", r)
	default:
	}
}

// TestControllerStatsCountsExaminedRelayedAndForeignFrames exercises
// Stats() the way cmd/intercept-trial samples it: a mix of frames that
// match and relay, frames addressed elsewhere (what PACKET_IGNORE_OUTGOING
// in capture_linux.go now asks the kernel to not even deliver), and a
// frame from a device that is not steered — every one of which must still
// count as "examined", since Stats() is meant to measure the real capture
// rate regardless of what matched.
func TestControllerStatsCountsExaminedRelayedAndForeignFrames(t *testing.T) {
	c, _, _ := newTestController(t, nil)
	if err := c.Steer(DeviceRef{MAC: devMAC, IP: devIP}, SteerOptions{}); err != nil {
		t.Fatal(err)
	}

	relayed := ethFrame(shepherdMAC, devMAC, 0x0800, []byte("hello"))
	foreign := ethFrame(gwMAC, devMAC, 0x0800, []byte("not for shepherd")) // e.g. Shepherd's own TX looping back
	unmatched := ethFrame(shepherdMAC, rndMAC(77), 0x0800, []byte("other device"))

	for _, f := range []Frame{relayed, foreign, unmatched} {
		if _, err := c.HandleFrame(f); err != nil {
			t.Fatalf("HandleFrame(%q): %v", f, err)
		}
	}

	st := c.Stats()
	if st.FramesExamined != 3 {
		t.Fatalf("FramesExamined = %d, want 3", st.FramesExamined)
	}
	wantBytes := uint64(len(relayed) + len(foreign) + len(unmatched))
	if st.BytesExamined != wantBytes {
		t.Fatalf("BytesExamined = %d, want %d", st.BytesExamined, wantBytes)
	}
	if st.FramesNotForShepherd != 1 {
		t.Fatalf("FramesNotForShepherd = %d, want 1", st.FramesNotForShepherd)
	}
	if st.FramesRelayed != 1 {
		t.Fatalf("FramesRelayed = %d, want 1", st.FramesRelayed)
	}
	if st.BytesRelayed != uint64(len(relayed)) {
		t.Fatalf("BytesRelayed = %d, want %d", st.BytesRelayed, len(relayed))
	}
}

// TestControllerStatsAccumulatesAcrossParallelRelays mirrors
// TestNewRelaySharesControllerStateAcrossSeparateSenders: ParallelRelay
// builds one Relay per capture worker, each on its own Sender, and
// Stats() must still see every one of them as a single global total.
func TestControllerStatsAccumulatesAcrossParallelRelays(t *testing.T) {
	c, _, _ := newTestController(t, nil)
	if err := c.Steer(DeviceRef{MAC: devMAC, IP: devIP}, SteerOptions{}); err != nil {
		t.Fatal(err)
	}
	other := c.NewRelay(NewFakeSender())

	if _, err := c.HandleFrame(ethFrame(shepherdMAC, devMAC, 0x0800, []byte("a"))); err != nil {
		t.Fatal(err)
	}
	if _, err := other.HandleFrame(ethFrame(shepherdMAC, devMAC, 0x0800, []byte("bb"))); err != nil {
		t.Fatal(err)
	}

	st := c.Stats()
	if st.FramesExamined != 2 || st.FramesRelayed != 2 {
		t.Fatalf("Stats() = %+v, want FramesExamined=2 FramesRelayed=2", st)
	}
}

func TestNewRelaySharesControllerStateAcrossSeparateSenders(t *testing.T) {
	onUnsteer, unsteerCh := onUnsteerChan()
	c, _, _ := newTestController(t, func(cfg *ControllerConfig) { cfg.OnUnsteer = onUnsteer })
	if err := c.Steer(DeviceRef{MAC: devMAC, IP: devIP}, SteerOptions{}); err != nil {
		t.Fatal(err)
	}

	// A second Relay, on a completely separate Sender, as ParallelRelay
	// builds one per capture worker: it must still see (and feed into)
	// the same steered set, byte counters and health as the Controller's
	// own relay, with nothing routed through the first Sender at all.
	otherSender := NewFakeSender()
	other := c.NewRelay(otherSender)

	frame := ethFrame(shepherdMAC, devMAC, 0x0800, []byte("via the second relay"))
	ok, err := other.HandleFrame(frame)
	if err != nil || !ok {
		t.Fatalf("HandleFrame via NewRelay: ok=%v err=%v", ok, err)
	}
	if got := len(otherSender.Frames()); got != 1 {
		t.Fatalf("otherSender got %d frames, want 1", got)
	}

	st := c.Status()
	if len(st) != 1 || st[0].BytesRelayed != uint64(len(frame)) || !st[0].Healthy {
		t.Fatalf("Status() = %+v, want one healthy device with %d bytes relayed", st, len(frame))
	}

	select {
	case r := <-unsteerCh:
		t.Fatalf("device was unsteered unexpectedly: %+v", r)
	default:
	}
}

func TestHandleFrameOnUnsteeredControllerIgnoresEverything(t *testing.T) {
	c, sender, _ := newTestController(t, nil)
	ok, err := c.HandleFrame(ethFrame(shepherdMAC, devMAC, 0x0800, []byte("x")))
	if ok || err != nil {
		t.Fatalf("got %v, %v", ok, err)
	}
	if len(sender.Frames()) != 0 {
		t.Fatal("nothing should have been sent")
	}
}

func TestIdleDeviceIsAutoUnsteeredAfterGraceWithCorrective(t *testing.T) {
	onUnsteer, unsteerCh := onUnsteerChan()
	c, sender, clk := newTestController(t, func(cfg *ControllerConfig) {
		cfg.HealthInterval = time.Second
		cfg.IdleGrace = 2 * time.Second
		cfg.StartupGrace = 2 * time.Second
		cfg.OnUnsteer = onUnsteer
	})
	wait := waitHealthTick(t, c)

	if err := c.Steer(DeviceRef{MAC: devMAC, IP: devIP}, SteerOptions{}); err != nil {
		t.Fatal(err)
	}
	if ok, err := c.HandleFrame(ethFrame(shepherdMAC, devMAC, 0x0800, []byte("x"))); !ok || err != nil {
		t.Fatalf("relay: %v %v", ok, err)
	}

	clk.Advance(time.Second) // tick at +1s: age 1s < 2s grace, still healthy
	wait()
	if len(c.Status()) != 1 {
		t.Fatal("device should still be steered within grace")
	}

	clk.Advance(time.Second) // tick at +2s: age 2s, not < 2s grace: unhealthy
	wait()

	if len(c.Status()) != 0 {
		t.Fatal("device should have been auto-unsteered")
	}
	rec := waitUnsteer(t, unsteerCh)
	if rec.MAC != devMAC || rec.Reason == "" {
		t.Fatalf("unsteer record = %+v", rec)
	}
	hist := c.History()
	if len(hist) != 1 || hist[0].MAC != devMAC {
		t.Fatalf("History() = %+v", hist)
	}

	frames := sender.Frames()
	last := arpOf(t, frames[len(frames)-1])
	if last.SenderMAC != gwMAC || last.TargetMAC != devMAC {
		t.Fatalf("no corrective ARP reply sent: %+v", last)
	}
}

func TestDeviceThatNeverRelaysIsUnsteeredAfterStartupGrace(t *testing.T) {
	onUnsteer, unsteerCh := onUnsteerChan()
	c, _, clk := newTestController(t, func(cfg *ControllerConfig) {
		cfg.HealthInterval = time.Second
		cfg.IdleGrace = 100 * time.Second // irrelevant: never verified
		cfg.StartupGrace = 2 * time.Second
		cfg.OnUnsteer = onUnsteer
	})
	wait := waitHealthTick(t, c)

	if err := c.Steer(DeviceRef{MAC: devMAC, IP: devIP}, SteerOptions{}); err != nil {
		t.Fatal(err)
	}
	clk.Advance(time.Second)
	wait()
	if len(c.Status()) != 1 {
		t.Fatal("still within startup grace")
	}
	clk.Advance(time.Second)
	wait()
	if len(c.Status()) != 0 {
		t.Fatal("should be unsteered: never relayed anything within startup grace")
	}
	rec := waitUnsteer(t, unsteerCh)
	if rec.MAC != devMAC {
		t.Fatalf("got %+v", rec)
	}
}

func TestRelaySendFailureAutoUnsteersImmediately(t *testing.T) {
	onUnsteer, unsteerCh := onUnsteerChan()
	c, sender, _ := newTestController(t, func(cfg *ControllerConfig) {
		cfg.HealthInterval = time.Hour // make sure the periodic loop isn't what catches this
		cfg.OnUnsteer = onUnsteer
	})
	if err := c.Steer(DeviceRef{MAC: devMAC, IP: devIP}, SteerOptions{}); err != nil {
		t.Fatal(err)
	}
	sender.SetError(errors.New("link down"))

	ok, err := c.HandleFrame(ethFrame(shepherdMAC, devMAC, 0x0800, []byte("x")))
	if ok || err == nil {
		t.Fatalf("got %v, %v", ok, err)
	}
	rec := waitUnsteer(t, unsteerCh)
	if rec.MAC != devMAC {
		t.Fatalf("got %+v", rec)
	}
	if len(c.Status()) != 0 {
		t.Fatal("device should have been unsteered at once on relay error")
	}
}

// --- trial mode ---

func TestTrialModeRevertsAtExactlyItsDurationNotEarlyOrLate(t *testing.T) {
	onUnsteer, unsteerCh := onUnsteerChan()
	c, _, clk := newTestController(t, func(cfg *ControllerConfig) {
		cfg.HealthInterval = time.Hour // keep the periodic loop out of the way
		cfg.OnUnsteer = onUnsteer
	})
	if err := c.Steer(DeviceRef{MAC: devMAC, IP: devIP}, SteerOptions{Trial: true, Duration: 5 * time.Second}); err != nil {
		t.Fatal(err)
	}

	clk.Advance(4999 * time.Millisecond)
	select {
	case r := <-unsteerCh:
		t.Fatalf("trial reverted early: %+v", r)
	default:
	}
	if len(c.Status()) != 1 {
		t.Fatal("device should still be steered one millisecond before its deadline")
	}

	clk.Advance(1 * time.Millisecond) // now exactly at the deadline
	rec := waitUnsteer(t, unsteerCh)
	if rec.MAC != devMAC || rec.Reason != "trial duration elapsed" {
		t.Fatalf("got %+v", rec)
	}
	if len(c.Status()) != 0 {
		t.Fatal("device should be unsteered exactly at its trial deadline")
	}
}

func TestTrialCancelledByManualUnsteerDoesNotDoubleFire(t *testing.T) {
	onUnsteer, unsteerCh := onUnsteerChan()
	c, _, clk := newTestController(t, func(cfg *ControllerConfig) {
		cfg.HealthInterval = time.Hour
		cfg.OnUnsteer = onUnsteer
	})
	if err := c.Steer(DeviceRef{MAC: devMAC, IP: devIP}, SteerOptions{Trial: true, Duration: 5 * time.Second}); err != nil {
		t.Fatal(err)
	}
	if err := c.Unsteer(devMAC); err != nil {
		t.Fatal(err)
	}
	rec := waitUnsteer(t, unsteerCh)
	if rec.Reason != "unsteered by caller" {
		t.Fatalf("got %+v", rec)
	}

	// The trial timer firing later must be a harmless no-op: Steer the
	// same MAC again (now free since it was removed) before advancing, so
	// a spurious second unsteer would show up against the WRONG device if
	// the watcher mis-fired.
	if err := c.Steer(DeviceRef{MAC: devMAC, IP: devIP}, SteerOptions{}); err != nil {
		t.Fatal(err)
	}
	clk.Advance(5 * time.Second)
	select {
	case r := <-unsteerCh:
		t.Fatalf("the expired trial watcher from the first Steer call fired again: %+v", r)
	case <-time.After(100 * time.Millisecond):
	}
	if len(c.Status()) != 1 {
		t.Fatal("the second, non-trial Steer should be unaffected")
	}
}

// --- panic stop ---

func TestPanicStopUnsteersEveryoneImmediatelyAndBlocksUntilRearm(t *testing.T) {
	onUnsteer, unsteerCh := onUnsteerChan()
	c, sender, _ := newTestController(t, func(cfg *ControllerConfig) { cfg.OnUnsteer = onUnsteer })
	for i := byte(20); i < 23; i++ {
		if err := c.Steer(DeviceRef{MAC: rndMAC(i), IP: ip(i)}, SteerOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	if len(c.Status()) != 3 {
		t.Fatal("setup: expected 3 steered devices")
	}

	release := sender.Block() // prove PanicStop does not wait on the Sender
	defer release()
	start := time.Now()
	c.PanicStop()
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("PanicStop blocked for %s with a wedged Sender", elapsed)
	}

	if len(c.Status()) != 0 {
		t.Fatal("PanicStop should unsteer everyone immediately")
	}
	for i := 0; i < 3; i++ {
		rec := waitUnsteer(t, unsteerCh)
		if rec.Reason != "panic stop" {
			t.Fatalf("got %+v", rec)
		}
	}
	if err := c.Steer(DeviceRef{MAC: rndMAC(9), IP: ip(9)}, SteerOptions{}); !errors.Is(err, ErrPanicked) {
		t.Fatalf("Steer after PanicStop: got %v", err)
	}

	c.Rearm()
	if err := c.Steer(DeviceRef{MAC: rndMAC(9), IP: ip(9)}, SteerOptions{}); err != nil {
		t.Fatalf("Steer after Rearm: %v", err)
	}
}

// --- a wedged or erroring Sender must never wedge the safety path ---

func TestUnsteerIsBoundedEvenWithAWedgedSender(t *testing.T) {
	c, sender, _ := newTestController(t, func(cfg *ControllerConfig) { cfg.SendTimeout = 30 * time.Millisecond })
	if err := c.Steer(DeviceRef{MAC: devMAC, IP: devIP}, SteerOptions{}); err != nil {
		t.Fatal(err)
	}
	release := sender.Block()
	defer release()

	start := time.Now()
	if err := c.Unsteer(devMAC); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Unsteer took %s with a wedged Sender", elapsed)
	}
}

func TestHealthLoopKeepsRunningWithAWedgedSender(t *testing.T) {
	onUnsteer, unsteerCh := onUnsteerChan()
	c, sender, clk := newTestController(t, func(cfg *ControllerConfig) {
		cfg.HealthInterval = time.Second
		cfg.StartupGrace = time.Second
		cfg.SendTimeout = 30 * time.Millisecond
		cfg.OnUnsteer = onUnsteer
	})
	wait := waitHealthTick(t, c)
	release := sender.Block()
	defer release()

	if err := c.Steer(DeviceRef{MAC: devMAC, IP: devIP}, SteerOptions{}); err != nil {
		t.Fatal(err)
	}
	clk.Advance(time.Second)
	wait() // must complete promptly even though every Send is blocked

	rec := waitUnsteer(t, unsteerCh)
	if rec.MAC != devMAC {
		t.Fatalf("got %+v", rec)
	}
}

// --- IPv6, end to end through the Controller ---

func TestControllerNeverRelaysIPv6EvenForASteeredDevice(t *testing.T) {
	c, sender, _ := newTestController(t, nil)
	if err := c.Steer(DeviceRef{MAC: devMAC, IP: devIP}, SteerOptions{}); err != nil {
		t.Fatal(err)
	}
	before := len(sender.Frames())
	ok, err := c.HandleFrame(ethFrame(shepherdMAC, devMAC, 0x86dd, []byte("x")))
	if ok || err != nil {
		t.Fatalf("got %v, %v", ok, err)
	}
	if len(sender.Frames()) != before {
		t.Fatal("an IPv6 frame must never be sent anywhere")
	}
}

// --- close ---

func TestCloseUnsteersEveryoneAndStopsTheLoop(t *testing.T) {
	cfg := testConfig()
	sender := cfg.Sender.(*FakeSender)
	c, err := NewController(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Steer(DeviceRef{MAC: devMAC, IP: devIP}, SteerOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if len(c.Status()) != 0 {
		t.Fatal("Close should unsteer everyone")
	}
	frames := sender.Frames()
	last := arpOf(t, frames[len(frames)-1])
	if last.SenderMAC != gwMAC {
		t.Fatal("Close should send the corrective revert")
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close should be a no-op, got %v", err)
	}
	if err := c.Steer(DeviceRef{MAC: devMAC, IP: devIP}, SteerOptions{}); !errors.Is(err, ErrClosed) {
		t.Fatalf("Steer after Close: got %v", err)
	}
}

// --- concurrency ---

func TestConcurrentSteerUnsteerStatus(t *testing.T) {
	c, _, _ := newTestController(t, nil)
	const n = 20
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			mac := rndMAC(byte(i))
			for j := 0; j < 25; j++ {
				_ = c.Steer(DeviceRef{MAC: mac, IP: ip(byte(i))}, SteerOptions{})
				_ = c.Status()
				_ = c.History()
				_ = c.Unsteer(mac)
			}
		}()
	}
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			default:
				c.Status()
			}
		}
	}()
	wg.Wait()
	close(done)
}

func TestExcludedMACsAndExcluderTogether(t *testing.T) {
	ex := fakeExcluder{excluded: map[arp.MAC]bool{rndMAC(32): true}}
	c, _, _ := newTestController(t, func(cfg *ControllerConfig) {
		cfg.Excluder = ex
		cfg.ExcludedMACs = []arp.MAC{rndMAC(31)}
	})
	for i, mac := range []arp.MAC{rndMAC(31), rndMAC(32)} {
		if err := c.Steer(DeviceRef{MAC: mac, IP: ip(byte(40 + i))}, SteerOptions{}); !errors.Is(err, ErrExcluded) {
			t.Errorf("%v: got %v", mac, err)
		}
	}
}

func TestSpoofInitialClaimAddressesTheDeviceOnSteer(t *testing.T) {
	c, sender, _ := newTestController(t, nil)
	ch, stop := sender.Watch()
	defer stop()
	if err := c.Steer(DeviceRef{MAC: devMAC, IP: devIP}, SteerOptions{}); err != nil {
		t.Fatal(err)
	}
	f := waitForFrame(t, ch, time.Second)
	claim := arpOf(t, f)
	if claim.SenderMAC != shepherdMAC || claim.SenderIP != gwIP || claim.TargetMAC != devMAC || claim.TargetIP != devIP {
		t.Fatalf("initial claim wrong: %+v", claim)
	}
}

func TestStatusSortedAndFieldsMatch(t *testing.T) {
	c, _, clk := newTestController(t, nil)
	for i := byte(23); i >= 21; i-- {
		if err := c.Steer(DeviceRef{MAC: rndMAC(i), IP: ip(i)}, SteerOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	st := c.Status()
	if len(st) != 3 {
		t.Fatalf("got %d", len(st))
	}
	for i := 1; i < len(st); i++ {
		if st[i-1].MAC.String() >= st[i].MAC.String() {
			t.Fatalf("Status() not sorted: %v", st)
		}
	}
	for _, d := range st {
		if !d.Since.Equal(clk.Now()) {
			t.Fatalf("Since = %v, want %v", d.Since, clk.Now())
		}
	}
}

func TestRecordRelayErrorMessageIncludesUnderlyingError(t *testing.T) {
	c, sender, _ := newTestController(t, func(cfg *ControllerConfig) { cfg.HealthInterval = time.Hour })
	if err := c.Steer(DeviceRef{MAC: devMAC, IP: devIP}, SteerOptions{}); err != nil {
		t.Fatal(err)
	}
	sender.SetError(fmt.Errorf("simulated nic failure"))
	c.HandleFrame(ethFrame(shepherdMAC, devMAC, 0x0800, []byte("x")))
	hist := c.History()
	if len(hist) != 1 {
		t.Fatalf("got %+v", hist)
	}
	if !containsSubstring(hist[0].Reason, "simulated nic failure") {
		t.Fatalf("reason %q does not mention the underlying error", hist[0].Reason)
	}
}

func containsSubstring(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
