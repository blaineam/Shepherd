// SPDX-License-Identifier: AGPL-3.0-or-later

package intercept

import (
	"context"
	"errors"
	"math/rand"
	"net/netip"
	"testing"
	"time"

	"shepherd/internal/arp"
)

func testSpooferConfig(sender Sender, clk Clock) SpooferConfig {
	return SpooferConfig{
		Sender: sender, Clock: clk,
		Interval: time.Second, SendTimeout: time.Second,
		ShepherdMAC: shepherdMAC, GatewayIP: gwIP, GatewayMAC: gwMAC,
		TargetMAC: devMAC, TargetIP: devIP,
	}
}

func TestSpooferConfigDefaults(t *testing.T) {
	cfg := SpooferConfig{
		Sender: NewFakeSender(), Clock: NewFakeClock(t0),
		ShepherdMAC: shepherdMAC, GatewayIP: gwIP, GatewayMAC: gwMAC,
		TargetMAC: devMAC, TargetIP: devIP,
	}
	sp := NewSpoofer(cfg)
	if sp.cfg.Interval != DefaultSpoofInterval {
		t.Errorf("Interval = %v, want %v", sp.cfg.Interval, DefaultSpoofInterval)
	}
	if sp.cfg.SendTimeout != DefaultSendTimeout {
		t.Errorf("SendTimeout = %v, want %v", sp.cfg.SendTimeout, DefaultSendTimeout)
	}
}

func TestSpooferStopIsIdempotent(t *testing.T) {
	sp := NewSpoofer(testSpooferConfig(NewFakeSender(), NewFakeClock(t0)))
	sp.Stop()
	sp.Stop() // must not panic or block
}

func TestSpooferSendsClaimThenCorrectiveOnStop(t *testing.T) {
	sender := NewFakeSender()
	clk := NewFakeClock(t0)
	sp := NewSpoofer(testSpooferConfig(sender, clk))

	done := make(chan struct{})
	go func() { sp.Run(context.Background()); close(done) }()

	ch, stop := sender.Watch()
	defer stop()
	sp.Stop()
	<-done

	frames := sender.Frames()
	if len(frames) < 2 {
		t.Fatalf("want at least claim+corrective, got %d frames", len(frames))
	}
	first := arpOf(t, frames[0])
	if first.SenderMAC != shepherdMAC || first.SenderIP != gwIP || first.TargetMAC != devMAC || first.TargetIP != devIP || first.Op != arp.OpReply {
		t.Fatalf("claim frame wrong: %+v", first)
	}
	last := arpOf(t, frames[len(frames)-1])
	if last.SenderMAC != gwMAC || last.SenderIP != gwIP || last.TargetMAC != devMAC || last.TargetIP != devIP || last.Op != arp.OpReply {
		t.Fatalf("corrective frame wrong: %+v", last)
	}
	select {
	case <-ch:
	default:
	}
}

func TestSpooferRepeatsOnInterval(t *testing.T) {
	sender := NewFakeSender()
	clk := NewFakeClock(t0)
	cfg := testSpooferConfig(sender, clk)
	cfg.Interval = 2 * time.Second
	sp := NewSpoofer(cfg)

	// armed synchronizes with the Run goroutine's own re-arm of its next
	// periodic timer, so each Advance below is guaranteed to land after
	// the waiter it is meant to fire, never before it (see Spoofer.armed).
	armedCh := make(chan struct{}, 1)
	sp.armed = func() {
		select {
		case armedCh <- struct{}{}:
		default:
		}
	}
	waitArmed := func() {
		select {
		case <-armedCh:
		case <-time.After(time.Second):
			t.Fatal("spoof loop never re-armed its next tick")
		}
	}

	done := make(chan struct{})
	go func() { sp.Run(context.Background()); close(done) }()
	waitArmed() // the initial claim was sent and the first tick is armed

	if got := len(sender.Frames()); got != 1 {
		t.Fatalf("frames after the initial claim = %d, want 1", got)
	}
	for i := 0; i < 3; i++ {
		clk.Advance(2 * time.Second)
		waitArmed()
		if got := len(sender.Frames()); got != i+2 {
			t.Fatalf("iteration %d: frames = %d, want %d", i, got, i+2)
		}
	}

	sp.Stop()
	<-done
}

func TestSpooferContextCancelSendsCorrective(t *testing.T) {
	sender := NewFakeSender()
	clk := NewFakeClock(t0)
	sp := NewSpoofer(testSpooferConfig(sender, clk))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { sp.Run(ctx); close(done) }()

	ch, stop := sender.Watch()
	defer stop()
	waitForFrame(t, ch, time.Second) // first claim, so Run has reached its select loop

	cancel()
	<-done

	frames := sender.Frames()
	last := arpOf(t, frames[len(frames)-1])
	if last.SenderMAC != gwMAC {
		t.Fatalf("context cancellation did not revert: %+v", last)
	}
}

func TestSpooferStopBeforeRunStillReverts(t *testing.T) {
	sender := NewFakeSender()
	clk := NewFakeClock(t0)
	sp := NewSpoofer(testSpooferConfig(sender, clk))
	sp.Stop() // before Run is ever called

	done := make(chan struct{})
	go func() { sp.Run(context.Background()); close(done) }()
	<-done

	frames := sender.Frames()
	if len(frames) < 1 {
		t.Fatal("no frames sent at all")
	}
	// Even Stop-before-Run must still produce the initial claim and the
	// corrective: a device must never end up with nothing un-steering it.
	last := arpOf(t, frames[len(frames)-1])
	if last.SenderMAC != gwMAC {
		t.Fatalf("no corrective after immediate stop: %+v", last)
	}
}

// panicOnceSender panics the first time Send is called (inside the
// spoof loop), to prove Spoofer.Run still sends the corrective revert
// and does not crash the caller.
type panicOnceSender struct {
	inner  *FakeSender
	panics bool
}

func (p *panicOnceSender) Send(f Frame) error {
	if !p.panics {
		p.panics = true
		panic("simulated spoof-loop panic")
	}
	return p.inner.Send(f)
}

func TestSpooferPanicDuringLoopStillReverts(t *testing.T) {
	inner := NewFakeSender()
	sender := &panicOnceSender{inner: inner}
	clk := NewFakeClock(t0)
	var gotErr error
	cfg := testSpooferConfig(sender, clk)
	cfg.OnSendError = func(err error) { gotErr = err }
	sp := NewSpoofer(cfg)

	done := make(chan struct{})
	go func() {
		defer close(done)
		sp.Run(context.Background()) // the first sendClaim panics internally
	}()
	sp.Stop()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run never returned after a panic in the loop")
	}

	if len(inner.Frames()) != 1 {
		t.Fatalf("want exactly the corrective after the panicking claim, got %d", len(inner.Frames()))
	}
	last := arpOf(t, inner.Frames()[0])
	if last.SenderMAC != gwMAC {
		t.Fatalf("corrective missing after panic: %+v", last)
	}
	_ = gotErr // best effort; not every path reports through OnSendError
}

// Property test: no matter what MAC/IP combination the Spoofer is asked
// to build frames for — including adversarial, non-IPv4 addresses that
// Controller.Steer would have rejected — its frame builder must never
// panic and must never produce anything but a plain IPv4 ARP reply.
// Mirrors internal/arp's fuzz patterns (random input, never panics).
func TestSpooferFrameBuilderNeverProducesIPv6OrPanics(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	randMAC := func() arp.MAC {
		var m arp.MAC
		rng.Read(m[:])
		return m
	}
	randAddr := func() netip.Addr {
		switch rng.Intn(3) {
		case 0:
			var b [4]byte
			rng.Read(b[:])
			return netip.AddrFrom4(b)
		case 1:
			var b [16]byte
			rng.Read(b[:])
			return netip.AddrFrom16(b) // IPv6: must never be sendable as ARP
		default:
			return netip.Addr{} // invalid/zero
		}
	}

	var sawBuildError bool
	for i := 0; i < 2000; i++ {
		sender := NewFakeSender()
		clk := NewFakeClock(t0)
		sp := NewSpoofer(SpooferConfig{
			Sender: sender, Clock: clk, Interval: time.Hour, SendTimeout: time.Second,
			ShepherdMAC: randMAC(), GatewayIP: randAddr(), GatewayMAC: randMAC(),
			TargetMAC: randMAC(), TargetIP: randAddr(),
			OnSendError: func(error) { sawBuildError = true },
		})
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Spoofer send path panicked: %v", r)
				}
			}()
			sp.sendClaim()
			sp.sendCorrective()
		}()
		for _, f := range sender.Frames() {
			if len(f) >= 14 && f[12] == 0x86 && f[13] == 0xdd {
				t.Fatalf("spoofer produced an IPv6-ethertype frame: % x", f)
			}
			// Every frame the spoofer ever sends must decode as plain
			// IPv4-over-Ethernet ARP; anything else is a bug.
			if _, err := arp.ParseFrame(f); err != nil {
				t.Fatalf("spoofer produced a non-ARP frame: % x (%v)", f, err)
			}
		}
	}
	if !sawBuildError {
		t.Fatal("expected at least one IPv6/invalid address to fail to build as an ARP frame")
	}
}

// panicClock panics from After, to exercise Spoofer.Run's own recover
// (as opposed to sendWithTimeout's, which guards a panicking Sender —
// already covered in sender_test.go).
type panicClock struct{ clk Clock }

func (p panicClock) Now() time.Time                       { return p.clk.Now() }
func (p panicClock) After(time.Duration) <-chan time.Time { panic("clock boom") }

func TestSpooferRecoversPanicFromItsOwnLoopLogic(t *testing.T) {
	sender := NewFakeSender()
	clk := NewFakeClock(t0)
	cfg := testSpooferConfig(sender, panicClock{clk})
	sp := NewSpoofer(cfg)
	done := make(chan struct{})
	go func() { sp.Run(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run never returned after a panic in its own loop logic")
	}
	frames := sender.Frames()
	if len(frames) != 2 {
		t.Fatalf("want claim+corrective, got %d", len(frames))
	}
	if arpOf(t, frames[1]).SenderMAC != gwMAC {
		t.Fatal("no corrective after internal panic")
	}
}

func TestSpooferSendErrorReported(t *testing.T) {
	sender := NewFakeSender()
	sender.SetError(errors.New("boom"))
	clk := NewFakeClock(t0)
	var errs []error
	cfg := testSpooferConfig(sender, clk)
	cfg.OnSendError = func(err error) { errs = append(errs, err) }
	sp := NewSpoofer(cfg)
	sp.sendClaim()
	if len(errs) != 1 {
		t.Fatalf("want 1 reported error, got %d", len(errs))
	}
}
