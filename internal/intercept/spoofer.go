// SPDX-License-Identifier: AGPL-3.0-or-later

package intercept

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"shepherd/internal/arp"
)

// DefaultSpoofInterval is how often the Spoofer repeats its claim while
// steering is active. A device's own ARP cache TTL is normally minutes,
// not seconds, so repeating this often is cheap insurance, not load.
const DefaultSpoofInterval = 2 * time.Second

// SpooferConfig configures one device's one-sided ARP steering. Every
// field is required except Interval and SendTimeout, which default.
type SpooferConfig struct {
	Sender Sender
	Clock  Clock

	Interval    time.Duration // default DefaultSpoofInterval
	SendTimeout time.Duration // default DefaultSendTimeout; bounds every Send

	ShepherdMAC arp.MAC // claimed as the gateway's MAC while steering
	GatewayIP   netip.Addr
	GatewayMAC  arp.MAC // the gateway's real MAC, restored on stop

	TargetMAC arp.MAC // the steered device
	TargetIP  netip.Addr

	// OnSendError, when set, is called with the error from a claim or
	// corrective send that failed or timed out. Optional.
	OnSendError func(error)
}

func (c SpooferConfig) withDefaults() SpooferConfig {
	if c.Interval <= 0 {
		c.Interval = DefaultSpoofInterval
	}
	if c.SendTimeout <= 0 {
		c.SendTimeout = DefaultSendTimeout
	}
	return c
}

// Spoofer periodically tells one device that Shepherd's MAC owns the
// gateway's IP, and restores the real mapping the moment it stops, so the
// device recovers immediately instead of waiting out its ARP cache TTL.
//
// Run blocks until ctx is cancelled or Stop is called. The corrective
// revert always runs before Run returns — on a cancelled context, on
// Stop, and even if something inside the loop panics, because a device
// must never be left steered with nothing un-steering it. A recovered
// panic is reported through OnSendError-style best effort (it does not
// propagate: a bug in the spoof loop must not crash Shepherd and leave
// every other steered device stuck) and Run returns normally.
type Spoofer struct {
	cfg  SpooferConfig
	stop chan struct{}

	// armed is a test-only hook, called synchronously in the Run
	// goroutine each time the next periodic timer has just been
	// registered with Clock. It lets tests drive a FakeClock through
	// several ticks without racing the loop's own re-arm (the same
	// problem, and the same fix, as Controller's afterHealthCheck).
	// Nothing in this package's public API sets it.
	armed func()
}

// NewSpoofer builds a Spoofer. Call Run in its own goroutine.
func NewSpoofer(cfg SpooferConfig) *Spoofer {
	return &Spoofer{cfg: cfg.withDefaults(), stop: make(chan struct{})}
}

// Stop asks Run to exit and send the corrective revert. Safe to call more
// than once, and safe to call before Run starts.
func (s *Spoofer) Stop() {
	select {
	case <-s.stop:
	default:
		close(s.stop)
	}
}

// Run sends the spoofed claim immediately, repeats it every Interval
// until ctx is cancelled or Stop is called, then sends the corrective
// revert and returns.
func (s *Spoofer) Run(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil && s.cfg.OnSendError != nil {
			s.cfg.OnSendError(fmt.Errorf("intercept: spoof loop panicked: %v", r))
		}
	}()

	func() {
		defer func() { recover() }() // the revert below must still run
		s.sendClaim()
		for {
			tick := s.cfg.Clock.After(s.cfg.Interval)
			if s.armed != nil {
				s.armed()
			}
			select {
			case <-ctx.Done():
				return
			case <-s.stop:
				return
			case <-tick:
				s.sendClaim()
			}
		}
	}()

	s.sendCorrective()
}

func (s *Spoofer) sendClaim() {
	s.send(arp.NewReply(s.cfg.ShepherdMAC, s.cfg.GatewayIP, s.cfg.TargetMAC, s.cfg.TargetIP))
}

func (s *Spoofer) sendCorrective() {
	s.send(arp.NewReply(s.cfg.GatewayMAC, s.cfg.GatewayIP, s.cfg.TargetMAC, s.cfg.TargetIP))
}

// send marshals f with internal/arp's own codec and transmits it with a
// bounded timeout. Marshal can only fail here on a non-IPv4 address, which
// Controller.Steer and NewController both reject before a Spoofer is ever
// built, so this is defense in depth, not a path tests need to force.
func (s *Spoofer) send(f arp.Frame) {
	b, err := f.Marshal()
	if err != nil {
		if s.cfg.OnSendError != nil {
			s.cfg.OnSendError(fmt.Errorf("intercept: build spoof frame: %w", err))
		}
		return
	}
	if err := sendWithTimeout(s.cfg.Sender, Frame(b), s.cfg.SendTimeout); err != nil {
		if s.cfg.OnSendError != nil {
			s.cfg.OnSendError(err)
		}
	}
}
