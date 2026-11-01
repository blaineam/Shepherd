// SPDX-License-Identifier: AGPL-3.0-or-later

package intercept

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"shepherd/internal/arp"
	"shepherd/internal/ndp"
)

// ndpSpooferConfig configures one device's one-sided IPv6 steering. It is
// the NDP counterpart of SpooferConfig: same periodic-claim-then-corrective
// shape, same bounded sends, same injectable Clock, but it advertises the
// gateway's link-local address with Neighbor Advertisements instead of
// claiming the gateway's IPv4 with ARP replies.
type ndpSpooferConfig struct {
	Sender Sender
	Clock  Clock

	Interval    time.Duration
	SendTimeout time.Duration

	ShepherdMAC      arp.MAC
	GatewayMAC       arp.MAC // the gateway's real MAC, restored on stop
	GatewayLinkLocal netip.Addr

	DeviceMAC arp.MAC
	DeviceIP6 netip.Addr

	OnSendError func(error)
}

func (c ndpSpooferConfig) withDefaults() ndpSpooferConfig {
	if c.Interval <= 0 {
		c.Interval = DefaultSpoofInterval
	}
	if c.SendTimeout <= 0 {
		c.SendTimeout = DefaultSendTimeout
	}
	return c
}

// ndpSpoofer periodically tells one device that the gateway's link-local
// address lives at Shepherd's MAC (an unsolicited Neighbor Advertisement),
// and restores the real mapping the instant it stops, so the device's
// neighbor cache recovers immediately instead of waiting out its own
// timers. Its lifecycle is identical to Spoofer's: Run blocks until ctx is
// cancelled or Stop is called, the corrective revert always runs before
// Run returns (cancel, Stop, or a panic in the loop), and a recovered
// panic is reported best-effort rather than propagating.
type ndpSpoofer struct {
	cfg  ndpSpooferConfig
	stop chan struct{}

	// armed mirrors Spoofer.armed: a test-only hook called synchronously
	// in the Run goroutine each time the next periodic timer is armed.
	armed func()
}

func newNDPSpoofer(cfg ndpSpooferConfig) *ndpSpoofer {
	return &ndpSpoofer{cfg: cfg.withDefaults(), stop: make(chan struct{})}
}

// Stop asks Run to exit and send the corrective revert. Safe to call more
// than once, and before Run starts.
func (s *ndpSpoofer) Stop() {
	select {
	case <-s.stop:
	default:
		close(s.stop)
	}
}

// Run sends the claim immediately, repeats it every Interval until ctx is
// cancelled or Stop is called, then sends the corrective revert.
func (s *ndpSpoofer) Run(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil && s.cfg.OnSendError != nil {
			s.cfg.OnSendError(fmt.Errorf("intercept: ndp spoof loop panicked: %v", r))
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

func (s *ndpSpoofer) sendClaim() {
	b, err := ndp.Claim(s.cfg.ShepherdMAC, s.cfg.DeviceMAC, s.cfg.GatewayLinkLocal, s.cfg.DeviceIP6)
	s.send(b, err)
}

func (s *ndpSpoofer) sendCorrective() {
	b, err := ndp.Corrective(s.cfg.GatewayMAC, s.cfg.DeviceMAC, s.cfg.GatewayLinkLocal, s.cfg.DeviceIP6)
	s.send(b, err)
}

// send transmits a pre-built frame with a bounded timeout. A build error
// (only possible on a non-IPv6 or multicast address, which Controller.Steer
// rejects before an ndpSpoofer is ever created) is reported best-effort,
// never panicked.
func (s *ndpSpoofer) send(b []byte, buildErr error) {
	if buildErr != nil {
		if s.cfg.OnSendError != nil {
			s.cfg.OnSendError(fmt.Errorf("intercept: build NDP frame: %w", buildErr))
		}
		return
	}
	if err := sendWithTimeout(s.cfg.Sender, Frame(b), s.cfg.SendTimeout); err != nil {
		if s.cfg.OnSendError != nil {
			s.cfg.OnSendError(err)
		}
	}
}
