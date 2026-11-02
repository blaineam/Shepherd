// SPDX-License-Identifier: AGPL-3.0-or-later

package dnsengine

import (
	"context"
	"net"
	"sync/atomic"
	"time"
)

// IPv6Probe decides whether AAAA answers are worth giving out: it asks
// whether this host can open an outbound IPv6 connection to the internet.
// A network that hands devices only private (fd..) or link-local IPv6
// addresses has no such route; every AAAA answer there is an address the
// device cannot reach, and devices that try it first, or handle the
// failure badly, report a network problem.
//
// The test is a TCP connect to a few well-known anycast resolvers on
// port 443. One success is enough to call IPv6 usable and it is believed at
// once; it takes two failed rounds in a row to call it unusable, so one
// lost packet does not flip the answer the whole network gets.
type IPv6Probe struct {
	// Targets are host:port IPv6 addresses to try; default DefaultIPv6Targets.
	Targets []string
	// Timeout bounds each connect; default 3s.
	Timeout time.Duration
	// Dial is a test seam; default net.Dialer.DialContext.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// OnChange is told when the verdict flips, for the log.
	OnChange func(usable bool)

	filtering atomic.Bool
	fails     int
}

// DefaultIPv6Targets are Cloudflare, Google and Quad9's public IPv6 addresses.
var DefaultIPv6Targets = []string{"[2606:4700:4700::1111]:443", "[2001:4860:4860::8888]:443", "[2620:fe::fe]:443"} // leakcheck:allow public resolvers

// Filtering reports whether AAAA answers should be withheld: true only
// once IPv6 has been found unusable.
func (p *IPv6Probe) Filtering() bool { return p.filtering.Load() }

// Check runs one round and updates the verdict.
func (p *IPv6Probe) Check(ctx context.Context) {
	usable := p.reachable(ctx)
	if usable {
		p.fails = 0
		if p.filtering.Swap(false) && p.OnChange != nil {
			p.OnChange(true)
		}
		return
	}
	p.fails++
	if p.fails >= 2 && !p.filtering.Swap(true) && p.OnChange != nil {
		p.OnChange(false)
	}
}

func (p *IPv6Probe) reachable(ctx context.Context) bool {
	targets := p.Targets
	if len(targets) == 0 {
		targets = DefaultIPv6Targets
	}
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	dial := p.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	won := make(chan bool, len(targets))
	for _, t := range targets {
		go func() {
			c, err := dial(ctx, "tcp6", t)
			if err == nil {
				_ = c.Close()
			}
			won <- err == nil
		}()
	}
	for range targets {
		if <-won {
			return true
		}
	}
	return false
}

// Run checks now and then every interval until ctx ends.
func (p *IPv6Probe) Run(ctx context.Context, every time.Duration) {
	p.Check(ctx)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.Check(ctx)
		}
	}
}
