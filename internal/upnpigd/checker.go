// SPDX-License-Identifier: AGPL-3.0-or-later

package upnpigd

import (
	"context"
	"log"
	"sync"
	"time"
)

// DefaultRefreshInterval is how often a Checker re-queries the router's
// NAT table when its caller does not configure its own interval. UPnP
// discovery and SOAP enumeration are slow and fragile compared to
// internal/portscan's own TCP connect probes (see docs/PORTSCAN.md), so a
// Checker never does a fresh round trip more often than this, no matter
// how many times Exposure is called in between — a home network's port
// forwarding rarely changes minute to minute.
const DefaultRefreshInterval = 10 * time.Minute

// MappingsFetcher is the part of Client a Checker needs: one cacheable
// call to the router's NAT table. Production passes a real *Client; tests
// inject a fake, the same way Checker itself stands in for a real IGD in
// internal/portscan's own tests.
type MappingsFetcher interface {
	Mappings(ctx context.Context) ([]Mapping, error)
}

// Checker caches a MappingsFetcher's result so that repeated Exposure
// lookups — one per open port, every portscan scan cycle — cost at most
// one discovery-and-enumerate round trip per RefreshInterval, never one
// per lookup.
//
// On a failed refresh (no IGD answered, or a query failed) Checker
// discards whatever mappings it had and reports every lookup as unknown
// until a refresh succeeds again. A NAT table is only trustworthy as of
// right now; serving an old one as if it still held after the router
// stopped answering would be exactly the kind of guess this feature must
// never make (see internal/portscan.ExposureUnknown). The first-ever
// failure is logged once; later failures stay silent — the same "log
// once, never spam" convention cmd/shepherd/geoblock.go uses for its own
// always-on dependency check.
type Checker struct {
	fetcher MappingsFetcher
	every   time.Duration

	mu          sync.Mutex
	mappings    []Mapping
	available   bool
	lastAttempt time.Time

	warnOnce sync.Once
}

// NewChecker wraps fetcher with caching. every <= 0 uses
// DefaultRefreshInterval.
func NewChecker(fetcher MappingsFetcher, every time.Duration) *Checker {
	if every <= 0 {
		every = DefaultRefreshInterval
	}
	return &Checker{fetcher: fetcher, every: every}
}

// refreshLocked re-queries the fetcher if the cache is older than every,
// or there has never been an attempt. Must be called with mu held; it
// performs the (possibly slow) network round trip while holding the lock,
// which is fine because internal/portscan only ever calls Exposure from
// one goroutine at a time per scan (Scanner.Scan serializes whole scans).
func (c *Checker) refreshLocked(ctx context.Context, now time.Time) {
	if !c.lastAttempt.IsZero() && now.Sub(c.lastAttempt) < c.every {
		return
	}
	c.lastAttempt = now
	mappings, err := c.fetcher.Mappings(ctx)
	if err != nil {
		c.mappings, c.available = nil, false
		c.warnOnce.Do(func() {
			log.Printf("portscan: UPnP IGD port-mapping lookup unavailable (%v); WAN-exposure will show as unknown until a router answers", err)
		})
		return
	}
	c.mappings, c.available = mappings, true
}

// Exposure reports whether ip:port (a TCP port internal/portscan found
// open) is currently forwarded from the WAN per the router's own NAT
// table, refreshing the cache first if it is older than every. ok is
// false whenever that cannot be determined this round — the caller must
// then record ExposureUnknown, never guess lan_only or wan_forwarded.
func (c *Checker) Exposure(ctx context.Context, ip string, port int) (wanForwarded bool, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.refreshLocked(ctx, time.Now())
	if !c.available {
		return false, false
	}
	for _, m := range c.mappings {
		if m.Enabled && m.Protocol == "TCP" && m.InternalPort == port && m.InternalClient == ip {
			return true, true
		}
	}
	return false, true
}
