// SPDX-License-Identifier: AGPL-3.0-or-later

package devices

import (
	"context"
	"strings"
	"sync"
	"time"
)

// ReverseLookup resolves an IP to PTR names. The caller supplies it (for
// example a net.Resolver pointed at the router) so tests never touch a
// network.
type ReverseLookup func(ctx context.Context, ip string) ([]string, error)

// ReverseDNSOptions tunes ReverseDNS.
type ReverseDNSOptions struct {
	Interval    time.Duration // minimum spacing between lookups; default 100ms
	TTL         time.Duration // cache for answers; default 6h
	NegativeTTL time.Duration // cache for failures and empty answers; default 30m
	MaxQueue    int           // default 256
	Timeout     time.Duration // per lookup; default 3s
	Now         func() time.Time
}

// ReverseDNS looks up PTR names for newly seen IPs, rate-limited and cached,
// and feeds the names to a Sink as SourceReverseDNS observations. Those never
// create a device on their own.
type ReverseDNS struct {
	lookup ReverseLookup
	sink   Sink
	opts   ReverseDNSOptions

	mu     sync.Mutex
	cache  map[string]time.Time // ip -> expiry
	queued map[string]bool
	queue  []string
	wake   chan struct{}
}

// NewReverseDNS builds a resolver front-end.
func NewReverseDNS(lookup ReverseLookup, sink Sink, opts ReverseDNSOptions) *ReverseDNS {
	if opts.Interval <= 0 {
		opts.Interval = 100 * time.Millisecond
	}
	if opts.TTL <= 0 {
		opts.TTL = 6 * time.Hour
	}
	if opts.NegativeTTL <= 0 {
		opts.NegativeTTL = 30 * time.Minute
	}
	if opts.MaxQueue <= 0 {
		opts.MaxQueue = 256
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 3 * time.Second
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &ReverseDNS{lookup: lookup, sink: sink, opts: opts,
		cache: map[string]time.Time{}, queued: map[string]bool{}, wake: make(chan struct{}, 1)}
}

// Submit queues an IP for lookup. It returns false when the IP is cached,
// already queued, invalid, or the queue is full.
func (r *ReverseDNS) Submit(ip string) bool {
	a, ok := parseIP(ip)
	if !ok {
		return false
	}
	ip = a.String()
	r.mu.Lock()
	defer r.mu.Unlock()
	if exp, ok := r.cache[ip]; ok && r.opts.Now().Before(exp) {
		return false
	}
	if r.queued[ip] || len(r.queue) >= r.opts.MaxQueue {
		return false
	}
	r.queued[ip] = true
	r.queue = append(r.queue, ip)
	select {
	case r.wake <- struct{}{}:
	default:
	}
	return true
}

// Pending is the number of queued lookups.
func (r *ReverseDNS) Pending() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.queue)
}

// Step performs one queued lookup, ignoring the rate limit (Run supplies
// it). It returns false when the queue was empty.
func (r *ReverseDNS) Step(ctx context.Context) bool {
	r.mu.Lock()
	if len(r.queue) == 0 {
		r.mu.Unlock()
		return false
	}
	ip := r.queue[0]
	r.queue = r.queue[1:]
	delete(r.queued, ip)
	r.mu.Unlock()

	lctx, cancel := context.WithTimeout(ctx, r.opts.Timeout)
	names, err := r.lookup(lctx, ip)
	cancel()

	ttl := r.opts.NegativeTTL
	if err == nil && len(names) > 0 {
		if n := strings.TrimSuffix(names[0], "."); n != "" {
			ttl = r.opts.TTL
			r.sink.Observe(Observation{Source: SourceReverseDNS, IP: ip, Hostname: n, Time: r.opts.Now()})
		}
	}
	r.mu.Lock()
	r.cache[ip] = r.opts.Now().Add(ttl)
	r.mu.Unlock()
	return true
}

// Run processes the queue at no more than one lookup per Interval until ctx
// is cancelled.
func (r *ReverseDNS) Run(ctx context.Context) error {
	t := time.NewTicker(r.opts.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if r.Step(ctx) {
				continue
			}
			select {
			case <-ctx.Done():
				return nil
			case <-r.wake:
			}
		}
	}
}

// AttachReverseDNS asks for a PTR lookup of every address of each new
// device the registry announces.
func AttachReverseDNS(reg *Registry, rd *ReverseDNS) (unsubscribe func()) {
	return reg.Subscribe(func(e Event) {
		if e.Kind == EventNewDevice && e.Device != nil {
			for _, ip := range e.Device.IPs {
				rd.Submit(ip)
			}
		}
	})
}

var _ Discoverer = (*ReverseDNS)(nil)
