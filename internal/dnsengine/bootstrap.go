// SPDX-License-Identifier: AGPL-3.0-or-later

package dnsengine

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// DefaultBootstrap is the default comma-separated list of plain resolvers used
// to look up the hostnames of tls:// and https:// upstreams. Use
// DefaultBootstrapServers for a slice.
const DefaultBootstrap = "9.9.9.9,1.1.1.1"

// DefaultBootstrapServers returns DefaultBootstrap as a slice.
func DefaultBootstrapServers() []string { return []string{"9.9.9.9", "1.1.1.1"} }

const (
	bootMinTTL = 60 * time.Second
	bootMaxTTL = time.Hour
	// bootPartialTTL is how long an answer is trusted when one address
	// family could not be fetched (a lost UDP packet): long enough not to
	// hammer the bootstrap resolvers, far shorter than the usual floor so
	// the missing addresses arrive quickly.
	bootPartialTTL = 5 * time.Second
)

// upstreamEnv is shared by every upstream of a pool.
type upstreamEnv struct {
	boot  *bootstrap
	roots *x509.CertPool // nil in production (system roots); tests inject a CA
}

func newUpstreamEnv() *upstreamEnv {
	b := newBootstrap()
	_ = b.setServers(DefaultBootstrapServers())
	return &upstreamEnv{boot: b}
}

// bootstrap resolves encrypted-upstream hostnames over plain UDP/TCP using a
// fixed list of IP-addressed resolvers. It never consults the system resolver:
// a resolver that depends on itself for DNS would deadlock the network.
type bootstrap struct {
	mu       sync.Mutex
	servers  []string // host:port
	raw      []string // as configured, for display and persistence
	cache    map[string]*bootEntry
	inflight map[string]*bootCall
	now      func() time.Time
	query    func(ctx context.Context, server string, m *dns.Msg) (*dns.Msg, error)
}

type bootEntry struct {
	addrs     []netip.Addr
	refreshAt time.Time
	expires   time.Time
}

type bootCall struct {
	done  chan struct{}
	addrs []netip.Addr
	err   error
}

// bootResult is what one resolution learned. lost4/lost6 mean that family's
// query failed (it timed out or was refused), which is different from the
// family having no records: an empty answer is complete, a lost one is not.
type bootResult struct {
	addrs        []netip.Addr
	ttl          time.Duration
	lost4, lost6 bool
}

func newBootstrap() *bootstrap {
	return &bootstrap{
		cache: map[string]*bootEntry{}, inflight: map[string]*bootCall{},
		now: time.Now, query: bootstrapQuery,
	}
}

func (b *bootstrap) setServers(servers []string) error {
	if len(servers) == 0 {
		return errors.New("bootstrap: at least one resolver is required")
	}
	out := make([]string, 0, len(servers))
	raw := make([]string, 0, len(servers))
	for _, s := range servers {
		u, err := parseUpstream(s)
		if err != nil || (u.kind != KindUDP) {
			return fmt.Errorf("bootstrap resolver %q must be an IP address with an optional port", s)
		}
		out = append(out, u.hostport)
		raw = append(raw, u.Addr)
	}
	b.mu.Lock()
	b.servers = out
	b.raw = raw
	b.mu.Unlock()
	return nil
}

func bootstrapQuery(ctx context.Context, server string, m *dns.Msg) (*dns.Msg, error) {
	c := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	resp, _, err := c.ExchangeContext(ctx, m, server)
	if err == nil && resp.Truncated {
		tc := &dns.Client{Net: "tcp", Timeout: 2 * time.Second}
		resp, _, err = tc.ExchangeContext(ctx, m, server)
	}
	return resp, err
}

// lookup returns the IP addresses of host. Literals are returned as is. A
// cached answer is served until it expires; it is refreshed in the background
// once three quarters of its lifetime have passed, and if a refresh fails the
// last good answer keeps being used rather than breaking a working upstream.
func (b *bootstrap) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, nil
	}
	b.mu.Lock()
	e := b.cache[host]
	now := b.now()
	if e != nil && now.Before(e.refreshAt) {
		addrs := append([]netip.Addr(nil), e.addrs...)
		b.mu.Unlock()
		return addrs, nil
	}
	call := b.startLocked(host)
	if e != nil && now.Before(e.expires) {
		addrs := append([]netip.Addr(nil), e.addrs...)
		b.mu.Unlock()
		return addrs, nil // refresh continues in the background
	}
	b.mu.Unlock()
	select {
	case <-call.done:
	case <-ctx.Done():
		return nil, fmt.Errorf("bootstrap: resolving %s: %w", host, ctx.Err())
	}
	if call.err != nil {
		if e != nil { // expired but better than nothing
			return append([]netip.Addr(nil), e.addrs...), nil
		}
		return nil, call.err
	}
	return append([]netip.Addr(nil), call.addrs...), nil
}

// startLocked joins or starts the single in-flight resolution of host.
func (b *bootstrap) startLocked(host string) *bootCall {
	if c, ok := b.inflight[host]; ok {
		return c
	}
	c := &bootCall{done: make(chan struct{})}
	b.inflight[host] = c
	servers := append([]string(nil), b.servers...)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		r, err := b.resolve(ctx, host, servers)
		addrs := r.addrs
		b.mu.Lock()
		if err == nil {
			now := b.now()
			ttl := min(max(r.ttl, bootMinTTL), bootMaxTTL)
			refresh := now.Add(ttl * 3 / 4)
			if r.lost4 || r.lost6 {
				// Part of the answer is missing. Keep what was known for the
				// missing family (a refresh must never replace a working
				// address with nothing), and ask again soon.
				addrs = mergeKnown(addrs, b.cache[host], r.lost4, r.lost6)
				refresh = now.Add(bootPartialTTL)
			}
			b.cache[host] = &bootEntry{addrs: addrs, refreshAt: refresh, expires: now.Add(ttl)}
		}
		delete(b.inflight, host)
		b.mu.Unlock()
		c.addrs, c.err = addrs, err
		close(c.done)
	}()
	return c
}

// resolve asks each bootstrap server in turn for both address families. A
// query that is lost is tried once more, and a family that is still lost is
// reported in the result, so a caller never mistakes "the packet was dropped"
// for "this host has no IPv4 address".
func (b *bootstrap) resolve(ctx context.Context, host string, servers []string) (bootResult, error) {
	fqdn := dns.Fqdn(host)
	var lastErr error
	for _, s := range servers {
		if ctx.Err() != nil {
			break
		}
		var wg sync.WaitGroup
		var res [2]struct {
			addrs []netip.Addr
			ttl   time.Duration
			rcode int
			err   error
		}
		for i, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				m := new(dns.Msg)
				m.SetQuestion(fqdn, qt)
				m.RecursionDesired = true
				var resp *dns.Msg
				var err error
				for attempt := 0; attempt < 2; attempt++ {
					if resp, err = b.query(ctx, s, m); err == nil || ctx.Err() != nil {
						break
					}
				}
				if err != nil {
					res[i].err = err
					return
				}
				res[i].rcode = resp.Rcode
				if resp.Rcode != dns.RcodeSuccess {
					return
				}
				res[i].addrs, res[i].ttl = extractAddrs(resp)
			}()
		}
		wg.Wait()
		var out bootResult
		for _, r := range res {
			out.addrs = append(out.addrs, r.addrs...)
			if r.ttl > 0 && (out.ttl == 0 || r.ttl < out.ttl) {
				out.ttl = r.ttl
			}
		}
		out.lost4, out.lost6 = res[0].err != nil, res[1].err != nil
		if len(out.addrs) > 0 {
			return out, nil
		}
		switch {
		case res[0].err != nil:
			lastErr = res[0].err
		case res[1].err != nil:
			lastErr = res[1].err
		case res[0].rcode == dns.RcodeNameError:
			lastErr = errors.New("no such host")
		default:
			lastErr = errors.New("no A or AAAA records")
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no bootstrap resolver reachable")
	}
	return bootResult{}, fmt.Errorf("bootstrap: cannot resolve %s: %w", host, lastErr)
}

// mergeKnown adds to a partial answer the addresses a previous entry held for
// the family that was lost. IPv4 stays ahead of IPv6, the order DoT dials in.
func mergeKnown(fresh []netip.Addr, old *bootEntry, lost4, lost6 bool) []netip.Addr {
	out := append([]netip.Addr(nil), fresh...)
	if old != nil {
		for _, a := range old.addrs {
			if (a.Is4() && lost4) || (a.Is6() && lost6) {
				if !slices.Contains(out, a) {
					out = append(out, a)
				}
			}
		}
	}
	slices.SortStableFunc(out, func(x, y netip.Addr) int {
		switch {
		case x.Is4() && !y.Is4():
			return -1
		case !x.Is4() && y.Is4():
			return 1
		}
		return 0
	})
	return out
}

func extractAddrs(resp *dns.Msg) ([]netip.Addr, time.Duration) {
	var addrs []netip.Addr
	var ttl time.Duration
	note := func(ip net.IP, t uint32) {
		a, ok := netip.AddrFromSlice(ip)
		if !ok {
			return
		}
		addrs = append(addrs, a.Unmap())
		if d := time.Duration(t) * time.Second; ttl == 0 || d < ttl {
			ttl = d
		}
	}
	for _, rr := range resp.Answer {
		switch v := rr.(type) {
		case *dns.A:
			note(v.A, v.Hdr.Ttl)
		case *dns.AAAA:
			note(v.AAAA, v.Hdr.Ttl)
		}
	}
	return addrs, ttl
}
