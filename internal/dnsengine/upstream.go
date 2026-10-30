// SPDX-License-Identifier: AGPL-3.0-or-later

package dnsengine

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Upstream is one resolver with live health state.
type Upstream struct {
	Addr       string
	network    string // udp, tcp or tcp-tls
	hostport   string
	serverName string

	mu      sync.Mutex
	healthy bool
	fails   int
	rtt     time.Duration
	lastErr string
	queries uint64
	errors  uint64
}

type UpstreamStatus struct {
	Addr      string  `json:"addr"`
	Healthy   bool    `json:"healthy"`
	RTTms     float64 `json:"rtt_ms"`
	Fails     int     `json:"consecutive_failures"`
	LastError string  `json:"last_error,omitempty"`
	Queries   uint64  `json:"queries"`
	Errors    uint64  `json:"errors"`
}

func parseUpstream(s string) (*Upstream, error) {
	scheme, rest := "udp", s
	if i := strings.Index(s, "://"); i >= 0 {
		scheme, rest = s[:i], s[i+3:]
	}
	u := &Upstream{Addr: s, healthy: true}
	port := "53"
	switch scheme {
	case "udp", "tcp":
		u.network = scheme
	case "tls":
		u.network, port = "tcp-tls", "853"
	default:
		return nil, fmt.Errorf("upstream %q: unsupported scheme %q (use udp, tcp or tls)", s, scheme)
	}
	host, p, err := net.SplitHostPort(rest)
	if err != nil {
		host, p = strings.Trim(rest, "[]"), port
	}
	if host == "" {
		return nil, fmt.Errorf("upstream %q: missing host", s)
	}
	u.hostport, u.serverName = net.JoinHostPort(host, p), host
	return u, nil
}

func (u *Upstream) exchange(ctx context.Context, m *dns.Msg, timeout time.Duration) (*dns.Msg, time.Duration, error) {
	c := &dns.Client{Net: u.network, Timeout: timeout}
	if u.network == "tcp-tls" {
		c.TLSConfig = &tls.Config{ServerName: u.serverName, MinVersion: tls.VersionTLS12}
	}
	resp, rtt, err := c.ExchangeContext(ctx, m, u.hostport)
	if err == nil && resp.Truncated && u.network == "udp" {
		tc := &dns.Client{Net: "tcp", Timeout: timeout}
		resp, rtt, err = tc.ExchangeContext(ctx, m, u.hostport)
	}
	return resp, rtt, err
}

func (u *Upstream) record(ok bool, rtt time.Duration, err error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.queries++
	if ok {
		u.fails, u.healthy, u.lastErr = 0, true, ""
		if u.rtt == 0 {
			u.rtt = rtt
		} else {
			u.rtt = (u.rtt*4 + rtt) / 5
		}
		return
	}
	u.errors++
	u.fails++
	u.lastErr = "SERVFAIL"
	if err != nil {
		u.lastErr = err.Error()
	}
	if u.fails >= 2 {
		u.healthy = false
	}
}

func (u *Upstream) status() UpstreamStatus {
	u.mu.Lock()
	defer u.mu.Unlock()
	return UpstreamStatus{
		Addr: u.Addr, Healthy: u.healthy, RTTms: float64(u.rtt.Microseconds()) / 1000,
		Fails: u.fails, LastError: u.lastErr, Queries: u.queries, Errors: u.errors,
	}
}

// probe sends a query for a unique name so the answer cannot come from any
// cache: it proves the upstream's whole resolution path works.
func (u *Upstream) probe(ctx context.Context, timeout time.Duration) {
	m := new(dns.Msg)
	m.SetQuestion(fmt.Sprintf("sp%08x.example.com.", rand.Uint32()), dns.TypeA)
	m.RecursionDesired = true
	resp, rtt, err := u.exchange(ctx, m, timeout)
	u.record(err == nil && resp != nil && resp.Rcode != dns.RcodeServerFailure, rtt, err)
}

// Pool forwards queries to the healthiest upstream and fails over on error.
type Pool struct {
	ups     []*Upstream
	timeout time.Duration
}

func NewPool(addrs []string) (*Pool, error) {
	if len(addrs) == 0 {
		return nil, errors.New("no upstreams configured")
	}
	p := &Pool{timeout: 2 * time.Second}
	for _, a := range addrs {
		u, err := parseUpstream(a)
		if err != nil {
			return nil, err
		}
		p.ups = append(p.ups, u)
	}
	return p, nil
}

// order puts healthy upstreams first, fastest first; ties keep config order.
func (p *Pool) order() []*Upstream {
	type ranked struct {
		u       *Upstream
		healthy bool
		rtt     time.Duration
	}
	rs := make([]ranked, len(p.ups))
	for i, u := range p.ups {
		u.mu.Lock()
		rtt := u.rtt
		if rtt == 0 {
			rtt = 50 * time.Millisecond
		}
		rs[i] = ranked{u, u.healthy, rtt}
		u.mu.Unlock()
	}
	sort.SliceStable(rs, func(i, j int) bool {
		if rs[i].healthy != rs[j].healthy {
			return rs[i].healthy
		}
		return rs[i].rtt < rs[j].rtt
	})
	out := make([]*Upstream, len(rs))
	for i, r := range rs {
		out[i] = r.u
	}
	return out
}

// Exchange tries up to three upstreams in health order. If every upstream
// fails it returns an error, or the last SERVFAIL if one answered that way.
func (p *Pool) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, *Upstream, time.Duration, error) {
	var lastResp *dns.Msg
	var lastUp *Upstream
	var lastErr error
	for i, u := range p.order() {
		if i == 3 || ctx.Err() != nil {
			break
		}
		resp, rtt, err := u.exchange(ctx, m, p.timeout)
		ok := err == nil && resp != nil && resp.Rcode != dns.RcodeServerFailure
		u.record(ok, rtt, err)
		if ok {
			return resp, u, rtt, nil
		}
		if err != nil {
			lastErr = err
		} else {
			lastResp, lastUp = resp, u
		}
	}
	if lastResp != nil {
		return lastResp, lastUp, 0, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no upstream answered")
	}
	return nil, nil, 0, lastErr
}

// Probe checks every upstream now and then on every interval until ctx ends.
func (p *Pool) Probe(ctx context.Context, every time.Duration) {
	run := func() {
		var wg sync.WaitGroup
		for _, u := range p.ups {
			wg.Add(1)
			go func() {
				defer wg.Done()
				u.probe(ctx, p.timeout)
			}()
		}
		wg.Wait()
	}
	run()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}

// Status returns per-upstream health in configuration order.
func (p *Pool) Status() []UpstreamStatus {
	out := make([]UpstreamStatus, len(p.ups))
	for i, u := range p.ups {
		out[i] = u.status()
	}
	return out
}
