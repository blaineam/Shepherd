// SPDX-License-Identifier: AGPL-3.0-or-later

package dnsengine

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Upstream kinds, as reported by Pool.List.
const (
	KindUDP = "udp"
	KindTCP = "tcp"
	KindDoT = "dot"
	KindDoH = "doh"
)

const defaultDoHPath = "/dns-query"

// Upstream is one resolver with live health state.
type Upstream struct {
	Addr       string // the configuration string, exactly as given (trimmed)
	kind       string
	network    string // udp, tcp, tcp-tls or https
	hostport   string
	serverName string // TLS name: empty when the host is an IP literal
	host       string
	dohURL     string
	env        *upstreamEnv

	clientOnce sync.Once
	client     *dohClient

	mu      sync.Mutex
	healthy bool
	fails   int
	rtt     time.Duration
	lastErr string
	queries uint64
	errors  uint64

	// onHealth, when set by the owning Pool, is called outside the lock
	// whenever record() changes healthy. See Pool.OnHealthChange.
	onHealth func(addr string, healthy bool)
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

// UpstreamInfo is one configured upstream with its status, for the portal.
type UpstreamInfo struct {
	Config string `json:"config"`
	Kind   string `json:"kind"` // udp, tcp, dot or doh
	UpstreamStatus
}

// key identifies the endpoint independent of how it was spelled.
func (u *Upstream) key() string { return u.network + "|" + u.hostport + "|" + u.dohURL }

// ValidateUpstream reports whether addr is a usable upstream address. Accepted
// forms: IP, IP:port, [v6]:port, udp://, tcp://, tls://host[:853] (DoT) and
// https://host[:port]/path (DoH). Plain upstreams must be IP literals so the
// pool never needs the system resolver.
func ValidateUpstream(addr string) error {
	_, err := parseUpstream(addr)
	return err
}

func parseUpstream(s string) (*Upstream, error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return nil, errors.New("upstream address is empty")
	}
	scheme, rest := "udp", raw
	if i := strings.Index(raw, "://"); i >= 0 {
		scheme, rest = strings.ToLower(raw[:i]), raw[i+3:]
	}
	u := &Upstream{Addr: raw, healthy: true}
	fail := func(format string, a ...any) (*Upstream, error) {
		return nil, fmt.Errorf("upstream %q: %s", raw, fmt.Sprintf(format, a...))
	}
	switch scheme {
	case "udp", "tcp":
		host, port, err := splitHostPort(rest, "53")
		if err != nil {
			return fail("%v", err)
		}
		if _, err := parseIPHost(host); err != nil {
			return fail("%v; plain upstreams must be IP addresses (use tls:// or https:// for a hostname)", err)
		}
		u.kind, u.network = scheme, scheme
		u.host, u.hostport = host, net.JoinHostPort(host, port)
	case "tls":
		host, port, err := splitHostPort(rest, "853")
		if err != nil {
			return fail("%v", err)
		}
		if err := checkHost(host); err != nil {
			return fail("%v", err)
		}
		u.kind, u.network = KindDoT, "tcp-tls"
		u.host, u.hostport = host, net.JoinHostPort(host, port)
		u.serverName = nameIfHost(host)
	case "https":
		pu, err := url.Parse(raw)
		if err != nil {
			return fail("malformed URL: %v", errors.Unwrap(err))
		}
		if pu.User != nil {
			return fail("credentials in the URL are not supported")
		}
		if pu.Fragment != "" || strings.Contains(raw, "#") {
			return fail("URL must not contain a fragment")
		}
		host := pu.Hostname()
		if host == "" {
			return fail("missing host")
		}
		if err := checkHost(host); err != nil {
			return fail("%v", err)
		}
		port := pu.Port()
		if port == "" {
			port = "443"
		}
		if err := checkPort(port); err != nil {
			return fail("%v", err)
		}
		if pu.Path == "" {
			pu.Path = defaultDoHPath
		}
		pu.Host = net.JoinHostPort(host, port)
		u.kind, u.network = KindDoH, "https"
		u.host, u.hostport, u.dohURL = host, pu.Host, pu.String()
		u.serverName = nameIfHost(host)
	case "http":
		return fail("plain http is not supported: DNS-over-HTTPS requires https://")
	default:
		return fail("unsupported scheme %q (use udp, tcp, tls or https)", scheme)
	}
	return u, nil
}

// splitHostPort accepts host, host:port, [v6] and [v6]:port, plus a bare IPv6.
func splitHostPort(s, defPort string) (string, string, error) {
	if s == "" {
		return "", "", errors.New("missing host")
	}
	if strings.ContainsAny(s, "/?# ") {
		return "", "", errors.New("unexpected path, query or space after the host")
	}
	host, port := s, defPort
	switch {
	case strings.HasPrefix(s, "["):
		if strings.HasSuffix(s, "]") {
			host = s[1 : len(s)-1]
		} else {
			h, p, err := net.SplitHostPort(s)
			if err != nil {
				return "", "", errors.New("malformed host:port")
			}
			host, port = h, p
		}
	case strings.Count(s, ":") == 1:
		h, p, err := net.SplitHostPort(s)
		if err != nil {
			return "", "", errors.New("malformed host:port")
		}
		host, port = h, p
	case strings.Count(s, ":") > 1:
		// bare IPv6 literal
	}
	if host == "" {
		return "", "", errors.New("missing host")
	}
	if err := checkPort(port); err != nil {
		return "", "", err
	}
	return host, port, nil
}

func checkPort(p string) error {
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("invalid port %q", p)
	}
	return nil
}

func parseIPHost(host string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return ip, fmt.Errorf("%q is not an IP address", host)
	}
	if ip.Zone() != "" {
		return ip, errors.New("IPv6 zones are not supported")
	}
	if ip.IsUnspecified() || ip.IsMulticast() {
		return ip, fmt.Errorf("%s is not a usable resolver address", ip)
	}
	return ip, nil
}

// checkHost accepts an IP literal or a valid DNS hostname.
func checkHost(host string) error {
	if _, err := netip.ParseAddr(host); err == nil {
		_, err := parseIPHost(host)
		return err
	}
	return checkHostname(host)
}

func checkHostname(h string) error {
	h = strings.TrimSuffix(h, ".")
	if h == "" || len(h) > 253 {
		return fmt.Errorf("invalid hostname %q", h)
	}
	labels := strings.Split(h, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return fmt.Errorf("invalid hostname %q", h)
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return fmt.Errorf("invalid hostname %q", h)
			}
		}
	}
	last := labels[len(labels)-1]
	if last[0] >= '0' && last[0] <= '9' {
		return fmt.Errorf("invalid hostname or malformed IP address %q", h)
	}
	return nil
}

func nameIfHost(host string) string {
	if _, err := netip.ParseAddr(host); err == nil {
		return ""
	}
	return host
}

// targets are the host:port endpoints to dial: the literal itself, or the
// bootstrap-resolved addresses of a hostname (never the system resolver).
func (u *Upstream) targets(ctx context.Context) ([]string, error) {
	if u.serverName == "" {
		return []string{u.hostport}, nil
	}
	_, port, _ := net.SplitHostPort(u.hostport)
	ips, err := u.env.boot.lookup(ctx, u.host)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(ips))
	for i, ip := range ips {
		out[i] = net.JoinHostPort(ip.String(), port)
	}
	return out, nil
}

func (u *Upstream) exchange(ctx context.Context, m *dns.Msg, timeout time.Duration) (*dns.Msg, time.Duration, error) {
	switch u.network {
	case "https":
		return u.exchangeDoH(ctx, m, timeout)
	case "tcp-tls":
		return u.exchangeDoT(ctx, m, timeout)
	}
	c := &dns.Client{Net: u.network, Timeout: timeout}
	resp, rtt, err := c.ExchangeContext(ctx, m, u.hostport)
	if err == nil && resp.Truncated && u.network == "udp" {
		tc := &dns.Client{Net: "tcp", Timeout: timeout}
		resp, rtt, err = tc.ExchangeContext(ctx, m, u.hostport)
	}
	return resp, rtt, err
}

func (u *Upstream) exchangeDoT(ctx context.Context, m *dns.Msg, timeout time.Duration) (*dns.Msg, time.Duration, error) {
	targets, err := u.targets(ctx)
	if err != nil {
		return nil, 0, err
	}
	c := &dns.Client{Net: "tcp-tls", Timeout: timeout, TLSConfig: &tls.Config{
		ServerName: u.serverName, MinVersion: tls.VersionTLS12, RootCAs: u.env.roots,
	}}
	var lastErr error
	for i, t := range targets {
		if i == 2 || ctx.Err() != nil {
			break
		}
		resp, rtt, err := c.ExchangeContext(ctx, m, t)
		if err == nil {
			return resp, rtt, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = ctx.Err()
	}
	return nil, 0, lastErr
}

func (u *Upstream) record(ok bool, rtt time.Duration, err error) {
	u.mu.Lock()
	was := u.healthy
	u.queries++
	if ok {
		u.fails, u.healthy, u.lastErr = 0, true, ""
		if u.rtt == 0 {
			u.rtt = rtt
		} else {
			u.rtt = (u.rtt*4 + rtt) / 5
		}
	} else {
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
	now, cb := u.healthy, u.onHealth
	u.mu.Unlock()
	// Called outside the lock: a callback that queries the pool (as the alarm
	// wiring does, to see every upstream's current state) must not deadlock.
	if cb != nil && now != was {
		cb(u.Addr, now)
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

// probeQuery builds a query for a unique name so the answer cannot come from
// any cache: it proves the upstream's whole resolution path works.
func probeQuery() *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(fmt.Sprintf("sp%08x.example.com.", rand.Uint32()), dns.TypeA)
	m.RecursionDesired = true
	return m
}

func answered(resp *dns.Msg, err error) bool {
	return err == nil && resp != nil && resp.Rcode != dns.RcodeServerFailure
}

func (u *Upstream) probe(ctx context.Context, timeout time.Duration) {
	resp, rtt, err := u.exchange(ctx, probeQuery(), timeout)
	u.record(answered(resp, err), rtt, err)
}

// Errors a caller can test with errors.Is to tell a conflict from a bad
// address (Pool.Add, Pool.Remove).
var (
	ErrDuplicateUpstream = errors.New("duplicate upstream")
	ErrUnknownUpstream   = errors.New("unknown upstream")
	ErrLastUpstream      = errors.New("last upstream")
)

// poolError keeps the readable message while matching a sentinel.
type poolError struct {
	kind error
	msg  string
}

func (e *poolError) Error() string        { return e.msg }
func (e *poolError) Is(target error) bool { return target == e.kind }

// PoolOption configures NewPool.
type PoolOption func(*Pool) error

// WithBootstrap sets the plain resolvers used to look up the hostnames of
// tls:// and https:// upstreams (default DefaultBootstrap). Each must be an IP
// address, optionally with a port.
func WithBootstrap(servers ...string) PoolOption {
	return func(p *Pool) error { return p.SetBootstrap(servers) }
}

// Pool forwards queries to the healthiest upstream and fails over on error.
// It is safe for concurrent use; the upstream list can change at runtime.
type Pool struct {
	// OnHealthChange, when set, is called every time one upstream's health
	// flips, with its configuration string and whether it is now healthy.
	// It must be cheap and non-blocking; it runs on whatever goroutine probed
	// or queried the upstream (Exchange or Probe). Set it before Probe starts
	// to avoid missing early transitions. This is the hook alarm wiring (see
	// cmd/shepherd/alarms.go) uses to raise upstream-down and
	// upstream-recovered alarms; nothing else in this package reads it.
	OnHealthChange func(addr string, healthy bool)

	mu      sync.RWMutex
	ups     []*Upstream
	timeout time.Duration
	env     *upstreamEnv
	kick    chan struct{}
}

func NewPool(addrs []string, opts ...PoolOption) (*Pool, error) {
	p := &Pool{timeout: 2 * time.Second, env: newUpstreamEnv(), kick: make(chan struct{}, 1)}
	for _, o := range opts {
		if err := o(p); err != nil {
			return nil, err
		}
	}
	if err := p.Set(addrs); err != nil {
		return nil, err
	}
	return p, nil
}

// parseAll validates every address and rejects duplicates.
func (p *Pool) parseAll(addrs []string) ([]*Upstream, error) {
	if len(addrs) == 0 {
		return nil, errors.New("no upstreams configured")
	}
	seen := map[string]string{}
	out := make([]*Upstream, 0, len(addrs))
	for _, a := range addrs {
		u, err := parseUpstream(a)
		if err != nil {
			return nil, err
		}
		if prev, dup := seen[u.key()]; dup {
			return nil, fmt.Errorf("upstream %q duplicates %q", u.Addr, prev)
		}
		seen[u.key()] = u.Addr
		u.env = p.env
		u.onHealth = p.notifyHealth
		out = append(out, u)
	}
	return out, nil
}

// notifyHealth forwards one upstream's health transition to OnHealthChange,
// read fresh on every call so it may be set after the pool (and its
// upstreams) are created.
func (p *Pool) notifyHealth(addr string, healthy bool) {
	if cb := p.OnHealthChange; cb != nil {
		cb(addr, healthy)
	}
}

func (p *Pool) wake() {
	select {
	case p.kick <- struct{}{}:
	default:
	}
}

// Set validates addrs, then atomically replaces the upstream list. Entries
// whose configuration string is unchanged keep their health statistics and
// connections; queries already in flight finish on the old entries.
func (p *Pool) Set(addrs []string) error {
	next, err := p.parseAll(addrs)
	if err != nil {
		return err
	}
	p.mu.Lock()
	old := map[string]*Upstream{}
	for _, u := range p.ups {
		old[u.Addr] = u
	}
	for i, u := range next {
		if keep, ok := old[u.Addr]; ok {
			next[i] = keep
			delete(old, u.Addr)
		}
	}
	hadOld := len(p.ups) > 0
	p.ups = next
	p.mu.Unlock()
	for _, u := range old {
		u.closeIdle()
	}
	if hadOld {
		p.wake()
	}
	return nil
}

// Add appends one upstream.
func (p *Pool) Add(addr string) error {
	u, err := parseUpstream(addr)
	if err != nil {
		return err
	}
	u.env = p.env
	u.onHealth = p.notifyHealth
	p.mu.Lock()
	for _, e := range p.ups {
		if e.key() == u.key() {
			p.mu.Unlock()
			return &poolError{ErrDuplicateUpstream, fmt.Sprintf("upstream %q is already configured as %q", u.Addr, e.Addr)}
		}
	}
	p.ups = append(append([]*Upstream(nil), p.ups...), u)
	p.mu.Unlock()
	p.wake()
	return nil
}

// Remove deletes one upstream by its configuration string. The last upstream
// cannot be removed.
func (p *Pool) Remove(addr string) error {
	addr = strings.TrimSpace(addr)
	p.mu.Lock()
	idx := -1
	for i, e := range p.ups {
		if e.Addr == addr {
			idx = i
		}
	}
	if idx < 0 {
		p.mu.Unlock()
		return &poolError{ErrUnknownUpstream, fmt.Sprintf("upstream %q is not configured", addr)}
	}
	if len(p.ups) == 1 {
		p.mu.Unlock()
		return &poolError{ErrLastUpstream, "cannot remove the last upstream"}
	}
	gone := p.ups[idx]
	next := make([]*Upstream, 0, len(p.ups)-1)
	next = append(next, p.ups[:idx]...)
	next = append(next, p.ups[idx+1:]...)
	p.ups = next
	p.mu.Unlock()
	gone.closeIdle()
	return nil
}

// SetBootstrap replaces the bootstrap resolvers (IP addresses, optional port).
func (p *Pool) SetBootstrap(servers []string) error {
	if err := p.env.boot.setServers(servers); err != nil {
		return err
	}
	p.wake() // encrypted upstreams that could not resolve may work now
	return nil
}

// Bootstrap returns the bootstrap resolvers as configured.
func (p *Pool) Bootstrap() []string {
	b := p.env.boot
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.raw...)
}

// snapshot returns the current upstream list; callers must not modify it.
func (p *Pool) snapshot() []*Upstream {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.ups
}

// List returns every upstream with its configuration and status, in order.
func (p *Pool) List() []UpstreamInfo {
	ups := p.snapshot()
	out := make([]UpstreamInfo, len(ups))
	for i, u := range ups {
		out[i] = UpstreamInfo{Config: u.Addr, Kind: u.kind, UpstreamStatus: u.status()}
	}
	return out
}

// TestResult is the outcome of probing one upstream.
type TestResult struct {
	OK    bool          `json:"ok"`
	RTT   time.Duration `json:"-"`
	RTTms float64       `json:"rtt_ms"`
	Rcode string        `json:"rcode,omitempty"`
	Err   string        `json:"error,omitempty"`
}

// Test probes addr exactly like the health prober (a unique, uncached name)
// without adding it to the pool or touching any pool statistics.
func (p *Pool) Test(ctx context.Context, addr string) TestResult {
	u, err := parseUpstream(addr)
	if err != nil {
		return TestResult{Err: err.Error()}
	}
	u.env = p.env
	defer u.closeIdle()
	// A cold encrypted upstream needs bootstrap, TCP and TLS before the query.
	resp, rtt, err := u.exchange(ctx, probeQuery(), 2*p.timeout)
	res := TestResult{OK: answered(resp, err), RTT: rtt, RTTms: float64(rtt.Microseconds()) / 1000}
	if resp != nil {
		res.Rcode = dns.RcodeToString[resp.Rcode]
	}
	switch {
	case err != nil:
		res.Err = err.Error()
	case !res.OK:
		res.Err = "upstream answered SERVFAIL"
	}
	return res
}

// order puts healthy upstreams first, fastest first; ties keep config order.
func (p *Pool) order() []*Upstream {
	ups := p.snapshot()
	type ranked struct {
		u       *Upstream
		healthy bool
		rtt     time.Duration
	}
	rs := make([]ranked, len(ups))
	for i, u := range ups {
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
		ok := answered(resp, err)
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

// Probe checks every upstream now and then on every interval (and right after
// the list changes) until ctx ends. Encrypted upstreams are probed like plain
// ones, so a resolver that connects but never answers is marked unhealthy.
func (p *Pool) Probe(ctx context.Context, every time.Duration) {
	run := func() {
		var wg sync.WaitGroup
		for _, u := range p.snapshot() {
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
		case <-p.kick:
			run()
		}
	}
}

// Status returns per-upstream health in configuration order.
func (p *Pool) Status() []UpstreamStatus {
	ups := p.snapshot()
	out := make([]UpstreamStatus, len(ups))
	for i, u := range ups {
		out[i] = u.status()
	}
	return out
}
