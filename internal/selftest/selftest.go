// SPDX-License-Identifier: AGPL-3.0-or-later

// Package selftest is Shepherd's built-in DNS self-test. Every minute it asks
// a few canary names of every address Shepherd says it listens on, over UDP
// and TCP, and checks that the listener answers at all, that a known-good
// name resolves, that a known-blocked name is blocked, that no upstream
// resolver is erroring or crawling, and that every LAN address on this host
// is either served or explicitly marked not served. The failures it exists
// for are silent ones: an address devices use with no listener behind it, a
// resolver failing a fifth of its queries, a host whose DNS quietly broke.
// See docs/DNS-QA.md.
package selftest

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"shepherd/internal/dnsengine"
)

// Check names, as they appear in a Problem and a Probe.
const (
	CheckListener = "listener" // nothing answers on a listen address
	CheckResolve  = "resolve"  // the known-good name did not resolve
	CheckBlock    = "block"    // the known-blocked name was not blocked
	CheckUpstream = "upstream" // an upstream errors too often or is slow
	CheckLAN      = "lan"      // a LAN address has no listener
)

// Statuses of a Report.
const (
	StatusOK   = "ok"
	StatusWarn = "warn"
	StatusFail = "fail"
)

// Probe is one query to one address over one protocol.
type Probe struct {
	Proto  string  `json:"proto"` // udp or tcp
	Check  string  `json:"check"` // listener, resolve or block
	OK     bool    `json:"ok"`
	Ms     float64 `json:"ms"`
	Detail string  `json:"detail,omitempty"`
}

// ListenerResult is everything asked of one listening address.
type ListenerResult struct {
	// Addr is host:port that was queried. A wildcard listener is queried on
	// loopback and on every LAN address, each its own result.
	Addr   string  `json:"addr"`
	OK     bool    `json:"ok"`
	Probes []Probe `json:"probes"`
}

// LANResult is one non-loopback IPv4 address of this host.
type LANResult struct {
	IP        string `json:"ip"`
	Interface string `json:"interface"`
	// State is "served", "not-served" (the owner said so in
	// selftest.not_served) or "unserved" (the one to worry about).
	State  string `json:"state"`
	Detail string `json:"detail,omitempty"`
}

// UpstreamResult is one upstream's behaviour over the rolling window.
type UpstreamResult struct {
	dnsengine.UpstreamWindow
	ErrorPct float64 `json:"error_pct"`
	OK       bool    `json:"ok"`
	Detail   string  `json:"detail,omitempty"`
}

// Problem is one failed check, in the form that is shown and alarmed on.
type Problem struct {
	Check    string `json:"check"`
	Subject  string `json:"subject"` // an address, an upstream, a LAN IP
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

// Key identifies a problem across runs, for cooldowns.
func (p Problem) Key() string { return p.Check + "|" + p.Subject }

// Report is the outcome of one run.
type Report struct {
	Time       time.Time        `json:"time"`
	DurationMs float64          `json:"duration_ms"`
	Status     string           `json:"status"`
	Listeners  []ListenerResult `json:"listeners"`
	LAN        []LANResult      `json:"lan"`
	Upstreams  []UpstreamResult `json:"upstreams"`
	Problems   []Problem        `json:"problems"`
	// Skipped are configured addresses this host does not have, left out of
	// the checks on purpose (Shepherd tolerates them at startup).
	Skipped []string `json:"skipped,omitempty"`
}

// Options configures a Tester. Everything but Addrs has a default.
type Options struct {
	// Addrs returns the host:port addresses Shepherd is listening on right
	// now. Required.
	Addrs func() []string
	// Skipped returns configured addresses that could not be bound.
	Skipped func() []string
	// Window returns per-upstream behaviour over the last d; nil skips the
	// upstream check. Usually Pool.Window.
	Window func(d time.Duration) []dnsengine.UpstreamWindow
	// GoodName must resolve (default example.com). BlockedName must be
	// blocked (default dnsengine.CanaryBlockedName, which the engine always
	// blocks); set it to a name on one of the owner's lists to test the
	// lists themselves.
	GoodName, BlockedName string
	// NotServed are LAN addresses the owner chose not to serve.
	NotServed []string
	// Timeout bounds each query (default 2s).
	Timeout time.Duration
	// UpstreamWindow is how far back the upstream check looks (default 15m).
	UpstreamWindow time.Duration
	// MinQueries is how many queries an upstream needs in the window before
	// its error rate is judged (default 10).
	MinQueries int
	// MaxErrorPct flags an upstream above this error rate (default 5).
	MaxErrorPct float64
	// SlowFactor flags an upstream whose p95 is this many times the median
	// of its peers' p95 (default 4), and at least SlowFloorMs (default
	// 250ms) so a 6ms resolver next to a 1ms one is not "slow".
	SlowFactor  float64
	SlowFloorMs float64
	// Interfaces lists this host's addresses; default net.Interfaces. A test
	// seam.
	Interfaces func() ([]HostAddr, error)
	// Exchange sends one query; default dns.Client. A test seam.
	Exchange func(ctx context.Context, network, addr string, m *dns.Msg, timeout time.Duration) (*dns.Msg, error)
	// Now is the clock; default time.Now.
	Now func() time.Time
}

// HostAddr is one address of one interface of this host.
type HostAddr struct {
	Interface string
	IP        net.IP
}

// Tester runs the checks and remembers the latest report.
type Tester struct {
	o Options

	mu     sync.Mutex
	latest *Report
}

// New builds a Tester, filling defaults.
func New(o Options) *Tester {
	if o.GoodName == "" {
		o.GoodName = "example.com"
	}
	if o.BlockedName == "" {
		o.BlockedName = dnsengine.CanaryBlockedName
	}
	if o.Timeout <= 0 {
		o.Timeout = 2 * time.Second
	}
	if o.UpstreamWindow <= 0 {
		o.UpstreamWindow = 15 * time.Minute
	}
	if o.MinQueries <= 0 {
		o.MinQueries = 10
	}
	if o.MaxErrorPct <= 0 {
		o.MaxErrorPct = 5
	}
	if o.SlowFactor <= 0 {
		o.SlowFactor = 4
	}
	if o.SlowFloorMs <= 0 {
		o.SlowFloorMs = 250
	}
	if o.Interfaces == nil {
		o.Interfaces = hostAddrs
	}
	if o.Exchange == nil {
		o.Exchange = exchange
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Tester{o: o}
}

// IsCanary reports whether name is one the self-test asks, so the engine can
// keep those queries out of the log and the device list (Engine.Quiet).
func (t *Tester) IsCanary(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	return name == strings.ToLower(t.o.GoodName) || name == strings.ToLower(t.o.BlockedName)
}

// Latest returns the most recent report.
func (t *Tester) Latest() (Report, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.latest == nil {
		return Report{}, false
	}
	return *t.latest, true
}

// Run runs a round now and then every interval until ctx ends, calling
// onReport with each report.
func (t *Tester) Run(ctx context.Context, every time.Duration, onReport func(Report)) {
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		r := t.RunOnce(ctx)
		if onReport != nil && ctx.Err() == nil {
			onReport(r)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// RunOnce runs every check and records the result.
func (t *Tester) RunOnce(ctx context.Context) Report {
	start := t.o.Now()
	r := Report{Time: start, Listeners: []ListenerResult{}, LAN: []LANResult{}, Upstreams: []UpstreamResult{}, Problems: []Problem{}}
	if t.o.Skipped != nil {
		r.Skipped = t.o.Skipped()
	}
	lan, _ := t.lanAddrs()
	targets := t.targets(t.o.Addrs(), lan)

	// Every address is asked concurrently: one dead listener costs its own
	// timeout, not a timeout per address.
	results := make([]ListenerResult, len(targets))
	var wg sync.WaitGroup
	for i, addr := range targets {
		wg.Add(1)
		go func() { defer wg.Done(); results[i] = t.checkAddr(ctx, addr) }()
	}
	wg.Wait()
	r.Listeners = results
	for _, l := range results {
		r.Problems = append(r.Problems, listenerProblems(l)...)
	}

	r.LAN = t.checkLAN(t.o.Addrs(), lan)
	for _, l := range r.LAN {
		if l.State == "unserved" {
			r.Problems = append(r.Problems, Problem{CheckLAN, l.IP, StatusWarn,
				fmt.Sprintf("%s (%s) has no DNS listener. Devices pointed at it get \"host not found\". Add it to dns.listen, or list it in selftest.not_served.", l.IP, l.Interface)})
		}
	}

	r.Upstreams = t.checkUpstreams()
	for _, u := range r.Upstreams {
		if !u.OK {
			r.Problems = append(r.Problems, Problem{CheckUpstream, u.Addr, StatusWarn, u.Addr + ": " + u.Detail})
		}
	}

	r.Status = StatusOK
	for _, p := range r.Problems {
		if p.Severity == StatusFail {
			r.Status = StatusFail
		} else if r.Status == StatusOK {
			r.Status = StatusWarn
		}
	}
	r.DurationMs = float64(t.o.Now().Sub(start).Microseconds()) / 1000
	sort.SliceStable(r.Problems, func(i, j int) bool {
		return r.Problems[i].Severity == StatusFail && r.Problems[j].Severity != StatusFail
	})
	t.mu.Lock()
	t.latest = &r
	t.mu.Unlock()
	return r
}

// targets turns the listen addresses into the addresses to query: a
// wildcard listener answers on loopback and on every LAN address, so each of
// those is asked in turn.
func (t *Tester) targets(listen []string, lan []HostAddr) []string {
	seen := map[string]bool{}
	var out []string
	add := func(a string) {
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	for _, a := range listen {
		host, port, err := net.SplitHostPort(a)
		if err != nil {
			add(a)
			continue
		}
		switch host {
		case "", "0.0.0.0":
			add(net.JoinHostPort("127.0.0.1", port))
			for _, h := range lan {
				add(net.JoinHostPort(h.IP.String(), port))
			}
		case "::":
			add(net.JoinHostPort("::1", port))
			add(net.JoinHostPort("127.0.0.1", port))
			for _, h := range lan {
				add(net.JoinHostPort(h.IP.String(), port))
			}
		default:
			add(net.JoinHostPort(host, port))
		}
	}
	return out
}

// checkAddr asks one address the three canary questions over UDP and TCP.
func (t *Tester) checkAddr(ctx context.Context, addr string) ListenerResult {
	res := ListenerResult{Addr: addr, OK: true, Probes: []Probe{}}
	for _, proto := range []string{"udp", "tcp"} {
		good := t.ask(ctx, proto, addr, t.o.GoodName)
		if good.err != nil {
			// Nothing answered: the one failure that matters most. The
			// block question would fail the same way, so ask nothing more.
			res.Probes = append(res.Probes, Probe{proto, CheckListener, false, good.ms, good.err.Error()})
			res.OK = false
			continue
		}
		res.Probes = append(res.Probes, Probe{proto, CheckListener, true, good.ms, ""})
		gp := Probe{Proto: proto, Check: CheckResolve, Ms: good.ms}
		switch {
		case good.resp.Rcode != dns.RcodeSuccess:
			gp.Detail = t.o.GoodName + " answered " + dns.RcodeToString[good.resp.Rcode]
		case len(good.resp.Answer) == 0:
			gp.Detail = t.o.GoodName + " answered with no address"
		default:
			gp.OK = true
		}
		res.Probes = append(res.Probes, gp)
		bad := t.ask(ctx, proto, addr, t.o.BlockedName)
		bp := Probe{Proto: proto, Check: CheckBlock, Ms: bad.ms}
		switch {
		case bad.err != nil:
			bp.Detail = bad.err.Error()
		case blocked(bad.resp):
			bp.OK = true
		default:
			bp.Detail = t.o.BlockedName + " was not blocked (answered " + dns.RcodeToString[bad.resp.Rcode] + ")"
		}
		res.Probes = append(res.Probes, bp)
	}
	for _, p := range res.Probes {
		if !p.OK {
			res.OK = false
		}
	}
	return res
}

// blocked reports whether resp is how Shepherd answers a blocked name:
// NXDOMAIN, or an unspecified address.
func blocked(resp *dns.Msg) bool {
	if resp.Rcode == dns.RcodeNameError {
		return true
	}
	if resp.Rcode != dns.RcodeSuccess {
		return false
	}
	for _, rr := range resp.Answer {
		switch v := rr.(type) {
		case *dns.A:
			return v.A.IsUnspecified()
		case *dns.AAAA:
			return v.AAAA.IsUnspecified()
		}
	}
	return false
}

type answer struct {
	resp *dns.Msg
	ms   float64
	err  error
}

func (t *Tester) ask(ctx context.Context, proto, addr, name string) answer {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m.RecursionDesired = true
	begin := time.Now()
	resp, err := t.o.Exchange(ctx, proto, addr, m, t.o.Timeout)
	ms := float64(time.Since(begin).Microseconds()) / 1000
	return answer{resp, ms, err}
}

func exchange(ctx context.Context, network, addr string, m *dns.Msg, timeout time.Duration) (*dns.Msg, error) {
	c := &dns.Client{Net: network, Timeout: timeout}
	resp, _, err := c.ExchangeContext(ctx, m, addr)
	return resp, err
}

func listenerProblems(l ListenerResult) []Problem {
	var out []Problem
	down := map[string]bool{}
	for _, p := range l.Probes {
		if p.OK {
			continue
		}
		switch p.Check {
		case CheckListener:
			down[p.Proto] = true
			out = append(out, Problem{CheckListener, l.Addr + "/" + p.Proto, StatusFail,
				fmt.Sprintf("Nothing answers DNS on %s over %s: %s", l.Addr, strings.ToUpper(p.Proto), p.Detail)})
		case CheckResolve:
			out = append(out, Problem{CheckResolve, l.Addr + "/" + p.Proto, StatusFail,
				fmt.Sprintf("%s over %s: %s", l.Addr, strings.ToUpper(p.Proto), p.Detail)})
		case CheckBlock:
			out = append(out, Problem{CheckBlock, l.Addr + "/" + p.Proto, StatusFail,
				fmt.Sprintf("%s over %s: %s", l.Addr, strings.ToUpper(p.Proto), p.Detail)})
		}
	}
	return out
}

// checkUpstreams judges each upstream's window: an error rate above the
// limit, or a p95 far above its peers'.
func (t *Tester) checkUpstreams() []UpstreamResult {
	out := []UpstreamResult{}
	if t.o.Window == nil {
		return out
	}
	ws := t.o.Window(t.o.UpstreamWindow)
	var p95s []float64
	for _, w := range ws {
		if w.Queries-w.Errors >= t.o.MinQueries/2 && w.P95ms > 0 {
			p95s = append(p95s, w.P95ms)
		}
	}
	for _, w := range ws {
		u := UpstreamResult{UpstreamWindow: w, ErrorPct: w.ErrorRate(), OK: true}
		if w.Queries >= t.o.MinQueries && u.ErrorPct > t.o.MaxErrorPct {
			u.OK = false
			u.Detail = fmt.Sprintf("%.0f%% of its last %d queries failed (limit %.0f%%)", u.ErrorPct, w.Queries, t.o.MaxErrorPct)
		}
		if peers := othersMedian(p95s, w.P95ms); u.OK && len(ws) > 1 && peers > 0 && w.P95ms >= t.o.SlowFloorMs && w.P95ms > t.o.SlowFactor*peers {
			u.OK = false
			u.Detail = fmt.Sprintf("p95 latency %.0f ms against %.0f ms for its peers", w.P95ms, peers)
		}
		out = append(out, u)
	}
	return out
}

// othersMedian is the median of vals after removing one occurrence of self.
func othersMedian(vals []float64, self float64) float64 {
	rest := make([]float64, 0, len(vals))
	removed := false
	for _, v := range vals {
		if v == self && !removed {
			removed = true
			continue
		}
		rest = append(rest, v)
	}
	if len(rest) == 0 {
		return 0
	}
	sort.Float64s(rest)
	return rest[len(rest)/2]
}
