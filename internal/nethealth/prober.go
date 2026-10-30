// SPDX-License-Identifier: AGPL-3.0-or-later

package nethealth

import (
	"context"
	"math"
	"net"
	"strconv"
	"sync"
	"time"
)

// DialFunc opens a bare TCP connection for one latency probe: nothing more
// than net.Dialer.DialContext does. Tests inject a fake that never touches a
// real socket; production uses the default, which does. This is the same
// seam internal/portscan.Scanner and internal/vulnscan.Scanner already use.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

func defaultDial(ctx context.Context, network, address string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

// TargetResult is one target's outcome for one probe cycle.
type TargetResult struct {
	Host         string  `json:"host"`
	Probes       int     `json:"probes"`
	Successes    int     `json:"successes"`
	AvgLatencyMS float64 `json:"avg_latency_ms,omitempty"`
	// JitterMS is the population standard deviation of this target's own
	// successful round trips this cycle (needs at least two to mean
	// anything; zero otherwise). Measuring jitter per target, rather than
	// pooling every target's latencies together, matters: targets sit at
	// different distances, and pooling would read as "jitter" what is
	// really just "these targets are not equally far away".
	JitterMS float64 `json:"jitter_ms,omitempty"`
	LossPct  float64 `json:"loss_pct"`
}

// Sample is one completed probe cycle across every target: Shepherd's
// network-health reading for that moment. LatencyMS and JitterMS are the
// mean of each reachable target's own AvgLatencyMS/JitterMS (see
// TargetResult); LossPct is the mean loss percentage across every target,
// reachable or not, so a target that is completely down pulls the overall
// number down rather than being silently excluded.
type Sample struct {
	Time             time.Time      `json:"time"`
	LatencyMS        float64        `json:"latency_ms,omitempty"`
	JitterMS         float64        `json:"jitter_ms,omitempty"`
	LossPct          float64        `json:"loss_pct"`
	ReachableTargets int            `json:"reachable_targets"`
	TotalTargets     int            `json:"total_targets"`
	Targets          []TargetResult `json:"targets,omitempty"`
}

// AllUnreachable reports a total outage: not one target answered at all.
func (s Sample) AllUnreachable() bool { return s.TotalTargets > 0 && s.ReachableTargets == 0 }

// Options configures a Prober. The zero value is usable: it dials real TCP
// connections, probes port 53, sends a burst of 5 probes per target per
// cycle with a 1 second timeout each, and keeps gentle defaults throughout
// (see docs/NETHEALTH.md).
type Options struct {
	// Dial opens one probe connection. Default: a real net.Dialer.
	Dial DialFunc
	// Port is the TCP port every probe connects to. Default: 53 (every
	// target here is a DNS resolver; see doc.go for why TCP:53 stands in
	// for ICMP echo).
	Port int
	// Burst is how many probes are sent to each target per cycle. Default: 5.
	Burst int
	// Timeout bounds one probe connection attempt. Default: 1 second.
	Timeout time.Duration
	Now     func() time.Time
}

const (
	defaultPort    = 53
	defaultBurst   = 5
	defaultTimeout = 1 * time.Second
)

// Prober runs periodic latency/jitter/loss/reachability probes and keeps
// their history in a Store. Safe for concurrent use.
type Prober struct {
	dial    DialFunc
	port    int
	burst   int
	timeout time.Duration
	now     func() time.Time

	// OnSample, when set, is called with the result after every completed
	// probe cycle, whether triggered by Run's schedule or a manual call.
	// cmd/shepherd uses it to persist history and to feed the degradation
	// alarm (see DegradationTracker). Left nil, nothing extra happens.
	OnSample func(Sample)
	// OnBufferbloat, when set, is called with the result after every
	// completed bufferbloat check (see RunBufferbloat). Left nil, nothing
	// extra happens.
	OnBufferbloat func(Bufferbloat)

	cycleMu sync.Mutex // serializes whole cycles: manual and scheduled runs never overlap

	mu    sync.Mutex
	store *Store
}

// New creates a Prober from opts, with a fresh, empty Store. Load replaces
// it with saved history.
func New(opts Options) *Prober {
	p := &Prober{
		dial:    opts.Dial,
		port:    opts.Port,
		burst:   opts.Burst,
		timeout: opts.Timeout,
		now:     opts.Now,
		store:   NewStore(StoreOptions{Now: opts.Now}),
	}
	if p.dial == nil {
		p.dial = defaultDial
	}
	if p.port <= 0 {
		p.port = defaultPort
	}
	if p.burst <= 0 {
		p.burst = defaultBurst
	}
	if p.timeout <= 0 {
		p.timeout = defaultTimeout
	}
	if p.now == nil {
		p.now = time.Now
	}
	return p
}

// probeOnce dials host on the configured port and reports the round trip
// time to a successful connection, or ok=false on any error (refused,
// filtered/timed out, or ctx already done).
func (p *Prober) probeOnce(ctx context.Context, host string) (rtt time.Duration, ok bool) {
	cctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	start := p.now()
	conn, err := p.dial(cctx, "tcp", net.JoinHostPort(host, strconv.Itoa(p.port)))
	if err != nil {
		return 0, false
	}
	rtt = p.now().Sub(start)
	_ = conn.Close()
	return rtt, true
}

func mean(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	var sum float64
	for _, x := range xs {
		sum += x
	}
	return sum / float64(len(xs))
}

// stddev is the population standard deviation of xs (divides by N, not
// N-1): with a small burst size this is a measure of this cycle's own
// spread, not an estimate of some larger population.
func stddev(xs []float64, m float64) float64 {
	if len(xs) < 2 {
		return 0
	}
	var sumSq float64
	for _, x := range xs {
		d := x - m
		sumSq += d * d
	}
	return math.Sqrt(sumSq / float64(len(xs)))
}

func msOf(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

// probeTarget runs the configured burst against one host.
func (p *Prober) probeTarget(ctx context.Context, host string) TargetResult {
	res := TargetResult{Host: host, Probes: p.burst}
	lats := make([]float64, 0, p.burst)
	for i := 0; i < p.burst; i++ {
		if ctx.Err() != nil {
			break
		}
		if rtt, ok := p.probeOnce(ctx, host); ok {
			res.Successes++
			lats = append(lats, msOf(rtt))
		}
	}
	if res.Probes > 0 {
		res.LossPct = 100 * float64(res.Probes-res.Successes) / float64(res.Probes)
	}
	if len(lats) > 0 {
		res.AvgLatencyMS = mean(lats)
		res.JitterMS = stddev(lats, res.AvgLatencyMS)
	}
	return res
}

// Probe runs one cycle against every target now, bounded by ctx, and
// returns the resulting Sample without touching history. Targets are
// probed concurrently (one goroutine per target; each target's own burst
// runs sequentially, which is what makes its jitter meaningful).
func (p *Prober) Probe(ctx context.Context, targets []string) Sample {
	now := p.now()
	results := make([]TargetResult, len(targets))
	var wg sync.WaitGroup
	for i, host := range targets {
		wg.Add(1)
		go func(i int, host string) {
			defer wg.Done()
			results[i] = p.probeTarget(ctx, host)
		}(i, host)
	}
	wg.Wait()

	s := Sample{Time: now, TotalTargets: len(targets), Targets: results}
	var latencies, jitters, losses []float64
	for _, r := range results {
		losses = append(losses, r.LossPct)
		if r.Successes > 0 {
			s.ReachableTargets++
			latencies = append(latencies, r.AvgLatencyMS)
		}
		if r.Successes > 1 {
			jitters = append(jitters, r.JitterMS)
		}
	}
	s.LatencyMS = mean(latencies)
	s.JitterMS = mean(jitters)
	s.LossPct = mean(losses)
	return s
}

// Run probes immediately, then again every `every` on a ticker, until ctx
// ends, recording each cycle's Sample into history and calling OnSample.
// lister is called fresh before every cycle. every <= 0 probes once and
// returns (used by tests; production always configures a real interval).
func (p *Prober) Run(ctx context.Context, lister func() []string, every time.Duration) {
	p.runOnce(ctx, lister())
	if every <= 0 {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if ctx.Err() != nil {
				return
			}
			p.runOnce(ctx, lister())
		}
	}
}

func (p *Prober) runOnce(ctx context.Context, targets []string) Sample {
	p.cycleMu.Lock()
	defer p.cycleMu.Unlock()
	s := p.Probe(ctx, targets)
	p.mu.Lock()
	p.store.Add(s)
	p.mu.Unlock()
	if p.OnSample != nil {
		p.OnSample(s)
	}
	return s
}

// Latest returns the most recent completed sample, if any.
func (p *Prober) Latest() (Sample, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.store.Latest()
}

// Series returns the stored history over [from, to] at the given
// resolution; see Store.Query.
func (p *Prober) Series(from, to time.Time, bucket Bucket) []Point {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.store.Query(from, to, bucket)
}
