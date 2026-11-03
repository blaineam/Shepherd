// SPDX-License-Identifier: AGPL-3.0-or-later

package routerusage

import (
	"context"
	"errors"
	"math"
	"sync"
	"time"

	"shepherd/internal/traffic"
)

const (
	// DefaultInterval between polls. Thirty seconds is a compromise: an
	// instantaneous-rate source under-counts bursts shorter than the gap,
	// and every poll is a request to someone's router or cloud API.
	DefaultInterval = 30 * time.Second
	// DefaultMaxGap is how stale the previous sample may be and still be
	// interpolated against. Past this -- a missed poll, a long backoff, a
	// suspended host -- the gap is left empty rather than invented, and
	// the next sample starts a new baseline.
	DefaultMaxGap = 3 * time.Minute
	// maxPlausibleBitsPerSecond bounds one device's interval. Anything
	// beyond it is a counter reset or a garbled reading, not traffic, and
	// re-baselines instead of recording an absurd spike.
	maxPlausibleBitsPerSecond = 10e9
)

// Recorder is the part of *traffic.Store the Collector needs.
type Recorder interface {
	Record(now time.Time, rows map[string]traffic.Delta)
}

// Resolver maps a normalized MAC to a Shepherd device ID. It returns false
// for a device the registry does not know, whose traffic is then counted
// towards nothing -- the registry learns devices by itself, so this
// corrects on a later poll.
type Resolver func(mac string) (deviceID string, ok bool)

// Options configures a Collector. Source, Recorder and Resolve are
// required; the rest default.
type Options struct {
	Source   Source
	Recorder Recorder
	Resolve  Resolver

	// Interval between polls (default DefaultInterval).
	Interval time.Duration
	// MaxGap bounds interpolation (default DefaultMaxGap).
	MaxGap time.Duration

	// Skip reports whether a device is already being measured exactly by
	// something else -- Watch mode, today -- so the two never double-count
	// the same device. Nil skips nothing.
	Skip func(deviceID string) bool

	// NeedsSignIn classifies an error as "the session expired, ask the
	// owner to sign in again" rather than a transient failure. Nil treats
	// every error as transient.
	NeedsSignIn func(error) bool

	// Now and After are the clock, for tests. Nil uses the real one.
	Now   func() time.Time
	After func(time.Duration) <-chan time.Time

	// Logf receives one line per state change, never per poll, and never
	// a credential. Nil discards.
	Logf func(string, ...any)
}

type prior struct {
	at                   time.Time
	downRate, upRate     float64 // KindRates, bits per second
	downBytes, upBytes   uint64  // KindCounters
	haveRates, haveBytes bool
}

// Collector polls a Source and records what it finds into the traffic
// store. Create it with New and run it with Run.
type Collector struct {
	opt Options

	mu     sync.Mutex
	last   map[string]prior
	status Status
}

// New returns a Collector. It panics on a missing required option, which
// is a programming error rather than anything an owner can cause.
func New(opt Options) *Collector {
	if opt.Source == nil || opt.Recorder == nil || opt.Resolve == nil {
		panic("routerusage: Source, Recorder and Resolve are required")
	}
	if opt.Interval <= 0 {
		opt.Interval = DefaultInterval
	}
	if opt.MaxGap <= 0 {
		opt.MaxGap = DefaultMaxGap
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.After == nil {
		opt.After = time.After
	}
	if opt.Logf == nil {
		opt.Logf = func(string, ...any) {}
	}
	return &Collector{
		opt:  opt,
		last: map[string]prior{},
		status: Status{
			Source:          opt.Source.Name(),
			Enabled:         true,
			Estimated:       opt.Source.Kind().Estimated(),
			IntervalSeconds: int(opt.Interval / time.Second),
		},
	}
}

// Status is a snapshot for the portal.
func (c *Collector) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status
}

// Run polls until ctx ends. It returns ctx.Err(), so a caller can treat a
// clean shutdown and a failure the same way.
func (c *Collector) Run(ctx context.Context) error {
	for {
		c.pollOnce(ctx)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.opt.After(c.opt.Interval):
		}
	}
}

// pollOnce reads the source and records one interval. Errors are recorded
// in the status and otherwise swallowed: a router that is briefly
// unreachable must not stop the collector.
func (c *Collector) pollOnce(ctx context.Context) {
	samples, err := c.opt.Source.Poll(ctx)
	now := c.opt.Now()
	if err != nil {
		c.fail(err)
		return
	}
	rows, seen, matched := c.convert(samples, now)
	if len(rows) > 0 {
		c.opt.Recorder.Record(now, rows)
	}
	c.mu.Lock()
	hadError := c.status.LastError != ""
	at := now
	c.status.LastPoll, c.status.DevicesSeen, c.status.Matched = &at, seen, matched
	c.status.LastError, c.status.NeedsSignIn = "", false
	c.mu.Unlock()
	if hadError {
		c.opt.Logf("routerusage: %s is answering again (%d devices)", c.opt.Source.Name(), seen)
	}
}

func (c *Collector) fail(err error) {
	needsSignIn := c.opt.NeedsSignIn != nil && c.opt.NeedsSignIn(err)
	c.mu.Lock()
	first := c.status.LastError == ""
	c.status.LastError, c.status.NeedsSignIn = err.Error(), needsSignIn
	c.mu.Unlock()
	// Only the first failure of a run is logged, so a router that is down
	// overnight does not fill the log with the same line.
	if first && !errors.Is(err, context.Canceled) {
		if needsSignIn {
			c.opt.Logf("routerusage: %s needs signing in again: %v", c.opt.Source.Name(), err)
		} else {
			c.opt.Logf("routerusage: %s could not be read: %v", c.opt.Source.Name(), err)
		}
	}
}

// convert turns one poll into per-device byte deltas, carrying the state
// each shape needs between polls.
func (c *Collector) convert(samples []Sample, now time.Time) (rows map[string]traffic.Delta, seen, matched int) {
	kind := c.opt.Source.Kind()
	rows = map[string]traffic.Delta{}
	c.mu.Lock()
	defer c.mu.Unlock()
	fresh := make(map[string]prior, len(samples))
	for _, s := range samples {
		mac := NormalizeMAC(s.MAC)
		if mac == "" {
			continue
		}
		seen++
		was, had := c.last[mac]
		cur := prior{at: now}
		switch kind {
		case KindCounters:
			cur.downBytes, cur.upBytes, cur.haveBytes = s.DownBytes, s.UpBytes, true
		default:
			cur.downRate, cur.upRate, cur.haveRates = nonNeg(s.DownBitsPerSecond), nonNeg(s.UpBitsPerSecond), true
		}
		fresh[mac] = cur

		id, known := c.opt.Resolve(mac)
		if !known {
			continue
		}
		matched++
		if c.opt.Skip != nil && c.opt.Skip(id) {
			continue
		}
		if !had {
			continue // the first reading is a baseline, never a measurement
		}
		d, ok := delta(kind, was, cur, c.opt.MaxGap)
		if !ok || (d.Up == 0 && d.Down == 0) {
			continue
		}
		prev := rows[id]
		rows[id] = traffic.Delta{Up: prev.Up + d.Up, Down: prev.Down + d.Down}
	}
	c.last = fresh // a device absent from this poll loses its baseline
	return rows, seen, matched
}

// delta is the bytes one device moved between two readings. ok is false
// when the pair cannot be turned into a measurement: too long a gap, a
// counter that went backwards, or a figure too large to be real.
func delta(kind Kind, was, now prior, maxGap time.Duration) (traffic.Delta, bool) {
	elapsed := now.at.Sub(was.at)
	if elapsed <= 0 || elapsed > maxGap {
		return traffic.Delta{}, false
	}
	var down, up float64
	switch kind {
	case KindCounters:
		if !was.haveBytes || !now.haveBytes {
			return traffic.Delta{}, false
		}
		// A counter that went backwards is a reboot, not negative traffic.
		if now.downBytes < was.downBytes || now.upBytes < was.upBytes {
			return traffic.Delta{}, false
		}
		down, up = float64(now.downBytes-was.downBytes), float64(now.upBytes-was.upBytes)
	default:
		if !was.haveRates || !now.haveRates {
			return traffic.Delta{}, false
		}
		// Trapezoid: the average of the rate at each end, over the gap.
		// It is an estimate, and the package doc says so. A burst that
		// starts and ends between two polls is invisible to it.
		secs := elapsed.Seconds()
		down = (was.downRate + now.downRate) / 2 * secs / 8
		up = (was.upRate + now.upRate) / 2 * secs / 8
	}
	ceiling := maxPlausibleBitsPerSecond * elapsed.Seconds() / 8
	if !sane(down, ceiling) || !sane(up, ceiling) {
		return traffic.Delta{}, false
	}
	return traffic.Delta{Up: uint64(up), Down: uint64(down)}, true
}

func sane(v, ceiling float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0) && v >= 0 && v <= ceiling
}

func nonNeg(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
		return 0
	}
	return v
}
