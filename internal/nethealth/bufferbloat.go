// SPDX-License-Identifier: AGPL-3.0-or-later

package nethealth

import (
	"context"
	"sort"
	"sync"
	"time"
)

// LoadFunc generates one bounded burst of real traffic (a download, in
// practice) and returns once it is done or ctx is cancelled. Production's
// default (DefaultLoadFunc) fetches a bounded number of bytes from a
// configurable URL; tests inject a fake that never touches the network.
// Whatever LoadFunc does, BufferbloatOptions.Duration is the only thing
// that bounds how long it is allowed to run — see RunBufferbloat.
type LoadFunc func(ctx context.Context) error

// Bufferbloat is one completed bufferbloat check: the network's own latency
// to PingTarget at idle, compared against the same latency while LoadFunc's
// burst is in flight. IncreaseMS and Grade are derived, kept alongside the
// raw numbers so a chart never has to recompute them.
type Bufferbloat struct {
	Time       time.Time `json:"time"`
	PingTarget string    `json:"ping_target"`
	IdleMS     float64   `json:"idle_ms"`
	LoadedMS   float64   `json:"loaded_ms"`
	IncreaseMS float64   `json:"increase_ms"`
	Grade      string    `json:"grade"`
	// LoadError is set when the load burst itself failed (e.g. no internet
	// path to the download endpoint); IdleMS/LoadedMS still reflect
	// whatever ping data was gathered, but the comparison is unreliable, so
	// callers should treat a non-empty LoadError as "no real reading".
	LoadError string `json:"load_error,omitempty"`
}

// gradeBufferbloat classifies the latency increase under load using the
// thresholds Shepherd's docs/NETHEALTH.md documents, adapted from the
// bands popularized by the Waveform/DSLReports bufferbloat tests (their
// exact cutoffs are not published as a spec, so these are Shepherd's own
// reasonable approximation of the same idea, not a reproduction of theirs):
// under 30ms added latency is excellent (A), under 60ms is good (B), under
// 200ms is noticeable but tolerable (C), under 400ms is bad (D), and
// anything higher, or an outright load failure, is a fail (F).
func gradeBufferbloat(increaseMS float64) string {
	switch {
	case increaseMS < 30:
		return "A"
	case increaseMS < 60:
		return "B"
	case increaseMS < 200:
		return "C"
	case increaseMS < 400:
		return "D"
	default:
		return "F"
	}
}

// BufferbloatOptions overrides, for one call, what the Prober was
// constructed with (Options.Load, Options.BufferbloatDuration). Leaving a
// field at its zero value uses the Prober's own configured default for it,
// which is what lets a manual "run bufferbloat test now" from the portal
// (BufferbloatOptions{}) use exactly the same load generator the scheduled
// check does, and what lets tests override just Load without touching the
// Prober's own construction.
type BufferbloatOptions struct {
	// Load generates the bounded traffic burst. Zero value: the Prober's
	// own configured Load (Options.Load, itself defaulting to
	// DefaultLoadFunc against DefaultLoadURL).
	Load LoadFunc
	// Duration bounds how long the load burst (and the "loaded" ping
	// measurement alongside it) is allowed to run. Zero value: the
	// Prober's own configured BufferbloatDuration (default 5 seconds).
	// This is the hard safety bound: whatever Load does internally, its
	// context is cancelled after this long, so a single bufferbloat check
	// can never turn into an extended saturation of the maintainer's own
	// uplink.
	Duration time.Duration
	// IdleBurst/LoadedBurst are how many pings to send while idle and while
	// loaded; both default to the Prober's own Burst.
	IdleBurst, LoadedBurst int
}

// Bufferbloat runs one bufferbloat check against pingTarget: a short idle
// ping burst, then LoadFunc's bounded traffic burst with pings running
// alongside it, then the comparison. It never runs two bufferbloat checks
// at once (same cycleMu as Probe), so a manual "test now" from the portal
// waits for a scheduled one already in flight rather than piling a second
// load burst on top of it.
func (p *Prober) Bufferbloat(ctx context.Context, pingTarget string, opts BufferbloatOptions) Bufferbloat {
	p.cycleMu.Lock()
	defer p.cycleMu.Unlock()
	return p.bufferbloatLocked(ctx, pingTarget, opts)
}

func (p *Prober) bufferbloatLocked(ctx context.Context, pingTarget string, opts BufferbloatOptions) Bufferbloat {
	if opts.Load == nil {
		opts.Load = p.load
	}
	if opts.Duration <= 0 {
		opts.Duration = p.bufferbloatDuration
	}
	idleBurst := opts.IdleBurst
	if idleBurst <= 0 {
		idleBurst = p.burst
	}
	loadedBurst := opts.LoadedBurst
	if loadedBurst <= 0 {
		loadedBurst = p.burst
	}

	now := p.now()
	b := Bufferbloat{Time: now, PingTarget: pingTarget}
	b.IdleMS = p.pingBurstMS(ctx, pingTarget, idleBurst)

	lctx, cancel := context.WithTimeout(ctx, opts.Duration)
	defer cancel()

	var wg sync.WaitGroup
	var loadErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		loadErr = opts.Load(lctx)
	}()

	b.LoadedMS = p.pingBurstMS(lctx, pingTarget, loadedBurst)
	wg.Wait()
	if loadErr != nil && lctx.Err() == nil {
		// A real failure (not just the bounded context ending on schedule).
		b.LoadError = loadErr.Error()
	}

	b.IncreaseMS = b.LoadedMS - b.IdleMS
	if b.IncreaseMS < 0 {
		b.IncreaseMS = 0 // loaded reading noisier/faster than idle: no bloat to report, never negative
	}
	if b.LoadError != "" {
		b.Grade = ""
	} else {
		b.Grade = gradeBufferbloat(b.IncreaseMS)
	}
	return b
}

// pingBurstMS sends n probes to host (spaced so they spread across whatever
// window the caller bounds ctx to) and returns the mean of the successful
// round trips, or 0 if every probe failed.
func (p *Prober) pingBurstMS(ctx context.Context, host string, n int) float64 {
	lats := make([]float64, 0, n)
	for i := 0; i < n; i++ {
		if ctx.Err() != nil {
			break
		}
		if rtt, ok := p.probeOnce(ctx, host); ok {
			lats = append(lats, msOf(rtt))
		}
	}
	return mean(lats)
}

// RunBufferbloat runs one bufferbloat check immediately, then again every
// `every` on a ticker, until ctx ends, recording each result into history
// and calling OnBufferbloat. target is called fresh before every check (so
// a changed upstream list is picked up without a restart). every <= 0 runs
// once and returns.
func (p *Prober) RunBufferbloat(ctx context.Context, target func() string, every time.Duration, opts BufferbloatOptions) {
	p.runBufferbloatOnce(ctx, target(), opts)
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
			p.runBufferbloatOnce(ctx, target(), opts)
		}
	}
}

func (p *Prober) runBufferbloatOnce(ctx context.Context, pingTarget string, opts BufferbloatOptions) Bufferbloat {
	b := p.bufferbloatLocked(ctx, pingTarget, opts)
	p.mu.Lock()
	p.store.AddBufferbloat(b)
	p.mu.Unlock()
	if p.OnBufferbloat != nil {
		p.OnBufferbloat(b)
	}
	return b
}

// BufferbloatNow runs one bufferbloat check immediately against
// pingTarget, recording it into history and calling OnBufferbloat exactly
// as a scheduled check would. This is what a manual "run bufferbloat test
// now" from the portal uses, even when the scheduled check is disabled.
func (p *Prober) BufferbloatNow(ctx context.Context, pingTarget string, opts BufferbloatOptions) Bufferbloat {
	return p.runBufferbloatOnce(ctx, pingTarget, opts)
}

// LatestBufferbloat returns the most recently recorded bufferbloat check.
func (p *Prober) LatestBufferbloat() (Bufferbloat, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.store.Bufferbloat) == 0 {
		return Bufferbloat{}, false
	}
	return p.store.Bufferbloat[len(p.store.Bufferbloat)-1], true
}

// BufferbloatHistory returns every stored bufferbloat check within [from, to].
func (p *Prober) BufferbloatHistory(from, to time.Time) []Bufferbloat {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []Bufferbloat
	for _, b := range p.store.Bufferbloat {
		if inRange(b.Time, from, to) {
			out = append(out, b)
		}
	}
	return out
}

func sortBufferbloat(xs []Bufferbloat) {
	sort.Slice(xs, func(i, j int) bool { return xs[i].Time.Before(xs[j].Time) })
}

func dropBufferbloatBefore(xs []Bufferbloat, cutoff time.Time) []Bufferbloat {
	kept := xs[:0:0]
	for _, b := range xs {
		if !b.Time.Before(cutoff) {
			kept = append(kept, b)
		}
	}
	return kept
}
