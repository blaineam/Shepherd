// SPDX-License-Identifier: AGPL-3.0-or-later

package nethealth

// Transition reports what a DegradationTracker's Update just decided, so a
// caller (cmd/shepherd/nethealth.go) knows exactly when to raise or resolve
// an alarm, without re-deriving that decision itself or raising on every
// single bad sample.
type Transition int

const (
	// TransitionNone means nothing changed: still healthy, or still
	// degraded (an alarm already raised stays raised; it is not re-raised
	// every cycle).
	TransitionNone Transition = iota
	// TransitionDegraded means the network just crossed from healthy into
	// sustained degradation: raise the alarm now.
	TransitionDegraded
	// TransitionRecovered means a sample came back healthy after the
	// network had been degraded: resolve the alarm now.
	TransitionRecovered
)

// DegradationOptions configures a DegradationTracker. The zero value is
// usable.
type DegradationOptions struct {
	// LossPctThreshold: a sample this bad or worse counts as "bad". Default: 20.
	LossPctThreshold float64
	// LatencyMSThreshold: a sample with mean latency this high or higher
	// (among reachable targets) counts as "bad", even at low loss — a
	// slow network degrades the experience just as a lossy one does.
	// Default: 150.
	LatencyMSThreshold float64
	// ConsecutiveBad is how many consecutive bad cycles are required before
	// declaring the network degraded. This is Shepherd's "don't cry wolf"
	// guard for this feature, in the same spirit as
	// cmd/shepherd/alarms.go's wireUpstreamAlarms requiring every upstream
	// to be down rather than just one: a single bad probe cycle is noise
	// (a transient Wi-Fi retry, a loaded CPU delaying a goroutine), not a
	// finding worth paging anyone about. Default: 3.
	ConsecutiveBad int
}

func (o DegradationOptions) withDefaults() DegradationOptions {
	if o.LossPctThreshold <= 0 {
		o.LossPctThreshold = 20
	}
	if o.LatencyMSThreshold <= 0 {
		o.LatencyMSThreshold = 150
	}
	if o.ConsecutiveBad <= 0 {
		o.ConsecutiveBad = 3
	}
	return o
}

// isBad reports whether s is bad enough to count toward sustained
// degradation: a total outage (nothing reachable), loss at or above
// LossPctThreshold, or mean latency at or above LatencyMSThreshold.
func (o DegradationOptions) isBad(s Sample) bool {
	if s.AllUnreachable() {
		return true
	}
	if s.LossPct >= o.LossPctThreshold {
		return true
	}
	if s.ReachableTargets > 0 && s.LatencyMS >= o.LatencyMSThreshold {
		return true
	}
	return false
}

// DegradationTracker turns a stream of Samples into the occasional alarm
// transition: it raises once sustained badness has been seen for
// ConsecutiveBad cycles in a row, and resolves as soon as a single healthy
// sample arrives afterward (recovery is good news, worth reporting right
// away — see docs/NETHEALTH.md; this mirrors internal/vulnscan's own
// immediate resolve-on-fixed philosophy). It never raises twice for the
// same ongoing episode.
type DegradationTracker struct {
	opt         DegradationOptions
	consecutive int
	raised      bool
}

// NewDegradationTracker creates a tracker from opts.
func NewDegradationTracker(opts DegradationOptions) *DegradationTracker {
	return &DegradationTracker{opt: opts.withDefaults()}
}

// Update folds in one more Sample and returns the resulting Transition.
func (t *DegradationTracker) Update(s Sample) Transition {
	if t.opt.isBad(s) {
		t.consecutive++
		if !t.raised && t.consecutive >= t.opt.ConsecutiveBad {
			t.raised = true
			return TransitionDegraded
		}
		return TransitionNone
	}
	t.consecutive = 0
	if t.raised {
		t.raised = false
		return TransitionRecovered
	}
	return TransitionNone
}

// Raised reports whether the tracker currently considers the network
// degraded (an alarm is open).
func (t *DegradationTracker) Raised() bool { return t.raised }
