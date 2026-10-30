// SPDX-License-Identifier: AGPL-3.0-or-later

package nethealth

import "testing"

func healthySample() Sample {
	return Sample{ReachableTargets: 2, TotalTargets: 2, LatencyMS: 20, LossPct: 0}
}
func lossySample() Sample {
	return Sample{ReachableTargets: 2, TotalTargets: 2, LatencyMS: 20, LossPct: 50}
}
func slowSample() Sample {
	return Sample{ReachableTargets: 2, TotalTargets: 2, LatencyMS: 500, LossPct: 0}
}
func outageSample() Sample {
	return Sample{ReachableTargets: 0, TotalTargets: 2, LatencyMS: 0, LossPct: 100}
}

func TestDegradationTrackerNeverRaisesOnASingleBadSample(t *testing.T) {
	tr := NewDegradationTracker(DegradationOptions{})
	for i := 0; i < 2; i++ {
		if got := tr.Update(lossySample()); got != TransitionNone {
			t.Fatalf("update %d: got %v, want TransitionNone (blip, not sustained)", i, got)
		}
	}
	if tr.Raised() {
		t.Fatal("should not be raised after only 2 bad cycles with default ConsecutiveBad=3")
	}
}

func TestDegradationTrackerRaisesAfterConsecutiveBad(t *testing.T) {
	tr := NewDegradationTracker(DegradationOptions{ConsecutiveBad: 3})
	tr.Update(lossySample())
	tr.Update(lossySample())
	got := tr.Update(lossySample())
	if got != TransitionDegraded {
		t.Fatalf("got %v, want TransitionDegraded on the 3rd consecutive bad cycle", got)
	}
	if !tr.Raised() {
		t.Fatal("expected Raised() true")
	}
}

func TestDegradationTrackerDoesNotReRaiseWhileAlreadyRaised(t *testing.T) {
	tr := NewDegradationTracker(DegradationOptions{ConsecutiveBad: 2})
	tr.Update(lossySample())
	if got := tr.Update(lossySample()); got != TransitionDegraded {
		t.Fatalf("got %v, want TransitionDegraded", got)
	}
	if got := tr.Update(lossySample()); got != TransitionNone {
		t.Fatalf("got %v, want TransitionNone (already raised)", got)
	}
}

func TestDegradationTrackerRecoversImmediately(t *testing.T) {
	tr := NewDegradationTracker(DegradationOptions{ConsecutiveBad: 1})
	tr.Update(lossySample())
	if !tr.Raised() {
		t.Fatal("expected raised after 1 bad cycle with ConsecutiveBad=1")
	}
	got := tr.Update(healthySample())
	if got != TransitionRecovered {
		t.Fatalf("got %v, want TransitionRecovered on the very next healthy sample", got)
	}
	if tr.Raised() {
		t.Fatal("expected Raised() false after recovery")
	}
}

func TestDegradationTrackerHealthyNeverTransitionsWhenNeverRaised(t *testing.T) {
	tr := NewDegradationTracker(DegradationOptions{})
	if got := tr.Update(healthySample()); got != TransitionNone {
		t.Fatalf("got %v, want TransitionNone", got)
	}
}

func TestDegradationTrackerBreakInBadStreakResetsCounter(t *testing.T) {
	tr := NewDegradationTracker(DegradationOptions{ConsecutiveBad: 3})
	tr.Update(lossySample())
	tr.Update(lossySample())
	tr.Update(healthySample()) // breaks the streak before it reaches 3
	tr.Update(lossySample())
	got := tr.Update(lossySample())
	if got != TransitionNone {
		t.Fatalf("got %v, want TransitionNone (streak was reset, only 2 consecutive bad now)", got)
	}
}

func TestDegradationTrackerSlowCountsAsBadEvenWithNoLoss(t *testing.T) {
	tr := NewDegradationTracker(DegradationOptions{ConsecutiveBad: 1})
	if got := tr.Update(slowSample()); got != TransitionDegraded {
		t.Fatalf("got %v, want TransitionDegraded (high latency alone should count as bad)", got)
	}
}

func TestDegradationTrackerOutageCountsAsBad(t *testing.T) {
	tr := NewDegradationTracker(DegradationOptions{ConsecutiveBad: 1})
	if got := tr.Update(outageSample()); got != TransitionDegraded {
		t.Fatalf("got %v, want TransitionDegraded", got)
	}
}

func TestDegradationOptionsDefaults(t *testing.T) {
	o := DegradationOptions{}.withDefaults()
	if o.LossPctThreshold != 20 || o.LatencyMSThreshold != 150 || o.ConsecutiveBad != 3 {
		t.Fatalf("got %+v", o)
	}
}
