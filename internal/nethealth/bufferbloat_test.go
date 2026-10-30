// SPDX-License-Identifier: AGPL-3.0-or-later

package nethealth

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestGradeBufferbloat(t *testing.T) {
	cases := []struct {
		ms   float64
		want string
	}{
		{0, "A"}, {29, "A"}, {30, "B"}, {59, "B"}, {60, "C"}, {199, "C"}, {200, "D"}, {399, "D"}, {400, "F"}, {1000, "F"},
	}
	for _, c := range cases {
		if got := gradeBufferbloat(c.ms); got != c.want {
			t.Errorf("gradeBufferbloat(%v) = %q, want %q", c.ms, got, c.want)
		}
	}
}

// fakeLoad blocks until ctx is done (simulating a load burst that runs for
// however long it is allowed to, same as the real HTTP download does under
// a context deadline) and never touches a real socket.
func fakeLoad(err error) LoadFunc {
	return func(ctx context.Context) error {
		<-ctx.Done()
		return err
	}
}

func TestBufferbloatComparesIdleAndLoaded(t *testing.T) {
	f := newFakeDial()
	f.delayMS["a"] = 10
	p := New(Options{Dial: f.dial, Now: f.now, Burst: 2, Timeout: time.Second})

	callCount := atomic.Int64{}
	load := func(ctx context.Context) error {
		callCount.Add(1)
		// Simulate load pushing latency up for the loaded probes that
		// follow, by bumping the fake dial's delay before returning.
		f.mu.Lock()
		f.delayMS["a"] = 100
		f.mu.Unlock()
		<-ctx.Done()
		return nil
	}

	b := p.Bufferbloat(context.Background(), "a", BufferbloatOptions{Load: load, Duration: 20 * time.Millisecond, IdleBurst: 2, LoadedBurst: 2})
	if callCount.Load() != 1 {
		t.Fatalf("load called %d times, want 1", callCount.Load())
	}
	if b.IdleMS <= 0 {
		t.Errorf("idle = %v, want > 0", b.IdleMS)
	}
	if b.LoadError != "" {
		t.Errorf("unexpected load error: %v", b.LoadError)
	}
	if b.Grade == "" {
		t.Errorf("expected a grade to be assigned")
	}
}

func TestBufferbloatIncreaseNeverNegative(t *testing.T) {
	f := newFakeDial()
	f.delayMS["a"] = 50
	p := New(Options{Dial: f.dial, Now: f.now, Burst: 2, Timeout: time.Second})
	// Loaded probes happen to look faster than idle (noise); IncreaseMS
	// must clamp to 0, never go negative.
	load := func(ctx context.Context) error {
		f.mu.Lock()
		f.delayMS["a"] = 5
		f.mu.Unlock()
		<-ctx.Done()
		return nil
	}
	b := p.Bufferbloat(context.Background(), "a", BufferbloatOptions{Load: load, Duration: 10 * time.Millisecond})
	if b.IncreaseMS != 0 {
		t.Errorf("IncreaseMS = %v, want 0 (clamped)", b.IncreaseMS)
	}
	if b.Grade != "A" {
		t.Errorf("grade = %q, want A", b.Grade)
	}
}

func TestBufferbloatLoadErrorReportedAndUngraded(t *testing.T) {
	f := newFakeDial()
	f.delayMS["a"] = 5
	p := New(Options{Dial: f.dial, Now: f.now, Burst: 1, Timeout: time.Second})
	wantErr := errors.New("boom")
	load := func(ctx context.Context) error { return wantErr }
	b := p.Bufferbloat(context.Background(), "a", BufferbloatOptions{Load: load, Duration: 50 * time.Millisecond})
	if b.LoadError != wantErr.Error() {
		t.Errorf("LoadError = %q, want %q", b.LoadError, wantErr.Error())
	}
	if b.Grade != "" {
		t.Errorf("expected no grade when the load burst failed, got %q", b.Grade)
	}
}

func TestBufferbloatBoundedByDuration(t *testing.T) {
	f := newFakeDial()
	p := New(Options{Dial: f.dial, Now: time.Now, Burst: 1, Timeout: 10 * time.Millisecond})
	start := time.Now()
	p.Bufferbloat(context.Background(), "a", BufferbloatOptions{Load: fakeLoad(nil), Duration: 30 * time.Millisecond})
	elapsed := time.Since(start)
	if elapsed > 500*time.Millisecond {
		t.Errorf("Bufferbloat took %v, expected to be bounded by Duration (30ms) plus pings", elapsed)
	}
}

func TestRunBufferbloatRecordsHistoryAndCallsHook(t *testing.T) {
	f := newFakeDial()
	f.delayMS["a"] = 1
	p := New(Options{Dial: f.dial, Now: f.now, Burst: 1, Timeout: time.Second})
	var got []Bufferbloat
	p.OnBufferbloat = func(b Bufferbloat) { got = append(got, b) }
	p.RunBufferbloat(context.Background(), func() string { return "a" }, 0, BufferbloatOptions{Load: fakeLoad(nil), Duration: 5 * time.Millisecond})
	if len(got) != 1 {
		t.Fatalf("OnBufferbloat called %d times, want 1", len(got))
	}
	latest, ok := p.LatestBufferbloat()
	if !ok || latest.Time != got[0].Time {
		t.Fatalf("LatestBufferbloat() = %+v, %v", latest, ok)
	}
	hist := p.BufferbloatHistory(time.Time{}, time.Now().Add(time.Hour))
	if len(hist) != 1 {
		t.Fatalf("BufferbloatHistory returned %d entries, want 1", len(hist))
	}
}

func TestBufferbloatFallsBackToProberConfiguredLoadAndDuration(t *testing.T) {
	// A manual "run bufferbloat test now" from the portal passes
	// BufferbloatOptions{} (zero value): it must use whatever Load/
	// BufferbloatDuration the Prober was constructed with, not some
	// unrelated package-level default, since the portal has no access to
	// cmd/shepherd's own configured load generator.
	f := newFakeDial()
	f.delayMS["a"] = 1
	var called atomic.Bool
	load := func(ctx context.Context) error {
		called.Store(true)
		<-ctx.Done()
		return nil
	}
	p := New(Options{Dial: f.dial, Now: f.now, Burst: 1, Timeout: time.Second, Load: load, BufferbloatDuration: 10 * time.Millisecond})

	start := time.Now()
	b := p.Bufferbloat(context.Background(), "a", BufferbloatOptions{})
	elapsed := time.Since(start)

	if !called.Load() {
		t.Fatal("expected the Prober's configured Load to be used")
	}
	if elapsed > 2*time.Second {
		t.Errorf("took %v, expected to be bounded by the Prober's configured 10ms BufferbloatDuration", elapsed)
	}
	if b.LoadError != "" {
		t.Errorf("unexpected load error: %v", b.LoadError)
	}
}

func TestRunBufferbloatStopsOnContextCancel(t *testing.T) {
	f := newFakeDial()
	p := New(Options{Dial: f.dial, Now: f.now, Burst: 1, Timeout: time.Second})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		p.RunBufferbloat(ctx, func() string { return "a" }, time.Millisecond, BufferbloatOptions{Load: fakeLoad(nil), Duration: time.Millisecond})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunBufferbloat did not return after ctx was cancelled")
	}
}
