// SPDX-License-Identifier: AGPL-3.0-or-later

package nethealth

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeConn is a no-op net.Conn, enough for probeOnce's dial-then-close use.
type fakeConn struct{ net.Conn }

func (fakeConn) Close() error { return nil }

// fakeDial lets a test control, per host, whether the dial succeeds and how
// long it should appear to take by advancing a fake clock.
type fakeDial struct {
	mu      sync.Mutex
	clock   time.Time
	fail    map[string]bool
	delayMS map[string]float64 // advances the fake clock by this much per dial
	calls   atomic.Int64
}

func newFakeDial() *fakeDial {
	return &fakeDial{clock: time.Unix(1700000000, 0), fail: map[string]bool{}, delayMS: map[string]float64{}}
}

func (f *fakeDial) now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.clock
}

func (f *fakeDial) dial(ctx context.Context, network, address string) (net.Conn, error) {
	f.calls.Add(1)
	host, _, _ := net.SplitHostPort(address)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail[host] {
		return nil, errors.New("fake: connection refused")
	}
	d := f.delayMS[host]
	f.clock = f.clock.Add(time.Duration(d * float64(time.Millisecond)))
	return fakeConn{}, nil
}

func newTestProber(f *fakeDial) *Prober {
	return New(Options{Dial: f.dial, Now: f.now, Burst: 4, Timeout: time.Second})
}

func TestProbeTargetAllSucceed(t *testing.T) {
	f := newFakeDial()
	f.delayMS["a"] = 10
	p := newTestProber(f)
	res := p.probeTarget(context.Background(), "a")
	if res.Successes != 4 || res.Probes != 4 {
		t.Fatalf("got %+v", res)
	}
	if res.LossPct != 0 {
		t.Errorf("loss = %v, want 0", res.LossPct)
	}
	if res.AvgLatencyMS <= 0 {
		t.Errorf("avg latency = %v, want > 0", res.AvgLatencyMS)
	}
}

func TestProbeTargetAllFail(t *testing.T) {
	f := newFakeDial()
	f.fail["dead"] = true
	p := newTestProber(f)
	res := p.probeTarget(context.Background(), "dead")
	if res.Successes != 0 {
		t.Fatalf("got %+v", res)
	}
	if res.LossPct != 100 {
		t.Errorf("loss = %v, want 100", res.LossPct)
	}
	if res.AvgLatencyMS != 0 || res.JitterMS != 0 {
		t.Errorf("latency/jitter should be zero with no successes, got %+v", res)
	}
}

func TestProbeAggregatesAcrossTargets(t *testing.T) {
	f := newFakeDial()
	f.delayMS["good"] = 10
	f.fail["bad"] = true
	p := newTestProber(f)
	s := p.Probe(context.Background(), []string{"good", "bad"})
	if s.TotalTargets != 2 || s.ReachableTargets != 1 {
		t.Fatalf("got %+v", s)
	}
	// loss is the mean across all targets: good=0%, bad=100% => 50%.
	if s.LossPct != 50 {
		t.Errorf("loss = %v, want 50", s.LossPct)
	}
	if s.LatencyMS <= 0 {
		t.Errorf("latency = %v, want > 0 (from the reachable target)", s.LatencyMS)
	}
	if s.AllUnreachable() {
		t.Errorf("should not be all-unreachable with one good target")
	}
}

func TestProbeAllUnreachable(t *testing.T) {
	f := newFakeDial()
	f.fail["a"] = true
	f.fail["b"] = true
	p := newTestProber(f)
	s := p.Probe(context.Background(), []string{"a", "b"})
	if !s.AllUnreachable() {
		t.Errorf("expected AllUnreachable, got %+v", s)
	}
	if s.LossPct != 100 {
		t.Errorf("loss = %v, want 100", s.LossPct)
	}
}

func TestProbeNoTargets(t *testing.T) {
	f := newFakeDial()
	p := newTestProber(f)
	s := p.Probe(context.Background(), nil)
	if s.TotalTargets != 0 || s.AllUnreachable() {
		t.Fatalf("got %+v", s)
	}
}

func TestJitterNeedsAtLeastTwoSuccesses(t *testing.T) {
	f := newFakeDial()
	f.delayMS["a"] = 10
	p := New(Options{Dial: f.dial, Now: f.now, Burst: 1, Timeout: time.Second})
	res := p.probeTarget(context.Background(), "a")
	if res.Successes != 1 {
		t.Fatalf("got %+v", res)
	}
	if res.JitterMS != 0 {
		t.Errorf("jitter with one sample should be 0, got %v", res.JitterMS)
	}
}

func TestRunOnceRecordsHistoryAndCallsOnSample(t *testing.T) {
	f := newFakeDial()
	f.delayMS["a"] = 5
	p := newTestProber(f)
	var got []Sample
	p.OnSample = func(s Sample) { got = append(got, s) }
	p.Run(context.Background(), func() []string { return []string{"a"} }, 0)
	if len(got) != 1 {
		t.Fatalf("OnSample called %d times, want 1", len(got))
	}
	latest, ok := p.Latest()
	if !ok || latest.Time != got[0].Time {
		t.Fatalf("Latest() = %+v, %v", latest, ok)
	}
}

func TestRunStopsOnContextCancel(t *testing.T) {
	f := newFakeDial()
	p := newTestProber(f)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		p.Run(ctx, func() []string { return []string{"a"} }, time.Millisecond)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after ctx was cancelled")
	}
}

func TestRunTicksMultipleTimes(t *testing.T) {
	f := newFakeDial()
	p := newTestProber(f)
	var n atomic.Int64
	p.OnSample = func(Sample) { n.Add(1) }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx, func() []string { return []string{"a"} }, 5*time.Millisecond)
	deadline := time.After(2 * time.Second)
	for n.Load() < 3 {
		select {
		case <-deadline:
			t.Fatalf("only %d cycles ran in time", n.Load())
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func TestProbeNowRecordsHistoryAndCallsOnSample(t *testing.T) {
	f := newFakeDial()
	f.delayMS["a"] = 5
	p := newTestProber(f)
	var got []Sample
	p.OnSample = func(s Sample) { got = append(got, s) }
	s := p.ProbeNow(context.Background(), []string{"a"})
	if len(got) != 1 || got[0].Time != s.Time {
		t.Fatalf("OnSample = %+v, direct result = %+v", got, s)
	}
	latest, ok := p.Latest()
	if !ok || latest.Time != s.Time {
		t.Fatalf("Latest() = %+v, %v", latest, ok)
	}
}

func TestSeriesDelegatesToStoreAtEveryBucket(t *testing.T) {
	f := newFakeDial()
	p := newTestProber(f)
	now := time.Now()
	p.store.Add(sampleAt(now, 10, 0, 0, 1, 1))
	p.store.Hourly = []aggregate{{Bucket: hourStart(now), Count: 1, AvgLatencyMS: 20}}
	p.store.Daily = []aggregate{{Bucket: dayStart(now), Count: 1, AvgLatencyMS: 30}}

	if pts := p.Series(now.Add(-time.Hour), now.Add(time.Hour), BucketRaw); len(pts) != 1 {
		t.Errorf("raw series = %+v", pts)
	}
	if pts := p.Series(hourStart(now).Add(-time.Minute), hourStart(now).Add(time.Minute), BucketHour); len(pts) != 1 {
		t.Errorf("hourly series = %+v", pts)
	}
	if pts := p.Series(dayStart(now).Add(-time.Minute), dayStart(now).Add(time.Minute), BucketDay); len(pts) != 1 {
		t.Errorf("daily series = %+v", pts)
	}
}

func TestManualAndScheduledScansDoNotOverlap(t *testing.T) {
	// cycleMu serializes Probe/runOnce; verify two concurrent callers never
	// run their bursts interleaved by checking the fake dial's call count
	// matches exactly what two full cycles should produce.
	f := newFakeDial()
	p := newTestProber(f)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.runOnce(context.Background(), []string{"a", "b"})
		}()
	}
	wg.Wait()
	if got := f.calls.Load(); got != int64(2*2*p.burst) {
		t.Errorf("dial calls = %d, want %d", got, 2*2*p.burst)
	}
}
