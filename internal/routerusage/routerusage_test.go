// SPDX-License-Identifier: AGPL-3.0-or-later

package routerusage

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"testing"
	"time"

	"shepherd/internal/importers"
	"shepherd/internal/traffic"
)

var t0 = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

// ---- fakes ------------------------------------------------------------------

type fakeSource struct {
	kind Kind
	mu   sync.Mutex
	runs []func() ([]Sample, error)
	n    int
}

func (f *fakeSource) Name() string { return "fake" }
func (f *fakeSource) Kind() Kind   { return f.kind }
func (f *fakeSource) Poll(context.Context) ([]Sample, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.n >= len(f.runs) {
		return nil, errors.New("no more polls scripted")
	}
	r := f.runs[f.n]
	f.n++
	return r()
}

func samples(ss ...Sample) func() ([]Sample, error) {
	return func() ([]Sample, error) { return ss, nil }
}

func boom(err error) func() ([]Sample, error) {
	return func() ([]Sample, error) { return nil, err }
}

type fakeRecorder struct {
	mu   sync.Mutex
	rows []map[string]traffic.Delta
}

func (r *fakeRecorder) Record(_ time.Time, rows map[string]traffic.Delta) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := map[string]traffic.Delta{}
	for k, v := range rows {
		cp[k] = v
	}
	r.rows = append(r.rows, cp)
}

func (r *fakeRecorder) all() []map[string]traffic.Delta {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]map[string]traffic.Delta(nil), r.rows...)
}

// harness drives a Collector one poll at a time with a clock the test
// moves. The clock is guarded because Run reads it from its own goroutine.
type harness struct {
	c   *Collector
	rec *fakeRecorder
	src *fakeSource

	mu  sync.Mutex
	now time.Time
}

func (h *harness) clock() time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.now
}

func (h *harness) advance(d time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.now = h.now.Add(d)
}

func newHarness(t *testing.T, kind Kind, mod func(*Options), runs ...func() ([]Sample, error)) *harness {
	t.Helper()
	h := &harness{rec: &fakeRecorder{}, src: &fakeSource{kind: kind, runs: runs}, now: t0}
	opt := Options{
		Source:   h.src,
		Recorder: h.rec,
		// Every MAC maps to a device id of "d-"+mac unless a test says otherwise.
		Resolve: func(mac string) (string, bool) { return "d-" + mac, true },
		Now:     h.clock,
	}
	if mod != nil {
		mod(&opt)
	}
	h.c = New(opt)
	return h
}

// step advances the clock by d and runs one poll.
func (h *harness) step(d time.Duration) {
	h.advance(d)
	h.c.pollOnce(context.Background())
}

// ---- MAC --------------------------------------------------------------------

func TestNormalizeMACAcceptsEverySeparatorRoutersUse(t *testing.T) {
	for _, in := range []string{"A4:83:E7:11:22:33", "a4-83-e7-11-22-33", "a483.e711.2233", "a483e7112233", " A4 83 E7 11 22 33 "} {
		if got := NormalizeMAC(in); got != "a483e7112233" {
			t.Errorf("NormalizeMAC(%q) = %q", in, got)
		}
	}
	for _, in := range []string{"", "not-a-mac", "a483e711223", "a483e71122334", "zz:83:e7:11:22:33", "a483e711223g"} {
		if got := NormalizeMAC(in); got != "" {
			t.Errorf("NormalizeMAC(%q) = %q, want empty", in, got)
		}
	}
}

func TestKindNamesItselfAndSaysWhetherItIsEstimated(t *testing.T) {
	if KindRates.String() != "rates" || !KindRates.Estimated() {
		t.Error("rates")
	}
	if KindCounters.String() != "counters" || KindCounters.Estimated() {
		t.Error("counters")
	}
}

// ---- rates ------------------------------------------------------------------

// A rate source is integrated with the trapezoid rule: the average of the
// rate at each end of the gap, over the gap.
func TestRatesAreIntegratedOverTheGapAndTheFirstPollIsOnlyABaseline(t *testing.T) {
	h := newHarness(t, KindRates, nil,
		samples(Sample{MAC: "aa:bb:cc:00:00:01", DownBitsPerSecond: 8e6, UpBitsPerSecond: 0}),
		samples(Sample{MAC: "aa:bb:cc:00:00:01", DownBitsPerSecond: 8e6, UpBitsPerSecond: 8e6}),
	)
	h.step(0)
	if got := h.rec.all(); len(got) != 0 {
		t.Fatalf("the first poll recorded %v, want nothing: it is only a baseline", got)
	}
	h.step(10 * time.Second)
	rows := h.rec.all()
	if len(rows) != 1 {
		t.Fatalf("rows = %v", rows)
	}
	d := rows[0]["d-aabbcc000001"]
	// Down held 8 Mbit/s for 10s = 10 MB. Up ramped 0 -> 8 Mbit/s, so half that.
	if d.Down != 10_000_000 || d.Up != 5_000_000 {
		t.Fatalf("delta = %+v, want down 10000000 up 5000000", d)
	}
}

func TestAGapLongerThanMaxGapIsLeftEmptyRatherThanInvented(t *testing.T) {
	h := newHarness(t, KindRates, func(o *Options) { o.MaxGap = time.Minute },
		samples(Sample{MAC: "aa:bb:cc:00:00:01", DownBitsPerSecond: 8e6}),
		samples(Sample{MAC: "aa:bb:cc:00:00:01", DownBitsPerSecond: 8e6}),
		samples(Sample{MAC: "aa:bb:cc:00:00:01", DownBitsPerSecond: 8e6}),
	)
	h.step(0)
	h.step(2 * time.Minute) // the host slept, or polls failed for a while
	if got := h.rec.all(); len(got) != 0 {
		t.Fatalf("recorded %v across a gap longer than MaxGap", got)
	}
	// The sample after the gap is a fresh baseline, so the next one counts.
	h.step(10 * time.Second)
	if got := h.rec.all(); len(got) != 1 {
		t.Fatalf("the poll after the gap should resume recording, got %v", got)
	}
}

func TestNonsenseRatesNeverBecomeTraffic(t *testing.T) {
	for name, s := range map[string]Sample{
		"negative":  {MAC: "aa:bb:cc:00:00:01", DownBitsPerSecond: -5e6},
		"not a num": {MAC: "aa:bb:cc:00:00:01", DownBitsPerSecond: nan()},
		"infinite":  {MAC: "aa:bb:cc:00:00:01", DownBitsPerSecond: inf()},
		"absurd":    {MAC: "aa:bb:cc:00:00:01", DownBitsPerSecond: 400e9},
	} {
		h := newHarness(t, KindRates, nil, samples(s), samples(s))
		h.step(0)
		h.step(10 * time.Second)
		for _, row := range h.rec.all() {
			if d := row["d-aabbcc000001"]; d.Down != 0 || d.Up != 0 {
				t.Errorf("%s: recorded %+v, want nothing", name, d)
			}
		}
	}
}

// ---- counters ---------------------------------------------------------------

func TestCountersAreDifferencedAndAResetDoesNotGoNegative(t *testing.T) {
	h := newHarness(t, KindCounters, nil,
		samples(Sample{MAC: "aa:bb:cc:00:00:02", DownBytes: 1000, UpBytes: 500}),
		samples(Sample{MAC: "aa:bb:cc:00:00:02", DownBytes: 3000, UpBytes: 900}),
		samples(Sample{MAC: "aa:bb:cc:00:00:02", DownBytes: 10, UpBytes: 5}), // the router rebooted
		samples(Sample{MAC: "aa:bb:cc:00:00:02", DownBytes: 110, UpBytes: 25}),
	)
	h.step(0)
	h.step(10 * time.Second)
	if d := h.rec.all()[0]["d-aabbcc000002"]; d.Down != 2000 || d.Up != 400 {
		t.Fatalf("delta = %+v, want down 2000 up 400", d)
	}
	h.step(10 * time.Second) // the reset itself records nothing
	if n := len(h.rec.all()); n != 1 {
		t.Fatalf("a counter reset recorded something: %v", h.rec.all())
	}
	h.step(10 * time.Second) // and the next pair counts from the new baseline
	if d := h.rec.all()[1]["d-aabbcc000002"]; d.Down != 100 || d.Up != 20 {
		t.Fatalf("after the reset, delta = %+v, want down 100 up 20", d)
	}
}

func TestACounterJumpTooLargeToBeRealIsRefused(t *testing.T) {
	h := newHarness(t, KindCounters, nil,
		samples(Sample{MAC: "aa:bb:cc:00:00:02", DownBytes: 0}),
		samples(Sample{MAC: "aa:bb:cc:00:00:02", DownBytes: 1 << 62}),
	)
	h.step(0)
	h.step(time.Second)
	if got := h.rec.all(); len(got) != 0 {
		t.Fatalf("recorded an impossible jump: %v", got)
	}
}

// ---- which devices count ----------------------------------------------------

func TestDevicesTheRegistryDoesNotKnowAreCountedTowardsNothing(t *testing.T) {
	h := newHarness(t, KindRates, func(o *Options) {
		o.Resolve = func(mac string) (string, bool) { return "", false }
	},
		samples(Sample{MAC: "aa:bb:cc:00:00:03", DownBitsPerSecond: 8e6}),
		samples(Sample{MAC: "aa:bb:cc:00:00:03", DownBitsPerSecond: 8e6}),
	)
	h.step(0)
	h.step(10 * time.Second)
	if got := h.rec.all(); len(got) != 0 {
		t.Fatalf("recorded %v for a device the registry does not know", got)
	}
	if st := h.c.Status(); st.DevicesSeen != 1 || st.Matched != 0 {
		t.Fatalf("status = %+v, want seen 1 matched 0", st)
	}
}

// Watch mode measures exactly. Where it is doing so, the router's estimate
// must not be added on top of it.
func TestADeviceWatchModeIsAlreadyMeasuringIsSkipped(t *testing.T) {
	h := newHarness(t, KindRates, func(o *Options) {
		o.Skip = func(id string) bool { return id == "d-aabbcc000004" }
	},
		samples(
			Sample{MAC: "aa:bb:cc:00:00:04", DownBitsPerSecond: 8e6},
			Sample{MAC: "aa:bb:cc:00:00:05", DownBitsPerSecond: 8e6},
		),
		samples(
			Sample{MAC: "aa:bb:cc:00:00:04", DownBitsPerSecond: 8e6},
			Sample{MAC: "aa:bb:cc:00:00:05", DownBitsPerSecond: 8e6},
		),
	)
	h.step(0)
	h.step(10 * time.Second)
	row := h.rec.all()[0]
	if _, present := row["d-aabbcc000004"]; present {
		t.Error("the watched device was counted twice")
	}
	if row["d-aabbcc000005"].Down == 0 {
		t.Error("the unwatched device was not counted")
	}
}

func TestSamplesWithoutAUsableMACAreIgnored(t *testing.T) {
	h := newHarness(t, KindRates, nil,
		samples(Sample{MAC: "nonsense", DownBitsPerSecond: 8e6}, Sample{MAC: "", DownBitsPerSecond: 8e6}),
	)
	h.step(0)
	if st := h.c.Status(); st.DevicesSeen != 0 {
		t.Fatalf("status = %+v, want nothing seen", st)
	}
}

// Two interfaces of one machine can resolve to the same device; their
// traffic adds up rather than one overwriting the other.
func TestTwoMACsOnOneDeviceAreSummed(t *testing.T) {
	h := newHarness(t, KindRates, func(o *Options) {
		o.Resolve = func(string) (string, bool) { return "d-one", true }
	},
		samples(
			Sample{MAC: "aa:bb:cc:00:00:06", DownBitsPerSecond: 8e6},
			Sample{MAC: "aa:bb:cc:00:00:07", DownBitsPerSecond: 8e6},
		),
		samples(
			Sample{MAC: "aa:bb:cc:00:00:06", DownBitsPerSecond: 8e6},
			Sample{MAC: "aa:bb:cc:00:00:07", DownBitsPerSecond: 8e6},
		),
	)
	h.step(0)
	h.step(10 * time.Second)
	if d := h.rec.all()[0]["d-one"]; d.Down != 20_000_000 {
		t.Fatalf("delta = %+v, want both interfaces summed (20000000)", d)
	}
}

// ---- status and errors ------------------------------------------------------

func TestAFailedPollIsReportedAndLoggedOnceUntilItRecovers(t *testing.T) {
	var lines []string
	h := newHarness(t, KindRates, func(o *Options) {
		o.Logf = func(f string, a ...any) { lines = append(lines, fmt.Sprintf(f, a...)) }
		o.NeedsSignIn = func(err error) bool { return errors.Is(err, importers.ErrEeroSessionExpire) }
	},
		boom(errors.New("the router did not answer")),
		boom(errors.New("the router did not answer")),
		samples(Sample{MAC: "aa:bb:cc:00:00:08", DownBitsPerSecond: 0}),
	)
	h.step(0)
	st := h.c.Status()
	if st.LastError == "" || st.NeedsSignIn || !st.LastPoll.IsZero() {
		t.Fatalf("status = %+v", st)
	}
	h.step(time.Second)
	if len(lines) != 1 {
		t.Fatalf("the same failure was logged %d times: %v", len(lines), lines)
	}
	h.step(time.Second)
	if st := h.c.Status(); st.LastError != "" || st.LastPoll.IsZero() {
		t.Fatalf("status after recovery = %+v", st)
	}
	if len(lines) != 2 {
		t.Fatalf("recovery was not logged: %v", lines)
	}
}

func TestAnExpiredSessionAsksForASignInRatherThanLookingLikeAnOutage(t *testing.T) {
	h := newHarness(t, KindRates, func(o *Options) { o.NeedsSignIn = EeroNeedsSignIn },
		boom(fmt.Errorf("reading devices: %w", importers.ErrEeroSessionExpire)),
	)
	h.step(0)
	if st := h.c.Status(); !st.NeedsSignIn {
		t.Fatalf("status = %+v, want NeedsSignIn", st)
	}
}

func TestACancelledPollIsNotLoggedAsAFailure(t *testing.T) {
	var lines []string
	h := newHarness(t, KindRates, func(o *Options) {
		o.Logf = func(f string, a ...any) { lines = append(lines, f) }
	}, boom(context.Canceled))
	h.step(0)
	if len(lines) != 0 {
		t.Fatalf("shutdown logged %v", lines)
	}
}

func TestStatusDescribesTheSourceBeforeAnyPoll(t *testing.T) {
	h := newHarness(t, KindRates, func(o *Options) { o.Interval = 45 * time.Second })
	st := h.c.Status()
	if st.Source != "fake" || !st.Enabled || !st.Estimated || st.IntervalSeconds != 45 {
		t.Fatalf("status = %+v", st)
	}
	if h.c.opt.MaxGap != DefaultMaxGap {
		t.Fatalf("MaxGap = %v, want the default", h.c.opt.MaxGap)
	}
	counters := newHarness(t, KindCounters, nil)
	if counters.c.Status().Estimated {
		t.Error("a counter source must not be labelled estimated")
	}
}

func TestNewRefusesAnIncompleteConfiguration(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("New accepted a configuration with no Source")
		}
	}()
	New(Options{Recorder: &fakeRecorder{}, Resolve: func(string) (string, bool) { return "", false }})
}

// ---- Run --------------------------------------------------------------------

func TestRunPollsOnTheIntervalUntilItsContextEnds(t *testing.T) {
	tick := make(chan time.Time)
	h := newHarness(t, KindRates, func(o *Options) {
		o.After = func(time.Duration) <-chan time.Time { return tick }
	},
		samples(Sample{MAC: "aa:bb:cc:00:00:09", DownBitsPerSecond: 8e6}),
		samples(Sample{MAC: "aa:bb:cc:00:00:09", DownBitsPerSecond: 8e6}),
		samples(Sample{MAC: "aa:bb:cc:00:00:09", DownBitsPerSecond: 8e6}),
	)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.c.Run(ctx) }()

	for i := 0; i < 2; i++ {
		h.advance(10 * time.Second)
		tick <- time.Time{}
	}
	cancel()
	// Release Run if it is already waiting on the next tick.
	select {
	case tick <- time.Time{}:
	default:
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return when its context ended")
	}
	if len(h.rec.all()) == 0 {
		t.Fatal("Run recorded nothing")
	}
}

// ---- the eero source --------------------------------------------------------

type fakeEero struct {
	devs []importers.EeroDevice
	err  error
	gotN string
}

func (f *fakeEero) Devices(_ context.Context, networkID string) ([]importers.EeroDevice, error) {
	f.gotN = networkID
	return f.devs, f.err
}

func TestEeroReportsMegabitsPerSecondAsBitsPerSecond(t *testing.T) {
	f := &fakeEero{devs: []importers.EeroDevice{
		{MAC: "AA:BB:CC:00:00:10", Nickname: "Living Room TV", DownMbps: 12.5, UpMbps: 0.5, HasUsage: true},
		{MAC: "", Nickname: "no mac"},
		{MAC: "AA:BB:CC:00:00:11", Hostname: "printer", HasUsage: true},
	}}
	src := NewEero(f, "net-1")
	if src.Name() != "eero" || src.Kind() != KindRates {
		t.Fatalf("source = %s/%s", src.Name(), src.Kind())
	}
	got, err := src.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if f.gotN != "net-1" {
		t.Fatalf("polled network %q", f.gotN)
	}
	if len(got) != 2 {
		t.Fatalf("samples = %+v, want the one without a MAC dropped", got)
	}
	if got[0].MAC != "aabbcc000010" || got[0].Name != "Living Room TV" ||
		got[0].DownBitsPerSecond != 12.5e6 || got[0].UpBitsPerSecond != 0.5e6 {
		t.Fatalf("sample = %+v", got[0])
	}
	if got[1].Name != "printer" {
		t.Fatalf("a device with only a hostname lost its name: %+v", got[1])
	}
}

func TestEeroSaysSoWhenTheAnswerCarriesNoUsageAtAll(t *testing.T) {
	f := &fakeEero{devs: []importers.EeroDevice{{MAC: "AA:BB:CC:00:00:12"}, {MAC: "AA:BB:CC:00:00:13"}}}
	got, err := NewEero(f, "n").Poll(context.Background())
	if !errors.Is(err, ErrNoUsage) {
		t.Fatalf("err = %v, want ErrNoUsage", err)
	}
	if len(got) != 2 {
		t.Fatalf("the devices themselves should still come back: %+v", got)
	}
	// An empty network is not the same thing as a network with no usage.
	if _, err := NewEero(&fakeEero{}, "n").Poll(context.Background()); err != nil {
		t.Fatalf("an empty network reported %v", err)
	}
}

func TestEeroPassesAReadFailureStraightOut(t *testing.T) {
	want := errors.New("nope")
	if _, err := NewEero(&fakeEero{err: want}, "n").Poll(context.Background()); !errors.Is(err, want) {
		t.Fatalf("err = %v", err)
	}
}

func TestEeroNeedsSignInOnlyForSessionProblems(t *testing.T) {
	for _, err := range []error{importers.ErrEeroSessionExpire, importers.ErrEeroUnauthorized, importers.ErrEeroNoSession} {
		if !EeroNeedsSignIn(fmt.Errorf("wrapped: %w", err)) {
			t.Errorf("%v should ask for a sign-in", err)
		}
	}
	for _, err := range []error{importers.ErrEeroRateLimited, errors.New("timeout"), ErrNoUsage} {
		if EeroNeedsSignIn(err) {
			t.Errorf("%v should not ask for a sign-in", err)
		}
	}
}

func nan() float64 { return math.NaN() }
func inf() float64 { return math.Inf(1) }

// ---- Manager ----------------------------------------------------------------

func newManagerHarness(t *testing.T, build Build) (*Manager, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	m := NewManager(ctx, build, nil)
	t.Cleanup(func() { m.Stop(); cancel() })
	return m, cancel
}

func TestManagerRunsNothingUntilAConnectionExists(t *testing.T) {
	m, _ := newManagerHarness(t, func() (*Collector, bool, error) { return nil, false, nil })
	m.Reload()
	if st := m.Status(); st.Enabled || st.Source != "" || st.LastError != "" {
		t.Fatalf("status = %+v, want nothing running", st)
	}
}

func TestManagerReportsAConnectionItCouldNotOpen(t *testing.T) {
	m, _ := newManagerHarness(t, func() (*Collector, bool, error) {
		return nil, false, errors.New("the stored session could not be read")
	})
	m.Reload()
	if st := m.Status(); st.LastError == "" {
		t.Fatalf("status = %+v, want the failure reported", st)
	}
	// And a later Reload that succeeds clears it.
	m.build = func() (*Collector, bool, error) { return nil, false, nil }
	m.Reload()
	if st := m.Status(); st.LastError != "" {
		t.Fatalf("status = %+v, want the failure cleared", st)
	}
}

func TestManagerStartsStopsAndRestartsOneCollector(t *testing.T) {
	tick := make(chan time.Time)
	polled := make(chan struct{}, 16)
	mk := func() *Collector {
		return New(Options{
			Source: &fakeSource{kind: KindCounters, runs: repeat(32, func() ([]Sample, error) {
				select {
				case polled <- struct{}{}:
				default:
				}
				return nil, nil
			})},
			Recorder: &fakeRecorder{},
			Resolve:  func(string) (string, bool) { return "", false },
			After:    func(time.Duration) <-chan time.Time { return tick },
		})
	}
	on := true
	m, _ := newManagerHarness(t, func() (*Collector, bool, error) {
		if !on {
			return nil, false, nil
		}
		return mk(), true, nil
	})

	m.Reload()
	waitPoll(t, polled)
	if st := m.Status(); st.Source != "fake" || st.Estimated {
		t.Fatalf("status = %+v", st)
	}
	// Reloading swaps in a fresh collector rather than running two.
	m.Reload()
	waitPoll(t, polled)

	on = false
	m.Reload()
	if st := m.Status(); st.Source != "" {
		t.Fatalf("status after turning it off = %+v", st)
	}
	// Stopping twice is harmless.
	m.Stop()
	m.Stop()
}

func repeat(n int, f func() ([]Sample, error)) []func() ([]Sample, error) {
	out := make([]func() ([]Sample, error), n)
	for i := range out {
		out[i] = f
	}
	return out
}

func waitPoll(t *testing.T, ch chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("the collector never polled")
	}
}
