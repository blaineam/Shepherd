// SPDX-License-Identifier: AGPL-3.0-or-later

package nethealth

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func sampleAt(t time.Time, latency, jitter, loss float64, reach, total int) Sample {
	return Sample{Time: t, LatencyMS: latency, JitterMS: jitter, LossPct: loss, ReachableTargets: reach, TotalTargets: total}
}

func TestStoreQueryRaw(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := base
	st := NewStore(StoreOptions{Now: func() time.Time { return now }})
	st.Add(sampleAt(base, 10, 1, 0, 2, 2))
	st.Add(sampleAt(base.Add(time.Minute), 20, 2, 0, 2, 2))

	pts := st.Query(base.Add(-time.Hour), base.Add(time.Hour), BucketRaw)
	if len(pts) != 2 {
		t.Fatalf("got %d points, want 2", len(pts))
	}
	if pts[0].AvgLatencyMS != 10 || pts[1].AvgLatencyMS != 20 {
		t.Errorf("got %+v", pts)
	}
}

func TestStoreQueryRangeExcludesOutOfWindow(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	st := NewStore(StoreOptions{Now: func() time.Time { return base }})
	st.Add(sampleAt(base, 10, 0, 0, 1, 1))
	st.Add(sampleAt(base.Add(time.Hour), 20, 0, 0, 1, 1))

	pts := st.Query(base, base.Add(30*time.Minute), BucketRaw)
	if len(pts) != 1 || pts[0].AvgLatencyMS != 10 {
		t.Fatalf("got %+v", pts)
	}
}

func TestStoreRollsRawIntoHourlyAfterRetention(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := base
	st := NewStore(StoreOptions{Retention: Retention{Raw: time.Hour, Hour: 48 * time.Hour, Day: 0}, Now: func() time.Time { return now }})

	st.Add(sampleAt(base, 10, 0, 0, 1, 1))
	st.Add(sampleAt(base.Add(10*time.Minute), 20, 0, 0, 1, 1))
	if len(st.Raw) != 2 || len(st.Hourly) != 0 {
		t.Fatalf("expected both raw samples still raw, got raw=%d hourly=%d", len(st.Raw), len(st.Hourly))
	}

	// Advance the clock past the raw retention window and add one more
	// sample: the two old ones should fold into a single hourly bucket.
	now = base.Add(2 * time.Hour)
	st.Add(sampleAt(now, 30, 0, 0, 1, 1))

	if len(st.Raw) != 1 {
		t.Fatalf("expected 1 raw sample left, got %d: %+v", len(st.Raw), st.Raw)
	}
	if len(st.Hourly) != 1 {
		t.Fatalf("expected 1 hourly bucket, got %d: %+v", len(st.Hourly), st.Hourly)
	}
	h := st.Hourly[0]
	if h.Count != 2 {
		t.Errorf("hourly count = %d, want 2", h.Count)
	}
	if h.AvgLatencyMS != 15 {
		t.Errorf("hourly avg latency = %v, want 15", h.AvgLatencyMS)
	}
	if h.MinLatencyMS != 10 || h.MaxLatencyMS != 20 {
		t.Errorf("hourly min/max = %v/%v, want 10/20", h.MinLatencyMS, h.MaxLatencyMS)
	}
	if !h.Bucket.Equal(hourStart(base)) {
		t.Errorf("hourly bucket = %v, want %v", h.Bucket, hourStart(base))
	}
}

func TestStoreRollsHourlyIntoDailyAfterRetention(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := base.Add(3 * time.Hour)
	st := NewStore(StoreOptions{Retention: Retention{Raw: time.Minute, Hour: time.Hour, Day: 0}, Now: func() time.Time { return now }})
	// Seed an hourly bucket directly (isolating this from the raw->hourly
	// fold, which TestStoreRollsRawIntoHourlyAfterRetention already covers)
	// and drive the hourly->daily fold with one explicit rollup() call.
	st.Hourly = []aggregate{{Bucket: hourStart(base), Count: 2, AvgLatencyMS: 15, MinLatencyMS: 10, MaxLatencyMS: 20}}
	st.rollup()

	if len(st.Hourly) != 0 {
		t.Fatalf("expected the old hourly bucket rolled away, got %+v", st.Hourly)
	}
	if len(st.Daily) != 1 {
		t.Fatalf("expected 1 daily bucket, got %d: %+v", len(st.Daily), st.Daily)
	}
	d := st.Daily[0]
	if !d.Bucket.Equal(dayStart(base)) {
		t.Errorf("daily bucket = %v, want %v", d.Bucket, dayStart(base))
	}
	if d.Count != 2 || d.AvgLatencyMS != 15 || d.MinLatencyMS != 10 || d.MaxLatencyMS != 20 {
		t.Errorf("got %+v", d)
	}
}

func TestStoreDailyRetentionDropsOldBuckets(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	st := NewStore(StoreOptions{Now: func() time.Time { return base }})
	st.Daily = []aggregate{
		{Bucket: dayStart(base.AddDate(0, 0, -400)), Count: 1},
		{Bucket: dayStart(base.AddDate(0, 0, -1)), Count: 1},
	}
	st.opt.Retention.Day = 30 * 24 * time.Hour
	st.rollup()
	if len(st.Daily) != 1 {
		t.Fatalf("expected the 400-day-old bucket dropped, got %+v", st.Daily)
	}
}

func TestStoreMaxBytesDropsOldestDaily(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	st := NewStore(StoreOptions{Now: func() time.Time { return base }})
	for i := 49; i >= 0; i-- { // oldest first, matching the sorted order foldIntoDaily maintains
		st.Daily = append(st.Daily, aggregate{Bucket: dayStart(base.AddDate(0, 0, -i)), Count: 1, AvgLatencyMS: float64(i)})
	}
	st.opt.Retention.MaxBytes = 500 // tiny cap: forces most entries out
	st.enforceMaxBytes()
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > 500 {
		t.Errorf("marshaled size %d exceeds cap 500", len(b))
	}
	// The newest entries (smallest i, i.e. smallest AvgLatencyMS, since the
	// seed above set AvgLatencyMS = i = days-ago) should survive; the
	// oldest should have been dropped first.
	if len(st.Daily) == 0 || len(st.Daily) >= 50 {
		t.Fatalf("expected enforceMaxBytes to drop some but not all entries, got %d", len(st.Daily))
	}
	for _, d := range st.Daily {
		if d.AvgLatencyMS >= float64(len(st.Daily)) {
			t.Errorf("unexpected old bucket survived: %+v (only the newest %d should remain)", d, len(st.Daily))
		}
	}
}

func TestStoreQueryHourAndDay(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	st := NewStore(StoreOptions{Now: func() time.Time { return base }})
	st.Hourly = []aggregate{{Bucket: hourStart(base), Count: 3, AvgLatencyMS: 12, MinLatencyMS: 5, MaxLatencyMS: 20, ReachableTargets: 2, TotalTargets: 2}}
	st.Daily = []aggregate{{Bucket: dayStart(base), Count: 7, AvgLatencyMS: 15, ReachableTargets: 1, TotalTargets: 2}}

	hourPts := st.Query(base.Add(-time.Hour), base.Add(time.Hour), BucketHour)
	if len(hourPts) != 1 || hourPts[0].Count != 3 || hourPts[0].AvgLatencyMS != 12 || hourPts[0].MinLatencyMS != 5 || hourPts[0].MaxLatencyMS != 20 {
		t.Fatalf("hour query = %+v", hourPts)
	}
	if hourPts[0].ReachableTargets != 2 || hourPts[0].TotalTargets != 2 {
		t.Errorf("hour query reachable/total = %+v", hourPts[0])
	}

	dayPts := st.Query(base.Add(-24*time.Hour), base.Add(24*time.Hour), BucketDay)
	if len(dayPts) != 1 || dayPts[0].Count != 7 || dayPts[0].AvgLatencyMS != 15 {
		t.Fatalf("day query = %+v", dayPts)
	}
	// ReachableTargets=1, TotalTargets=2 round to the nearest int cleanly here.
	if dayPts[0].ReachableTargets != 1 || dayPts[0].TotalTargets != 2 {
		t.Errorf("day query reachable/total = %+v", dayPts[0])
	}
}

func TestAddBufferbloatPrunesByDailyRetention(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	st := NewStore(StoreOptions{Retention: Retention{Day: 10 * 24 * time.Hour}, Now: func() time.Time { return base }})
	st.AddBufferbloat(Bufferbloat{Time: base.AddDate(0, 0, -20), Grade: "A"})
	st.AddBufferbloat(Bufferbloat{Time: base.AddDate(0, 0, -1), Grade: "B"})
	if len(st.Bufferbloat) != 1 || st.Bufferbloat[0].Grade != "B" {
		t.Fatalf("got %+v, want only the recent entry kept", st.Bufferbloat)
	}
}

func TestFoldIntoDailyMergesASecondHourlyBucketIntoTheSameDay(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := base.Add(5 * time.Hour)
	st := NewStore(StoreOptions{Retention: Retention{Raw: time.Minute, Hour: time.Hour, Day: 0}, Now: func() time.Time { return now }})
	st.Hourly = []aggregate{
		{Bucket: hourStart(base), Count: 2, AvgLatencyMS: 10, MinLatencyMS: 8, MaxLatencyMS: 12},
		{Bucket: hourStart(base.Add(time.Hour)), Count: 1, AvgLatencyMS: 40, MinLatencyMS: 40, MaxLatencyMS: 40},
	}
	st.rollup()
	if len(st.Daily) != 1 {
		t.Fatalf("expected both hourly buckets to merge into one daily bucket, got %+v", st.Daily)
	}
	d := st.Daily[0]
	if d.Count != 3 {
		t.Fatalf("day count = %d, want 3", d.Count)
	}
	// weighted mean: (10*2 + 40*1) / 3 = 20
	if d.AvgLatencyMS != 20 {
		t.Errorf("day avg latency = %v, want 20", d.AvgLatencyMS)
	}
	if d.MinLatencyMS != 8 || d.MaxLatencyMS != 40 {
		t.Errorf("day min/max = %v/%v, want 8/40", d.MinLatencyMS, d.MaxLatencyMS)
	}
}

func TestStoreLatest(t *testing.T) {
	st := NewStore(StoreOptions{})
	if _, ok := st.Latest(); ok {
		t.Fatal("expected no latest sample on an empty store")
	}
	base := time.Now()
	st.Add(sampleAt(base, 1, 0, 0, 1, 1))
	st.Add(sampleAt(base.Add(time.Second), 2, 0, 0, 1, 1))
	latest, ok := st.Latest()
	if !ok || latest.LatencyMS != 2 {
		t.Fatalf("got %+v, %v", latest, ok)
	}
}

func TestAggregateMergeIsOrderIndependentWeighting(t *testing.T) {
	bucket := time.Now()
	var a aggregate
	a.mergeSample(Sample{LatencyMS: 10}, bucket)
	a.mergeSample(Sample{LatencyMS: 30}, bucket)
	if a.AvgLatencyMS != 20 || a.Count != 2 {
		t.Fatalf("got %+v", a)
	}

	// Merging an aggregate that itself represents 3 samples should weight
	// 3x as heavily as a single mergeSample call.
	var b aggregate
	b.mergeAggregate(aggregate{Count: 3, AvgLatencyMS: 60, MinLatencyMS: 50, MaxLatencyMS: 70}, bucket)
	b.mergeSample(Sample{LatencyMS: 0}, bucket)
	// (60*3 + 0*1) / 4 = 45
	if b.AvgLatencyMS != 45 {
		t.Errorf("weighted avg = %v, want 45", b.AvgLatencyMS)
	}
	if b.Count != 4 {
		t.Errorf("count = %d, want 4", b.Count)
	}
}

func TestProberSaveLoadRoundTrips(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/nethealth.json"

	f := newFakeDial()
	f.delayMS["a"] = 10
	p := newTestProber(f)
	p.Run(context.Background(), func() []string { return []string{"a"} }, 0)
	if err := p.Save(path); err != nil {
		t.Fatal(err)
	}

	p2 := New(Options{})
	if err := p2.Load(path); err != nil {
		t.Fatal(err)
	}
	got, ok := p2.Latest()
	if !ok {
		t.Fatal("expected a loaded sample")
	}
	want, _ := p.Latest()
	if !got.Time.Equal(want.Time) || got.LatencyMS != want.LatencyMS {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestProberLoadMissingFileReturnsNotExist(t *testing.T) {
	p := New(Options{})
	err := p.Load("/nonexistent/path/nethealth.json")
	if err == nil {
		t.Fatal("expected an error")
	}
}
