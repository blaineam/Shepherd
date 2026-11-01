// SPDX-License-Identifier: AGPL-3.0-or-later

package traffic

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

func rows(id string, up, down uint64) map[string]Delta {
	return map[string]Delta{id: {Up: up, Down: down}}
}

func TestRecordAccumulatesIntoMinuteBuckets(t *testing.T) {
	s := NewStore(Options{})
	s.Record(t0, rows("a", 100, 1000))
	s.Record(t0.Add(20*time.Second), rows("a", 50, 500))
	s.Record(t0.Add(70*time.Second), rows("a", 1, 2))
	s.Record(t0.Add(70*time.Second), map[string]Delta{"b": {Up: 7}, "": {Up: 9}, "idle": {}})

	pts := s.Series([]string{"a"}, t0.Add(-time.Hour), t0.Add(time.Hour), BucketMinute)
	if len(pts) != 2 || pts[0].Up != 150 || pts[0].Down != 1500 || pts[1].Up != 1 || pts[1].Down != 2 {
		t.Fatalf("minute series = %+v", pts)
	}
	if !pts[0].Time.Equal(t0) || !pts[1].Time.Equal(t0.Add(time.Minute)) {
		t.Fatalf("bucket starts = %v %v", pts[0].Time, pts[1].Time)
	}
	// The empty ID and the zero delta leave no trace.
	if got := s.Devices(); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("Devices = %v", got)
	}
	// nil ids is the whole network.
	all := s.Series(nil, t0, t0.Add(time.Hour), BucketMinute)
	if len(all) != 2 || all[1].Up != 8 {
		t.Fatalf("network series = %+v", all)
	}
	// An unknown device is simply empty, never nil.
	if got := s.Series([]string{"nope"}, t0, t0, BucketMinute); got == nil || len(got) != 0 {
		t.Fatalf("unknown device series = %#v", got)
	}
}

func TestSeriesFoldsFinerDataUpAndRespectsTheRange(t *testing.T) {
	s := NewStore(Options{})
	base := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 180; i++ { // three hours of minutes
		s.Record(base.Add(time.Duration(i)*time.Minute), rows("a", 1, 10))
	}
	hours := s.Series([]string{"a"}, base, base.Add(3*time.Hour), BucketHour)
	if len(hours) != 3 {
		t.Fatalf("hourly points = %d, want 3: %+v", len(hours), hours)
	}
	for _, h := range hours {
		if h.Up != 60 || h.Down != 600 {
			t.Fatalf("hour %v = %+v, want 60/600", h.Time, h)
		}
	}
	days := s.Series(nil, base, base.Add(3*time.Hour), BucketDay)
	if len(days) != 1 || days[0].Up != 180 || days[0].Down != 1800 || !days[0].Time.Equal(base) {
		t.Fatalf("daily = %+v", days)
	}
	// The range is inclusive on both ends and excludes the rest.
	part := s.Series(nil, base.Add(time.Hour), base.Add(time.Hour+9*time.Minute), BucketMinute)
	if len(part) != 10 {
		t.Fatalf("ranged minutes = %d, want 10", len(part))
	}
}

func TestRollupMovesAgedMinutesToHoursAndHoursToDays(t *testing.T) {
	ret := Retention{Minute: 2 * time.Hour, Hour: 48 * time.Hour, Day: 0}
	s := NewStore(Options{Retention: ret})
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	// Record across four days, one point every 10 minutes, with a rising
	// clock so rollups happen as they would live.
	var want Delta
	for i := 0; i < 4*24*6; i++ {
		now := base.Add(time.Duration(i) * 10 * time.Minute)
		s.Record(now, rows("a", 10, 100))
		want.Up += 10
		want.Down += 100
	}
	s.mu.Lock()
	ser := s.devices["a"]
	nMin, nHour, nDay := len(ser.Minute), len(ser.Hour), len(ser.Day)
	s.mu.Unlock()
	// Only the last two hours stay at minute resolution, the last 48 hours
	// at hourly, the rest as days.
	if nMin == 0 || nMin > 13 {
		t.Fatalf("minute points = %d, want about 12", nMin)
	}
	if nHour == 0 || nHour > 49 {
		t.Fatalf("hour points = %d, want about 48", nHour)
	}
	if nDay < 1 || nDay > 3 {
		t.Fatalf("day points = %d, want 1 to 3", nDay)
	}
	// Nothing was lost in the folding: the daily series over everything
	// is the whole recorded total.
	days := s.Series(nil, base, base.Add(5*24*time.Hour), BucketDay)
	var got Delta
	for _, p := range days {
		got.Up += p.Up
		got.Down += p.Down
	}
	if got != want {
		t.Fatalf("daily total %+v, recorded %+v", got, want)
	}
	// Totals agrees, at whatever resolution each piece ended up.
	tot := s.Totals(base, base.Add(5*24*time.Hour))
	if tot["a"] != want {
		t.Fatalf("Totals = %+v, want %+v", tot["a"], want)
	}
	// And a minute-level query cannot reach into the rolled-up past.
	early := s.Series(nil, base, base.Add(time.Hour), BucketMinute)
	if len(early) != 0 {
		t.Fatalf("minute query into rolled-up range returned %d points", len(early))
	}
}

func TestDailyRetentionAndEmptyDevicesAreDropped(t *testing.T) {
	s := NewStore(Options{Retention: Retention{Minute: time.Minute, Hour: time.Minute, Day: 24 * time.Hour}})
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	s.Record(base, rows("old", 1, 1))
	s.Record(base.Add(3*time.Minute), rows("new", 1, 1))
	// Nothing dropped yet: "old" is a day point within a day.
	if len(s.Devices()) != 2 {
		t.Fatalf("devices = %v", s.Devices())
	}
	s.Record(base.Add(3*24*time.Hour), rows("new", 1, 1))
	if got := s.Devices(); len(got) != 1 || got[0] != "new" {
		t.Fatalf("after daily retention: %v, want [new]", got)
	}
}

func TestMaxBytesDropsTheOldestDaysFirst(t *testing.T) {
	// A tiny cap: room for a handful of points.
	s := NewStore(Options{Retention: Retention{Minute: time.Minute, Hour: time.Minute, Day: 0, MaxBytes: 400}})
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 30; i++ {
		s.Record(base.Add(time.Duration(i)*24*time.Hour), rows("a", 1, 1))
		s.Record(base.Add(time.Duration(i)*24*time.Hour+time.Second), rows("b", 1, 1))
	}
	s.mu.Lock()
	b, _ := json.Marshal(s.devices)
	s.mu.Unlock()
	if len(b) > 400 {
		t.Fatalf("store is %d bytes, cap 400", len(b))
	}
	days := s.Series(nil, base, base.Add(60*24*time.Hour), BucketDay)
	if len(days) == 0 {
		t.Fatal("everything was dropped")
	}
	// What survives is the newest.
	last := days[len(days)-1].Time
	if !last.Equal(base.Add(28*24*time.Hour)) && !last.Equal(base.Add(29*24*time.Hour)) {
		t.Fatalf("newest surviving day %v, want the end of the series", last)
	}
	for i := 1; i < len(days); i++ {
		if !days[i].Time.After(days[i-1].Time) {
			t.Fatalf("days out of order: %+v", days)
		}
	}
	// A cap of 0 means no cap.
	u := NewStore(Options{Retention: Retention{Minute: time.Minute, Hour: time.Minute, MaxBytes: 0}})
	for i := 0; i < 400; i++ {
		u.Record(base.Add(time.Duration(i)*24*time.Hour), rows("a", 1, 1))
	}
	if n := len(u.Series(nil, base, base.Add(500*24*time.Hour), BucketDay)); n != 400 {
		t.Fatalf("uncapped store kept %d days, want 400", n)
	}
}

func TestOutOfOrderRecordsLandInTheRightBucket(t *testing.T) {
	s := NewStore(Options{})
	s.Record(t0.Add(2*time.Minute), rows("a", 1, 0))
	s.Record(t0, rows("a", 2, 0))
	s.Record(t0.Add(time.Minute), rows("a", 3, 0))
	s.Record(t0, rows("a", 4, 0))
	pts := s.Series(nil, t0, t0.Add(time.Hour), BucketMinute)
	if len(pts) != 3 || pts[0].Up != 6 || pts[1].Up != 3 || pts[2].Up != 1 {
		t.Fatalf("series = %+v", pts)
	}
}

func TestSaveAndLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "traffic.json")
	s := NewStore(Options{})
	s.Record(t0, rows("a", 5, 50))
	s.Record(t0.Add(time.Minute), rows("b", 6, 60))
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, want 0600", info.Mode().Perm())
	}
	l := NewStore(Options{})
	if err := l.Load(path); err != nil {
		t.Fatal(err)
	}
	if got := l.Series(nil, t0, t0.Add(time.Hour), BucketMinute); len(got) != 2 || got[0].Up != 5 || got[1].Down != 60 {
		t.Fatalf("loaded series = %+v", got)
	}
	if err := l.Load(filepath.Join(dir, "missing.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file: %v", err)
	}
	if err := os.WriteFile(path, []byte("{nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := l.Load(path); err == nil {
		t.Fatal("corrupt file loaded without error")
	}
	// A saved file with an empty or unsorted device is tidied on load.
	raw := `{"empty":{},"null":null,"x":{"minute":[{"time":"2026-11-01T12:01:00Z","up":1,"down":0},{"time":"2026-11-01T12:00:00Z","up":2,"down":0}]}}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := l.Load(path); err != nil {
		t.Fatal(err)
	}
	if got := l.Devices(); len(got) != 1 || got[0] != "x" {
		t.Fatalf("Devices after load = %v", got)
	}
	if got := l.Series(nil, t0, t0.Add(time.Hour), BucketMinute); got[0].Up != 2 || got[1].Up != 1 {
		t.Fatalf("unsorted points were not sorted: %+v", got)
	}
}

func TestRecordSavesOnItsOwnScheduleAndReportsErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "traffic.json")
	var saveErrs []error
	s := NewStore(Options{Path: path, SaveEvery: time.Minute, OnSaveError: func(err error) { saveErrs = append(saveErrs, err) }})
	s.Record(t0, rows("a", 1, 1)) // first record: lastSave is zero, so this saves
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("first record did not save: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	s.Record(t0.Add(30*time.Second), rows("a", 1, 1))
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("saved again inside SaveEvery")
	}
	s.Record(t0.Add(61*time.Second), rows("a", 1, 1))
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("did not save after SaveEvery: %v", err)
	}
	// Nothing new to say, nothing written.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	s.Record(t0.Add(3*time.Minute), map[string]Delta{})
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("saved with nothing dirty")
	}
	// A save failure is reported, not fatal.
	bad := NewStore(Options{Path: filepath.Join(dir, "no", "such", "dir", "t.json"), OnSaveError: func(err error) { saveErrs = append(saveErrs, err) }})
	bad.Record(t0, rows("a", 1, 1))
	if len(saveErrs) != 1 {
		t.Fatalf("save errors = %v, want one", saveErrs)
	}
	// Without a callback the error is swallowed.
	quiet := NewStore(Options{Path: filepath.Join(dir, "no", "such", "dir", "t.json")})
	quiet.Record(t0, rows("a", 1, 1))
}

func TestBucketsAndDefaults(t *testing.T) {
	for _, s := range []string{"minute", "hour", "day"} {
		if b, ok := ParseBucket(s); !ok || string(b) != s {
			t.Fatalf("ParseBucket(%q) = %q, %v", s, b, ok)
		}
	}
	if _, ok := ParseBucket("raw"); ok {
		t.Fatal("raw is not a traffic bucket")
	}
	if DefaultBucket(t0, t0.Add(6*time.Hour)) != BucketMinute || DefaultBucket(t0, t0.Add(24*time.Hour)) != BucketMinute {
		t.Fatal("a day or less should be minutes")
	}
	if DefaultBucket(t0, t0.Add(7*24*time.Hour)) != BucketHour {
		t.Fatal("a week should be hours")
	}
	if DefaultBucket(t0, t0.Add(90*24*time.Hour)) != BucketDay {
		t.Fatal("90 days should be days")
	}
	def := NewStore(Options{})
	if def.Retention() != DefaultRetention() || def.Retention().Minute != 48*time.Hour {
		t.Fatalf("default retention = %+v", def.Retention())
	}
	if bucketStart(t0.Add(90*time.Second), "weird") != minuteStart(t0.Add(90*time.Second)) {
		t.Fatal("an unknown bucket should fall back to minutes")
	}
}
