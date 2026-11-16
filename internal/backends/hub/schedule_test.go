// SPDX-License-Identifier: AGPL-3.0-or-later

package hub

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"shepherd/internal/backends"
)

// at builds a time in New York: 2026-11-16 is a Monday.
func at(t *testing.T, day, clock string) time.Time {
	t.Helper()
	loc, _ := time.LoadLocation("America/New_York")
	v, err := time.ParseInLocation("2006-01-02 15:04", day+" "+clock, loc)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestAWindowWithinOneDay(t *testing.T) {
	s := Schedule{RuleID: "r", Days: []int{1, 2, 3, 4, 5}, Start: "15:00", End: "18:00", TZ: "America/New_York"}
	for when, want := range map[string]bool{
		"2026-11-16 14:59": false, "2026-11-16 15:00": true, "2026-11-16 17:59": true, "2026-11-16 18:00": false,
		"2026-11-21 16:00": false, // Saturday
	} {
		day, clock, _ := strings.Cut(when, " ")
		if got := s.Active(at(t, day, clock)); got != want {
			t.Errorf("%s: active = %v, want %v", when, got, want)
		}
	}
}

func TestAWindowPastMidnightBelongsToTheDayItStartedOn(t *testing.T) {
	// School nights: Sunday to Thursday, 21:00 to 07:00.
	s := Schedule{RuleID: "r", Days: []int{0, 1, 2, 3, 4}, Start: "21:00", End: "07:00", TZ: "America/New_York"}
	for when, want := range map[string]bool{
		"2026-11-16 20:59": false, // Monday before
		"2026-11-16 21:00": true,  // Monday night
		"2026-11-17 06:59": true,  // Tuesday morning, still Monday's window
		"2026-11-17 07:00": false,
		"2026-11-20 22:00": false, // Friday night: not a school night
		"2026-11-21 06:00": false, // Saturday morning follows Friday night, and Friday is not listed
		"2026-11-22 06:00": false, // Sunday morning follows Saturday night, not listed
		"2026-11-22 23:00": true,  // Sunday night
	} {
		day, clock, _ := strings.Cut(when, " ")
		if got := s.Active(at(t, day, clock)); got != want {
			t.Errorf("%s: active = %v, want %v", when, got, want)
		}
	}
}

func TestAScheduleUsesItsOwnTimeZone(t *testing.T) {
	s := Schedule{RuleID: "r", Days: []int{0, 1, 2, 3, 4, 5, 6}, Start: "09:00", End: "10:00", TZ: "Asia/Tokyo"}
	// 09:30 in Tokyo is 00:30 in UTC.
	if !s.Active(time.Date(2026, 11, 16, 0, 30, 0, 0, time.UTC)) {
		t.Fatal("the window is in Tokyo time")
	}
	if s.Active(time.Date(2026, 11, 16, 9, 30, 0, 0, time.UTC)) {
		t.Fatal("09:30 UTC is 18:30 in Tokyo")
	}
	if (Schedule{TZ: "Nowhere/Land", Start: "09:00", End: "10:00", Days: []int{1}}).Active(time.Now()) {
		t.Fatal("an unknown zone is never active")
	}
}

func TestAScheduleThatCouldNotBeAppliedIsRefused(t *testing.T) {
	ok := Schedule{RuleID: "r", Days: []int{1}, Start: "09:00", End: "10:00", TZ: "UTC"}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, s := range map[string]Schedule{
		"no rule":  {Days: []int{1}, Start: "09:00", End: "10:00", TZ: "UTC"},
		"no days":  {RuleID: "r", Start: "09:00", End: "10:00", TZ: "UTC"},
		"bad day":  {RuleID: "r", Days: []int{7}, Start: "09:00", End: "10:00", TZ: "UTC"},
		"repeat":   {RuleID: "r", Days: []int{1, 1}, Start: "09:00", End: "10:00", TZ: "UTC"},
		"bad time": {RuleID: "r", Days: []int{1}, Start: "9am", End: "10:00", TZ: "UTC"},
		"same":     {RuleID: "r", Days: []int{1}, Start: "09:00", End: "09:00", TZ: "UTC"},
		"no zone":  {RuleID: "r", Days: []int{1}, Start: "09:00", End: "10:00"},
		"bad zone": {RuleID: "r", Days: []int{1}, Start: "09:00", End: "10:00", TZ: "Mars/Base"},
	} {
		if err := s.Validate(); !errors.Is(err, backends.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func scheduledHub(t *testing.T, f *fake, now *time.Time, path string) *Hub {
	t.Helper()
	h := New(Options{Backend: f, SchedulePath: path, Now: func() time.Time { return *now }})
	h.Refresh(ctx)
	return h
}

func TestAScheduleKeepsItsRuleEnforcingOnlyInsideTheWindow(t *testing.T) {
	now := at(t, "2026-11-16", "20:00") // Monday evening, before the window
	f := &fake{rules: []backends.Rule{{ID: "r1", Action: "block"}}}
	h := scheduledHub(t, f, &now, "")
	s, err := h.AddSchedule(ctx, Schedule{RuleID: "r1", Days: []int{1}, Start: "21:00", End: "23:00", TZ: "America/New_York"})
	if err != nil || s.ID == "" {
		t.Fatalf("%+v, %v", s, err)
	}
	// Outside the window the rule is paused at once.
	if !h.Snapshot().Rules[0].Paused || strings.Join(f.calls, ",") != "pause r1" {
		t.Fatalf("calls = %v", f.calls)
	}
	// Nothing happens while the rule already agrees.
	h.ApplySchedules(ctx)
	if len(f.calls) != 1 {
		t.Fatalf("calls = %v", f.calls)
	}
	// The window opens: the rule is resumed.
	now = at(t, "2026-11-16", "21:00")
	h.ApplySchedules(ctx)
	if h.Snapshot().Rules[0].Paused || len(f.calls) != 2 || f.calls[1] != "pause r1" {
		// the fake records a resume as "pause r1" too; the state is what matters
		t.Fatalf("calls = %v paused = %v", f.calls, h.Snapshot().Rules[0].Paused)
	}
	// And closes again.
	now = at(t, "2026-11-16", "23:00")
	h.ApplySchedules(ctx)
	if !h.Snapshot().Rules[0].Paused {
		t.Fatal("the rule should be paused after the window")
	}
	audit := h.Snapshot().Audit
	if audit[0].Action != "schedule pauses rule" || audit[1].Action != "schedule resumes rule" {
		t.Fatalf("audit = %+v", audit)
	}
}

func TestAFailedScheduleChangeIsNotRepeatedEveryTick(t *testing.T) {
	now := at(t, "2026-11-16", "20:00")
	f := &fake{rules: []backends.Rule{{ID: "r1"}}}
	h := scheduledHub(t, f, &now, "")
	if _, err := h.AddSchedule(ctx, Schedule{RuleID: "r1", Days: []int{1}, Start: "21:00", End: "23:00", TZ: "America/New_York"}); err != nil {
		t.Fatal(err)
	}
	f.writeErr = errors.New("box offline")
	f.rules[0].Paused = false
	h.Refresh(ctx) // rules reread: unpaused again, schedule wants it paused
	n := len(f.calls)
	for i := 0; i < 5; i++ {
		now = now.Add(scheduleEvery)
		h.ApplySchedules(ctx)
	}
	if len(f.calls) > n+1 {
		t.Fatalf("a failing change was retried every tick: %v", f.calls)
	}
	// Past the back-off it tries again, and once it works the back-off clears.
	f.writeErr = nil
	now = now.Add(retryAfter)
	h.ApplySchedules(ctx)
	if !h.Snapshot().Rules[0].Paused {
		t.Fatal("it never recovered")
	}
}

func TestSchedulesPersistAndSkipWhatIsNoLongerValid(t *testing.T) {
	path := t.TempDir() + "/schedules.json"
	now := at(t, "2026-11-16", "12:00")
	f := &fake{rules: []backends.Rule{{ID: "r1"}}}
	h := scheduledHub(t, f, &now, path)
	if _, err := h.AddSchedule(ctx, Schedule{RuleID: "r1", Days: []int{3, 1}, Start: "21:00", End: "07:00", TZ: "America/New_York"}); err != nil {
		t.Fatal(err)
	}
	h2 := New(Options{Backend: f, SchedulePath: path, Now: func() time.Time { return now }})
	got := h2.Schedules()
	if len(got) != 1 || got[0].RuleID != "r1" || got[0].Days[0] != 1 {
		t.Fatalf("after restart = %+v", got)
	}
	if err := os.WriteFile(path, []byte(`[{"id":"x","rule_id":"r","days":[9],"start":"09:00","end":"10:00","tz":"UTC"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if n := len(New(Options{Backend: f, SchedulePath: path}).Schedules()); n != 0 {
		t.Fatalf("an invalid stored schedule was kept (%d)", n)
	}
	if err := os.WriteFile(path, []byte("{nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if n := len(New(Options{Backend: f, SchedulePath: path}).Schedules()); n != 0 {
		t.Fatal("garbage was kept")
	}
}

func TestSchedulesAreRefusedWhereTheyCouldNotWork(t *testing.T) {
	now := at(t, "2026-11-16", "12:00")
	good := Schedule{RuleID: "r1", Days: []int{1}, Start: "21:00", End: "23:00", TZ: "UTC"}

	ro := &fake{ro: true, rules: []backends.Rule{{ID: "r1"}}}
	if _, err := scheduledHub(t, ro, &now, "").AddSchedule(ctx, good); !errors.Is(err, backends.ErrReadOnly) {
		t.Fatalf("read-only: %v", err)
	}

	f := &fake{rules: []backends.Rule{{ID: "r1"}}}
	h := scheduledHub(t, f, &now, "")
	missing := good
	missing.RuleID = "nope"
	if _, err := h.AddSchedule(ctx, missing); !errors.Is(err, backends.ErrInvalid) {
		t.Fatalf("unknown rule: %v", err)
	}
	if _, err := h.AddSchedule(ctx, Schedule{RuleID: "r1"}); !errors.Is(err, backends.ErrInvalid) {
		t.Fatalf("invalid: %v", err)
	}
	if _, err := h.AddSchedule(ctx, good); err != nil {
		t.Fatal(err)
	}
	if _, err := h.AddSchedule(ctx, good); !errors.Is(err, backends.ErrInvalid) {
		t.Fatalf("a second schedule on the same rule: %v", err)
	}
	if _, err := New(Options{Backend: readerOnly{}}).AddSchedule(ctx, good); !errors.Is(err, backends.ErrInvalid) {
		t.Fatalf("a backend with no rules: %v", err)
	}
}

func TestAReadOnlyConnectionNeverAppliesSchedules(t *testing.T) {
	now := at(t, "2026-11-16", "20:00")
	f := &fake{rules: []backends.Rule{{ID: "r1"}}}
	h := scheduledHub(t, f, &now, "")
	if _, err := h.AddSchedule(ctx, Schedule{RuleID: "r1", Days: []int{1}, Start: "21:00", End: "23:00", TZ: "America/New_York"}); err != nil {
		t.Fatal(err)
	}
	f.ro = true
	f.calls = nil
	f.rules[0].Paused = false
	h.Refresh(ctx)
	h.ApplySchedules(ctx)
	if len(f.calls) != 0 {
		t.Fatalf("a read-only connection wrote: %v", f.calls)
	}
}

func TestRemovingAScheduleLeavesTheRuleAsItIs(t *testing.T) {
	now := at(t, "2026-11-16", "20:00")
	f := &fake{rules: []backends.Rule{{ID: "r1"}}}
	h := scheduledHub(t, f, &now, t.TempDir()+"/s.json")
	s, _ := h.AddSchedule(ctx, Schedule{RuleID: "r1", Days: []int{1}, Start: "21:00", End: "23:00", TZ: "America/New_York"})
	if err := h.DeleteSchedule(s.ID); err != nil || len(h.Schedules()) != 0 {
		t.Fatalf("%v", err)
	}
	n := len(f.calls)
	now = at(t, "2026-11-16", "21:30")
	h.ApplySchedules(ctx)
	if len(f.calls) != n {
		t.Fatal("a removed schedule still acted")
	}
	if err := h.DeleteSchedule("nope"); !errors.Is(err, backends.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestQueryFlowsPassesTheFilterThrough(t *testing.T) {
	now := time.Unix(1000, 0)
	f := &fake{flows: []backends.Flow{flow(990, "a.example", false, 1, 1)}}
	h := newHub(t, f, &sinks{}, &now)
	page, err := h.QueryFlows(ctx, backends.FlowQuery{DeviceMAC: "02005e000001", Limit: 5})
	if err != nil || len(page.Flows) != 1 {
		t.Fatalf("%+v, %v", page, err)
	}
	if got := f.queries[len(f.queries)-1]; got.DeviceMAC != "02005e000001" || got.Limit != 5 {
		t.Fatalf("query = %+v", got)
	}
	if _, err := New(Options{Backend: failing{}}).QueryFlows(ctx, backends.FlowQuery{}); !errors.Is(err, backends.ErrInvalid) {
		t.Fatalf("err = %v", err)
	}
}
