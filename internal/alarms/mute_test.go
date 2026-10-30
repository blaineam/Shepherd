// SPDX-License-Identifier: AGPL-3.0-or-later

package alarms

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func forever() MuteSpec { return MuteSpec{Preset: MuteForever} }

func TestRuleMatching(t *testing.T) {
	a := &Alarm{Type: "t1", DeviceID: "d1", GroupIDs: []string{"g1", "g2"}, Domain: "ads.tracker.example.com", Key: "t1|d1|ads"}
	cases := []struct {
		name string
		m    RuleMatch
		want bool
	}{
		{"empty matches nothing", RuleMatch{}, false},
		{"device", RuleMatch{DeviceIDs: []string{"x", "d1"}}, true},
		{"other device", RuleMatch{DeviceIDs: []string{"x"}}, false},
		{"group", RuleMatch{GroupIDs: []string{"g2"}}, true},
		{"other group", RuleMatch{GroupIDs: []string{"g9"}}, false},
		{"type", RuleMatch{Types: []string{"t1"}}, true},
		{"other type", RuleMatch{Types: []string{"t2"}}, false},
		{"domain exact", RuleMatch{Domains: []string{"ads.tracker.example.com"}}, true},
		{"domain parent", RuleMatch{Domains: []string{"example.com"}}, true},
		{"domain lookalike", RuleMatch{Domains: []string{"ample.com"}}, false},
		{"key prefix", RuleMatch{KeyPrefixes: []string{"t1|d1"}}, true},
		{"other key prefix", RuleMatch{KeyPrefixes: []string{"t2|"}}, false},
		{"fields are ANDed", RuleMatch{DeviceIDs: []string{"d1"}, Types: []string{"t2"}}, false},
		{"all fields", RuleMatch{DeviceIDs: []string{"d1"}, GroupIDs: []string{"g1"}, Types: []string{"t1"}, Domains: []string{"example.com"}, KeyPrefixes: []string{"t1"}}, true},
	}
	for _, c := range cases {
		if got := c.m.Matches(a); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
	// A device rule never matches an alarm with no device, nor a domain rule one with no domain.
	if (RuleMatch{DeviceIDs: []string{""}}).Matches(&Alarm{}) || (RuleMatch{Domains: []string{"example.com"}}).Matches(&Alarm{}) {
		t.Fatal("empty-field match")
	}
}

func TestMutedAlarmsAreRecordedButNeverNotified(t *testing.T) {
	e, _, rec := newTestEngine(t)
	r, res, err := e.CreateRule(RuleSpec{Name: "Guest TV", Match: RuleMatch{DeviceIDs: []string{dev(1)}}, Duration: forever(), Reason: "noisy"})
	if err != nil || res.Handle == "" || len(res.Rules) != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	a := mustRaise(t, e, Event{Type: TypeNewDevice, DeviceID: dev(1)})
	if a.State != StateMuted || a.MutedBy != r.ID {
		t.Fatalf("a = %+v", a)
	}
	if len(rec.sends()) != 0 {
		t.Fatal("a muted alarm notified")
	}
	if got, ok := e.Get(a.ID); !ok || got.State != StateMuted {
		t.Fatal("muted alarm not recorded")
	}
	// Other devices still notify.
	mustRaise(t, e, Event{Type: TypeNewDevice, DeviceID: dev(2)})
	if len(rec.sends()) != 1 {
		t.Fatal("unrelated alarm silenced")
	}
	// A repeat of a muted alarm stays muted and counts.
	b := mustRaise(t, e, Event{Type: TypeNewDevice, DeviceID: dev(1)})
	if b.ID != a.ID || b.Count != 2 || b.State != StateMuted {
		t.Fatalf("b = %+v", b)
	}
	if rules := e.ListRules(false); len(rules) != 1 || rules[0].Name != "Guest TV" || rules[0].Reason != "noisy" {
		t.Fatalf("rules = %+v", rules)
	}
	if s := e.Summary(); s.ActiveRules != 1 || s.ByState[StateMuted] != 1 {
		t.Fatalf("summary: %+v", s)
	}
}

func TestMuteRuleExpiry(t *testing.T) {
	e, clk, rec := newTestEngine(t)
	r, _, err := e.CreateRule(RuleSpec{Match: RuleMatch{Types: []string{"custom"}}, Duration: MuteSpec{Preset: MuteHour}})
	if err != nil {
		t.Fatal(err)
	}
	a := mustRaise(t, e, Event{Type: "custom", Key: "k"})
	if a.State != StateMuted {
		t.Fatal("not muted")
	}
	clk.Advance(59 * time.Minute)
	e.Tick()
	if got, _ := e.Get(a.ID); got.State != StateMuted {
		t.Fatal("expired early")
	}
	// Fresh alarms of the type stay muted right up to the boundary...
	if b := mustRaise(t, e, Event{Type: "custom", Key: "k2"}); b.State != StateMuted {
		t.Fatal("rule not in force")
	}
	rec.reset()
	clk.Advance(time.Minute)
	// ...and at the boundary the rule no longer applies, even before a sweep.
	if c := mustRaise(t, e, Event{Type: "custom", Key: "k3"}); c.State != StateNew || len(rec.kinds(ChangeRaised)) != 1 || !rec.kinds(ChangeRaised)[0].Notify.Send {
		t.Fatalf("expired rule still muting: %+v", c)
	}
	// The sweep returns the muted alarms to new, and (they are still being seen) tells channels once.
	got, _ := e.Get(a.ID)
	if got.State != StateNew || got.MutedBy != "" {
		t.Fatalf("after expiry: %+v", got)
	}
	if e.Summary().ActiveRules != 0 || len(e.ListRules(false)) != 0 || len(e.ListRules(true)) != 1 {
		t.Fatal("expired rule listing")
	}
	_ = r
}

func TestSweepNotifiesOnlyIfStillActive(t *testing.T) {
	e, clk, rec := newTestEngine(t)
	e.CreateRule(RuleSpec{Match: RuleMatch{Types: []string{"custom"}}, Duration: MuteSpec{Preset: MuteHour}})
	mustRaise(t, e, Event{Type: "custom", Key: "stale"})
	clk.Advance(30 * time.Minute)
	mustRaise(t, e, Event{Type: "custom", Key: "live"})
	// Make "stale" older than the dedupe window by the time the mute ends.
	clk.Advance(2 * time.Hour)
	// "live" was seen 2.5 hours ago too; ensure one that was seen recently exists.
	rec.reset()
	e.Tick()
	if n := len(rec.sends()); n != 0 {
		t.Fatalf("%d notifications for alarms that stopped long ago", n)
	}
	e2, clk2, rec2 := newTestEngine(t)
	e2.CreateRule(RuleSpec{Match: RuleMatch{Types: []string{"custom"}}, Duration: MuteSpec{Preset: MuteHour}})
	mustRaise(t, e2, Event{Type: "custom", Key: "active"})
	clk2.Advance(59 * time.Minute)
	mustRaise(t, e2, Event{Type: "custom", Key: "active"}) // still happening
	clk2.Advance(2 * time.Minute)
	rec2.reset()
	e2.Tick()
	if st := rec2.kinds(ChangeState); len(st) != 1 || !st[0].Notify.Send {
		t.Fatalf("a mute that ends on a live problem must notify once: %+v", rec2.all())
	}
}

func TestSnooze(t *testing.T) {
	e, clk, rec := newTestEngine(t)
	a := mustRaise(t, e, Event{Type: "custom", Key: "k"})
	res, err := e.Snooze(a.ID, MuteSpec{Preset: MuteHour})
	if err != nil || res.Changed != 1 || res.Handle == "" || len(res.Rules) != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	got, _ := e.Get(a.ID)
	if got.State != StateMuted || got.MutedBy != "snooze" || !got.MutedUntil.Equal(t0.Add(time.Hour)) {
		t.Fatalf("snoozed: %+v", got)
	}
	if len(e.ListRules(true)) != 0 {
		t.Fatal("snooze created a rule")
	}
	// The same key repeating stays quiet during the snooze, and the snooze ends on time.
	rec.reset()
	mustRaise(t, e, Event{Type: "custom", Key: "k"})
	if len(rec.sends()) != 0 {
		t.Fatal("snoozed alarm notified")
	}
	clk.Advance(time.Hour)
	e.Tick()
	if got, _ := e.Get(a.ID); got.State != StateNew || !got.MutedUntil.IsZero() {
		t.Fatalf("after snooze: %+v", got)
	}
	// A forever snooze never ends.
	b := mustRaise(t, e, Event{Type: "custom", Key: "k2"})
	e.Snooze(b.ID, forever())
	clk.Advance(300 * time.Hour)
	e.Tick()
	if got, _ := e.Get(b.ID); got.State != StateMuted {
		t.Fatal("forever snooze ended")
	}
	if _, err := e.Snooze("missing", forever()); err != nil {
		t.Fatal(err) // unknown IDs are skipped, not fatal
	}
	if _, err := e.Snooze(a.ID, MuteSpec{Preset: "soon"}); !errors.Is(err, ErrBadMuteSpec) {
		t.Fatal(err)
	}
}

func TestMuteSpecResolve(t *testing.T) {
	loc, err := time.LoadLocation("America/Chicago")
	if err != nil {
		t.Skip("no tzdata")
	}
	now := time.Date(2030, 3, 4, 23, 30, 0, 0, loc)
	cases := []struct {
		spec MuteSpec
		want time.Time
	}{
		{MuteSpec{Preset: MuteHour}, now.Add(time.Hour)},
		{MuteSpec{Preset: MuteTomorrow}, time.Date(2030, 3, 5, 8, 0, 0, 0, loc)},
		{MuteSpec{Preset: MuteDays, Days: 3}, time.Date(2030, 3, 7, 23, 30, 0, 0, loc)},
		{MuteSpec{Preset: MuteForever}, time.Time{}},
		{MuteSpec{Preset: MuteUntil, Until: now.Add(5 * time.Hour)}, now.Add(5 * time.Hour)},
	}
	for _, c := range cases {
		got, err := c.spec.Resolve(now, loc, 8)
		if err != nil || !got.Equal(c.want) {
			t.Errorf("%+v: %v %v", c.spec, got, err)
		}
	}
	// At 02:00 "until tomorrow morning" is this morning, not 30 hours away.
	early := time.Date(2030, 3, 5, 2, 0, 0, 0, loc)
	if got, _ := (MuteSpec{Preset: MuteTomorrow}).Resolve(early, loc, 8); !got.Equal(time.Date(2030, 3, 5, 8, 0, 0, 0, loc)) {
		t.Fatalf("early: %v", got)
	}
	// "N days" across the spring-forward change keeps the wall-clock time.
	spring := time.Date(2030, 3, 9, 10, 0, 0, 0, loc)
	if got, _ := (MuteSpec{Preset: MuteDays, Days: 2}).Resolve(spring, loc, 8); got.Hour() != 10 {
		t.Fatalf("DST: %v", got)
	}
	for _, bad := range []MuteSpec{{Preset: MuteDays}, {Preset: MuteDays, Days: 4000}, {Preset: MuteUntil, Until: now.Add(-time.Hour)}, {Preset: ""}, {Preset: "x"}} {
		if _, err := bad.Resolve(now, loc, 8); !errors.Is(err, ErrBadMuteSpec) {
			t.Errorf("%+v: %v", bad, err)
		}
	}
}

func TestRuleValidation(t *testing.T) {
	e, _, _ := newTestEngine(t)
	many := make([]string, 51)
	for i := range many {
		many[i] = fmt.Sprint("d", i)
	}
	bad := map[string]RuleSpec{
		"no criteria": {Duration: forever()},
		"too many":    {Match: RuleMatch{DeviceIDs: many}, Duration: forever()},
		"empty entry": {Match: RuleMatch{Types: []string{" "}}, Duration: forever()},
		"huge entry":  {Match: RuleMatch{KeyPrefixes: []string{strings.Repeat("k", 300)}}, Duration: forever()},
		"bad spec":    {Match: RuleMatch{Types: []string{"x"}}, Duration: MuteSpec{Preset: "nope"}},
	}
	for name, s := range bad {
		if _, _, err := e.CreateRule(s); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, _, err := e.CreateRule(bad["no criteria"]); !errors.Is(err, ErrInvalidRule) {
		t.Fatal("error type")
	}
	if len(e.ListRules(true)) != 0 {
		t.Fatal("a rejected rule was stored")
	}
	// Normalization: trimmed, lower-cased domains, de-duplicated.
	r, _, err := e.CreateRule(RuleSpec{Match: RuleMatch{Domains: []string{" Example.COM. ", "example.com"}, Types: []string{"a", "a"}}, Duration: forever(), Name: strings.Repeat("n", 200)})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Match.Domains) != 1 || r.Match.Domains[0] != "example.com" || len(r.Match.Types) != 1 || len(r.Name) != 80 {
		t.Fatalf("rule = %+v", r)
	}
}

func TestCreateRuleMutesExistingAndUndoes(t *testing.T) {
	e, _, rec := newTestEngine(t)
	a := mustRaise(t, e, Event{Type: "custom", Key: "a", DeviceID: dev(1)})
	b := mustRaise(t, e, Event{Type: "custom", Key: "b", DeviceID: dev(2)})
	c := mustRaise(t, e, Event{Type: "custom", Key: "c", DeviceID: dev(1)})
	e.Acknowledge(Selector{IDs: []string{c.ID}})
	rule, res, err := e.CreateRule(RuleSpec{Match: RuleMatch{DeviceIDs: []string{dev(1)}}, Duration: forever()})
	if err != nil || res.Matched != 1 || res.Changed != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	get := func(id string) State { x, _ := e.Get(id); return x.State }
	if get(a.ID) != StateMuted || get(b.ID) != StateNew || get(c.ID) != StateAcknowledged {
		t.Fatal("retroactive mute")
	}
	if len(rec.kinds(ChangeRule)) != 1 {
		t.Fatal("rule change not emitted")
	}
	undo, err := e.Undo(res.Handle)
	if err != nil || undo.Changed != 1 {
		t.Fatalf("%+v %v", undo, err)
	}
	if get(a.ID) != StateNew || len(e.ListRules(false)) != 0 {
		t.Fatal("undo did not restore")
	}
	// RemoveRule returns muted alarms to new.
	rule2, _, _ := e.CreateRule(RuleSpec{Match: RuleMatch{DeviceIDs: []string{dev(2)}}, Duration: forever()})
	if get(b.ID) != StateMuted {
		t.Fatal("mute")
	}
	rm, err := e.RemoveRule(rule2.ID)
	if err != nil || rm.Changed != 1 || get(b.ID) != StateNew {
		t.Fatalf("%+v %v", rm, err)
	}
	if _, err := e.RemoveRule(rule2.ID); !errors.Is(err, ErrRuleNotFound) {
		t.Fatal(err)
	}
	if _, err := e.RemoveRule("nope"); !errors.Is(err, ErrRuleNotFound) {
		t.Fatal(err)
	}
	_ = rule
}

// ---- quiet hours ---------------------------------------------------------------------

func quietPrefs(tz string, ws ...QuietWindow) Preferences {
	p := testPrefs()
	p.Timezone = tz
	p.Quiet = QuietPref{Enabled: true, Windows: ws}
	return p
}

func TestQuietHoursAcrossMidnight(t *testing.T) {
	p := quietPrefs("UTC", QuietWindow{Start: "22:00", End: "07:00", Allow: SeverityCritical})
	at := func(day, h, m int) time.Time { return time.Date(2030, 3, day, h, m, 0, 0, time.UTC) }
	cases := []struct {
		t    time.Time
		sev  Severity
		hold time.Time
	}{
		{at(4, 21, 59), SeverityHigh, time.Time{}},
		{at(4, 22, 0), SeverityHigh, at(5, 7, 0)},
		{at(4, 23, 59), SeverityLow, at(5, 7, 0)},
		{at(5, 0, 0), SeverityHigh, at(5, 7, 0)},
		{at(5, 6, 59), SeverityMedium, at(5, 7, 0)},
		{at(5, 7, 0), SeverityHigh, time.Time{}},
		{at(5, 3, 0), SeverityCritical, time.Time{}}, // critical bypasses
	}
	for _, c := range cases {
		if got := p.QuietUntil(c.t, c.sev, time.UTC); !got.Equal(c.hold) {
			t.Errorf("%v %s: hold %v, want %v", c.t, c.sev, got, c.hold)
		}
	}
	// Disabled quiet hours hold nothing; a window with no Allow holds critical too.
	off := p
	off.Quiet.Enabled = false
	if !off.QuietUntil(at(5, 3, 0), SeverityLow, time.UTC).IsZero() {
		t.Fatal("disabled")
	}
	strict := quietPrefs("UTC", QuietWindow{Start: "22:00", End: "07:00"})
	if got := strict.QuietUntil(at(5, 3, 0), SeverityCritical, time.UTC); !got.Equal(at(5, 7, 0)) {
		t.Fatalf("strict: %v", got)
	}
}

func TestQuietHoursTimeZones(t *testing.T) {
	tokyo, err1 := time.LoadLocation("Asia/Tokyo")
	la, err2 := time.LoadLocation("America/Los_Angeles")
	if err1 != nil || err2 != nil {
		t.Skip("no tzdata")
	}
	// The same instant is 03:00 in Tokyo (quiet) and 10:00 the day before in
	// Los Angeles (not quiet).
	instant := time.Date(2030, 3, 4, 18, 0, 0, 0, time.UTC)
	w := QuietWindow{Start: "22:00", End: "07:00", Allow: SeverityCritical}
	pt := quietPrefs("Asia/Tokyo", w)
	pl := quietPrefs("America/Los_Angeles", w)
	if loc, _ := pt.Location(); loc.String() != "Asia/Tokyo" {
		t.Fatal("location")
	}
	holdT := pt.QuietUntil(instant, SeverityHigh, tokyo)
	if want := time.Date(2030, 3, 5, 7, 0, 0, 0, tokyo); !holdT.Equal(want) {
		t.Fatalf("tokyo hold %v want %v", holdT, want)
	}
	if got := pl.QuietUntil(instant, SeverityHigh, la); !got.IsZero() {
		t.Fatalf("los angeles should not be quiet: %v", got)
	}
	// Springing forward: the window ends at 07:00 wall-clock on the 10th even
	// though that night is only 8 hours long.
	night := time.Date(2030, 3, 10, 1, 0, 0, 0, la)
	hold := pl.QuietUntil(night, SeverityHigh, la)
	if hold.Hour() != 7 || hold.Day() != 10 {
		t.Fatalf("DST hold: %v", hold)
	}
	// Engine-level: an alarm in the quiet window is held, not dropped.
	e, clk, rec := newTestEngine(t, func(o *Options) { o.Preferences = &pt })
	clk.Set(instant)
	mustRaise(t, e, Event{Type: "custom", Key: "q", Severity: SeverityHigh})
	got := rec.kinds(ChangeRaised)[0].Notify
	if !got.Send || got.Reason != "quiet-hours" || !got.HoldUntil.Equal(holdT) {
		t.Fatalf("notify = %+v", got)
	}
	mustRaise(t, e, Event{Type: "custom", Key: "c", Severity: SeverityCritical})
	if n := rec.kinds(ChangeRaised)[1].Notify; !n.HoldUntil.IsZero() || !n.Send {
		t.Fatalf("critical must bypass: %+v", n)
	}
}

func TestQuietWindowDaysAndOverlap(t *testing.T) {
	// Weekends only: 23:00 to 09:00, starting Friday (5) and Saturday (6).
	p := quietPrefs("UTC", QuietWindow{Start: "23:00", End: "09:00", Days: []int{5, 6}, Allow: SeverityCritical})
	d := func(day, h int) time.Time { return time.Date(2030, 3, day, h, 0, 0, 0, time.UTC) } // 2030-03-08 is a Friday
	if p.QuietUntil(d(8, 22), SeverityLow, time.UTC) != (time.Time{}) {
		t.Fatal("friday before the window")
	}
	if !p.QuietUntil(d(8, 23), SeverityLow, time.UTC).Equal(d(9, 9)) {
		t.Fatal("friday night")
	}
	if !p.QuietUntil(d(9, 8), SeverityLow, time.UTC).Equal(d(9, 9)) {
		t.Fatal("saturday morning belongs to Friday's window")
	}
	if !p.QuietUntil(d(10, 2), SeverityLow, time.UTC).Equal(d(10, 9)) {
		t.Fatal("sunday 02:00 belongs to Saturday's window")
	}
	if !p.QuietUntil(d(10, 10), SeverityLow, time.UTC).IsZero() || !p.QuietUntil(d(11, 2), SeverityLow, time.UTC).IsZero() {
		t.Fatal("monday 02:00 is not in a weekend window")
	}
	// A same-day window and an all-day window, overlapping: the latest end wins.
	o := quietPrefs("UTC",
		QuietWindow{Start: "09:00", End: "10:00"},
		QuietWindow{Start: "09:30", End: "12:00"},
		QuietWindow{Start: "00:00", End: "00:00", Days: []int{0}, Allow: SeverityCritical})
	if got := o.QuietUntil(d(4, 9), SeverityLow, time.UTC); !got.IsZero() == false {
		t.Fatal("09:00 should be quiet")
	}
	if got := o.QuietUntil(time.Date(2030, 3, 4, 9, 45, 0, 0, time.UTC), SeverityLow, time.UTC); !got.Equal(d(4, 12)) {
		t.Fatalf("overlap: %v", got)
	}
	if got := o.QuietUntil(time.Date(2030, 3, 10, 15, 0, 0, 0, time.UTC), SeverityLow, time.UTC); !got.Equal(d(11, 0)) {
		t.Fatalf("all-day sunday: %v", got)
	}
	if !o.QuietUntil(time.Date(2030, 3, 11, 15, 0, 0, 0, time.UTC), SeverityLow, time.UTC).IsZero() {
		t.Fatal("all-day window leaked to Monday")
	}
}

// Property: QuietUntil agrees with a minute-by-minute brute force definition
// of "inside the window" for random windows, days and zones.
func TestQuietUntilMatchesBruteForce(t *testing.T) {
	loc, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		loc = time.UTC
	}
	rngStates := []int{3, 11, 29, 57}
	for _, seed := range rngStates {
		start := (seed * 137) % 1440
		end := (seed * 331) % 1440
		w := QuietWindow{Start: fmt.Sprintf("%02d:%02d", start/60, start%60), End: fmt.Sprintf("%02d:%02d", end/60, end%60), Days: []int{seed % 7, (seed + 3) % 7}}
		p := quietPrefs(loc.String(), w)
		base := time.Date(2030, 6, 1, 0, 0, 0, 0, loc)
		for m := 0; m < 3*1440; m += 7 {
			ts := base.Add(time.Duration(m) * time.Minute)
			inside := bruteInside(w, ts, start, end)
			got := p.QuietUntil(ts, SeverityLow, loc)
			if inside != !got.IsZero() {
				t.Fatalf("window %+v at %v: inside=%v hold=%v", w, ts, inside, got)
			}
			if inside && !got.After(ts) {
				t.Fatalf("hold %v is not after %v", got, ts)
			}
		}
	}
}

func bruteInside(w QuietWindow, ts time.Time, start, end int) bool {
	has := func(day time.Weekday) bool {
		for _, d := range w.Days {
			if time.Weekday(d) == day {
				return true
			}
		}
		return false
	}
	m := ts.Hour()*60 + ts.Minute()
	switch {
	case start == end:
		return has(ts.Weekday())
	case start < end:
		return has(ts.Weekday()) && m >= start && m < end
	}
	return (m >= start && has(ts.Weekday())) || (m < end && has(ts.AddDate(0, 0, -1).Weekday()))
}

func TestNextAt(t *testing.T) {
	loc, err := time.LoadLocation("America/Chicago")
	if err != nil {
		t.Skip("no tzdata")
	}
	now := time.Date(2030, 3, 4, 7, 59, 0, 0, loc)
	if got := NextAt(now, "08:00", loc); !got.Equal(time.Date(2030, 3, 4, 8, 0, 0, 0, loc)) {
		t.Fatal(got)
	}
	if got := NextAt(now.Add(time.Minute), "08:00", loc); !got.Equal(time.Date(2030, 3, 5, 8, 0, 0, 0, loc)) {
		t.Fatal(got)
	}
	// Given in UTC but evaluated in the household's zone.
	if got := NextAt(now.UTC(), "08:00", loc); !got.Equal(time.Date(2030, 3, 4, 8, 0, 0, 0, loc)) {
		t.Fatal(got)
	}
}

// ---- learning mode ----------------------------------------------------------------------

func learnPrefs() Preferences {
	p := testPrefs()
	p.Learning = LearningPref{Enabled: true, Period: Duration(72 * time.Hour), DevicePeriod: Duration(24 * time.Hour)}
	return p
}

func TestLearningModeRecordsAsInfoWithoutNotifying(t *testing.T) {
	p := learnPrefs()
	e, clk, rec := newTestEngine(t, func(o *Options) { o.Preferences = &p })
	if got := e.LearningUntil(); !got.Equal(t0.Add(72 * time.Hour)) {
		t.Fatalf("learning until %v", got)
	}
	a := mustRaise(t, e, Event{Type: TypeNewDevice, DeviceID: dev(1)})
	if a.Severity != SeverityInfo || a.RawSeverity != SeverityHigh || !a.Learning || a.State != StateNew {
		t.Fatalf("learning alarm: %+v", a)
	}
	if len(rec.sends()) != 0 || rec.kinds(ChangeRaised)[0].Notify.Reason != "learning" {
		t.Fatalf("learning alarm notified: %+v", rec.all())
	}
	// Types that are not flagged still notify during learning.
	mustRaise(t, e, Event{Type: TypeUpstreamDown})
	if len(rec.sends()) != 1 {
		t.Fatal("unflagged type was suppressed")
	}
	// The test type bypasses learning mode.
	mustRaise(t, e, Event{Type: TypeTest})
	if len(rec.sends()) != 2 {
		t.Fatal("test bypass")
	}
	// After the period, flagged types notify at their own severity.
	clk.Advance(72 * time.Hour)
	b := mustRaise(t, e, Event{Type: TypeNewDevice, DeviceID: dev(2)})
	if b.Severity != SeverityHigh || b.Learning || len(rec.sends()) != 3 {
		t.Fatalf("after learning: %+v", b)
	}
	// Turning learning off ends it at once.
	p2 := learnPrefs()
	p2.Learning.Enabled = false
	e2, _, rec2 := newTestEngine(t, func(o *Options) { o.Preferences = &p2 })
	if !e2.LearningUntil().IsZero() {
		t.Fatal("learning until when off")
	}
	mustRaise(t, e2, Event{Type: TypeNewDevice, DeviceID: dev(1)})
	if len(rec2.sends()) != 1 {
		t.Fatal("learning off")
	}
}

func TestPerDeviceLearning(t *testing.T) {
	p := learnPrefs()
	p.Learning.Period = Duration(time.Hour)
	e, clk, rec := newTestEngine(t, func(o *Options) { o.Preferences = &p })
	clk.Advance(2 * time.Hour) // install learning is over
	// A device first seen now: its own flagged alarms are recorded as info for a day.
	mustRaise(t, e, Event{Type: TypeNewDevice, DeviceID: dev(1)}) // not DeviceLearning: notifies
	if len(rec.sends()) != 1 {
		t.Fatalf("new-device must notify: %d", len(rec.sends()))
	}
	a := mustRaise(t, e, Event{Type: TypeBlockedSpike, DeviceID: dev(1)})
	if !a.Learning || a.Severity != SeverityInfo || len(rec.sends()) != 1 {
		t.Fatalf("device learning: %+v", a)
	}
	// An older device is unaffected.
	e.NoteDeviceSeen(dev(2), t0.Add(-48*time.Hour))
	b := mustRaise(t, e, Event{Type: TypeBlockedSpike, DeviceID: dev(2)})
	if b.Learning {
		t.Fatalf("old device in learning: %+v", b)
	}
	// A day later the new device's alarms notify.
	clk.Advance(25 * time.Hour)
	c := mustRaise(t, e, Event{Type: TypeBlockedSpike, DeviceID: dev(1), Key: "later"})
	if c.Learning {
		t.Fatalf("after device period: %+v", c)
	}
	// Alarms without a device are not subject to device learning.
	d := mustRaise(t, e, Event{Type: TypeBlockedSpike, Key: "nodev"})
	if d.Learning {
		t.Fatal("device learning without a device")
	}
}

func TestMuteBeatsLearningAndBypassBeatsMute(t *testing.T) {
	p := learnPrefs()
	e, _, rec := newTestEngine(t, func(o *Options) { o.Preferences = &p })
	e.CreateRule(RuleSpec{Match: RuleMatch{Types: []string{TypeNewDevice, TypeTest}}, Duration: forever()})
	a := mustRaise(t, e, Event{Type: TypeNewDevice, DeviceID: dev(1)})
	if a.State != StateMuted || a.Learning {
		t.Fatalf("a = %+v", a)
	}
	mustRaise(t, e, Event{Type: TypeTest})
	if len(rec.sends()) != 1 {
		t.Fatal("test notifications ignore mute rules")
	}
}
