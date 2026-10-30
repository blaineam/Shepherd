// SPDX-License-Identifier: AGPL-3.0-or-later

package alarms

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

// seed raises a varied set of alarms and returns them by name.
func seed(t testing.TB, e *Engine, clk *FakeClock) map[string]Alarm {
	t.Helper()
	out := map[string]Alarm{}
	add := func(name string, ev Event) {
		clk.Advance(time.Minute)
		out[name] = mustRaise(t, e, ev)
	}
	add("nd1", Event{Type: TypeNewDevice, DeviceID: dev(1), GroupIDs: []string{"kids"}, Title: "New device: Tablet", Evidence: []Evidence{{"Vendor", "Example Corp"}}})
	add("nd2", Event{Type: TypeNewDevice, DeviceID: dev(2), Title: "New device: Camera"})
	add("up", Event{Type: TypeUpstreamDown, Key: "up|1", Title: "Upstream down"})
	add("bs", Event{Type: TypeBlockedSpike, DeviceID: dev(1), Domain: "ads.example.com", Key: "bs|1", Body: "lots blocked"})
	add("pr", Event{Type: TypePrivateRelay, DeviceID: dev(2), Key: "pr|2"})
	return out
}

func ids(as ...Alarm) []string {
	var out []string
	for _, a := range as {
		out = append(out, a.ID)
	}
	return out
}

func TestAcknowledgeResolveByIDsAndUndo(t *testing.T) {
	e, clk, rec := newTestEngine(t)
	s := seed(t, e, clk)
	rec.reset()
	clk.Advance(time.Minute)
	res, err := e.Acknowledge(Selector{IDs: append(ids(s["nd1"], s["nd2"]), "missing", s["nd1"].ID)})
	if err != nil || res.Matched != 2 || res.Changed != 2 || res.Skipped != 1 || res.Handle == "" {
		t.Fatalf("%+v %v", res, err)
	}
	if got, _ := e.Get(s["nd1"].ID); got.State != StateAcknowledged || !got.AckedAt.Equal(clk.Now()) {
		t.Fatalf("nd1 = %+v", got)
	}
	if len(rec.kinds(ChangeState)) != 2 {
		t.Fatalf("changes = %d", len(rec.kinds(ChangeState)))
	}
	// Acknowledging again changes nothing (and gives no handle).
	again, _ := e.Acknowledge(Selector{IDs: ids(s["nd1"])})
	if again.Matched != 1 || again.Changed != 0 || again.Handle != "" {
		t.Fatalf("again: %+v", again)
	}
	// Resolve acknowledged and new alike; undo restores each one's own previous state.
	rr, err := e.Resolve(Selector{IDs: ids(s["nd1"], s["up"])})
	if err != nil || rr.Changed != 2 {
		t.Fatalf("%+v %v", rr, err)
	}
	if got, _ := e.Get(s["up"].ID); got.State != StateResolved || got.ResolvedAt.IsZero() {
		t.Fatalf("up = %+v", got)
	}
	// Resolved alarms are not acknowledged or muted by later batches.
	if r, _ := e.Acknowledge(Selector{IDs: ids(s["up"])}); r.Changed != 0 {
		t.Fatal("resolved alarm acknowledged")
	}
	u, err := e.Undo(rr.Handle)
	if err != nil || u.Changed != 2 {
		t.Fatalf("%+v %v", u, err)
	}
	if got, _ := e.Get(s["nd1"].ID); got.State != StateAcknowledged || !got.ResolvedAt.IsZero() {
		t.Fatalf("nd1 after undo: %+v", got)
	}
	if got, _ := e.Get(s["up"].ID); got.State != StateNew {
		t.Fatalf("up after undo: %+v", got)
	}
	// A handle works once.
	if _, err := e.Undo(rr.Handle); !errors.Is(err, ErrUndoNotFound) {
		t.Fatalf("second undo: %v", err)
	}
	if _, err := e.Undo("nope"); !errors.Is(err, ErrUndoNotFound) {
		t.Fatal(err)
	}
}

func TestUndoSkipsAlarmsChangedSince(t *testing.T) {
	e, clk, _ := newTestEngine(t)
	s := seed(t, e, clk)
	res, _ := e.Resolve(Selector{IDs: ids(s["nd1"], s["nd2"])})
	// nd2 is changed again after the resolve: undo must not clobber that.
	e.Delete(Selector{IDs: ids(s["nd2"])})
	u, err := e.Undo(res.Handle)
	if err != nil || u.Changed != 1 || u.Skipped != 1 {
		t.Fatalf("%+v %v", u, err)
	}
}

func TestUndoExpires(t *testing.T) {
	e, clk, _ := newTestEngine(t, func(o *Options) { o.UndoTTL = time.Minute })
	s := seed(t, e, clk)
	res, _ := e.Resolve(Selector{IDs: ids(s["nd1"])})
	clk.Advance(2 * time.Minute)
	if _, err := e.Undo(res.Handle); !errors.Is(err, ErrUndoExpired) && !errors.Is(err, ErrUndoNotFound) {
		t.Fatalf("err = %v", err)
	}
	// The tick also reaps expired handles, and old ones are capped at 50.
	res2, _ := e.Resolve(Selector{IDs: ids(s["nd2"])})
	clk.Advance(2 * time.Minute)
	e.Tick()
	if _, err := e.Undo(res2.Handle); !errors.Is(err, ErrUndoNotFound) {
		t.Fatalf("reaped handle: %v", err)
	}
	e3, _, _ := newTestEngine(t)
	var first string
	for i := 0; i < 60; i++ {
		a := mustRaise(t, e3, Event{Type: "custom", Key: fmt.Sprint(i), DeviceID: dev(i)})
		r, _ := e3.Acknowledge(Selector{IDs: []string{a.ID}})
		if i == 0 {
			first = r.Handle
		}
	}
	if _, err := e3.Undo(first); !errors.Is(err, ErrUndoNotFound) {
		t.Fatal("oldest handle survived the cap")
	}
}

func TestBatchByFilter(t *testing.T) {
	e, clk, _ := newTestEngine(t)
	s := seed(t, e, clk)
	res, err := e.Acknowledge(Selector{Filter: &Filter{Types: []string{TypeNewDevice}}})
	if err != nil || res.Matched != 2 || res.Changed != 2 {
		t.Fatalf("%+v %v", res, err)
	}
	// IDs and a filter combine as an intersection.
	res, _ = e.Resolve(Selector{IDs: ids(s["nd1"], s["up"]), Filter: &Filter{States: []State{StateNew}}})
	if res.Matched != 1 || res.Changed != 1 {
		t.Fatalf("%+v", res)
	}
	if got, _ := e.Get(s["up"].ID); got.State != StateResolved {
		t.Fatal("intersection picked the wrong alarm")
	}
	// All selects everything visible; an empty selector is refused.
	if _, err := e.Acknowledge(Selector{}); !errors.Is(err, ErrEmptySelector) {
		t.Fatalf("empty: %v", err)
	}
	if _, err := e.Delete(Selector{}); !errors.Is(err, ErrEmptySelector) {
		t.Fatalf("empty delete: %v", err)
	}
	all, err := e.Resolve(Selector{All: true})
	if err != nil || all.Matched != 5 || all.Changed != 4 {
		t.Fatalf("%+v %v", all, err)
	}
}

func TestFilters(t *testing.T) {
	e, clk, _ := newTestEngine(t)
	s := seed(t, e, clk)
	e.Acknowledge(Selector{IDs: ids(s["nd2"])})
	e.Archive(Selector{IDs: ids(s["pr"])})
	cases := []struct {
		name string
		f    Filter
		want []string
	}{
		{"all excludes archived by default", Filter{}, []string{"nd1", "nd2", "up", "bs"}},
		{"include archived", Filter{IncludeArchived: true}, []string{"nd1", "nd2", "up", "bs", "pr"}},
		{"type", Filter{Types: []string{TypeNewDevice}}, []string{"nd1", "nd2"}},
		{"severity set", Filter{Severities: []Severity{SeverityLow, SeverityInfo}}, []string{"bs"}},
		{"min severity", Filter{MinSeverity: SeverityHigh}, []string{"nd1", "nd2", "up"}},
		{"state", Filter{States: []State{StateAcknowledged}}, []string{"nd2"}},
		{"device", Filter{DeviceID: dev(1)}, []string{"nd1", "bs"}},
		{"group", Filter{GroupID: "kids"}, []string{"nd1"}},
		{"since", Filter{Since: s["up"].LastSeen}, []string{"up", "bs"}},
		{"until", Filter{Until: s["nd2"].FirstSeen}, []string{"nd1", "nd2"}},
		{"range", Filter{Since: s["nd2"].LastSeen, Until: s["bs"].FirstSeen}, []string{"nd2", "up", "bs"}},
		{"text title", Filter{Text: "TABLET"}, []string{"nd1"}},
		{"text body", Filter{Text: "lots blocked"}, []string{"bs"}},
		{"text evidence", Filter{Text: "example corp"}, []string{"nd1"}},
		{"text domain", Filter{Text: "ads.example"}, []string{"bs"}},
		{"text key", Filter{Text: "up|1"}, []string{"up"}},
		{"text none", Filter{Text: "zzz"}, nil},
		{"combined", Filter{Types: []string{TypeNewDevice}, States: []State{StateNew}}, []string{"nd1"}},
		{"bad severity", Filter{MinSeverity: "bogus"}, nil},
	}
	for _, c := range cases {
		page := e.List(Query{Filter: c.f, Sort: SortFirstSeen, Asc: true})
		var got []string
		for _, a := range page.Alarms {
			got = append(got, a.ID)
		}
		var want []string
		for _, n := range c.want {
			want = append(want, s[n].ID)
		}
		if fmt.Sprint(got) != fmt.Sprint(want) || page.Total != len(want) {
			t.Errorf("%s: got %v want %v", c.name, got, want)
		}
	}
}

func TestListSortingAndPaging(t *testing.T) {
	e, clk, _ := newTestEngine(t)
	s := seed(t, e, clk)
	// Make the counts differ.
	clk.Advance(time.Minute)
	mustRaise(t, e, Event{Type: TypeUpstreamDown, Key: "up|1", Count: 4})
	order := func(q Query) []string {
		var out []string
		for _, a := range e.List(q).Alarms {
			for n, x := range s {
				if x.ID == a.ID {
					out = append(out, n)
				}
			}
		}
		return out
	}
	if got := order(Query{}); fmt.Sprint(got) != "[up pr bs nd2 nd1]" {
		t.Fatalf("default (last seen, newest first): %v", got)
	}
	if got := order(Query{Asc: true}); fmt.Sprint(got) != "[nd1 nd2 bs pr up]" {
		t.Fatalf("asc: %v", got)
	}
	if got := order(Query{Sort: SortFirstSeen}); fmt.Sprint(got) != "[pr bs up nd2 nd1]" {
		t.Fatalf("first seen: %v", got)
	}
	if got := order(Query{Sort: SortSeverity}); got[len(got)-1] != "pr" || got[0] != "up" {
		t.Fatalf("severity: %v", got)
	}
	if got := order(Query{Sort: SortCount}); got[0] != "up" {
		t.Fatalf("count: %v", got)
	}
	if got := order(Query{Sort: SortTitle, Asc: true}); fmt.Sprint(got) != "[nd2 nd1 pr bs up]" && len(got) != 5 {
		t.Fatalf("title: %v", got)
	}
	p := e.List(Query{Limit: 2, Offset: 1})
	if len(p.Alarms) != 2 || p.Total != 5 || p.Offset != 1 || p.Limit != 2 {
		t.Fatalf("page = %+v", p)
	}
	if p := e.List(Query{Offset: 99}); len(p.Alarms) != 0 || p.Total != 5 {
		t.Fatalf("past the end: %+v", p)
	}
	if p := e.List(Query{Offset: -4, Limit: 9999}); p.Offset != 0 || p.Limit != 500 {
		t.Fatalf("clamps: %+v", p)
	}
	if p := e.List(Query{}); p.Limit != 50 {
		t.Fatalf("default limit %d", p.Limit)
	}
	// Paging through the whole set never repeats or skips (stable order).
	seen := map[string]bool{}
	for off := 0; off < 5; off += 2 {
		for _, a := range e.List(Query{Sort: SortSeverity, Limit: 2, Offset: off}).Alarms {
			if seen[a.ID] {
				t.Fatalf("repeated %s", a.ID)
			}
			seen[a.ID] = true
		}
	}
	if len(seen) != 5 {
		t.Fatalf("paged %d of 5", len(seen))
	}
}

func TestSummary(t *testing.T) {
	e, clk, _ := newTestEngine(t)
	s := seed(t, e, clk)
	e.Acknowledge(Selector{IDs: ids(s["nd1"])})
	e.Resolve(Selector{IDs: ids(s["up"])})
	e.Snooze(s["bs"].ID, forever())
	sum := e.Summary()
	if sum.Total != 5 || sum.ByState[StateNew] != 2 || sum.ByState[StateAcknowledged] != 1 || sum.ByState[StateMuted] != 1 || sum.ByState[StateResolved] != 1 {
		t.Fatalf("by state: %+v", sum)
	}
	if sum.BySeverity[SeverityHigh] != 1 || sum.BySeverity[SeverityInfo] != 1 || sum.BySeverity[SeverityCritical] != 0 || sum.Highest != SeverityHigh {
		t.Fatalf("by severity: %+v", sum)
	}
	empty, _, _ := newTestEngine(t)
	if s := empty.Summary(); s.Total != 0 || s.Highest != "" || len(s.ByState) != 4 || len(s.BySeverity) != 5 {
		t.Fatalf("empty: %+v", s)
	}
	// Archiving a new alarm drops it out of Total, ByState and the severity
	// badge count: an archived alarm must not keep contributing to a number
	// the maintainer sees elsewhere and wonders why it won't go down.
	e.Archive(Selector{IDs: ids(s["nd2"])}) // nd2 is new, severity high
	sum = e.Summary()
	if sum.Total != 4 || sum.ByState[StateNew] != 1 {
		t.Fatalf("after archive: %+v", sum)
	}
	if sum.BySeverity[SeverityHigh] != 0 {
		t.Fatalf("archived alarm still counted in badge: %+v", sum)
	}
}

func TestArchiveAndUnarchive(t *testing.T) {
	e, clk, rec := newTestEngine(t)
	s := seed(t, e, clk)
	rec.reset()
	clk.Advance(time.Minute)
	res, err := e.Archive(Selector{IDs: ids(s["nd1"], s["nd2"])})
	if err != nil || res.Matched != 2 || res.Changed != 2 || res.Handle == "" {
		t.Fatalf("%+v %v", res, err)
	}
	got, _ := e.Get(s["nd1"].ID)
	if !got.Archived || got.ArchivedAt.IsZero() || got.State != StateNew {
		t.Fatalf("nd1 = %+v (archiving must not touch State)", got)
	}
	if len(rec.kinds(ChangeState)) != 2 {
		t.Fatalf("changes = %d", len(rec.kinds(ChangeState)))
	}
	// Archiving again changes nothing (and gives no handle).
	again, _ := e.Archive(Selector{IDs: ids(s["nd1"])})
	if again.Matched != 1 || again.Changed != 0 || again.Handle != "" {
		t.Fatalf("again: %+v", again)
	}
	// The default filter hides archived alarms; IncludeArchived reveals them.
	if page := e.List(Query{}); page.Total != 3 {
		t.Fatalf("default total = %d, want 3", page.Total)
	}
	if page := e.List(Query{Filter: Filter{IncludeArchived: true}}); page.Total != 5 {
		t.Fatalf("include_archived total = %d, want 5", page.Total)
	}
	// Unarchive one directly.
	ur, err := e.Unarchive(Selector{IDs: ids(s["nd1"])})
	if err != nil || ur.Changed != 1 {
		t.Fatalf("%+v %v", ur, err)
	}
	if got, _ := e.Get(s["nd1"].ID); got.Archived || !got.ArchivedAt.IsZero() {
		t.Fatalf("nd1 after unarchive: %+v", got)
	}
	// Undoing the original archive batch un-archives nd2 (untouched since)
	// but skips nd1 (already changed by the direct Unarchive above).
	u, err := e.Undo(res.Handle)
	if err != nil || u.Changed != 1 || u.Skipped != 1 {
		t.Fatalf("%+v %v", u, err)
	}
	if got, _ := e.Get(s["nd2"].ID); got.Archived {
		t.Fatalf("nd2 after undo: %+v", got)
	}
	// Archive works on an alarm in any state, including resolved ones.
	e.Resolve(Selector{IDs: ids(s["up"])})
	if r, err := e.Archive(Selector{IDs: ids(s["up"])}); err != nil || r.Changed != 1 {
		t.Fatalf("archive resolved: %+v %v", r, err)
	}
	if got, _ := e.Get(s["up"].ID); !got.Archived || got.State != StateResolved {
		t.Fatalf("up = %+v", got)
	}
}

func TestArchiveByFilterAndBundle(t *testing.T) {
	e, clk, _ := newTestEngine(t)
	seed(t, e, clk)
	// By filter: archive every new-device alarm.
	res, err := e.Archive(Selector{Filter: &Filter{Types: []string{TypeNewDevice}}})
	if err != nil || res.Matched != 2 || res.Changed != 2 {
		t.Fatalf("%+v %v", res, err)
	}
	// Archiving a bundle archives its live members too.
	for i := 0; i < 8; i++ {
		clk.Advance(time.Millisecond)
		mustRaise(t, e, Event{Type: "custom", DeviceID: dev(9), Key: fmt.Sprint(i)})
	}
	b := e.List(Query{Filter: Filter{DeviceID: dev(9)}}).Alarms[0]
	kids := e.Children(b.ID)
	if len(kids) == 0 {
		t.Fatal("expected a bundle with members")
	}
	if r, err := e.Archive(Selector{IDs: []string{b.ID}}); err != nil || r.Changed != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	for _, k := range kids {
		if got, _ := e.Get(k.ID); !got.Archived {
			t.Fatalf("bundle member not archived: %+v", got)
		}
	}
}

func TestMuteByVariants(t *testing.T) {
	// By key: one rule per key, applies to later repeats and to other new alarms with that key prefix.
	e, clk, rec := newTestEngine(t)
	s := seed(t, e, clk)
	res, err := e.Mute(Selector{IDs: ids(s["up"], s["bs"])}, MuteRequest{By: MuteByKey, Duration: forever()})
	if err != nil || len(res.Rules) != 2 || res.Changed != 2 || res.Handle == "" {
		t.Fatalf("%+v %v", res, err)
	}
	rec.reset()
	if a := mustRaise(t, e, Event{Type: TypeUpstreamDown, Key: "up|1|again"}); a.State != StateMuted {
		t.Fatal("key prefix rule did not apply")
	}
	// By type: one rule, mutes the other new alarms of that type too.
	e2, clk2, _ := newTestEngine(t)
	s2 := seed(t, e2, clk2)
	res, err = e2.Mute(Selector{IDs: ids(s2["nd1"])}, MuteRequest{By: MuteByType, Duration: MuteSpec{Preset: MuteHour}})
	if err != nil || len(res.Rules) != 1 || res.Changed != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if got, _ := e2.Get(s2["nd2"].ID); got.State != StateMuted {
		t.Fatal("type rule must mute the other new-device alarm too")
	}
	// By device.
	e3, clk3, _ := newTestEngine(t)
	s3 := seed(t, e3, clk3)
	res, _ = e3.Mute(Selector{IDs: ids(s3["nd1"])}, MuteRequest{By: MuteByDevice, Duration: forever()})
	if got, _ := e3.Get(s3["bs"].ID); got.State != StateMuted || res.Changed != 1 {
		t.Fatalf("device rule: %+v %+v", got, res)
	}
	if got, _ := e3.Get(s3["nd2"].ID); got.State != StateNew {
		t.Fatal("device rule leaked")
	}
	// By type+device: one rule per pair.
	e4, clk4, _ := newTestEngine(t)
	s4 := seed(t, e4, clk4)
	res, _ = e4.Mute(Selector{IDs: ids(s4["nd1"], s4["bs"], s4["up"])}, MuteRequest{By: MuteByTypeDevice, Duration: forever()})
	if len(res.Rules) != 2 {
		t.Fatalf("pairs: %+v", res)
	}
	if got, _ := e4.Get(s4["up"].ID); got.State != StateNew {
		t.Fatal("an alarm without a device has no type+device pair")
	}
	// By domain.
	e5, clk5, _ := newTestEngine(t)
	s5 := seed(t, e5, clk5)
	res, _ = e5.Mute(Selector{IDs: ids(s5["bs"])}, MuteRequest{By: MuteByDomain, Duration: forever()})
	if a := mustRaise(t, e5, Event{Type: "custom", Key: "d", Domain: "x.ads.example.com"}); a.State != StateMuted || len(res.Rules) != 1 {
		t.Fatalf("domain: %+v", a)
	}
	// Nothing to build a rule from, bad scope, bad duration.
	if _, err := e5.Mute(Selector{IDs: ids(s5["up"])}, MuteRequest{By: MuteByDevice, Duration: forever()}); !errors.Is(err, ErrNothingToMute) {
		t.Fatalf("no device: %v", err)
	}
	if _, err := e5.Mute(Selector{IDs: ids(s5["up"])}, MuteRequest{By: MuteByDomain, Duration: forever()}); !errors.Is(err, ErrNothingToMute) {
		t.Fatalf("no domain: %v", err)
	}
	if _, err := e5.Mute(Selector{IDs: ids(s5["up"])}, MuteRequest{By: MuteByTypeDevice, Duration: forever()}); !errors.Is(err, ErrNothingToMute) {
		t.Fatalf("no pair: %v", err)
	}
	if _, err := e5.Mute(Selector{IDs: ids(s5["up"])}, MuteRequest{By: "nonsense", Duration: forever()}); !errors.Is(err, ErrBadMuteBy) {
		t.Fatalf("bad scope: %v", err)
	}
	if _, err := e5.Mute(Selector{IDs: ids(s5["up"])}, MuteRequest{By: MuteByKey, Duration: MuteSpec{Preset: "x"}}); !errors.Is(err, ErrBadMuteSpec) {
		t.Fatalf("bad duration: %v", err)
	}
	if _, err := e5.Mute(Selector{}, MuteRequest{By: MuteByKey, Duration: forever()}); !errors.Is(err, ErrEmptySelector) {
		t.Fatalf("empty: %v", err)
	}
	// A failed mute leaves no stray rules behind.
	before := len(e5.ListRules(true))
	e5.Mute(Selector{IDs: ids(s5["up"])}, MuteRequest{By: MuteByKey, Duration: MuteSpec{Preset: MuteUntil, Until: t0}})
	if len(e5.ListRules(true)) != before {
		t.Fatal("rules leaked from a failed mute")
	}
}

func TestMuteSelectedAcknowledgedAlarmsAndUndo(t *testing.T) {
	e, clk, _ := newTestEngine(t)
	s := seed(t, e, clk)
	e.Acknowledge(Selector{IDs: ids(s["nd1"])})
	res, err := e.Mute(Selector{IDs: ids(s["nd1"])}, MuteRequest{By: MuteByDevice, Duration: forever()})
	if err != nil || res.Changed != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if got, _ := e.Get(s["nd1"].ID); got.State != StateMuted {
		t.Fatal("selected acknowledged alarm not muted")
	}
	if got, _ := e.Get(s["bs"].ID); got.State != StateMuted {
		t.Fatal("same device alarm not muted")
	}
	u, err := e.Undo(res.Handle)
	if err != nil || u.Changed != 2 {
		t.Fatalf("%+v %v", u, err)
	}
	if got, _ := e.Get(s["nd1"].ID); got.State != StateAcknowledged {
		t.Fatalf("undo restored %s, want acknowledged", got.State)
	}
	if len(e.ListRules(false)) != 0 {
		t.Fatal("undo left the rule")
	}
	// Snooze undo.
	sn, _ := e.Snooze(s["up"].ID, MuteSpec{Preset: MuteHour})
	if _, err := e.Undo(sn.Handle); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.Get(s["up"].ID); got.State != StateNew || got.MutedBy != "" {
		t.Fatalf("snooze undo: %+v", got)
	}
}

func TestDeleteAndRetention(t *testing.T) {
	e, clk, rec := newTestEngine(t, func(o *Options) {
		o.Retention = Retention{MaxAge: 24 * time.Hour, MaxCount: 4, TombstoneAge: time.Hour}
	})
	s := seed(t, e, clk) // five alarms, but the cap is four... pruning runs on Prune/Tick
	rec.reset()
	res, err := e.Delete(Selector{IDs: append(ids(s["nd1"], s["nd1"], s["pr"]), "ghost")})
	if err != nil || res.Matched != 2 || res.Changed != 2 || res.Skipped != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if len(rec.kinds(ChangeDeleted)) != 2 {
		t.Fatal("deleted changes")
	}
	if _, ok := e.Get(s["nd1"].ID); ok {
		t.Fatal("deleted alarm visible")
	}
	if e.List(Query{}).Total != 3 {
		t.Fatal("list shows deleted")
	}
	// The tombstone replicates, then is purged after TombstoneAge.
	if snap := e.Export(); len(snap.Alarms) != 5 {
		t.Fatalf("export has %d records", len(snap.Alarms))
	}
	clk.Advance(2 * time.Hour)
	if p := e.Prune(); p.Tombstones != 2 {
		t.Fatalf("prune: %+v", p)
	}
	if len(e.Export().Alarms) != 3 {
		t.Fatal("tombstones not purged")
	}
	// A deleted key can fire again.
	mustRaise(t, e, Event{Type: TypeUpstreamDown, Key: "fresh"})
	// Age: resolved and acknowledged alarms go after MaxAge; new ones after twice that.
	e.Resolve(Selector{IDs: ids(s["up"])})
	clk.Advance(25 * time.Hour)
	if p := e.Prune(); p.Aged != 1 {
		t.Fatalf("age prune: %+v", p)
	}
	clk.Advance(30 * time.Hour)
	if p := e.Prune(); p.Aged < 1 {
		t.Fatalf("new alarms past twice MaxAge: %+v", p)
	}
	if p := e.Prune(); p != (PruneResult{}) {
		t.Fatalf("nothing left to prune: %+v", p)
	}
}

func TestRetentionCountCapDropsResolvedFirst(t *testing.T) {
	e, clk, _ := newTestEngine(t, func(o *Options) { o.Retention = Retention{MaxCount: 3} })
	var all []Alarm
	for i := 0; i < 6; i++ {
		clk.Advance(time.Minute)
		all = append(all, mustRaise(t, e, Event{Type: "custom", Key: fmt.Sprint(i), DeviceID: dev(i)}))
	}
	e.Resolve(Selector{IDs: ids(all[4], all[5])})
	e.Acknowledge(Selector{IDs: ids(all[3])})
	p := e.Prune()
	if p.Overflow != 3 {
		t.Fatalf("prune: %+v", p)
	}
	for _, i := range []int{4, 5, 3} {
		if _, ok := e.Get(all[i].ID); ok {
			t.Fatalf("alarm %d should have gone first", i)
		}
	}
	for _, i := range []int{0, 1, 2} {
		if _, ok := e.Get(all[i].ID); !ok {
			t.Fatalf("new alarm %d was pruned", i)
		}
	}
}

func TestBulkChangeForLargeBatches(t *testing.T) {
	e, clk, rec := newTestEngine(t, func(o *Options) { o.StormThreshold = -1 })
	for i := 0; i < 130; i++ {
		clk.Advance(time.Second)
		mustRaise(t, e, Event{Type: "custom", Key: fmt.Sprint(i)})
	}
	rec.reset()
	res, err := e.Acknowledge(Selector{All: true})
	if err != nil || res.Changed != 130 {
		t.Fatalf("%+v %v", res, err)
	}
	if got := rec.all(); len(got) != 1 || got[0].Kind != ChangeBulk || got[0].Count != 130 {
		t.Fatalf("a big batch should emit one bulk change, got %d changes", len(got))
	}
}

func TestChildrenAndGetOfMembers(t *testing.T) {
	e, clk, _ := newTestEngine(t)
	for i := 0; i < 8; i++ {
		clk.Advance(time.Millisecond)
		mustRaise(t, e, Event{Type: "custom", DeviceID: dev(1), Key: fmt.Sprint(i)})
	}
	b := e.List(Query{}).Alarms[0]
	kids := e.Children(b.ID)
	if len(kids) != 5 {
		t.Fatalf("kids = %d", len(kids))
	}
	if got, ok := e.Get(kids[0].ID); !ok || got.ParentID != b.ID {
		t.Fatal("member not retrievable")
	}
	if len(e.Children("nope")) != 0 {
		t.Fatal("children of nothing")
	}
	// Members can be selected explicitly even though lists hide them.
	if r, _ := e.Acknowledge(Selector{IDs: []string{kids[0].ID}}); r.Changed != 1 {
		t.Fatalf("%+v", r)
	}
	// Resolving a bundle resolves members, so a new storm can start.
	e.Resolve(Selector{IDs: []string{b.ID}})
	if s := e.Summary(); s.ByState[StateResolved] != 1 {
		t.Fatalf("summary: %+v", s)
	}
}
