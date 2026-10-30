// SPDX-License-Identifier: AGPL-3.0-or-later

package alarms

import (
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRaiseFillsDefaults(t *testing.T) {
	e, _, rec := newTestEngine(t)
	a := mustRaise(t, e, Event{Type: TypeNewDevice, DeviceID: dev(1), Evidence: []Evidence{{"Client", "192.0.2.10"}}})
	if a.Title != "New device" || a.Severity != SeverityHigh || a.State != StateNew || a.Count != 1 {
		t.Fatalf("a = %+v", a)
	}
	if a.Key != "new-device|dev-1|" || a.URL != "/alarms/"+a.ID || a.Node != "n1" || a.Updated.Wall == 0 {
		t.Fatalf("a = %+v", a)
	}
	if !a.FirstSeen.Equal(t0) || !a.LastSeen.Equal(t0) {
		t.Fatalf("times: %+v", a)
	}
	cs := rec.all()
	if len(cs) != 1 || cs[0].Kind != ChangeRaised || !cs[0].Notify.Send {
		t.Fatalf("changes = %+v", cs)
	}
	got, ok := e.Get(a.ID)
	if !ok || got.ID != a.ID {
		t.Fatal("get")
	}
	got.Evidence[0].Value = "mutated"
	if again, _ := e.Get(a.ID); again.Evidence[0].Value != "192.0.2.10" {
		t.Fatal("Get must return a copy")
	}
	if _, ok := e.Get("nope"); ok {
		t.Fatal("get nope")
	}
}

func TestRaiseSanitizesInput(t *testing.T) {
	e, _, _ := newTestEngine(t)
	if _, err := e.RaiseSync(Event{}); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("empty: %v", err)
	}
	if _, err := e.RaiseSync(Event{Type: strings.Repeat("x", 65)}); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("long type: %v", err)
	}
	ev := Event{
		Type: "custom", Severity: "bogus", Title: strings.Repeat("t", 500), Body: strings.Repeat("b", 5000),
		Source: strings.Repeat("s", 200), DeviceID: " dev ", Domain: "Tracker.Example.COM.", Key: strings.Repeat("k", 500),
		URL: "https://evil.example.com/", Count: -3,
	}
	for i := 0; i < 30; i++ {
		ev.Evidence = append(ev.Evidence, Evidence{strings.Repeat("l", 100), strings.Repeat("v", 1000)})
		ev.GroupIDs = append(ev.GroupIDs, fmt.Sprint("g", i))
	}
	a := mustRaise(t, e, ev)
	if len(a.Title) != 200 || len(a.Body) != 2000 || len(a.Source) != 64 || a.DeviceID != "dev" || a.Domain != "tracker.example.com" ||
		len(a.Key) != 300 || len(a.Evidence) != 20 || len(a.Evidence[0].Label) != 60 || len(a.Evidence[0].Value) != 300 ||
		len(a.GroupIDs) != 20 || a.Count != 1 || a.Severity != SeverityMedium {
		t.Fatalf("not sanitized: %+v", a)
	}
	if a.URL != "/alarms/"+a.ID {
		t.Fatalf("foreign URL kept: %q", a.URL)
	}
	for _, u := range []string{"//evil.example.com", "/ok\r\nX: y", "/" + strings.Repeat("a", 400)} {
		if b := mustRaise(t, e, Event{Type: "custom", Key: "u" + u[:3], URL: u}); b.URL == u {
			t.Fatalf("url %q kept", u)
		}
	}
	if b := mustRaise(t, e, Event{Type: "custom", Key: "ok", URL: "/devices/dev-1"}); b.URL != "/devices/dev-1" {
		t.Fatalf("route dropped: %q", b.URL)
	}
	// Unregistered types are recorded with a medium default rather than lost.
	if a.Type != "custom" {
		t.Fatal("type")
	}
}

func TestDedupeFoldsRepeatsWithoutRenotifying(t *testing.T) {
	e, clk, rec := newTestEngine(t)
	ev := Event{Type: TypeUpstreamDown, Key: "upstream|pool1", Body: "first"}
	a := mustRaise(t, e, ev)
	clk.Advance(10 * time.Minute)
	ev.Body = "second"
	ev.Evidence = []Evidence{{"Pool", "pool1"}}
	b := mustRaise(t, e, ev)
	if b.ID != a.ID || b.Count != 2 || b.Body != "second" || !b.LastSeen.Equal(t0.Add(10*time.Minute)) || !b.FirstSeen.Equal(t0) {
		t.Fatalf("fold: %+v", b)
	}
	if len(rec.sends()) != 1 {
		t.Fatalf("a repeat must not re-notify: %d sends", len(rec.sends()))
	}
	if up := rec.kinds(ChangeUpdated); len(up) != 1 || up[0].Notify.Send {
		t.Fatalf("updates = %+v", up)
	}
	// Dedupe is measured from the last sighting, so a steady trickle stays one alarm.
	for i := 0; i < 10; i++ {
		clk.Advance(50 * time.Minute)
		mustRaise(t, e, ev)
	}
	if e.Summary().Total != 1 {
		t.Fatal("steady trickle split into several alarms")
	}
	if got, _ := e.Get(a.ID); got.Count != 12 {
		t.Fatalf("count = %d", got.Count)
	}
	// Event.Count adds that many occurrences.
	ev.Count = 5
	if got := mustRaise(t, e, ev); got.Count != 17 {
		t.Fatalf("count = %d", got.Count)
	}
}

func TestDedupeQuietGapAndResolveFireAgain(t *testing.T) {
	e, clk, rec := newTestEngine(t)
	ev := Event{Type: TypeUpstreamDown, Key: "k"}
	a := mustRaise(t, e, ev)
	clk.Advance(time.Hour + time.Second) // a quiet gap longer than the window
	b := mustRaise(t, e, ev)
	if b.ID == a.ID || len(rec.sends()) != 2 {
		t.Fatalf("a quiet gap must fire again: %+v sends=%d", b, len(rec.sends()))
	}
	if _, err := e.Resolve(Selector{IDs: []string{b.ID}}); err != nil {
		t.Fatal(err)
	}
	clk.Advance(time.Second)
	c := mustRaise(t, e, ev)
	if c.ID == b.ID || len(rec.sends()) != 3 {
		t.Fatalf("resolving must let it fire again: %+v sends=%d", c, len(rec.sends()))
	}
	// Disabled dedupe makes every event its own alarm.
	e2, _, _ := newTestEngine(t, func(o *Options) { o.DedupeWindow = -1; o.StormThreshold = -1 })
	x := mustRaise(t, e2, ev)
	y := mustRaise(t, e2, ev)
	if x.ID == y.ID {
		t.Fatal("dedupe should be off")
	}
}

func TestDedupeEscalation(t *testing.T) {
	e, clk, rec := newTestEngine(t)
	a := mustRaise(t, e, Event{Type: "custom", Key: "k", Severity: SeverityLow})
	e.Acknowledge(Selector{IDs: []string{a.ID}})
	clk.Advance(time.Minute)
	b := mustRaise(t, e, Event{Type: "custom", Key: "k", Severity: SeverityCritical})
	if b.ID != a.ID || b.Severity != SeverityCritical || b.State != StateNew {
		t.Fatalf("escalated: %+v", b)
	}
	esc := rec.kinds(ChangeEscalated)
	if len(esc) != 1 || !esc[0].Notify.Send {
		t.Fatalf("escalation must notify once: %+v", esc)
	}
	// The same or a lower severity afterwards does not.
	mustRaise(t, e, Event{Type: "custom", Key: "k", Severity: SeverityCritical})
	mustRaise(t, e, Event{Type: "custom", Key: "k", Severity: SeverityLow})
	if len(rec.kinds(ChangeEscalated)) != 1 {
		t.Fatal("repeat re-escalated")
	}
	// A muted alarm stays quiet even if it escalates.
	m := mustRaise(t, e, Event{Type: "custom", Key: "m", Severity: SeverityLow})
	e.Snooze(m.ID, MuteSpec{Preset: MuteHour})
	rec.reset()
	mustRaise(t, e, Event{Type: "custom", Key: "m", Severity: SeverityCritical})
	if len(rec.sends()) != 0 {
		t.Fatal("muted alarm notified on escalation")
	}
}

// TestEscalationUnarchives: an archived alarm that comes back worse deserves
// to resurface, so a dedupe repeat that escalates its severity also clears
// Archived (see Alarm.Archived's doc comment).
func TestEscalationUnarchives(t *testing.T) {
	e, clk, _ := newTestEngine(t)
	a := mustRaise(t, e, Event{Type: "custom", Key: "k", Severity: SeverityLow})
	if _, err := e.Archive(Selector{IDs: []string{a.ID}}); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.Get(a.ID); !got.Archived {
		t.Fatalf("archive did not stick: %+v", got)
	}
	clk.Advance(time.Minute)
	b := mustRaise(t, e, Event{Type: "custom", Key: "k", Severity: SeverityCritical})
	if b.ID != a.ID || b.Archived || !b.ArchivedAt.IsZero() {
		t.Fatalf("escalated repeat must unarchive: %+v", b)
	}
	// A repeat at the same or a lower severity leaves an archived alarm alone.
	if _, err := e.Archive(Selector{IDs: []string{a.ID}}); err != nil {
		t.Fatal(err)
	}
	c := mustRaise(t, e, Event{Type: "custom", Key: "k", Severity: SeverityCritical})
	if !c.Archived {
		t.Fatalf("non-escalating repeat should leave Archived alone: %+v", c)
	}
}

// Property: for any sequence of events over a few keys, with storm control
// off, every event is accounted for in exactly one alarm's count, every alarm
// notified exactly once, and an alarm is never created while an open alarm
// with the same key was seen inside the window.
func TestDedupeProperty(t *testing.T) {
	for seed := int64(1); seed <= 40; seed++ {
		rng := rand.New(rand.NewSource(seed))
		window := 30 * time.Minute
		e, clk, rec := newTestEngine(t, func(o *Options) { o.DedupeWindow = window; o.StormThreshold = -1 })
		events := 0
		lastSeen := map[string]time.Time{}
		for i := 0; i < 200; i++ {
			clk.Advance(time.Duration(rng.Intn(40*60)) * time.Second)
			key := fmt.Sprint("k", rng.Intn(4))
			if rng.Intn(15) == 0 {
				for _, a := range e.List(Query{Filter: Filter{States: []State{StateNew}}, Limit: 500}).Alarms {
					if a.Key == key {
						e.Resolve(Selector{IDs: []string{a.ID}})
						delete(lastSeen, key)
					}
				}
			}
			before := e.Summary().Total
			a := mustRaise(t, e, Event{Type: "custom", Key: key, Severity: SeverityHigh})
			events++
			created := e.Summary().Total > before
			if seen, open := lastSeen[key]; open && clk.Now().Sub(seen) <= window && created {
				t.Fatalf("seed %d: created a duplicate inside the window", seed)
			}
			lastSeen[key] = a.LastSeen
		}
		total := 0
		for _, a := range e.List(Query{Limit: 500, Filter: Filter{IncludeChildren: true}}).Alarms {
			total += a.Count
		}
		if total != events {
			t.Fatalf("seed %d: counts sum to %d, want %d", seed, total, events)
		}
		if got, want := len(rec.sends()), e.Summary().Total; got != want {
			t.Fatalf("seed %d: %d notifications for %d alarms", seed, got, want)
		}
	}
}

func TestStormControlBundlesABurst(t *testing.T) {
	e, clk, rec := newTestEngine(t)
	for i := 0; i < 47; i++ {
		clk.Advance(100 * time.Millisecond)
		mustRaise(t, e, Event{Type: TypeBlockedSpike, DeviceID: dev(1), Key: fmt.Sprint("k", i), Title: fmt.Sprint("blocked ", i)})
	}
	page := e.List(Query{})
	if page.Total != 1 {
		t.Fatalf("visible alarms = %d, want one bundle", page.Total)
	}
	b := page.Alarms[0]
	if !b.Bundle || b.Count != 47 || b.Title != "47 similar alerts: Blocked-query spike" || b.DeviceID != dev(1) {
		t.Fatalf("bundle = %+v", b)
	}
	kids := e.Children(b.ID)
	if len(kids) != 5 || kids[0].ParentID != b.ID {
		t.Fatalf("children = %d", len(kids))
	}
	if all := e.List(Query{Filter: Filter{IncludeChildren: true}}); all.Total != 6 {
		t.Fatalf("with children: %d", all.Total)
	}
	if s := e.Summary(); s.Total != 1 || s.ByState[StateNew] != 1 {
		t.Fatalf("summary: %+v", s)
	}
	// Five individual alerts, then one bundle that notifies once.
	if got := len(rec.sends()); got != 6 {
		t.Fatalf("%d notifications for a 47-alarm storm, want 6", got)
	}
	if up := rec.kinds(ChangeUpdated); len(up) == 0 {
		t.Fatal("no updates")
	}
	// Other devices and other types are separate storms.
	mustRaise(t, e, Event{Type: TypeBlockedSpike, DeviceID: dev(2), Key: "x"})
	mustRaise(t, e, Event{Type: TypeDNSErrorSpike, DeviceID: dev(1), Key: "y"})
	if e.List(Query{}).Total != 3 {
		t.Fatal("unrelated alarms were bundled")
	}
	// After a quiet gap the same bucket starts over.
	clk.Advance(5 * time.Minute)
	n := mustRaise(t, e, Event{Type: TypeBlockedSpike, DeviceID: dev(1), Key: "later"})
	if n.Bundle || n.ID == b.ID {
		t.Fatalf("after the gap: %+v", n)
	}
	// Acknowledging the bundle acknowledges its members.
	res, err := e.Acknowledge(Selector{IDs: []string{b.ID}})
	if err != nil || res.Changed != 1 {
		t.Fatalf("ack: %+v %v", res, err)
	}
	for _, k := range e.Children(b.ID) {
		if k.State != StateAcknowledged {
			t.Fatalf("member state %s", k.State)
		}
	}
	// Deleting the bundle deletes its members.
	e.Delete(Selector{IDs: []string{b.ID}})
	if _, ok := e.Get(kids[0].ID); ok {
		t.Fatal("member survived")
	}
}

func TestStormControlProperty(t *testing.T) {
	for seed := int64(1); seed <= 30; seed++ {
		rng := rand.New(rand.NewSource(seed))
		thr := 2 + rng.Intn(6)
		e, clk, rec := newTestEngine(t, func(o *Options) { o.StormThreshold = thr; o.StormWindow = time.Minute })
		events := 0
		bursts := 0
		for b := 0; b < 5; b++ {
			bursts++
			n := rng.Intn(60) + 1
			for i := 0; i < n; i++ {
				clk.Advance(time.Duration(rng.Intn(500)) * time.Millisecond)
				mustRaise(t, e, Event{Type: TypeBlockedSpike, DeviceID: dev(1), Key: fmt.Sprint("k", b, "-", i)})
				events++
			}
			clk.Advance(2 * time.Minute) // a quiet gap ends the storm
		}
		if got := len(rec.sends()); got > bursts*(thr+1) {
			t.Fatalf("seed %d: %d notifications for %d bursts at threshold %d", seed, got, bursts, thr)
		}
		// Nothing is lost: counts of the visible alarms add up to the events.
		sum := 0
		for _, a := range e.List(Query{Limit: 500}).Alarms {
			sum += a.Count
		}
		if sum != events {
			t.Fatalf("seed %d: visible counts %d, events %d", seed, sum, events)
		}
	}
}

func TestStormSeverityAndMuting(t *testing.T) {
	e, _, rec := newTestEngine(t)
	sevs := []Severity{SeverityLow, SeverityLow, SeverityCritical, SeverityLow, SeverityLow, SeverityLow}
	for i, s := range sevs {
		mustRaise(t, e, Event{Type: "custom", DeviceID: dev(1), Key: fmt.Sprint(i), Severity: s})
	}
	b := e.List(Query{}).Alarms[0]
	if !b.Bundle || b.Severity != SeverityCritical {
		t.Fatalf("bundle severity: %+v", b)
	}
	// A bundle matching a mute rule is recorded muted and does not notify.
	e2, _, rec2 := newTestEngine(t)
	e2.CreateRule(RuleSpec{Match: RuleMatch{DeviceIDs: []string{dev(1)}}, Duration: MuteSpec{Preset: MuteForever}})
	for i := 0; i < 9; i++ {
		mustRaise(t, e2, Event{Type: "custom", DeviceID: dev(1), Key: fmt.Sprint(i)})
	}
	if len(rec2.sends()) != 0 {
		t.Fatal("muted storm notified")
	}
	if s := e2.Summary(); s.ByState[StateMuted] != 1 {
		t.Fatalf("summary: %+v", s)
	}
	_ = rec
}

func TestAsyncRaiseDrainAndDrops(t *testing.T) {
	block := make(chan struct{})
	started := make(chan struct{}, 1)
	e, _, _ := newTestEngine(t, func(o *Options) { o.Queue = 4 })
	var once sync.Once
	e.Subscribe(func(Change) {
		once.Do(func() { started <- struct{}{}; <-block })
	})
	if !e.Raise(Event{Type: "custom", Key: "first"}) {
		t.Fatal("first raise")
	}
	<-started // the worker is now stuck inside a subscriber
	accepted := 0
	for i := 0; i < 20; i++ {
		if e.Raise(Event{Type: "custom", Key: fmt.Sprint("k", i)}) {
			accepted++
		}
	}
	if accepted != 4 || e.Dropped() != 16 {
		t.Fatalf("accepted %d dropped %d", accepted, e.Dropped())
	}
	if e.Summary().Dropped != 16 {
		t.Fatal("summary drop counter")
	}
	close(block)
	e.Drain()
	if e.Summary().Total != 5 {
		t.Fatalf("total = %d", e.Summary().Total)
	}
	e.Close()
	if e.Raise(Event{Type: "custom"}) || e.Dropped() != 17 {
		t.Fatal("raise after close must drop")
	}
	e.Drain() // returns instead of hanging
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRaiseIsNonBlockingUnderConcurrency(t *testing.T) {
	e, _, _ := newTestEngine(t, func(o *Options) { o.Queue = 64 })
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				e.Raise(Event{Type: "custom", Key: fmt.Sprint(g, "-", i%20)})
				e.Summary()
				e.List(Query{Limit: 10})
			}
		}()
	}
	wg.Wait()
	e.Drain()
	if e.Summary().Total == 0 {
		t.Fatal("nothing recorded")
	}
}

func TestEventTimeAndDeviceFirstSeen(t *testing.T) {
	e, clk, _ := newTestEngine(t)
	past := t0.Add(-time.Hour)
	a := mustRaise(t, e, Event{Type: "custom", Key: "p", Time: past})
	if !a.FirstSeen.Equal(past) {
		t.Fatalf("event time ignored: %v", a.FirstSeen)
	}
	future := mustRaise(t, e, Event{Type: "custom", Key: "f", Time: t0.Add(time.Hour)})
	if !future.FirstSeen.Equal(clk.Now()) {
		t.Fatal("a future event time must be clamped to now")
	}
	e.NoteDeviceSeen("", t0)
	e.NoteDeviceSeen(dev(9), t0.Add(-time.Hour))
	e.NoteDeviceSeen(dev(9), t0) // first call wins
	e.mu.Lock()
	got := e.deviceSeen[dev(9)]
	e.mu.Unlock()
	if !got.Equal(t0.Add(-time.Hour)) {
		t.Fatalf("device seen = %v", got)
	}
}

func TestSubscribeAndEventsChannel(t *testing.T) {
	e, _, _ := newTestEngine(t)
	var n int
	unsub := e.Subscribe(func(Change) { n++ })
	ch, cancel := e.Events(2)
	mustRaise(t, e, Event{Type: "custom", Key: "a"})
	unsub()
	mustRaise(t, e, Event{Type: "custom", Key: "b"})
	mustRaise(t, e, Event{Type: "custom", Key: "c"})
	mustRaise(t, e, Event{Type: "custom", Key: "d"}) // channel full: dropped, never blocks
	if n != 1 {
		t.Fatalf("unsubscribed callback ran %d times", n)
	}
	if len(ch) != 2 {
		t.Fatalf("buffered %d", len(ch))
	}
	cancel()
	cancel()
	for range ch {
	}
	mustRaise(t, e, Event{Type: "custom", Key: "e"}) // no panic after close
	if _, c2 := e.Events(0); c2 == nil {
		t.Fatal("cancel")
	}
}

func TestTypeRegistry(t *testing.T) {
	e, _, _ := newTestEngine(t)
	if got := len(e.Types()); got != len(BuiltinTypes()) {
		t.Fatalf("types = %d", got)
	}
	want := map[string]struct {
		sev   Severity
		learn bool
	}{
		TypeNewDevice: {SeverityHigh, true}, TypeDeviceLeft: {SeverityLow, true}, TypeUpstreamDown: {SeverityHigh, false},
		TypeUpstreamRecovered: {SeverityLow, false}, TypeListUpdateRejected: {SeverityMedium, false},
		TypeHistoryLocked: {SeverityMedium, false}, TypeHistoryError: {SeverityMedium, false}, TypeMapDataFailed: {SeverityLow, false},
		TypeDNSErrorSpike: {SeverityMedium, true}, TypeBlockedSpike: {SeverityLow, true}, TypePrivateRelay: {SeverityInfo, false},
		TypePortOpened: {SeverityHigh, true}, TypeNewInboundExposure: {SeverityCritical, false}, TypeThreatMatch: {SeverityCritical, false},
		TypeSelfUpdate: {SeverityLow, false}, TypeVulnerabilityFound: {SeverityHigh, false}, TypeTest: {SeverityHigh, false},
	}
	for id, w := range want {
		ty, ok := e.Type(id)
		if !ok || ty.DefaultSeverity != w.sev || ty.LearningSuppresses != w.learn || !ty.Builtin || ty.Title == "" || ty.Description == "" || len(ty.Channels) == 0 {
			t.Errorf("%s: %+v", id, ty)
		}
	}
	if ty, _ := e.Type(TypePrivateRelay); len(ty.Channels) != 1 || ty.Channels[0] != ChannelPortal {
		t.Fatalf("private relay channels: %v", ty.Channels)
	}
	if ty, _ := e.Type(TypeTest); !ty.Bypass {
		t.Fatal("test must bypass")
	}
	if err := e.Register(AlarmType{ID: "ports.risky-service", Title: "Risky service", DefaultSeverity: SeverityHigh}); err != nil {
		t.Fatal(err)
	}
	if ty, ok := e.Type("ports.risky-service"); !ok || ty.Builtin || len(ty.Channels) != 3 {
		t.Fatalf("registered: %+v", ty)
	}
	bad := map[string]AlarmType{
		"dup":      {ID: "ports.risky-service", Title: "x", DefaultSeverity: SeverityLow},
		"builtin":  {ID: TypeNewDevice, Title: "x", DefaultSeverity: SeverityLow},
		"bad id":   {ID: "Has Space", Title: "x", DefaultSeverity: SeverityLow},
		"no title": {ID: "ok-id", DefaultSeverity: SeverityLow},
		"bad sev":  {ID: "ok-id", Title: "x", DefaultSeverity: "huge"},
		"channel":  {ID: "ok-id", Title: "x", DefaultSeverity: SeverityLow, Channels: []string{"fax"}},
	}
	for name, ty := range bad {
		if err := e.Register(ty); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if err := e.Register(bad["builtin"]); !errors.Is(err, ErrBuiltinType) {
		t.Fatal(err)
	}
	if err := e.Register(bad["dup"]); !errors.Is(err, ErrTypeExists) {
		t.Fatal(err)
	}
	if err := e.Register(bad["bad id"]); !errors.Is(err, ErrInvalidType) {
		t.Fatal(err)
	}
	if _, ok := e.Type("nope"); ok {
		t.Fatal("unknown type found")
	}
	// A registered type is used by Raise.
	a := mustRaise(t, e, Event{Type: "ports.risky-service"})
	if a.Severity != SeverityHigh || a.Title != "Risky service" {
		t.Fatalf("a = %+v", a)
	}
}

func TestSeverityHelpers(t *testing.T) {
	if !SeverityCritical.AtLeast(SeverityHigh) || SeverityLow.AtLeast(SeverityHigh) || Severity("x").AtLeast(SeverityInfo) || SeverityInfo.AtLeast("x") {
		t.Fatal("AtLeast")
	}
	if s, ok := ParseSeverity(" HIGH "); !ok || s != SeverityHigh {
		t.Fatal("parse")
	}
	if _, ok := ParseSeverity("urgent"); ok {
		t.Fatal("parse bogus")
	}
	if len(Severities()) != 5 || Severity("x").Rank() != -1 {
		t.Fatal("severities")
	}
	if !StateMuted.Valid() || State("x").Valid() {
		t.Fatal("state valid")
	}
}
