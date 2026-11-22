// SPDX-License-Identifier: AGPL-3.0-or-later

package namesync

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// fake is a Source held in memory.
type fake struct {
	id string

	mu      sync.Mutex
	entries []Entry
	ro      string
	max     int
	readErr error
	// renameErr fails every rename; stale makes a rename succeed without
	// changing what Entries returns, like a service answering from a cache.
	renameErr error
	stale     bool
	renames   []string // "mac=name"
}

func (f *fake) ID() string       { return f.id }
func (f *fake) Label() string    { return strings.ToUpper(f.id[:1]) + f.id[1:] }
func (f *fake) MaxLen() int      { return f.max }
func (f *fake) ReadOnly() string { f.mu.Lock(); defer f.mu.Unlock(); return f.ro }
func (f *fake) Entries(context.Context) ([]Entry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Entry(nil), f.entries...), f.readErr
}
func (f *fake) Rename(_ context.Context, e Entry, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.renameErr != nil {
		return f.renameErr
	}
	f.renames = append(f.renames, e.MAC+"="+name)
	if f.stale {
		return nil
	}
	for i := range f.entries {
		if f.entries[i].MAC == e.MAC {
			f.entries[i].Name = name
			// A name written from outside is one somebody chose.
			if f.entries[i].Learned {
				f.entries[i].Learned, f.entries[i].Typed = false, true
			}
		}
	}
	return nil
}

func (f *fake) set(mac, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.entries {
		if f.entries[i].MAC == mac {
			f.entries[i].Name = name
			return
		}
	}
	f.entries = append(f.entries, Entry{MAC: mac, Name: name})
}

func (f *fake) name(mac string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range f.entries {
		if e.MAC == mac {
			return e.Name
		}
	}
	return ""
}

func (f *fake) wrote() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.renames...)
}

const (
	macA = "02005e000001"
	macB = "02005e000002"
	macC = "02005e000003"
)

type rig struct {
	t         *testing.T
	e         *Engine
	now       time.Time
	shep, eer *fake
	fw        *fake
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{t: t, now: time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC),
		shep: &fake{id: "shepherd"}, eer: &fake{id: "eero"}, fw: &fake{id: "firewalla", max: 32}}
	r.e = New(Options{
		Sources: func() []Source { return []Source{r.shep, r.eer, r.fw} },
		Now:     func() time.Time { return r.now },
	})
	return r
}

func (r *rig) sync() Report {
	r.t.Helper()
	rep, err := r.e.Sync(context.Background())
	if err != nil {
		r.t.Fatalf("Sync: %v", err)
	}
	return rep
}

func (r *rig) preview() Report {
	r.t.Helper()
	rep, err := r.e.Preview(context.Background())
	if err != nil {
		r.t.Fatalf("Preview: %v", err)
	}
	return rep
}

func (r *rig) wantNames(mac, name string) {
	r.t.Helper()
	for _, f := range []*fake{r.shep, r.eer, r.fw} {
		if got := f.name(mac); got != name {
			r.t.Errorf("%s calls %s %q, want %q", f.id, mac, got, name)
		}
	}
}

func TestFirstSyncKeepsTheMostReadableName(t *testing.T) {
	r := newRig(t)
	// A: eero has the name a person typed; the others have junk.
	r.shep.entries = append(r.shep.entries, Entry{MAC: macA, Name: "ESP_4F21C0", Learned: true})
	r.eer.entries = append(r.eer.entries, Entry{MAC: macA, Name: "Kitchen plug", Typed: true})
	r.fw.entries = append(r.fw.entries, Entry{MAC: macA, Name: "02005E00A1B2"})
	// B: only Shepherd knows what it is, from mDNS.
	r.shep.entries = append(r.shep.entries, Entry{MAC: macB, Name: "Sam’s MacBook Pro", Learned: true})
	r.eer.entries = append(r.eer.entries, Entry{MAC: macB, Name: "", Learned: true})
	r.fw.entries = append(r.fw.entries, Entry{MAC: macB, Name: "Mac-K7QZ4T9XWB"})
	// C: nobody knows; a maker's name is not worth copying.
	r.shep.entries = append(r.shep.entries, Entry{MAC: macC, Name: "", Learned: true})
	r.eer.entries = append(r.eer.entries, Entry{MAC: macC, Name: "Unknown"})
	r.fw.entries = append(r.fw.entries, Entry{MAC: macC, Name: "ExampleCo Networks", Vendor: "ExampleCo Networks"})

	pre := r.preview()
	if !pre.DryRun || pre.Written != 4 || len(pre.Changes) != 2 {
		t.Fatalf("preview = %+v", pre)
	}
	if len(r.shep.wrote())+len(r.eer.wrote())+len(r.fw.wrote()) != 0 {
		t.Fatal("a preview wrote something")
	}
	if st := r.e.Status(); st.Last != nil || len(st.Log) != 0 {
		t.Fatalf("a preview left a mark: %+v", st)
	}

	rep := r.sync()
	if rep.DryRun || rep.Written != 4 || rep.Failed != 0 || rep.Held != 0 {
		t.Fatalf("sync = %+v", rep)
	}
	r.wantNames(macA, "Kitchen plug")
	r.wantNames(macB, "Sam’s MacBook Pro")
	if r.fw.name(macC) != "ExampleCo Networks" || r.eer.name(macC) != "Unknown" || r.shep.name(macC) != "" {
		t.Error("a device nobody has named was renamed")
	}
	a := rep.Changes[0]
	if a.MAC != macA || a.Reason != "first" || a.From != "eero" || a.Names["firewalla"] != "02005E00A1B2" ||
		!reflect.DeepEqual(a.Writes, []string{"shepherd", "firewalla"}) {
		t.Errorf("change = %+v", a)
	}
	if len(rep.Sources) != 3 || rep.Sources[2].Label != "Firewalla" || rep.Sources[2].Devices != 3 {
		t.Errorf("sources = %+v", rep.Sources)
	}

	// Run again: everything agrees, nothing is written.
	again := r.sync()
	if again.Written != 0 || len(again.Changes) != 0 || again.InSync != 2 {
		t.Fatalf("second sync = %+v", again)
	}
	st := r.e.Status()
	if st.Last == nil || len(st.Log) != 4 || st.Log[0].Old == st.Log[0].New {
		t.Fatalf("status = %+v", st)
	}
}

func TestATieGoesToTheEarlierSource(t *testing.T) {
	r := newRig(t)
	r.shep.entries = []Entry{{MAC: macA, Name: "Den TV", Typed: true}}
	r.eer.entries = []Entry{{MAC: macA, Name: "Living room TV", Typed: true}}
	r.fw.entries = []Entry{{MAC: macA, Name: "Lounge television"}}
	r.sync()
	r.wantNames(macA, "Den TV")
}

func TestAnEditAnywhereIsWrittenEverywhere(t *testing.T) {
	r := newRig(t)
	for _, f := range []*fake{r.shep, r.eer, r.fw} {
		f.entries = []Entry{{MAC: macA, Name: "Kitchen plug"}}
	}
	r.sync()

	for i, f := range []*fake{r.fw, r.eer, r.shep} {
		name := []string{"Coffee maker", "Espresso machine", "Kettle"}[i]
		r.now = r.now.Add(time.Hour)
		f.set(macA, name)
		rep := r.sync()
		if rep.Written != 2 || rep.Changes[0].Reason != "edit" || rep.Changes[0].From != f.id {
			t.Fatalf("after editing on %s: %+v", f.id, rep)
		}
		r.wantNames(macA, name)
	}
}

func TestTwoEditsAtOnceKeepTheMoreReadable(t *testing.T) {
	r := newRig(t)
	for _, f := range []*fake{r.shep, r.eer, r.fw} {
		f.entries = []Entry{{MAC: macA, Name: "Plug"}}
	}
	r.sync()
	r.now = r.now.Add(time.Hour)
	r.eer.set(macA, "XP200M")
	r.fw.set(macA, "Kitchen plug")
	r.sync()
	r.wantNames(macA, "Kitchen plug")
}

func TestClearingANameOrAHostnameChangingIsNotAnEdit(t *testing.T) {
	r := newRig(t)
	r.shep.entries = []Entry{{MAC: macA, Name: "Kitchen plug", Typed: true}, {MAC: macB, Name: "Den TV", Learned: true}}
	r.eer.entries = []Entry{{MAC: macA, Name: "Kitchen plug"}, {MAC: macB, Name: "Den TV"}}
	r.fw.entries = []Entry{{MAC: macA, Name: "Kitchen plug"}, {MAC: macB, Name: "Den TV"}}
	r.sync()

	r.now = r.now.Add(time.Hour)
	// Somebody blanks the name on eero; a device re-announces itself with
	// a new hostname in Shepherd, where nobody typed anything.
	r.eer.set(macA, "")
	r.shep.mu.Lock()
	r.shep.entries[1].Name = "Den-TV-2"
	r.shep.mu.Unlock()
	rep := r.sync()
	if rep.Written != 2 {
		t.Fatalf("sync = %+v", rep)
	}
	for _, c := range rep.Changes {
		if c.Reason != "catchup" {
			t.Errorf("change = %+v", c)
		}
	}
	r.wantNames(macA, "Kitchen plug")
	r.wantNames(macB, "Den TV")
}

func TestAReadOnlyPlaceIsReadAndCaughtUpLater(t *testing.T) {
	r := newRig(t)
	r.fw.ro = "Allow changes is off"
	r.shep.entries = []Entry{{MAC: macA, Name: "Kitchen plug", Typed: true}}
	r.eer.entries = []Entry{{MAC: macA, Name: "XP200M"}}
	r.fw.entries = []Entry{{MAC: macA, Name: "XP200M"}}
	rep := r.sync()
	if rep.Written != 1 || rep.Held != 1 || !reflect.DeepEqual(rep.Changes[0].Held, []string{"firewalla"}) || rep.Sources[2].ReadOnly == "" {
		t.Fatalf("sync = %+v", rep)
	}
	if r.fw.name(macA) != "XP200M" || len(r.fw.wrote()) != 0 {
		t.Fatal("a read-only place was written")
	}

	// An edit on the read-only place still goes out to the others.
	r.now = r.now.Add(time.Hour)
	r.fw.set(macA, "Coffee maker")
	r.sync()
	if r.shep.name(macA) != "Coffee maker" || r.eer.name(macA) != "Coffee maker" {
		t.Fatal("an edit on a read-only place was not read")
	}

	// And once it can be written, it is caught up.
	r.now = r.now.Add(time.Hour)
	r.shep.set(macA, "Espresso machine")
	r.sync()
	r.fw.mu.Lock()
	r.fw.ro = ""
	r.fw.mu.Unlock()
	r.now = r.now.Add(time.Hour)
	rep = r.sync()
	if rep.Written != 1 || rep.Changes[0].Reason != "catchup" {
		t.Fatalf("catch-up = %+v", rep)
	}
	r.wantNames(macA, "Espresso machine")
}

func TestALongNameIsCutForAPlaceThatLimitsIt(t *testing.T) {
	r := newRig(t)
	long := "The television in the upstairs guest bedroom"
	r.shep.entries = []Entry{{MAC: macA, Name: long, Typed: true}}
	r.eer.entries = []Entry{{MAC: macA, Name: "TV"}}
	r.fw.entries = []Entry{{MAC: macA, Name: "TV"}}
	r.sync()
	if got := r.fw.name(macA); got != long[:32] {
		t.Fatalf("firewalla got %q", got)
	}
	// The cut name is not an edit, and is not written again.
	r.now = r.now.Add(time.Hour)
	if rep := r.sync(); rep.Written != 0 || rep.InSync != 1 {
		t.Fatalf("second sync = %+v", rep)
	}
	if r.shep.name(macA) != long || r.eer.name(macA) != long {
		t.Fatal("the cut name came back as an edit")
	}
}

func TestAStaleAnswerAfterAWriteIsNotAnEditBack(t *testing.T) {
	r := newRig(t)
	r.shep.entries = []Entry{{MAC: macA, Name: "Kitchen plug", Typed: true}}
	r.eer.entries = []Entry{{MAC: macA, Name: "XP200M"}}
	r.fw.entries = []Entry{{MAC: macA, Name: "Kitchen plug"}}
	r.eer.stale = true
	r.sync()
	if got := r.eer.wrote(); len(got) != 1 {
		t.Fatalf("wrote %v", got)
	}

	// eero still answers with the old name: nothing is reverted, and it is
	// not written again while the answer may only be late.
	r.now = r.now.Add(2 * time.Minute)
	if rep := r.sync(); rep.Written != 0 || len(rep.Changes) != 0 {
		t.Fatalf("stale sync = %+v", rep)
	}
	if r.shep.name(macA) != "Kitchen plug" || r.fw.name(macA) != "Kitchen plug" {
		t.Fatal("a stale answer reverted the name")
	}

	// A new name in the meantime is still sent: only a repeat is held back.
	r.shep.set(macA, "Coffee maker")
	if rep := r.sync(); rep.Written != 2 || rep.Changes[0].Reason != "edit" {
		t.Fatalf("edit during the window = %+v", rep)
	}
	r.shep.set(macA, "Kitchen plug")
	r.now = r.now.Add(time.Minute)
	r.sync()

	// Past the window the write is taken not to have stuck, and is retried.
	r.now = r.now.Add(echoWindow)
	r.eer.mu.Lock()
	r.eer.stale = false
	r.eer.mu.Unlock()
	r.sync()
	r.now = r.now.Add(time.Minute)
	r.sync()
	r.wantNames(macA, "Kitchen plug")
}

func TestARefusedNameIsReportedAndLeftAloneForAWhile(t *testing.T) {
	r := newRig(t)
	r.shep.entries = []Entry{{MAC: macA, Name: "Kitchen plug", Typed: true}}
	r.eer.entries = []Entry{{MAC: macA, Name: "XP200M"}}
	r.fw.entries = []Entry{{MAC: macA, Name: "Kitchen plug"}}
	r.eer.renameErr = errors.New("HTTP 500")
	rep := r.sync()
	if rep.Failed != 1 || rep.Written != 0 || rep.Changes[0].Failed["eero"] != "HTTP 500" {
		t.Fatalf("sync = %+v", rep)
	}

	r.eer.mu.Lock()
	r.eer.renameErr = nil
	r.eer.mu.Unlock()
	r.now = r.now.Add(time.Minute)
	if rep := r.sync(); rep.Held != 1 || rep.Written != 0 {
		t.Fatalf("retried too soon: %+v", rep)
	}
	r.now = r.now.Add(retryAfter)
	if rep := r.sync(); rep.Written != 1 {
		t.Fatalf("not retried: %+v", rep)
	}
	r.wantNames(macA, "Kitchen plug")
}

func TestAPlaceThatCannotBeReadIsLeftOut(t *testing.T) {
	r := newRig(t)
	r.shep.entries = []Entry{{MAC: macA, Name: "Kitchen plug", Typed: true}}
	r.eer.entries = []Entry{{MAC: macA, Name: "XP200M"}}
	r.fw.entries = []Entry{{MAC: macA, Name: "XP200M"}, {MAC: "", Name: "VPN profile"}}
	r.eer.readErr = errors.New("the session has expired")
	rep := r.sync()
	if rep.Sources[1].Error != "the session has expired" || rep.Written != 1 || r.fw.name(macA) != "Kitchen plug" {
		t.Fatalf("sync = %+v", rep)
	}
	if len(r.eer.wrote()) != 0 {
		t.Fatal("an unreadable place was written")
	}
	// When it is back it is new here, so the best name is chosen afresh.
	r.eer.readErr = nil
	r.now = r.now.Add(time.Hour)
	r.sync()
	r.wantNames(macA, "Kitchen plug")
}

func TestADeviceListedTwiceKeepsItsBetterName(t *testing.T) {
	r := newRig(t)
	r.shep.entries = []Entry{{MAC: macA, Name: "", Learned: true}}
	r.eer.entries = []Entry{{MAC: macA, Name: "XP200M"}, {MAC: macA, Name: "Kitchen plug"}, {MAC: macA, Name: "Unknown"}}
	r.fw.entries = nil
	r.sync()
	if r.shep.name(macA) != "Kitchen plug" {
		t.Fatalf("shepherd got %q", r.shep.name(macA))
	}
}

func TestSyncNeedsTwoPlaces(t *testing.T) {
	e := New(Options{Sources: func() []Source { return []Source{&fake{id: "shepherd"}} }})
	if _, err := e.Sync(context.Background()); !errors.Is(err, ErrNothingToSync) {
		t.Fatalf("err = %v", err)
	}
	if _, err := New(Options{}).Preview(context.Background()); !errors.Is(err, ErrNothingToSync) {
		t.Fatalf("err = %v", err)
	}
	if e.Status().Running {
		t.Fatal("still marked running")
	}
}

func TestACancelledRunWritesNothingMore(t *testing.T) {
	r := newRig(t)
	r.shep.entries = []Entry{{MAC: macA, Name: "Kitchen plug", Typed: true}}
	r.eer.entries = []Entry{{MAC: macA, Name: "XP200M"}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rep, err := r.e.Sync(ctx)
	if err != nil || rep.Failed != 1 || len(r.eer.wrote()) != 0 {
		t.Fatalf("rep = %+v, err = %v", rep, err)
	}
}

func TestStateSurvivesARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "names.json")
	r := newRig(t)
	r.e = New(Options{Sources: r.e.o.Sources, Now: r.e.o.Now, StatePath: path})
	for _, f := range []*fake{r.shep, r.eer, r.fw} {
		f.entries = []Entry{{MAC: macA, Name: "Kitchen plug"}}
	}
	r.sync()
	if err := r.e.SetAuto(true); err != nil {
		t.Fatal(err)
	}

	// A new engine remembers what it saw, so an edit made while it was
	// down is still an edit, not a first sync.
	r.eer.set(macA, "TV")
	r.e = New(Options{Sources: r.e.o.Sources, Now: r.e.o.Now, StatePath: path})
	if !r.e.Status().Auto {
		t.Fatal("the switch was forgotten")
	}
	r.now = r.now.Add(time.Hour)
	rep := r.sync()
	if rep.Written != 2 || rep.Changes[0].Reason != "edit" {
		t.Fatalf("sync = %+v", rep)
	}
	r.wantNames(macA, "TV")
	if len(r.e.Status().Log) != 2 {
		t.Fatalf("log = %+v", r.e.Status().Log)
	}
}

func TestUnreadableOrEmptyStateStartsAgain(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	var logged []string
	e := New(Options{StatePath: bad, Logf: func(f string, a ...any) { logged = append(logged, f) }})
	if e.st.Base == nil || len(logged) != 1 {
		t.Fatalf("state = %+v, logged %v", e.st, logged)
	}
	empty := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(empty, []byte(`{"auto":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	e = New(Options{StatePath: empty})
	if !e.st.Auto || e.st.Base == nil || e.st.Seen == nil || e.st.Pending == nil {
		t.Fatalf("state = %+v", e.st)
	}
}

func TestStateThatCannotBeKeptIsReported(t *testing.T) {
	r := newRig(t)
	var logged []string
	r.e = New(Options{Sources: r.e.o.Sources, Now: r.e.o.Now, StatePath: filepath.Join(t.TempDir(), "missing", "names.json"),
		Logf: func(f string, a ...any) { logged = append(logged, f) }})
	r.shep.entries = []Entry{{MAC: macA, Name: "Kitchen plug"}}
	r.eer.entries = []Entry{{MAC: macA, Name: "Kitchen plug"}}
	r.sync()
	if len(logged) != 1 || !strings.Contains(logged[0], "keeping state") {
		t.Fatalf("logged %v", logged)
	}
	if err := r.e.SetAuto(false); err == nil {
		t.Fatal("SetAuto hid the failure")
	}
}

func TestTheLogIsCapped(t *testing.T) {
	r := newRig(t)
	r.shep.entries = []Entry{{MAC: macA, Name: "a b"}}
	r.eer.entries = []Entry{{MAC: macA, Name: "a b"}}
	r.fw.entries = nil
	r.sync()
	for i := 0; i < maxLog+5; i++ {
		r.now = r.now.Add(time.Hour)
		r.shep.set(macA, "Name number "+strings.Repeat("x", i%7)+string(rune('a'+i%26)))
		r.sync()
	}
	if n := len(r.e.Status().Log); n != maxLog {
		t.Fatalf("log holds %d", n)
	}
}

// waitFor polls until ok, so the Run tests do not depend on timing.
func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for i := 0; i < 400; i++ {
		if ok() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestRunSyncsOnTheIntervalAndAfterAKickOnlyWhileSwitchedOn(t *testing.T) {
	shep := &fake{id: "shepherd", entries: []Entry{{MAC: macA, Name: "Kitchen plug", Typed: true}}}
	eer := &fake{id: "eero", entries: []Entry{{MAC: macA, Name: "XP200M"}}}
	var mu sync.Mutex
	var logged []string
	e := New(Options{
		Sources:  func() []Source { return []Source{shep, eer} },
		Interval: time.Hour, KickDelay: time.Millisecond,
		Logf: func(f string, a ...any) { mu.Lock(); logged = append(logged, f); mu.Unlock() },
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.Run(ctx); close(done) }()

	// Off: a kick does nothing.
	e.Kick()
	e.Kick() // a second kick while one is waiting is dropped, not queued
	time.Sleep(30 * time.Millisecond)
	if len(eer.wrote()) != 0 {
		t.Fatal("synced while switched off")
	}
	// On: switching it on kicks a run.
	if err := e.SetAuto(true); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the first run", func() bool { return eer.name(macA) == "Kitchen plug" })
	waitFor(t, "the run to be logged", func() bool { mu.Lock(); defer mu.Unlock(); return len(logged) == 1 })

	shep.set(macA, "Coffee maker")
	e.Kick()
	waitFor(t, "the kicked run", func() bool { return eer.name(macA) == "Coffee maker" })
	cancel()
	<-done
}

func TestRunReportsARunThatCannotStartAndStopsDuringTheSettle(t *testing.T) {
	var mu sync.Mutex
	var logged []string
	e := New(Options{Interval: 5 * time.Millisecond, KickDelay: time.Hour,
		Logf: func(f string, a ...any) { mu.Lock(); logged = append(logged, f); mu.Unlock() }})
	e.st.Auto = true
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.Run(ctx); close(done) }()
	waitFor(t, "the failed run to be logged", func() bool { mu.Lock(); defer mu.Unlock(); return len(logged) > 0 })
	e.Kick()
	time.Sleep(20 * time.Millisecond)
	cancel()
	<-done
}

func TestStartRunsInTheBackgroundOnce(t *testing.T) {
	shep := &fake{id: "shepherd", entries: []Entry{{MAC: macA, Name: "Kitchen plug", Typed: true}}}
	eer := &fake{id: "eero", entries: []Entry{{MAC: macA, Name: "XP200M"}}}
	e := New(Options{Sources: func() []Source { return []Source{shep, eer} }})
	// Hold the run lock so the first Start is still "running" for the second.
	e.run.Lock()
	if !e.Start(context.Background()) {
		t.Fatal("Start refused")
	}
	if e.Start(context.Background()) {
		t.Fatal("a second Start ran beside the first")
	}
	if !e.Status().Running {
		t.Fatal("not marked running")
	}
	e.run.Unlock()
	waitFor(t, "the background run", func() bool { return eer.name(macA) == "Kitchen plug" && !e.Status().Running })

	var logged int
	var mu sync.Mutex
	lone := New(Options{Logf: func(string, ...any) { mu.Lock(); logged++; mu.Unlock() }})
	lone.Start(context.Background())
	waitFor(t, "the failure to be logged", func() bool { mu.Lock(); defer mu.Unlock(); return logged == 1 })
}

func TestNamesThatDifferOnlyInCaseOrPunctuationAlreadyMatch(t *testing.T) {
	r := newRig(t)
	r.shep.entries = []Entry{{MAC: macA, Name: "xp200m", Learned: true}, {MAC: macB, Name: "Sam's  Laptop", Typed: true}}
	r.eer.entries = []Entry{{MAC: macA, Name: "XP200M"}, {MAC: macB, Name: "Sam’s Laptop"}}
	r.fw.entries = []Entry{{MAC: macA, Name: "Xp200M"}, {MAC: macB, Name: "sam's laptop"}}
	if rep := r.sync(); rep.Written != 0 || len(rep.Changes) != 0 || rep.InSync != 2 {
		t.Fatalf("sync = %+v", rep)
	}
	// Changing only the case later is not an edit either.
	r.now = r.now.Add(time.Hour)
	r.eer.set(macA, "xP200m")
	if rep := r.sync(); rep.Written != 0 {
		t.Fatalf("a change of case was written: %+v", rep)
	}
	// A real rename still is.
	r.now = r.now.Add(time.Hour)
	r.eer.set(macA, "Desk lamp plug")
	r.sync()
	r.wantNames(macA, "Desk lamp plug")
}

// groupRank is how a membership sync ranks values: being in a group beats
// being in none, and no group is better than another.
func groupRank(e Entry) int {
	if e.Name == "" {
		return Useless
	}
	return Machine
}

func newGroupRig(t *testing.T) *rig {
	r := newRig(t)
	r.e = New(Options{Sources: r.e.o.Sources, Now: r.e.o.Now, Rank: groupRank, ClearIsEdit: true})
	return r
}

func TestWithClearIsEditRemovingAValueRemovesItEverywhere(t *testing.T) {
	r := newGroupRig(t)
	// The first sync: a device in a group in one place joins it in the
	// others; "KP" style readability plays no part.
	r.shep.entries = []Entry{{MAC: macA, Name: "Smart Home"}, {MAC: macB, Name: ""}}
	r.eer.entries = []Entry{{MAC: macA, Name: ""}, {MAC: macB, Name: ""}}
	r.fw.entries = []Entry{{MAC: macA, Name: ""}, {MAC: macB, Name: "Q404"}}
	rep := r.sync()
	if rep.Written != 4 {
		t.Fatalf("first sync = %+v", rep)
	}
	r.wantNames(macA, "Smart Home")
	r.wantNames(macB, "Q404")

	// A run later, the writes are seen to have stuck.
	r.now = r.now.Add(time.Minute)
	if rep := r.sync(); rep.Written != 0 || rep.InSync != 2 {
		t.Fatalf("settling = %+v", rep)
	}

	// Taking the device out of its group in one place takes it out everywhere.
	r.now = r.now.Add(time.Hour)
	r.fw.set(macA, "")
	rep = r.sync()
	if rep.Written != 2 || rep.Changes[0].Reason != "edit" || rep.Changes[0].From != "firewalla" || rep.Changes[0].Name != "" {
		t.Fatalf("after a removal = %+v", rep)
	}
	r.wantNames(macA, "")

	// "No group" is then the agreed state: nothing to write, and it counts
	// as matching.
	r.now = r.now.Add(time.Hour)
	if rep := r.sync(); rep.Written != 0 || rep.InSync != 2 {
		t.Fatalf("settled = %+v", rep)
	}

	// A removal and a move at once: the move wins, whichever came first.
	r.now = r.now.Add(time.Hour)
	r.shep.set(macB, "")
	r.eer.set(macB, "Blaine")
	r.sync()
	r.wantNames(macB, "Blaine")
}

func TestWithClearIsEditAnAgreedEmptyValueIsCaughtUpLater(t *testing.T) {
	r := newGroupRig(t)
	for _, f := range []*fake{r.shep, r.eer, r.fw} {
		f.entries = []Entry{{MAC: macA, Name: "Smart Home"}}
	}
	r.sync()
	// The removal cannot reach a read-only place yet.
	r.fw.ro = "Allow changes is off"
	r.now = r.now.Add(time.Hour)
	r.shep.set(macA, "")
	rep := r.sync()
	if rep.Written != 1 || rep.Held != 1 || r.fw.name(macA) != "Smart Home" {
		t.Fatalf("held removal = %+v", rep)
	}
	r.fw.mu.Lock()
	r.fw.ro = ""
	r.fw.mu.Unlock()
	r.now = r.now.Add(time.Hour)
	rep = r.sync()
	if rep.Written != 1 || rep.Changes[0].Reason != "catchup" {
		t.Fatalf("catch-up = %+v", rep)
	}
	r.wantNames(macA, "")
}
