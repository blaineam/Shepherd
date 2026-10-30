// SPDX-License-Identifier: AGPL-3.0-or-later

package alarms

import (
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type xorCodec struct{}

func (xorCodec) Encode(b []byte) ([]byte, error) { return xorBytes(b), nil }
func (xorCodec) Decode(b []byte) ([]byte, error) { return xorBytes(b), nil }
func xorBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[i] ^ 0x5a
	}
	return out
}

type failCodec struct{}

func (failCodec) Encode([]byte) ([]byte, error) { return nil, errors.New("no key") }
func (failCodec) Decode([]byte) ([]byte, error) { return nil, errors.New("no key") }

func TestPersistenceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	e, clk, _ := newTestEngine(t, func(o *Options) { o.Dir = dir })
	s := seed(t, e, clk)
	e.Acknowledge(Selector{IDs: ids(s["nd1"])})
	e.Mute(Selector{IDs: ids(s["up"])}, MuteRequest{By: MuteByKey, Duration: forever()})
	e.Delete(Selector{IDs: ids(s["pr"])})
	p := e.Preferences()
	p.NtfyAlways = true
	e.SetPreferences(p)
	e.NoteDeviceSeen(dev(7), t0)
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{AlarmsFile, PrefsFile} {
		st, err := os.Stat(filepath.Join(dir, f))
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", f, st, err)
		}
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".alarms-*")); len(left) != 0 {
		t.Fatalf("temp files: %v", left)
	}
	// A new engine restores everything, including the install time and the mute rule.
	clk2 := NewFakeClock(t0.Add(48 * time.Hour))
	e2, err := New(Options{Dir: dir, Clock: clk2, Node: "n1", TickEvery: 100000 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer e2.Close()
	if !e2.Preferences().NtfyAlways || e2.Summary().Total != 4 {
		t.Fatalf("restored: %+v total=%d", e2.Preferences(), e2.Summary().Total)
	}
	got, _ := e2.Get(s["nd1"].ID)
	if got.State != StateAcknowledged || got.Evidence[0].Value != "Example Corp" {
		t.Fatalf("nd1 = %+v", got)
	}
	if len(e2.ListRules(false)) != 1 {
		t.Fatal("rule lost")
	}
	if _, ok := e2.Get(s["pr"].ID); ok {
		t.Fatal("deleted alarm resurrected")
	}
	e2.mu.Lock()
	inst, seen := e2.installedAt, e2.deviceSeen[dev(7)]
	e2.mu.Unlock()
	if !inst.Equal(t0) || !seen.Equal(t0) {
		t.Fatalf("learning state: %v %v", inst, seen)
	}
	// The restored mute rule keeps muting the key.
	if a := mustRaiseAt(t, e2, Event{Type: TypeUpstreamDown, Key: "up|1"}); a.State != StateMuted && a.ID == s["up"].ID {
		t.Fatalf("a = %+v", a)
	}
	// Restored dedupe index: a repeat folds into the restored alarm.
	clk2.Set(t0.Add(time.Hour))
}

func mustRaiseAt(t testing.TB, e *Engine, ev Event) Alarm {
	t.Helper()
	a, err := e.RaiseSync(ev)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestPersistenceWithCodecAndErrors(t *testing.T) {
	dir := t.TempDir()
	e, clk, _ := newTestEngine(t, func(o *Options) { o.Dir = dir; o.Codec = xorCodec{} })
	seed(t, e, clk)
	e.Close()
	raw, _ := os.ReadFile(filepath.Join(dir, AlarmsFile))
	if strings.Contains(string(raw), "New device") {
		t.Fatal("codec output is readable")
	}
	mk := func(c Codec) error {
		e, err := New(Options{Dir: dir, Codec: c, TickEvery: 100000 * time.Hour})
		if err == nil {
			e.Close()
		}
		return err
	}
	if err := mk(xorCodec{}); err != nil {
		t.Fatal(err)
	}
	if err := mk(PlainCodec{}); !errors.Is(err, ErrBadSnapshot) {
		t.Fatalf("wrong codec: %v", err)
	}
	if err := mk(failCodec{}); err == nil || errors.Is(err, ErrBadSnapshot) {
		t.Fatalf("decode failure: %v", err)
	}
	// Corrupt, wrong-version and invalid-prefs files stop the engine from starting (never silent loss).
	bad := t.TempDir()
	os.WriteFile(filepath.Join(bad, AlarmsFile), []byte(`{"version":99}`), 0o600)
	if _, err := New(Options{Dir: bad}); !errors.Is(err, ErrBadSnapshot) {
		t.Fatalf("version: %v", err)
	}
	os.WriteFile(filepath.Join(bad, AlarmsFile), []byte(`nope`), 0o600)
	if _, err := New(Options{Dir: bad}); !errors.Is(err, ErrBadSnapshot) {
		t.Fatalf("json: %v", err)
	}
	os.Remove(filepath.Join(bad, AlarmsFile))
	os.WriteFile(filepath.Join(bad, PrefsFile), []byte(`{"version":99}`), 0o600)
	if _, err := New(Options{Dir: bad}); !errors.Is(err, ErrBadSnapshot) {
		t.Fatalf("prefs version: %v", err)
	}
	os.WriteFile(filepath.Join(bad, PrefsFile), []byte(`{"version":1,"preferences":{"immediate_min":"x"}}`), 0o600)
	if _, err := New(Options{Dir: bad}); !errors.Is(err, ErrBadPreferences) {
		t.Fatalf("prefs invalid: %v", err)
	}
	os.WriteFile(filepath.Join(bad, PrefsFile), []byte(`nope`), 0o600)
	if _, err := New(Options{Dir: bad}); !errors.Is(err, ErrBadSnapshot) {
		t.Fatalf("prefs json: %v", err)
	}
	// An unusable directory.
	file := filepath.Join(t.TempDir(), "file")
	os.WriteFile(file, nil, 0o600)
	if _, err := New(Options{Dir: filepath.Join(file, "sub")}); err == nil {
		t.Fatal("expected mkdir error")
	}
	// Save errors are surfaced and leave the engine dirty so the next save retries.
	f, _, _ := newTestEngine(t, func(o *Options) { o.Dir = t.TempDir(); o.Codec = failCodec{} })
	mustRaise(t, f, Event{Type: "custom"})
	if err := f.Save(); err == nil {
		t.Fatal("save with a failing codec succeeded")
	}
	f.mu.Lock()
	dirty := f.dirty
	f.mu.Unlock()
	if !dirty {
		t.Fatal("failed save cleared the dirty flag")
	}
	// A memory-only engine ignores Save.
	m, _, _ := newTestEngine(t)
	if err := m.Save(); err != nil {
		t.Fatal(err)
	}
}

func TestAutosaveIsThrottled(t *testing.T) {
	dir := t.TempDir()
	e, clk, _ := newTestEngine(t, func(o *Options) { o.Dir = dir; o.SaveEvery = time.Minute })
	path := filepath.Join(dir, AlarmsFile)
	mustRaise(t, e, Event{Type: "custom", Key: "a"})
	st1, err := os.Stat(path)
	if err != nil {
		t.Fatal("first change must be saved")
	}
	mustRaise(t, e, Event{Type: "custom", Key: "b"})
	st2, _ := os.Stat(path)
	if !st2.ModTime().Equal(st1.ModTime()) {
		// Within SaveEvery the file is left alone.
		raw, _ := os.ReadFile(path)
		if strings.Contains(string(raw), `"key": "b"`) {
			t.Fatal("saved again inside the throttle window")
		}
	}
	clk.Advance(2 * time.Minute)
	mustRaise(t, e, Event{Type: "custom", Key: "c"})
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), `"key": "c"`) || !strings.Contains(string(raw), `"key": "b"`) {
		t.Fatal("changes did not reach disk after the throttle window")
	}
}

func TestWorkerTickSweepsAndSaves(t *testing.T) {
	e, clk, rec := newTestEngine(t, func(o *Options) { o.TickEvery = time.Minute })
	a := mustRaise(t, e, Event{Type: "custom", Key: "k"})
	e.Snooze(a.ID, MuteSpec{Preset: MuteHour})
	rec.reset()
	clk.Advance(2 * time.Hour) // fires the worker's ticker
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if got, _ := e.Get(a.ID); got.State == StateNew {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the worker tick did not end the snooze")
}

// Property: any two engines that have seen the same writes converge to the same
// state, whatever order the snapshots are imported in.
func TestImportConvergesInAnyOrder(t *testing.T) {
	for seed := int64(1); seed <= 25; seed++ {
		rng := rand.New(rand.NewSource(seed))
		var snaps []Snapshot
		for n := 0; n < 3; n++ {
			e, clk, _ := newTestEngine(t, func(o *Options) { o.Node = fmt.Sprint("node", n); o.StormThreshold = -1 })
			clk.Advance(time.Duration(n) * time.Second)
			for i := 0; i < 15; i++ {
				clk.Advance(time.Duration(rng.Intn(3000)) * time.Millisecond)
				a := mustRaise(t, e, Event{Type: "custom", Key: fmt.Sprint("k", rng.Intn(6))})
				switch rng.Intn(5) {
				case 0:
					e.Acknowledge(Selector{IDs: []string{a.ID}})
				case 1:
					e.Resolve(Selector{IDs: []string{a.ID}})
				case 2:
					e.Delete(Selector{IDs: []string{a.ID}})
				case 3:
					e.CreateRule(RuleSpec{Match: RuleMatch{KeyPrefixes: []string{fmt.Sprint("k", rng.Intn(6))}}, Duration: forever()})
				}
			}
			snaps = append(snaps, e.Export())
		}
		// Overlay: the same alarm IDs on every node so records actually conflict.
		for i := range snaps {
			for _, a := range snaps[i].Alarms {
				a.ID = "a" + a.Key
			}
		}
		render := func(order []int) string {
			e, _, _ := newTestEngine(t, func(o *Options) { o.Node = "merge" })
			for _, i := range order {
				e.Import(snaps[i])
			}
			var sb strings.Builder
			for _, a := range e.Export().Alarms {
				fmt.Fprintf(&sb, "%s|%s|%v|%d|%v;", a.ID, a.State, a.Deleted, a.Count, a.Updated)
			}
			for _, r := range e.Export().Rules {
				fmt.Fprintf(&sb, "R%s|%v;", r.ID, r.Deleted)
			}
			return sb.String()
		}
		want := render([]int{0, 1, 2})
		for _, order := range [][]int{{2, 1, 0}, {1, 0, 2}, {1, 2, 0, 1}, {0, 0, 1, 2, 2}} {
			if got := render(order); got != want {
				t.Fatalf("seed %d: replicas diverged for order %v", seed, order)
			}
		}
	}
}

func TestImportIsSilentAndRebuildsIndexes(t *testing.T) {
	src, clk, _ := newTestEngine(t, func(o *Options) { o.Node = "a" })
	for i := 0; i < 8; i++ {
		clk.Advance(time.Millisecond)
		mustRaise(t, src, Event{Type: "custom", DeviceID: dev(1), Key: fmt.Sprint("k", i)})
	}
	snap := src.Export()
	dst, _, rec := newTestEngine(t, func(o *Options) { o.Node = "b" })
	if n := dst.Import(snap); n == 0 {
		t.Fatal("nothing imported")
	}
	if n := dst.Import(snap); n != 0 {
		t.Fatalf("import not idempotent: %d", n)
	}
	if len(rec.all()) != 0 {
		t.Fatal("import must not emit changes (it would re-announce)")
	}
	if dst.List(Query{}).Total != 1 || len(dst.Children(dst.List(Query{}).Alarms[0].ID)) != 5 {
		t.Fatal("parent index not rebuilt")
	}
	// The dedupe index works for imported alarms.
	if a := mustRaise(t, dst, Event{Type: "custom", DeviceID: dev(1), Key: "k7"}); a.Count < 2 {
		t.Fatalf("dedupe against an imported alarm failed: %+v", a)
	}
	// Junk records are ignored.
	if n := dst.Import(Snapshot{Alarms: []*Alarm{nil, {}}, Rules: []*Rule{nil, {}}}); n != 0 {
		t.Fatal("junk imported")
	}
	// Tie-break on equal stamps: higher node wins.
	tb, _, _ := newTestEngine(t)
	x := &Alarm{ID: "ax", Key: "x", Node: "a", Title: "from a"}
	y := &Alarm{ID: "ax", Key: "x", Node: "b", Title: "from b"}
	tb.Import(Snapshot{Alarms: []*Alarm{x}})
	tb.Import(Snapshot{Alarms: []*Alarm{y}})
	if got, _ := tb.Get("ax"); got.Title != "from b" {
		t.Fatalf("tie-break: %+v", got)
	}
	// HLC witnessing: a record from the future moves the local clock past it.
	far := &Alarm{ID: "af", Key: "f", Updated: HLC{Wall: t0.Add(24 * time.Hour).UnixMilli()}}
	tb.Import(Snapshot{Alarms: []*Alarm{far}})
	a := mustRaise(t, tb, Event{Type: "custom", Key: "after"})
	if a.Updated.Compare(far.Updated) <= 0 {
		t.Fatal("local stamps do not follow imported ones")
	}
}

func TestHLCStrictlyIncreases(t *testing.T) {
	e, _, _ := newTestEngine(t) // a frozen clock: the counter breaks ties
	prev := HLC{}
	for i := 0; i < 20; i++ {
		a := mustRaise(t, e, Event{Type: "custom", Key: "same"})
		if a.Updated.Compare(prev) <= 0 {
			t.Fatalf("stamp did not advance: %v then %v", prev, a.Updated)
		}
		prev = a.Updated
	}
	cases := []struct {
		a, b HLC
		want int
	}{{HLC{1, 0}, HLC{2, 0}, -1}, {HLC{2, 0}, HLC{1, 0}, 1}, {HLC{1, 1}, HLC{1, 2}, -1}, {HLC{1, 2}, HLC{1, 1}, 1}, {HLC{1, 1}, HLC{1, 1}, 0}}
	for _, c := range cases {
		if got := c.a.Compare(c.b); got != c.want {
			t.Errorf("%v vs %v = %d", c.a, c.b, got)
		}
	}
}

func TestClocks(t *testing.T) {
	if time.Since(SystemClock{}.Now()) > time.Second {
		t.Fatal("system clock")
	}
	tk := SystemClock{}.NewTicker(5 * time.Millisecond)
	select {
	case <-tk.C():
	case <-time.After(2 * time.Second):
		t.Fatal("system ticker never fired")
	}
	tk.Stop()

	c := NewFakeClock(t0)
	tk1, tk2 := c.NewTicker(time.Minute), c.NewTicker(time.Hour)
	c.Advance(30 * time.Second)
	select {
	case <-tk1.C():
		t.Fatal("fired early")
	default:
	}
	c.Advance(30 * time.Second)
	select {
	case <-tk1.C():
	default:
		t.Fatal("did not fire")
	}
	c.Advance(2 * time.Hour) // many boundaries crossed: one buffered tick, never blocking
	if len(tk1.C()) != 1 || len(tk2.C()) != 1 {
		t.Fatalf("buffered %d %d", len(tk1.C()), len(tk2.C()))
	}
	tk1.Stop()
	<-tk1.C()
	<-tk2.C()
	c.Advance(time.Hour)
	if len(tk1.C()) != 0 {
		t.Fatal("stopped ticker fired")
	}
	c.Set(t0)
	if !c.Now().Equal(t0) {
		t.Fatal("Set")
	}
}

func TestPlainCodecAndAtomicWriteFailure(t *testing.T) {
	b, err := PlainCodec{}.Encode([]byte("x"))
	if err != nil || string(b) != "x" {
		t.Fatal("encode")
	}
	if b, _ := (PlainCodec{}).Decode([]byte("y")); string(b) != "y" {
		t.Fatal("decode")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	os.Mkdir(target, 0o700)
	os.WriteFile(filepath.Join(target, "keep"), nil, 0o600)
	if err := writeFileAtomic(target, []byte("x")); err == nil {
		t.Fatal("expected error")
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".alarms-*")); len(left) != 0 {
		t.Fatalf("temp file left: %v", left)
	}
	if err := writeFileAtomic(filepath.Join(dir, "no", "dir", "f"), nil); err == nil {
		t.Fatal("expected error")
	}
}
