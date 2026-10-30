// SPDX-License-Identifier: AGPL-3.0-or-later

package alarms

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// t0 is a Monday, noon UTC.
var t0 = time.Date(2030, 3, 4, 12, 0, 0, 0, time.UTC)

// recorder collects the engine's change stream.
type recorder struct {
	mu sync.Mutex
	cs []Change
}

func (r *recorder) add(c Change) {
	r.mu.Lock()
	r.cs = append(r.cs, c)
	r.mu.Unlock()
}

func (r *recorder) all() []Change {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Change(nil), r.cs...)
}

func (r *recorder) reset() {
	r.mu.Lock()
	r.cs = nil
	r.mu.Unlock()
}

// sends returns the changes that told channels to notify.
func (r *recorder) sends() []Change {
	var out []Change
	for _, c := range r.all() {
		if c.Notify.Send {
			out = append(out, c)
		}
	}
	return out
}

func (r *recorder) kinds(k ChangeKind) []Change {
	var out []Change
	for _, c := range r.all() {
		if c.Kind == k {
			out = append(out, c)
		}
	}
	return out
}

// testPrefs are the defaults with learning off and UTC, so tests control what
// they exercise.
func testPrefs() Preferences {
	p := DefaultPreferences()
	p.Learning.Enabled = false
	p.Timezone = "UTC"
	return p
}

func newTestEngine(t testing.TB, mod ...func(*Options)) (*Engine, *FakeClock, *recorder) {
	t.Helper()
	clk := NewFakeClock(t0)
	var n atomic.Int64
	p := testPrefs()
	o := Options{
		Node: "n1", Clock: clk, Preferences: &p,
		// Tests call Tick themselves; the worker's ticker must not race them.
		TickEvery: 100000 * time.Hour,
		NewID:     func() string { return fmt.Sprintf("%04d", n.Add(1)) },
	}
	for _, m := range mod {
		m(&o)
	}
	e, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	rec := &recorder{}
	e.Subscribe(rec.add)
	return e, clk, rec
}

func mustRaise(t testing.TB, e *Engine, ev Event) Alarm {
	t.Helper()
	a, err := e.RaiseSync(ev)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func dev(n int) string { return fmt.Sprintf("dev-%d", n) }
