// SPDX-License-Identifier: AGPL-3.0-or-later

package devices

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func addDev(t testing.TB, r *Registry, clk *fakeClock, mac, ip string) string {
	t.Helper()
	id := r.Observe(Observation{Source: SourceNeighbor, MAC: mac, IP: ip, Time: clk.Now()})
	if id == "" {
		t.Fatalf("observation of %s rejected", ip)
	}
	return id
}

func TestWanderingTogglesAndIsIdempotent(t *testing.T) {
	r, clk := newReg(t)
	id := addDev(t, r, clk, "02:00:5e:00:00:01", "192.0.2.10")
	until := clk.Now().Add(time.Hour)

	if err := r.SetWandering(id, true, until); err != nil {
		t.Fatal(err)
	}
	if d := mustDevice(t, r, id); !d.Wandering || !d.WanderingUntil.Equal(until) {
		t.Errorf("after on: %+v", d)
	}
	if res := r.BulkSetWandering([]string{id}, true, until); res.Changed != 0 {
		t.Errorf("repeating the same request must change nothing, changed %d", res.Changed)
	}
	later := until.Add(time.Hour)
	if res := r.BulkSetWandering([]string{id}, true, later); res.Changed != 1 || !mustDevice(t, r, id).WanderingUntil.Equal(later) {
		t.Errorf("changing the timer is a change: %+v", res)
	}
	if err := r.SetWandering(id, false, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if d := mustDevice(t, r, id); d.Wandering || !d.WanderingUntil.IsZero() {
		t.Errorf("turning it off must clear the timer: %+v", d)
	}
	if res := r.BulkSetWandering([]string{id}, false, time.Time{}); res.Changed != 0 {
		t.Errorf("turning off twice changed %d", res.Changed)
	}
	if err := r.SetWandering("nope", true, time.Time{}); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown device: %v", err)
	}
	res := r.BulkSetWandering([]string{id, "nope"}, true, time.Time{})
	if res.Changed != 1 || len(res.Missing) != 1 || res.Missing[0] != "nope" {
		t.Errorf("bulk with a missing id: %+v", res)
	}
}

func TestExpireWanderingEndsOnlyTimersThatHaveRunOut(t *testing.T) {
	r, clk := newReg(t)
	timed := addDev(t, r, clk, "02:00:5e:00:00:01", "192.0.2.10")
	open := addDev(t, r, clk, "02:00:5e:00:00:02", "192.0.2.11")
	other := addDev(t, r, clk, "02:00:5e:00:00:03", "192.0.2.12")
	r.SetWandering(timed, true, clk.Now().Add(time.Hour))
	r.SetWandering(open, true, time.Time{})

	if n := r.ExpireWandering(clk.Now()); n != 0 {
		t.Errorf("nothing has run out yet, expired %d", n)
	}
	clk.Advance(61 * time.Minute)
	if n := r.ExpireWandering(clk.Now()); n != 1 {
		t.Errorf("expired %d, want 1", n)
	}
	if mustDevice(t, r, timed).Wandering {
		t.Error("the timed device must be back to protected")
	}
	if !mustDevice(t, r, open).Wandering {
		t.Error("an open-ended device must stay wandering")
	}
	if mustDevice(t, r, other).Wandering {
		t.Error("an untouched device must stay protected")
	}
	if n := r.ExpireWandering(clk.Now().Add(1000 * time.Hour)); n != 0 {
		t.Errorf("open-ended devices never expire, expired %d", n)
	}
}

func TestWanderingSurvivesMergeAndSplit(t *testing.T) {
	r, clk := newReg(t)
	a := addDev(t, r, clk, "02:00:5e:00:00:01", "192.0.2.10")
	b := addDev(t, r, clk, "02:00:5e:00:00:02", "192.0.2.11")
	c := addDev(t, r, clk, "02:00:5e:00:00:03", "192.0.2.12")
	d := addDev(t, r, clk, "02:00:5e:00:00:04", "192.0.2.13")

	// only the source is wandering: it carries over
	r.SetWandering(b, true, clk.Now().Add(2*time.Hour))
	if err := r.Merge(a, b); err != nil {
		t.Fatal(err)
	}
	if got := mustDevice(t, r, a); !got.Wandering || !got.WanderingUntil.Equal(clk.Now().Add(2*time.Hour)) {
		t.Errorf("source-only merge: %+v", got)
	}
	// both timed: the longer wins
	r.SetWandering(c, true, clk.Now().Add(5*time.Hour))
	if err := r.Merge(a, c); err != nil {
		t.Fatal(err)
	}
	if got := mustDevice(t, r, a); !got.WanderingUntil.Equal(clk.Now().Add(5 * time.Hour)) {
		t.Errorf("the longer timer must win: %+v", got)
	}
	// a shorter source does not shorten it
	r.SetWandering(d, true, clk.Now().Add(time.Hour))
	if err := r.Merge(a, d); err != nil {
		t.Fatal(err)
	}
	if got := mustDevice(t, r, a); !got.WanderingUntil.Equal(clk.Now().Add(5 * time.Hour)) {
		t.Errorf("a shorter timer must not win: %+v", got)
	}
	// an open-ended one beats a timed one, from either side
	e := addDev(t, r, clk, "02:00:5e:00:00:05", "192.0.2.14")
	r.SetWandering(e, true, time.Time{})
	if err := r.Merge(a, e); err != nil {
		t.Fatal(err)
	}
	if got := mustDevice(t, r, a); !got.Wandering || !got.WanderingUntil.IsZero() {
		t.Errorf("open-ended must win: %+v", got)
	}
	f := addDev(t, r, clk, "02:00:5e:00:00:06", "192.0.2.15")
	r.SetWandering(f, true, clk.Now().Add(time.Hour))
	if err := r.Merge(a, f); err != nil {
		t.Fatal(err)
	}
	if got := mustDevice(t, r, a); !got.WanderingUntil.IsZero() {
		t.Errorf("a timed source must not end an open-ended device: %+v", got)
	}
	// a source that is not wandering changes nothing
	g := addDev(t, r, clk, "02:00:5e:00:00:07", "192.0.2.16")
	if err := r.Merge(a, g); err != nil || !mustDevice(t, r, a).Wandering {
		t.Errorf("merging a protected device must not end wandering: %v", err)
	}
}

func TestSearchWanderingFilter(t *testing.T) {
	r, clk := newReg(t)
	on := addDev(t, r, clk, "02:00:5e:00:00:01", "192.0.2.10")
	timed := addDev(t, r, clk, "02:00:5e:00:00:02", "192.0.2.11")
	expired := addDev(t, r, clk, "02:00:5e:00:00:03", "192.0.2.12")
	addDev(t, r, clk, "02:00:5e:00:00:04", "192.0.2.13")
	r.SetWandering(on, true, time.Time{})
	r.SetWandering(timed, true, clk.Now().Add(time.Hour))
	r.SetWandering(expired, true, clk.Now().Add(-time.Minute)) // the flag is still stored but the timer has run out

	got := map[string]bool{}
	for _, d := range r.Search("wandering:true", SearchOptions{}).Items {
		got[d.ID] = true
	}
	if len(got) != 2 || !got[on] || !got[timed] {
		t.Errorf("wandering:true = %v, want the open-ended and the live timed device", got)
	}
	if n := r.Search("wandering:false", SearchOptions{}).Total; n != 2 {
		t.Errorf("wandering:false matched %d, want 2 (protected and expired)", n)
	}
	if n := r.Search("-wandering:true", SearchOptions{}).Total; n != 2 {
		t.Errorf("negated filter matched %d", n)
	}
	if n := r.Search("wandering:maybe", SearchOptions{}).Total; n != 0 {
		t.Errorf("a bad value must match nothing, matched %d", n)
	}
}

func TestWanderingPersistsAndReachesTheLookup(t *testing.T) {
	r, clk := newReg(t)
	id := addDev(t, r, clk, "02:00:5e:00:00:01", "192.0.2.10")
	until := clk.Now().Add(3 * time.Hour)
	r.SetWandering(id, true, until)

	l := NewLookup(r)
	defer l.Close()
	info := l.DeviceFor("192.0.2.10")
	if !info.Wandering || !info.WanderingUntil.Equal(until) || info.ID != id {
		t.Errorf("the DNS lookup must carry the mode and timer: %+v", info)
	}
	r.SetWandering(id, false, time.Time{})
	if l.DeviceFor("192.0.2.10").Wandering {
		t.Error("the lookup must follow the registry at once")
	}
	r.SetWandering(id, true, until)

	path := filepath.Join(t.TempDir(), "devices.json")
	if err := r.Save(path); err != nil {
		t.Fatal(err)
	}
	r2, _ := newReg(t)
	if err := r2.Load(path); err != nil {
		t.Fatal(err)
	}
	if d := mustDevice(t, r2, id); !d.Wandering || !d.WanderingUntil.Equal(until) {
		t.Errorf("the mode and timer must survive a restart: %+v", d)
	}
}

func TestSplitCopiesWandering(t *testing.T) {
	r, clk := newReg(t)
	id := addDev(t, r, clk, "02:00:5e:00:00:01", "192.0.2.10")
	second := addDev(t, r, clk, "02:00:5e:00:00:09", "192.0.2.19")
	if err := r.Merge(id, second); err != nil {
		t.Fatal(err)
	}
	r.SetWandering(id, true, time.Time{})
	newID, err := r.Split(id, "02:00:5e:00:00:09", "192.0.2.19")
	if err != nil {
		t.Fatal(err)
	}
	if !mustDevice(t, r, newID).Wandering {
		t.Error("a split-off device keeps its parent's mode")
	}
}
