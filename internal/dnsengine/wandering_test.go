// SPDX-License-Identifier: AGPL-3.0-or-later

package dnsengine

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// wanderEngine answers 192.0.2.9 for everything and blocks ads.example, so a
// block is unmistakable (0.0.0.0) next to an answer (192.0.2.9).
func wanderEngine(t *testing.T, info DeviceInfo) (*Engine, *fakeNamer) {
	t.Helper()
	var hits atomic.Int32
	pool, err := NewPool([]string{fakeUpstream(t, "192.0.2.9", &hits)})
	if err != nil {
		t.Fatal(err)
	}
	namer := &fakeNamer{}
	namer.set("192.0.2.50", info)
	e := &Engine{Filter: NewFilter(), Pool: pool, Cache: NewCache(100), Log: NewQueryLog(50), Stats: NewStats(), Names: namer}
	e.Filter.SetList("ads", set("ads.example"))
	e.Filter.SetPolicy(PolicyPrivateRelay, policyDomains[PolicyPrivateRelay])
	return e, namer
}

func lookup(t *testing.T, e *Engine, name string) (Entry, *dns.Msg) {
	t.Helper()
	w := udpWriter() // the client is 192.0.2.50
	e.ServeDNS(w, query(name, dns.TypeA))
	all := e.Log.All()
	return all[len(all)-1], w.msgs[0]
}

func answerIP(m *dns.Msg) string {
	if len(m.Answer) == 0 {
		return ""
	}
	if a, ok := m.Answer[0].(*dns.A); ok {
		return a.A.String()
	}
	return ""
}

func TestWanderingDeviceIsNeverFilteredButEveryRequestIsWatched(t *testing.T) {
	e, _ := wanderEngine(t, DeviceInfo{ID: "d-1", Name: "Garage camera", Wandering: true})

	entry, resp := lookup(t, e, "x.ads.example.")
	if answerIP(resp) != "192.0.2.9" {
		t.Fatalf("a wandering device must get the real answer, got %v", resp.Answer)
	}
	if entry.Action != "allowed" || entry.Reason != "wandering" || !entry.Wandering || entry.Shadow != "ads (network)" {
		t.Errorf("entry = action %q reason %q wandering %v shadow %q, want allowed/wandering/true/ads (network)", entry.Action, entry.Reason, entry.Wandering, entry.Shadow)
	}
	if entry.Device != "Garage camera" || entry.DeviceID != "d-1" {
		t.Errorf("the request must still be attributed to the device: %+v", entry)
	}

	// Even the Private Relay policy is not applied: all filtering is off.
	entry, resp = lookup(t, e, "mask.icloud.com.")
	if resp.Rcode != dns.RcodeSuccess || answerIP(resp) != "192.0.2.9" {
		t.Errorf("Private Relay hostnames must resolve for a wandering device, got rcode %d", resp.Rcode)
	}
	if entry.Shadow != PolicyPrivateRelay+" (network)" {
		t.Errorf("the shadow must say the policy would have blocked it, got %q", entry.Shadow)
	}

	// A name nothing would block carries no shadow but is still marked.
	entry, _ = lookup(t, e, "fine.example.")
	if entry.Shadow != "" || !entry.Wandering || entry.Reason != "wandering" {
		t.Errorf("an unblocked name: %+v", entry)
	}

	// Cached answers keep the marker too.
	lookup(t, e, "again.example.")
	entry, _ = lookup(t, e, "again.example.")
	if entry.Action != "cached" || !entry.Wandering {
		t.Errorf("cached entry = %+v", entry)
	}
	if s := e.Stats.Snapshot(); s.Blocked != 0 {
		t.Errorf("nothing from a wandering device may count as blocked, got %d", s.Blocked)
	}
}

func TestWanderingTimerIsHonoredAtQueryTime(t *testing.T) {
	future := time.Now().Add(time.Hour)
	e, namer := wanderEngine(t, DeviceInfo{ID: "d-1", Wandering: true, WanderingUntil: future})
	if _, resp := lookup(t, e, "a.ads.example."); answerIP(resp) != "192.0.2.9" {
		t.Error("a live timer means wandering")
	}
	// The timer runs out: filtering resumes at once, without waiting for any sweep.
	namer.set("192.0.2.50", DeviceInfo{ID: "d-1", Wandering: true, WanderingUntil: time.Now().Add(-time.Second)})
	entry, resp := lookup(t, e, "b.ads.example.")
	if answerIP(resp) != "0.0.0.0" || entry.Action != "blocked" || entry.Wandering || entry.Shadow != "" {
		t.Errorf("an expired timer must mean protected again: %+v answer %v", entry, resp.Answer)
	}
}

func TestExcludedAndWanderingAreDifferentThings(t *testing.T) {
	// Excluded: left alone. No filtering, no shadow, not flagged as wandering.
	e, namer := wanderEngine(t, DeviceInfo{ID: "d-1", Excluded: true})
	entry, resp := lookup(t, e, "x.ads.example.")
	if answerIP(resp) != "192.0.2.9" || entry.Reason != "excluded" || entry.Wandering || entry.Shadow != "" {
		t.Errorf("excluded: %+v", entry)
	}
	// Both set: the watching mode wins, so the shadow is recorded.
	namer.set("192.0.2.50", DeviceInfo{ID: "d-1", Excluded: true, Wandering: true})
	entry, resp = lookup(t, e, "y.ads.example.")
	if answerIP(resp) != "192.0.2.9" || entry.Reason != "wandering" || !entry.Wandering || entry.Shadow != "ads (network)" {
		t.Errorf("excluded and wandering: %+v", entry)
	}
	// Neither: normal protection.
	namer.set("192.0.2.50", DeviceInfo{ID: "d-1"})
	if entry, _ = lookup(t, e, "z.ads.example."); entry.Action != "blocked" {
		t.Errorf("protected: %+v", entry)
	}
}

func TestShadowNamesTheScopeWhenThereIsOne(t *testing.T) {
	e, _ := wanderEngine(t, DeviceInfo{ID: "d-1", Wandering: true})
	// A scoped decision names where it came from, and the shadow keeps that.
	store, err := OpenPolicyStore(t.TempDir()+"/policy.json", e.Filter, PolicyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_ = store
	if err := store.AddRule(Scope{Kind: "network"}, "block", "scoped.example"); err != nil {
		t.Fatal(err)
	}
	entry, resp := lookup(t, e, "scoped.example.")
	if answerIP(resp) != "192.0.2.9" || entry.Shadow == "" {
		t.Errorf("a scoped block must be shadowed, not enforced: %+v", entry)
	}
}

func TestDeviceInfoWanderingHelper(t *testing.T) {
	now := time.Now()
	for name, c := range map[string]struct {
		info DeviceInfo
		want bool
	}{
		"off":              {DeviceInfo{}, false},
		"on, open-ended":   {DeviceInfo{Wandering: true}, true},
		"on, live timer":   {DeviceInfo{Wandering: true, WanderingUntil: now.Add(time.Minute)}, true},
		"on, expired":      {DeviceInfo{Wandering: true, WanderingUntil: now.Add(-time.Minute)}, false},
		"timer but not on": {DeviceInfo{WanderingUntil: now.Add(time.Minute)}, false},
	} {
		if got := c.info.wandering(now); got != c.want {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
}
