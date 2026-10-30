// SPDX-License-Identifier: AGPL-3.0-or-later

package devices

import (
	"sync"
	"testing"
)

type recorder struct {
	mu  sync.Mutex
	evs []Event
}

func (r *recorder) add(e Event) { r.mu.Lock(); r.evs = append(r.evs, e); r.mu.Unlock() }
func (r *recorder) kinds() []EventKind {
	r.mu.Lock()
	defer r.mu.Unlock()
	var k []EventKind
	for _, e := range r.evs {
		k = append(k, e.Kind)
	}
	return k
}

func TestEvents(t *testing.T) {
	r, _ := newReg(t)
	rec := &recorder{}
	unsub := r.Subscribe(rec.add)
	ch, cancel := r.Events(2)

	id := r.Observe(Observation{MAC: macA, IP: "192.0.2.1"})
	r.Observe(Observation{MAC: macA, IP: "192.0.2.1"}) // nothing new: no event
	r.Observe(Observation{Source: SourceMDNS, IP: "192.0.2.1", Hostname: "lamp"})
	r.Rename(id, "Desk Lamp")
	r.SetExcluded(id, true)
	r.CreateGroup("G", "")
	r.RenameGroup("g", "G2")
	r.BulkAssignGroup([]string{id}, "g")
	other := r.Observe(Observation{MAC: macB, IP: "192.0.2.2", Source: SourceDHCP, Hostname: "other"})
	r.Merge(id, other)
	nid, _ := r.Split(id, macB)
	r.Delete(nid)
	r.DeleteGroup("g")

	want := []EventKind{EventNewDevice, EventRenamed, EventRenamed, EventUpdated, EventGroupCreated, EventGroupUpdated,
		EventGroupMembers, EventNewDevice, EventMerged, EventSplit, EventDeleted, EventGroupDeleted, EventGroupMembers}
	got := rec.kinds()
	if len(got) < len(want) {
		t.Fatalf("events %v", got)
	}
	i := 0
	for _, k := range got {
		if i < len(want) && k == want[i] {
			i++
		}
	}
	if i != len(want) {
		t.Fatalf("event sequence mismatch:\n got %v\nwant %v", got, want)
	}
	first := rec.evs[0]
	if first.Kind != EventNewDevice || first.Device == nil || first.Device.ID != id || first.Time.IsZero() || first.NewName == "" {
		t.Fatalf("new-device event: %+v", first)
	}
	if rec.evs[1].OldName != "192.0.2.1" || rec.evs[1].NewName != "lamp" {
		t.Fatalf("rename event: %+v", rec.evs[1])
	}

	// Channel got the first two; the rest were dropped, not blocked.
	if len(ch) != 2 {
		t.Fatalf("channel len %d", len(ch))
	}
	cancel()
	cancel() // idempotent
	if _, ok := <-ch; !ok {
		// drains buffered events first; eventually closed
	}
	for range ch {
	}

	unsub()
	n := len(rec.evs)
	r.Observe(Observation{IP: "192.0.2.50"})
	if len(rec.evs) != n {
		t.Fatal("event after unsubscribe")
	}
	// Buffer below 1 is raised to 1.
	ch2, c2 := r.Events(0)
	r.Observe(Observation{IP: "192.0.2.51"})
	if len(ch2) != 1 {
		t.Fatal("min buffer")
	}
	c2()
}

func TestImportIsSilent(t *testing.T) {
	a, _ := newReg(t)
	a.Observe(Observation{MAC: macA, IP: "192.0.2.1"})
	b, _ := newReg(t)
	rec := &recorder{}
	b.Subscribe(rec.add)
	b.Import(a.Export())
	if len(rec.evs) != 0 {
		t.Fatalf("import emitted %v", rec.kinds())
	}
}

func TestCallbackMayReenterRegistry(t *testing.T) {
	r, _ := newReg(t)
	r.Subscribe(func(e Event) {
		if e.Kind == EventNewDevice {
			r.Len()
			r.SetTags(e.DeviceID, []string{"new"})
		}
	})
	id := r.Observe(Observation{IP: "192.0.2.1"})
	eq(t, mustDevice(t, r, id).Tags, []string{"new"})
}
