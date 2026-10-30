// SPDX-License-Identifier: AGPL-3.0-or-later

package devices

import (
	"errors"
	"testing"
)

func TestEnsureQuarantineGroupIsIdempotentAndFixedID(t *testing.T) {
	r, _ := newReg(t)
	g1 := r.EnsureQuarantineGroup()
	if g1.ID != QuarantineGroupID || g1.Name != "Quarantine" {
		t.Fatalf("first call = %+v", g1)
	}
	g2 := r.EnsureQuarantineGroup()
	if g2.ID != g1.ID || g2.Name != g1.Name || g2.Color != g1.Color {
		t.Errorf("a second call must not change it: %+v vs %+v", g1, g2)
	}
	got, ok := r.GetGroup(QuarantineGroupID)
	if !ok || got.ID != QuarantineGroupID {
		t.Errorf("GetGroup(quarantine) = %+v, %v", got, ok)
	}
	found := false
	for _, g := range r.Groups() {
		if g.ID == QuarantineGroupID {
			found = true
		}
	}
	if !found {
		t.Error("the quarantine group must appear in Groups()")
	}
}

func TestEnsureQuarantineGroupAfterDeletedTombstone(t *testing.T) {
	// A record that exists but is marked Deleted (the shape a sync tombstone
	// or an old data file could leave) must be treated as absent, not reused.
	r, _ := newReg(t)
	r.groups[QuarantineGroupID] = &Group{ID: QuarantineGroupID, Deleted: true}
	g := r.EnsureQuarantineGroup()
	if g.Deleted || g.Name != "Quarantine" {
		t.Errorf("a tombstoned record must be replaced, got %+v", g)
	}
}

func TestQuarantineGroupCannotBeDeletedButCanBeRenamedAndRecolored(t *testing.T) {
	r, _ := newReg(t)
	r.EnsureQuarantineGroup()
	if err := r.DeleteGroup(QuarantineGroupID); !errors.Is(err, ErrReservedGroup) {
		t.Errorf("delete = %v, want ErrReservedGroup", err)
	}
	if got, _ := r.GetGroup(QuarantineGroupID); got.Deleted {
		t.Error("the refused delete must not have touched the group")
	}
	if err := r.RenameGroup(QuarantineGroupID, "Holding Pen"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if err := r.SetGroupColor(QuarantineGroupID, "#ff0000"); err != nil {
		t.Fatalf("recolor: %v", err)
	}
	got, _ := r.GetGroup(QuarantineGroupID)
	if got.Name != "Holding Pen" || got.Color != "#ff0000" {
		t.Errorf("after rename/recolor: %+v", got)
	}

	// An ordinary group is unaffected and still deletable.
	ordinary, err := r.CreateGroup("Kids", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.DeleteGroup(ordinary.ID); err != nil {
		t.Errorf("an ordinary group must still be deletable: %v", err)
	}
}

func TestAssigningToAnotherGroupReleasesQuarantine(t *testing.T) {
	r, clk := newReg(t)
	r.EnsureQuarantineGroup()
	kids, err := r.CreateGroup("Kids", "")
	if err != nil {
		t.Fatal(err)
	}
	id := addDev(t, r, clk, "02:00:5e:00:00:01", "192.0.2.10")

	if res, err := r.BulkAssignGroup([]string{id}, QuarantineGroupID); err != nil || res.Changed != 1 {
		t.Fatalf("enter quarantine: %+v %v", res, err)
	}
	if d := mustDevice(t, r, id); !contains(d.Groups, QuarantineGroupID) {
		t.Fatalf("device not in quarantine: %+v", d)
	}

	res, err := r.BulkAssignGroup([]string{id}, kids.ID)
	if err != nil || res.Changed != 1 {
		t.Fatalf("assign to Kids: %+v %v", res, err)
	}
	d := mustDevice(t, r, id)
	if contains(d.Groups, QuarantineGroupID) {
		t.Errorf("assigning to a real group must release quarantine: %+v", d)
	}
	if !contains(d.Groups, kids.ID) {
		t.Errorf("the device must now be in Kids: %+v", d)
	}

	// Idempotent: assigning to the same group again changes nothing.
	if res, err := r.BulkAssignGroup([]string{id}, kids.ID); err != nil || res.Changed != 0 {
		t.Errorf("repeat assign: %+v %v", res, err)
	}

	// A manual move back into quarantine is still allowed.
	if res, err := r.BulkAssignGroup([]string{id}, QuarantineGroupID); err != nil || res.Changed != 1 {
		t.Fatalf("move back to quarantine: %+v %v", res, err)
	}
	if d := mustDevice(t, r, id); !contains(d.Groups, QuarantineGroupID) {
		t.Errorf("device should be back in quarantine: %+v", d)
	}
	// Being back in quarantine does not remove Kids: only assigning to a
	// *different* real group releases quarantine, quarantine itself does not
	// evict other groups.
	if d := mustDevice(t, r, id); !contains(d.Groups, kids.ID) {
		t.Errorf("re-entering quarantine must not drop Kids: %+v", d)
	}
}

func TestBulkRemoveGroupReleasesQuarantineWithoutAssigningElsewhere(t *testing.T) {
	r, clk := newReg(t)
	r.EnsureQuarantineGroup()
	id := addDev(t, r, clk, "02:00:5e:00:00:01", "192.0.2.10")
	r.BulkAssignGroup([]string{id}, QuarantineGroupID)

	res, err := r.BulkRemoveGroup([]string{id}, QuarantineGroupID)
	if err != nil || res.Changed != 1 {
		t.Fatalf("release: %+v %v", res, err)
	}
	d := mustDevice(t, r, id)
	if contains(d.Groups, QuarantineGroupID) || len(d.Groups) != 0 {
		t.Errorf("released device should be in no group: %+v", d)
	}
}
