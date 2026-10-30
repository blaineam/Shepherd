// SPDX-License-Identifier: AGPL-3.0-or-later

package devices

import (
	"errors"
	"strings"
	"testing"
)

func seed(t testing.TB, r *Registry) (a, b, c string) {
	t.Helper()
	a = r.Observe(Observation{MAC: macA, IP: "192.0.2.1"})
	b = r.Observe(Observation{MAC: vmac, IP: "192.0.2.2"})
	c = r.Observe(Observation{Source: SourceDNS, IP: "192.0.2.3"})
	return
}

func TestRenameSetNotesTypeExcludedTags(t *testing.T) {
	r, _ := newReg(t)
	a, _, _ := seed(t, r)

	if err := r.Rename(a, "  Hall Camera "); err != nil {
		t.Fatal(err)
	}
	d := mustDevice(t, r, a)
	eq(t, d.Alias, "Hall Camera")
	eq(t, d.Type, TypeCamera) // guessed from the alias
	if err := r.Rename(a, "Hall Camera"); err != nil {
		t.Fatal(err) // no-op
	}
	if err := r.Rename(a, strings.Repeat("x", 200)); !errors.Is(err, ErrInvalid) {
		t.Fatal("long alias accepted")
	}
	if err := r.Rename("nope", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing device")
	}
	if err := r.Rename(a, ""); err != nil {
		t.Fatal(err)
	}
	eq(t, mustDevice(t, r, a).Alias, "")

	for _, f := range []func() error{
		func() error { return r.SetNotes(a, "n") },
		func() error { return r.SetExcluded(a, true) },
		func() error { return r.SetTags(a, []string{"B", " a ", "b", ""}) },
	} {
		if err := f(); err != nil {
			t.Fatal(err)
		}
	}
	d = mustDevice(t, r, a)
	eq(t, d.Notes, "n")
	if !d.Excluded || !r.IsExcluded(a) || r.IsExcluded("nope") {
		t.Fatal("excluded")
	}
	eq(t, d.Tags, []string{"a", "b"})
	// Unchanged writes are no-ops.
	_ = r.SetNotes(a, "n")
	_ = r.SetTags(a, []string{"a", "b"})
	if r.SetNotes("nope", "") == nil || r.SetTags("nope", nil) == nil || r.SetExcluded("nope", true) == nil {
		t.Fatal("missing device accepted")
	}

	if err := r.SetType(a, "tv"); err != nil {
		t.Fatal(err)
	}
	if err := r.SetType(a, "tv"); err != nil {
		t.Fatal(err)
	}
	d = mustDevice(t, r, a)
	if d.Type != TypeTV || !d.TypeUser {
		t.Fatalf("type override: %+v", d)
	}
	// Discovery must not overwrite a user-set type.
	r.Observe(Observation{MAC: macA, Services: []string{"_ipp._tcp"}})
	eq(t, mustDevice(t, r, a).Type, TypeTV)
	if err := r.SetType(a, "auto"); err != nil {
		t.Fatal(err)
	}
	eq(t, mustDevice(t, r, a).Type, TypePrinter)
	if err := r.SetType(a, ""); err != nil { // already auto
		t.Fatal(err)
	}
	if err := r.SetType(a, "toaster"); !errors.Is(err, ErrInvalid) {
		t.Fatal("bad type")
	}
	if err := r.SetType("nope", "tv"); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing")
	}
}

func TestDeleteAndResurrect(t *testing.T) {
	r, _ := newReg(t)
	a, b, _ := seed(t, r)
	if err := r.Delete(a); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Get(a); ok || r.Len() != 2 {
		t.Fatal("not deleted")
	}
	if dev, _ := r.ScopesFor("192.0.2.1"); dev != "" {
		t.Fatal("deleted device still scoped")
	}
	if err := r.Delete(a); !errors.Is(err, ErrNotFound) {
		t.Fatal("double delete")
	}
	// Seen again: a fresh device.
	a2 := r.Observe(Observation{MAC: macA, IP: "192.0.2.1"})
	if d := mustDevice(t, r, a2); d.Alias != "" || len(d.MACs) != 1 {
		t.Fatalf("resurrected with stale data: %+v", d)
	}
	_ = b
}

func TestGroupsCRUD(t *testing.T) {
	r, _ := newReg(t)
	a, b, c := seed(t, r)
	kids, err := r.CreateGroup("Kids", "#ff8800")
	if err != nil || kids.ID != "kids" {
		t.Fatalf("%v %+v", err, kids)
	}
	if _, err := r.CreateGroup("kids", ""); !errors.Is(err, ErrDuplicateName) {
		t.Fatal("duplicate name")
	}
	if _, err := r.CreateGroup("  ", ""); !errors.Is(err, ErrInvalid) {
		t.Fatal("empty name")
	}
	if _, err := r.CreateGroup(strings.Repeat("g", 80), ""); !errors.Is(err, ErrInvalid) {
		t.Fatal("long name")
	}
	k2, err := r.CreateGroup("Kids!", "")
	if err != nil || k2.ID != "kids-2" {
		t.Fatalf("slug collision: %v %+v", err, k2)
	}
	g3, _ := r.CreateGroup("!!!", "")
	eq(t, g3.ID, "group")
	z, _ := r.CreateGroup("Zero", "")
	_ = z

	res, err := r.BulkAssignGroup([]string{a, b, c, "ghost", a}, "kids")
	if err != nil || res.Changed != 3 || len(res.Missing) != 1 || res.Missing[0] != "ghost" {
		t.Fatalf("%v %+v", err, res)
	}
	res, _ = r.BulkAssignGroup([]string{a}, "kids")
	if res.Changed != 0 {
		t.Fatal("re-assign changed")
	}
	if _, err := r.BulkAssignGroup([]string{a}, "nope"); !errors.Is(err, ErrGroupNotFound) {
		t.Fatal("assign to missing group")
	}
	if _, err := r.BulkRemoveGroup([]string{a}, "nope"); !errors.Is(err, ErrGroupNotFound) {
		t.Fatal("remove from missing group")
	}
	g, ok := r.GetGroup("kids")
	if !ok || len(g.Members) != 3 || g.Color != "#ff8800" {
		t.Fatalf("%+v", g)
	}
	if _, ok := r.GetGroup("nope"); ok {
		t.Fatal("phantom group")
	}
	if byName, ok := r.GroupByName(" KIDS "); !ok || byName.ID != "kids" {
		t.Fatal("GroupByName")
	}
	if _, ok := r.GroupByName("nobody"); ok {
		t.Fatal("GroupByName phantom")
	}

	if _, gids := r.ScopesFor("192.0.2.1"); len(gids) != 1 || gids[0] != "kids" {
		t.Fatalf("scope groups: %v", gids)
	}

	res, _ = r.BulkRemoveGroup([]string{a, "ghost"}, "kids")
	if res.Changed != 1 || len(res.Missing) != 1 {
		t.Fatalf("%+v", res)
	}
	res, _ = r.BulkRemoveGroup([]string{a}, "kids")
	if res.Changed != 0 {
		t.Fatal("remove twice changed")
	}

	if err := r.RenameGroup("kids", "Children"); err != nil {
		t.Fatal(err)
	}
	if err := r.RenameGroup("kids", "Children"); err != nil {
		t.Fatal(err)
	}
	if err := r.RenameGroup("kids", "zero"); !errors.Is(err, ErrDuplicateName) {
		t.Fatal("rename collision")
	}
	if err := r.RenameGroup("kids", ""); !errors.Is(err, ErrInvalid) {
		t.Fatal("rename empty")
	}
	if err := r.RenameGroup("nope", "x"); !errors.Is(err, ErrGroupNotFound) {
		t.Fatal("rename missing")
	}
	if err := r.SetGroupColor("kids", "#000"); err != nil {
		t.Fatal(err)
	}
	if err := r.SetGroupColor("kids", "#000"); err != nil {
		t.Fatal(err)
	}
	gs := r.Groups()
	if len(gs) != 4 || gs[1].Name != "Children" || gs[1].Color != "#000" {
		t.Fatalf("groups: %+v", gs)
	}

	if err := r.DeleteGroup("kids"); err != nil {
		t.Fatal(err)
	}
	if err := r.DeleteGroup("kids"); !errors.Is(err, ErrGroupNotFound) {
		t.Fatal("double delete group")
	}
	if d := mustDevice(t, r, b); len(d.Groups) != 0 {
		t.Fatalf("device kept deleted group: %v", d.Groups)
	}
	if _, gids := r.ScopesFor("192.0.2.2"); gids != nil {
		t.Fatal("scope kept deleted group")
	}
	// Recreating the same name reuses the tombstoned ID cleanly.
	again, err := r.CreateGroup("Kids", "")
	if err != nil || again.ID != "kids" || len(again.Members) != 0 {
		t.Fatalf("%v %+v", err, again)
	}
	if err := r.DeleteGroup("zero"); err != nil { // group with no members emits no member event
		t.Fatal(err)
	}
}

func TestBulkExcludedTagsDelete(t *testing.T) {
	r, _ := newReg(t)
	a, b, c := seed(t, r)
	res := r.BulkSetExcluded([]string{a, b, "ghost"}, true)
	if res.Changed != 2 || len(res.Missing) != 1 {
		t.Fatalf("%+v", res)
	}
	if r.BulkSetExcluded([]string{a, b}, true).Changed != 0 {
		t.Fatal("excluded no-op changed")
	}
	if r.BulkSetTags([]string{a, b, c}, []string{"Guest", "iot"}, nil).Changed != 3 {
		t.Fatal("add tags")
	}
	if r.BulkSetTags([]string{a, b, c}, []string{"guest"}, nil).Changed != 0 {
		t.Fatal("re-add tags")
	}
	if r.BulkSetTags([]string{a}, nil, []string{"GUEST"}).Changed != 1 {
		t.Fatal("remove tag")
	}
	eq(t, mustDevice(t, r, a).Tags, []string{"iot"})
	res = r.BulkDelete([]string{a, c, "ghost", a})
	if res.Changed != 2 || r.Len() != 1 {
		t.Fatalf("%+v len %d", res, r.Len())
	}
}

func TestMergeDevices(t *testing.T) {
	r, _ := newReg(t)
	a, b, c := seed(t, r)
	r.CreateGroup("G1", "")
	r.CreateGroup("G2", "")
	r.BulkAssignGroup([]string{a}, "g1")
	r.BulkAssignGroup([]string{b}, "g2")
	r.SetTags(a, []string{"x"})
	r.SetTags(b, []string{"y"})
	r.SetNotes(a, "note a")
	r.SetNotes(b, "note b")
	r.SetExcluded(b, true)
	r.SetType(b, "speaker")
	r.Rename(b, "Bee")
	r.Observe(Observation{Source: SourceMDNS, IP: "192.0.2.2", Hostname: "bee-host", Services: []string{"_raop._tcp"}})

	if err := r.Merge(a, b, c, b); err != nil {
		t.Fatal(err)
	}
	d := mustDevice(t, r, a)
	eq(t, d.MACs, []string{macA, vmac})
	// Two identities (one hardware, one randomized) allow two IPv4 addresses;
	// the oldest-seen one retires to the past list.
	eq(t, d.IPs, []string{"192.0.2.2", "192.0.2.3"})
	eq(t, d.PastIPs, []string{"192.0.2.1"})
	eq(t, d.Groups, []string{"g1", "g2"})
	eq(t, d.Tags, []string{"x", "y"})
	eq(t, d.Notes, "note a\nnote b")
	eq(t, d.Alias, "Bee")
	eq(t, d.MDNSName, "bee-host")
	eq(t, d.Vendor, "ExampleCo")
	if !d.Excluded || !d.TypeUser || d.Type != TypeSpeaker {
		t.Fatalf("flags not merged: %+v", d)
	}
	if _, ok := r.Get(b); ok || r.Len() != 1 {
		t.Fatal("source still live")
	}
	if dev, groups := r.ScopesFor("192.0.2.2"); dev != a || len(groups) != 2 {
		t.Fatalf("scope after merge: %s %v", dev, groups)
	}
}

func TestMergeErrors(t *testing.T) {
	r, _ := newReg(t)
	a, b, _ := seed(t, r)
	if err := r.Merge("nope", a); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing target")
	}
	if err := r.Merge(a, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing source")
	}
	if err := r.Merge(a, a); !errors.Is(err, ErrInvalid) {
		t.Fatal("self merge")
	}
	if err := r.Merge(a); !errors.Is(err, ErrInvalid) {
		t.Fatal("no sources")
	}
	_ = b
}

func TestSplit(t *testing.T) {
	r, _ := newReg(t)
	a, b, _ := seed(t, r)
	r.CreateGroup("G", "")
	r.BulkAssignGroup([]string{a}, "g")
	r.SetExcluded(a, true)
	if err := r.Merge(a, b); err != nil {
		t.Fatal(err)
	}
	nid, err := r.Split(a, vmac, "192.0.2.2")
	if err != nil {
		t.Fatal(err)
	}
	if r.Len() != 3 || nid == a {
		t.Fatal("split did not create a device")
	}
	orig, nd := mustDevice(t, r, a), mustDevice(t, r, nid)
	eq(t, orig.MACs, []string{macA})
	eq(t, nd.MACs, []string{vmac})
	eq(t, nd.IPs, []string{"192.0.2.2"})
	eq(t, nd.Vendor, "ExampleCo")
	eq(t, nd.Groups, []string{"g"})
	if !nd.Excluded {
		t.Fatal("split device lost exclusion")
	}
	if dev, _ := r.ScopesFor("192.0.2.2"); dev != nid {
		t.Fatal("moved IP not rescoped")
	}
	if dev, _ := r.ScopesFor("192.0.2.1"); dev != a {
		t.Fatal("kept IP lost")
	}
	// The split MAC stays on its own device when seen again.
	if got := r.Observe(Observation{MAC: vmac, IP: "192.0.2.2"}); got != nid {
		t.Fatal("re-merged after split")
	}

	// Splitting only IPs off an IP-only device.
	r2, _ := newReg(t)
	x := r2.Observe(Observation{Source: SourceMDNS, IP: "192.0.2.7", Hostname: "multi"})
	r2.Observe(Observation{Source: SourceMDNS, IP: "2001:db8::7", Hostname: "multi"})
	y, err := r2.Split(x, "", "2001:db8::7")
	if err != nil {
		t.Fatal(err)
	}
	eq(t, mustDevice(t, r2, y).IPs, []string{"2001:db8::7"})
	eq(t, mustDevice(t, r2, x).IPs, []string{"192.0.2.7"})
}

func TestSplitErrors(t *testing.T) {
	r, _ := newReg(t)
	a, _, _ := seed(t, r)
	if _, err := r.Split("nope", macA); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing")
	}
	if _, err := r.Split(a, "zz"); !errors.Is(err, ErrInvalid) {
		t.Fatal("bad mac")
	}
	if _, err := r.Split(a, macB); !errors.Is(err, ErrInvalid) {
		t.Fatal("foreign mac")
	}
	if _, err := r.Split(a, "", "bogus"); !errors.Is(err, ErrInvalid) {
		t.Fatal("bad ip")
	}
	if _, err := r.Split(a, "", "192.0.2.200"); !errors.Is(err, ErrInvalid) {
		t.Fatal("foreign ip")
	}
	if _, err := r.Split(a, ""); !errors.Is(err, ErrInvalid) {
		t.Fatal("nothing to split")
	}
	if _, err := r.Split(a, macA, "192.0.2.1"); !errors.Is(err, ErrEmptySplit) {
		t.Fatal("empty split")
	}
}

func TestListAndGet(t *testing.T) {
	r, _ := newReg(t)
	a, _, _ := seed(t, r)
	r.Rename(a, "Zed")
	l := r.List()
	if len(l) != 3 || l[len(l)-1].Alias != "Zed" {
		t.Fatalf("list order: %v", l)
	}
	// Returned devices are copies.
	l[0].Tags = append(l[0].Tags, "mutated")
	d := mustDevice(t, r, a)
	d.IPs[0] = "mutated"
	if got := mustDevice(t, r, a); got.IPs[0] == "mutated" {
		t.Fatal("Get leaked internal slice")
	}
	if _, ok := r.Get("nope"); ok {
		t.Fatal("phantom")
	}
	if itoa(0) != "0" || itoa(105) != "105" {
		t.Fatal("itoa")
	}
}
