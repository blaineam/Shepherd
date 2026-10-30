// SPDX-License-Identifier: AGPL-3.0-or-later

package importers

import (
	"reflect"
	"strings"
	"testing"

	"shepherd/internal/devices"
)

func TestApplyCreatesDevicesAndGroups(t *testing.T) {
	reg := newReg(t)
	rep := mustApply(t, samplePlan(), reg, Options{})
	if rep.DryRun || rep.Created != 3 || rep.GroupsCreated != 1 || rep.MembershipsAdded != 1 || rep.Named != 3 {
		t.Fatalf("report: %+v", rep)
	}
	tab := byMAC(t, reg, "02:00:5e:00:00:01")
	if tab.Alias != "Kids Tablet" || tab.Hostname != "tab-1" || tab.Vendor != "ExampleCo" || !reflect.DeepEqual(tab.Tags, []string{"child"}) {
		t.Fatalf("tablet: %+v", tab)
	}
	if !reflect.DeepEqual(groupNames(reg, tab), []string{"Kids"}) {
		t.Fatalf("groups: %v", groupNames(reg, tab))
	}
	if g, _ := reg.GroupByName("kids"); g.Color != "#3366cc" || len(g.Members) != 1 {
		t.Fatalf("group: %+v", g)
	}
	tv := byMAC(t, reg, "00:00:5e:00:00:02")
	if tv.Type != devices.TypeTV || !tv.TypeUser || tv.Notes != "by the window" {
		t.Fatalf("tv: %+v", tv)
	}
	router := byMAC(t, reg, "00:00:5e:00:00:03")
	if !router.Excluded || router.Type != devices.TypeRouter || !reg.IsExcluded(router.ID) {
		t.Fatalf("router: %+v", router)
	}
	if !strings.Contains(strings.Join(rep.Warnings, " "), "1 device(s) use randomized") {
		t.Fatalf("expected randomized warning: %v", rep.Warnings)
	}
}

func TestApplyIsIdempotent(t *testing.T) {
	reg := newReg(t)
	mustApply(t, samplePlan(), reg, Options{})
	before, groupsBefore := reg.List(), reg.Groups()
	rep := mustApply(t, samplePlan(), reg, Options{})
	if rep.Changed() || rep.Created != 0 || rep.MatchedByMAC != 3 || rep.Unchanged != 3 {
		t.Fatalf("second apply changed things: %+v", rep)
	}
	if !reflect.DeepEqual(before, reg.List()) || !reflect.DeepEqual(groupsBefore, reg.Groups()) {
		t.Fatal("registry differs after the second apply")
	}
	if !strings.Contains(rep.String(), "Nothing to change.") {
		t.Fatal(rep.String())
	}
}

func TestPreviewChangesNothingAndMatchesApply(t *testing.T) {
	reg := newReg(t)
	before := reg.List()
	pre, err := Preview(samplePlan(), reg)
	if err != nil {
		t.Fatal(err)
	}
	if !pre.DryRun || len(reg.List()) != len(before) || len(reg.Groups()) != 0 {
		t.Fatal("preview changed the registry")
	}
	if !strings.Contains(pre.String(), "nothing has been changed") || !strings.Contains(pre.String(), `create group "Kids"`) {
		t.Fatalf("text:\n%s", pre.String())
	}
	rep := mustApply(t, samplePlan(), reg, Options{})
	pre.DryRun, rep.DryRun = false, false
	if pre.Created != rep.Created || pre.Named != rep.Named || pre.GroupsCreated != rep.GroupsCreated ||
		pre.MembershipsAdded != rep.MembershipsAdded || pre.TypesSet != rep.TypesSet || pre.MarkedExcluded != rep.MarkedExcluded {
		t.Fatalf("preview %+v != apply %+v", pre, rep)
	}
	// And a preview of a finished import shows nothing to do.
	again, _ := Preview(samplePlan(), reg)
	if again.Changed() {
		t.Fatalf("preview after apply: %+v", again)
	}
}

func TestUserAliasWinsUnlessOverwrite(t *testing.T) {
	reg := newReg(t)
	id := reg.Observe(devices.Observation{Source: devices.SourceManual, MAC: "00:00:5e:00:00:02", IP: "192.0.2.11"})
	if err := reg.Rename(id, "My Own Name"); err != nil {
		t.Fatal(err)
	}
	p := Plan{Devices: []PlanDevice{{MAC: "00:00:5e:00:00:02", Name: "Living Room TV"}}}

	pre, _ := Preview(p, reg)
	if len(pre.Conflicts) != 1 || !strings.Contains(pre.Conflicts[0], "kept your name") || pre.Renamed != 0 {
		t.Fatalf("preview: %+v", pre)
	}
	rep := mustApply(t, p, reg, Options{})
	if rep.Renamed != 0 || len(rep.Conflicts) != 1 {
		t.Fatalf("apply: %+v", rep)
	}
	if d, _ := reg.Get(id); d.Alias != "My Own Name" {
		t.Fatalf("alias overwritten: %q", d.Alias)
	}

	pw, _ := PreviewWith(p, reg, Options{OverwriteNames: true})
	if pw.Renamed != 1 {
		t.Fatalf("overwrite preview: %+v", pw)
	}
	rep = mustApply(t, p, reg, Options{OverwriteNames: true})
	if rep.Renamed != 1 {
		t.Fatalf("overwrite apply: %+v", rep)
	}
	if d, _ := reg.Get(id); d.Alias != "Living Room TV" {
		t.Fatalf("alias %q", d.Alias)
	}
	// Equal alias is not a conflict.
	if rep := mustApply(t, p, reg, Options{}); rep.Changed() || len(rep.Conflicts) != 0 {
		t.Fatalf("%+v", rep)
	}
}

func TestMatchByIPLearnsMAC(t *testing.T) {
	reg := newReg(t)
	id := reg.Observe(devices.Observation{Source: devices.SourceNeighbor, IP: "192.0.2.50"})
	rep := mustApply(t, Plan{Devices: []PlanDevice{{MAC: "00:00:5e:00:00:50", IPs: []string{"192.0.2.50"}, Name: "Printer"}}}, reg, Options{})
	if rep.MatchedByIP != 1 || rep.Created != 0 || rep.Updated != 1 {
		t.Fatalf("%+v", rep)
	}
	d, _ := reg.Get(id)
	if d.Alias != "Printer" || len(d.MACs) != 1 || reg.Len() != 1 {
		t.Fatalf("device %+v, len %d", d, reg.Len())
	}
	if again := mustApply(t, Plan{Devices: []PlanDevice{{MAC: "00:00:5e:00:00:50", IPs: []string{"192.0.2.50"}, Name: "Printer"}}}, reg, Options{}); again.Changed() {
		t.Fatalf("%+v", again)
	}
}

func TestNoMACDevices(t *testing.T) {
	reg := newReg(t)
	p := Plan{Devices: []PlanDevice{
		{IPs: []string{"192.0.2.60", "192.0.2.61"}, Name: "Garage Camera", Hostname: "cam"},
		{Name: "Nothing identifies me"},
	}}
	rep := mustApply(t, p, reg, Options{})
	if rep.Created != 1 || reg.Len() != 1 || !strings.Contains(strings.Join(rep.Warnings, " "), "neither a usable MAC") {
		t.Fatalf("%+v len %d", rep, reg.Len())
	}
	d, ok := reg.FindByIP("192.0.2.60")
	if !ok || d.Alias != "Garage Camera" || d.Hostname != "cam" || len(d.IPs) != 1 {
		t.Fatalf("%+v", d)
	}
	if rep := mustApply(t, p, reg, Options{}); rep.Changed() || rep.MatchedByIP != 1 {
		t.Fatalf("second: %+v", rep)
	}
}

func TestIPHeldByOtherHardwareIsNotMoved(t *testing.T) {
	reg := newReg(t)
	other := reg.Observe(devices.Observation{Source: devices.SourceNeighbor, MAC: "00:00:5e:00:00:70", IP: "192.0.2.70"})
	p := Plan{Devices: []PlanDevice{{MAC: "00:00:5e:00:00:71", IPs: []string{"192.0.2.70"}, Name: "Newcomer"}}}
	pre, _ := Preview(p, reg)
	if len(pre.Conflicts) != 1 || !strings.Contains(pre.Conflicts[0], "not moved") {
		t.Fatalf("%+v", pre)
	}
	rep := mustApply(t, p, reg, Options{})
	if rep.Created != 1 || len(rep.Conflicts) != 1 {
		t.Fatalf("%+v", rep)
	}
	if d, _ := reg.Get(other); !reflect.DeepEqual(d.IPs, []string{"192.0.2.70"}) {
		t.Fatalf("holder lost its address: %+v", d)
	}
	if d := byMAC(t, reg, "00:00:5e:00:00:71"); len(d.IPs) != 0 || d.Alias != "Newcomer" {
		t.Fatalf("%+v", d)
	}
}

func TestRandomizedMACRotationFoldsIntoHolder(t *testing.T) {
	reg := newReg(t)
	id := reg.Observe(devices.Observation{Source: devices.SourceNeighbor, MAC: "02:00:5e:00:00:80", IP: "192.0.2.80"})
	p := Plan{Devices: []PlanDevice{{MAC: "02:00:5e:00:00:81", IPs: []string{"192.0.2.80"}, Name: "Alex Phone"}}}
	rep := mustApply(t, p, reg, Options{})
	if rep.MatchedByIP != 1 || rep.Created != 0 || reg.Len() != 1 {
		t.Fatalf("%+v len %d", rep, reg.Len())
	}
	d, _ := reg.Get(id)
	if d.Alias != "Alex Phone" || len(d.MACs) != 2 {
		t.Fatalf("%+v", d)
	}
	if again := mustApply(t, p, reg, Options{}); again.Changed() {
		t.Fatalf("%+v", again)
	}
}

func TestExistingDeviceKeepsCurrentIPv4AndHostname(t *testing.T) {
	reg := newReg(t)
	id := reg.Observe(devices.Observation{Source: devices.SourceDHCP, MAC: "00:00:5e:00:00:90", IP: "192.0.2.90", Hostname: "real-host"})
	p := Plan{Devices: []PlanDevice{{MAC: "00:00:5e:00:00:90", IPs: []string{"198.51.100.9", "2001:db8::9", "2001:db8::a"}, Hostname: "stale-host", Name: "Study PC"}}}
	rep := mustApply(t, p, reg, Options{})
	d, _ := reg.Get(id)
	if d.Hostname != "real-host" || !reflect.DeepEqual(d.IPs, []string{"192.0.2.90", "2001:db8::9", "2001:db8::a"}) {
		t.Fatalf("%+v", d)
	}
	if !rep.Changed() {
		t.Fatal("expected a change")
	}
	if again := mustApply(t, p, reg, Options{}); again.Changed() {
		t.Fatalf("not idempotent: %+v", again)
	}
}

func TestNewDeviceWithTwoIPv4KeepsFirst(t *testing.T) {
	reg := newReg(t)
	p := Plan{Devices: []PlanDevice{{MAC: "00:00:5e:00:00:91", IPs: []string{"192.0.2.91", "192.0.2.92"}}}}
	mustApply(t, p, reg, Options{})
	if d := byMAC(t, reg, "00:00:5e:00:00:91"); !reflect.DeepEqual(d.IPs, []string{"192.0.2.91"}) {
		t.Fatalf("%+v", d)
	}
	if again := mustApply(t, p, reg, Options{}); again.Changed() {
		t.Fatalf("%+v", again)
	}
}

func TestTypeNotesTagsAndGroupColorPolicy(t *testing.T) {
	reg := newReg(t)
	id := reg.Observe(devices.Observation{Source: devices.SourceManual, MAC: "00:00:5e:00:00:a0", IP: "192.0.2.100"})
	_ = reg.SetType(id, "camera")
	_ = reg.SetNotes(id, "mine")
	_ = reg.SetTags(id, []string{"keep"})
	g, _ := reg.CreateGroup("Cameras", "")
	p := Plan{
		Groups:  []PlanGroup{{Name: "cameras", Color: "#aabbcc"}},
		Devices: []PlanDevice{{MAC: "00:00:5e:00:00:a0", Type: "tv", Notes: "theirs", Tags: []string{"new"}, Groups: []string{"Cameras"}, Paused: true}},
	}
	rep := mustApply(t, p, reg, Options{})
	d, _ := reg.Get(id)
	if d.Type != devices.TypeCamera || d.Notes != "mine" || !reflect.DeepEqual(d.Tags, []string{"keep", "new"}) {
		t.Fatalf("%+v", d)
	}
	if got, _ := reg.GetGroup(g.ID); got.Color != "#aabbcc" || len(got.Members) != 1 {
		t.Fatalf("%+v", got)
	}
	joined := strings.Join(rep.Conflicts, "|")
	if !strings.Contains(joined, "kept your type") || !strings.Contains(joined, "kept your existing notes") {
		t.Fatalf("conflicts: %v", rep.Conflicts)
	}
	if !strings.Contains(rep.String(), "paused at the source") || !strings.Contains(rep.String(), "set the color") {
		t.Fatalf("text:\n%s", rep.String())
	}
	if again := mustApply(t, p, reg, Options{}); again.Changed() {
		t.Fatalf("%+v", again)
	}
}

func TestSameTypeIsNotAConflict(t *testing.T) {
	reg := newReg(t)
	p := Plan{Devices: []PlanDevice{{MAC: "00:00:5e:00:00:b0", Type: "camera"}}}
	mustApply(t, p, reg, Options{})
	if rep := mustApply(t, p, reg, Options{}); rep.Changed() || len(rep.Conflicts) != 0 {
		t.Fatalf("%+v", rep)
	}
}

func TestApplyNeverDeletes(t *testing.T) {
	reg := newReg(t)
	keep := reg.Observe(devices.Observation{Source: devices.SourceManual, MAC: "00:00:5e:00:00:c0", IP: "192.0.2.120"})
	g, _ := reg.CreateGroup("Mine", "")
	_, _ = reg.BulkAssignGroup([]string{keep}, g.ID)
	mustApply(t, samplePlan(), reg, Options{})
	d, ok := reg.Get(keep)
	if !ok || !reflect.DeepEqual(d.Groups, []string{g.ID}) {
		t.Fatalf("%+v", d)
	}
	if _, ok := reg.GetGroup(g.ID); !ok {
		t.Fatal("group deleted")
	}
}

func TestApplyErrors(t *testing.T) {
	if _, err := Apply(Plan{}, nil, Options{}); err != ErrNoRegistry {
		t.Fatal(err)
	}
	if _, err := Preview(Plan{Devices: make([]PlanDevice, MaxDevices+1)}, newReg(t)); err != ErrPlanTooLarge {
		t.Fatal(err)
	}
}

func TestUnusableMACWithIPStillImports(t *testing.T) {
	reg := newReg(t)
	p := Plan{Devices: []PlanDevice{{MAC: "00:00:00:00:00:00", IPs: []string{"192.0.2.130"}, Name: "Odd"}}}
	rep := mustApply(t, p, reg, Options{})
	if rep.Created != 1 || reg.Len() != 1 {
		t.Fatalf("%+v", rep)
	}
}

func TestReportStringSections(t *testing.T) {
	rep := Report{Source: "", Conflicts: []string{"c"}, Warnings: []string{"w"}, Lines: []string{"l"}}
	s := rep.String()
	for _, want := range []string{"an unknown source", "  ! c", "  ? w", "  + l"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in\n%s", want, s)
		}
	}
}
