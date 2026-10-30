// SPDX-License-Identifier: AGPL-3.0-or-later

package importers

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"shepherd/internal/devices"
)

func fixtureSnapshot(t *testing.T) Snapshot {
	t.Helper()
	f := newFakeEero(t)
	c, _ := testClient(t, f, nil)
	login(t, c)
	s, err := c.Snapshot(context.Background(), Network{ID: "1001", Name: "Home"})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func planDev(p Plan, mac string) *PlanDevice {
	for i := range p.Devices {
		if p.Devices[i].MAC == mac {
			return &p.Devices[i]
		}
	}
	return nil
}

func TestMapEeroFixture(t *testing.T) {
	plan := MapEero(fixtureSnapshot(t))
	if plan.Source != "eero (Home)" {
		t.Fatalf("source %q", plan.Source)
	}
	var gs []string
	for _, g := range plan.Groups {
		gs = append(gs, g.Name)
	}
	if !reflect.DeepEqual(gs, []string{"Kids", "Adults"}) {
		t.Fatalf("groups %v", gs)
	}
	tab := planDev(plan, "02:00:5e:00:00:11")
	if tab == nil || tab.Name != "Kids Tablet" || tab.Hostname != "tablet-1" || tab.Vendor != "ExampleCo" || !tab.Paused ||
		!reflect.DeepEqual(tab.Groups, []string{"Kids"}) || tab.Hints[0] != "tablet" || tab.Notes != "Imported from eero: wireless via Living Room" {
		t.Fatalf("%+v", tab)
	}
	tv := planDev(plan, "00:00:5e:00:00:12")
	if tv == nil || len(tv.Groups) != 0 || tv.Name != "Living Room TV" {
		t.Fatalf("%+v", tv)
	}
	guest := planDev(plan, "02:00:5e:00:00:13")
	if guest == nil || guest.Name != "" || guest.Hostname != "visitor-phone" || !reflect.DeepEqual(guest.Tags, []string{"guest"}) {
		t.Fatalf("%+v", guest)
	}
	gw := planDev(plan, "00:00:5e:00:00:01")
	if gw == nil || !gw.Infrastructure || gw.Name != "Living Room eero" || gw.Vendor != "eero" || gw.IPs[0] != "192.0.2.1" {
		t.Fatalf("%+v", gw)
	}
	if beacon := planDev(plan, "00:00:5e:00:00:02"); beacon == nil || !beacon.Infrastructure || beacon.Name != "Hallway eero" {
		t.Fatalf("%+v", beacon)
	}
}

func TestMapEeroEndToEndPreviewApplyIdempotent(t *testing.T) {
	plan := MapEero(fixtureSnapshot(t))
	reg := newReg(t)
	pre, err := Preview(plan, reg)
	if err != nil || pre.Created != 5 || pre.GroupsCreated != 2 || pre.MembershipsAdded != 1 {
		t.Fatalf("%v %+v", err, pre)
	}
	if reg.Len() != 0 {
		t.Fatal("preview created devices")
	}
	rep := mustApply(t, plan, reg, Options{})
	if rep.Created != 5 || reg.Len() != 5 {
		t.Fatalf("%+v", rep)
	}
	for _, mac := range []string{"00:00:5e:00:00:01", "00:00:5e:00:00:02"} {
		d := byMAC(t, reg, mac)
		if !d.Excluded || d.Type != devices.TypeRouter || !reg.IsExcluded(d.ID) {
			t.Fatalf("infrastructure %s not excluded: %+v", mac, d)
		}
	}
	tab := byMAC(t, reg, "02:00:5e:00:00:11")
	if tab.Alias != "Kids Tablet" || !reflect.DeepEqual(groupNames(reg, tab), []string{"Kids"}) {
		t.Fatalf("%+v", tab)
	}
	before := reg.List()
	if again := mustApply(t, plan, reg, Options{}); again.Changed() || !reflect.DeepEqual(before, reg.List()) {
		t.Fatalf("second apply changed things: %+v", again)
	}
}

func TestMapEeroWarnings(t *testing.T) {
	s := Snapshot{
		Network:  Network{Name: "N\x00ame"},
		Warnings: []string{"carried over"},
		Nodes: []EeroNode{
			{MAC: "00:00:5e:00:00:01", Location: "Hall"},
			{MAC: "not-a-mac", Location: "Broken"},
			{MAC: "00:00:5e:00:00:03", Model: "eero Pro"},
			{MAC: "00:00:5e:00:00:04"},
		},
		Profiles: []EeroProfile{
			{URL: "/p/1", Name: "Kids", DeviceURLs: []string{"/devices/02:00:5e:00:00:51", "/devices/garbage", "/devices/02:00:5e:00:00:52"}},
			{URL: "/p/2", Name: "Guests", DeviceMACs: []string{"02-00-5e-00-00-51", "zz"}},
			{URL: "/p/3", Name: " ; "},
			{URL: "/p/4", Name: ""},
		},
		Devices: []EeroDevice{
			{URL: "/devices/02:00:5e:00:00:51", MAC: "02:00:5e:00:00:51", Nickname: "Two Profiles", ProfileName: "Kids"},
			{MAC: "00:00:5e:00:00:60", Manufacturer: "eero", Hostname: "mystery-eero"},
			{MAC: "bad mac", Nickname: "IP Only", IPs: []string{"192.0.2.70"}, ProfileURL: "/p/1", Connection: "wired"},
			{MAC: "bad mac", Nickname: "Unidentifiable"},
			{MAC: "00:00:5e:00:00:03", Nickname: "", Hostname: "pro"},
			{MAC: "00:00:5e:00:00:80", Nickname: "Own Profile Only", ProfileName: "Brand New"},
		},
	}
	plan := MapEero(s)
	if plan.Source != "eero (Name)" {
		t.Fatalf("source %q", plan.Source)
	}
	joined := strings.Join(plan.Warnings, "\n")
	for _, want := range []string{
		"carried over", "no usable MAC address", "could not be identified", "empty name",
		"more than one profile", "made by eero but is not in the list", "is not usable",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing warning %q in:\n%s", want, joined)
		}
	}
	if d := planDev(plan, "02:00:5e:00:00:51"); d == nil || len(d.Groups) != 0 {
		t.Fatalf("two-profile device must not be grouped: %+v", d)
	}
	if d := planDev(plan, "02:00:5e:00:00:52"); d == nil || !reflect.DeepEqual(d.Groups, []string{"Kids"}) {
		t.Fatalf("profile-only device: %+v", d)
	}
	if d := planDev(plan, "00:00:5e:00:00:80"); d == nil || !reflect.DeepEqual(d.Groups, []string{"Brand New"}) {
		t.Fatalf("%+v", d)
	}
	if d := planDev(plan, "00:00:5e:00:00:60"); d == nil || d.Infrastructure {
		t.Fatalf("an unconfirmed eero device must not be marked infrastructure: %+v", d)
	}
	if d := planDev(plan, "00:00:5e:00:00:03"); d == nil || !d.Infrastructure || d.Name != "eero eero Pro" {
		t.Fatalf("%+v", d)
	}
	if d := planDev(plan, "00:00:5e:00:00:04"); d == nil || d.Name != "eero" || d.Vendor != "eero" {
		t.Fatalf("%+v", d)
	}
	var ipOnly *PlanDevice
	for i := range plan.Devices {
		if plan.Devices[i].MAC == "" && plan.Devices[i].Name == "IP Only" {
			ipOnly = &plan.Devices[i]
		}
		if plan.Devices[i].Name == "Unidentifiable" {
			t.Fatal("a device with no MAC or IP was kept")
		}
	}
	if ipOnly == nil || ipOnly.IPs[0] != "192.0.2.70" || ipOnly.Notes != "Imported from eero: wired" {
		t.Fatalf("%+v", ipOnly)
	}
	// And the whole thing still applies.
	rep := mustApply(t, plan, newReg(t), Options{})
	if rep.Created == 0 {
		t.Fatalf("%+v", rep)
	}
}

func TestMapEeroNoNodeMatchWarning(t *testing.T) {
	plan := MapEero(Snapshot{
		Nodes:   []EeroNode{{MAC: "bad"}},
		Devices: []EeroDevice{{MAC: "02:00:5e:00:00:01"}},
	})
	if !strings.Contains(strings.Join(plan.Warnings, " "), "no eero router or node was matched") {
		t.Fatalf("%v", plan.Warnings)
	}
	if got := MapEero(Snapshot{}); got.Source != "eero" || len(got.Devices) != 0 {
		t.Fatalf("%+v", got)
	}
}

func TestMapEeroCapsHostileText(t *testing.T) {
	long := strings.Repeat("A", 1000)
	plan := MapEero(Snapshot{
		Profiles: []EeroProfile{{URL: "/p/1", Name: long}},
		Devices:  []EeroDevice{{MAC: "02:00:5e:00:00:01", Nickname: "‮evil\x00" + long, Hostname: long, ProfileURL: "/p/1"}},
	})
	reg := newReg(t)
	mustApply(t, plan, reg, Options{})
	d := byMAC(t, reg, "02:00:5e:00:00:01")
	if len(d.Alias) > MaxAliasBytes || strings.ContainsAny(d.Alias, "\x00‮") || len(d.Hostname) > MaxHostnameBytes {
		t.Fatalf("%q %q", d.Alias, d.Hostname)
	}
	if gs := groupNames(reg, d); len(gs) != 1 || len(gs[0]) > MaxGroupBytes {
		t.Fatalf("%v", gs)
	}
}
