// SPDX-License-Identifier: AGPL-3.0-or-later

package devices

import (
	"strings"
	"testing"
	"time"
)

const (
	macA = "02:00:5e:00:00:0a"
	macB = "02:00:5e:00:00:0b"
	macC = "02:00:5e:00:00:0c"
	vmac = "00:00:5e:00:53:01" // universally administered: vendor "ExampleCo"
)

func TestObserveIgnoresEmpty(t *testing.T) {
	r, _ := newReg(t)
	for _, o := range []Observation{{}, {IP: "not-an-ip"}, {IP: "0.0.0.0"}, {IP: "224.0.0." + "251"}, {IP: "127.0.0.1"}, {MAC: strings.Repeat("ff:", 5) + "ff"}, {Hostname: "x"}} {
		if id := r.Observe(o); id != "" {
			t.Fatalf("%+v created %q", o, id)
		}
	}
	if r.Len() != 0 {
		t.Fatal("registry not empty")
	}
}

func TestObserveCreatesByMAC(t *testing.T) {
	r, clk := newReg(t)
	id := r.Observe(Observation{Source: SourceNeighbor, MAC: "00-00-5E-00-53-01", IP: "192.0.2.10"})
	d := mustDevice(t, r, id)
	eq(t, d.MACs, []string{vmac})
	eq(t, d.IPs, []string{"192.0.2.10"})
	eq(t, d.Vendor, "ExampleCo")
	eq(t, d.DisplayName(), "ExampleCo device")
	if !d.FirstSeen.Equal(clk.Now()) || d.Node != "node-a" || d.Updated.Wall == 0 {
		t.Fatalf("bad bookkeeping: %+v", d)
	}
	// Same MAC again: same device.
	if again := r.Observe(Observation{MAC: vmac}); again != id || r.Len() != 1 {
		t.Fatal("duplicate device")
	}
	got, ok := r.FindByMAC("00:00:5E:00:53:01")
	if !ok || got.ID != id {
		t.Fatal("FindByMAC")
	}
	got, ok = r.FindByIP("::ffff:192.0.2.10")
	if !ok || got.ID != id {
		t.Fatal("FindByIP via v4-mapped")
	}
	if _, ok := r.FindByIP("bogus"); ok {
		t.Fatal("bogus ip found")
	}
	if _, ok := r.FindByIP("192.0.2.99"); ok {
		t.Fatal("unknown ip found")
	}
	if _, ok := r.FindByMAC("zz"); ok {
		t.Fatal("bogus mac found")
	}
	if _, ok := r.FindByMAC(macC); ok {
		t.Fatal("unknown mac found")
	}
	// Deterministic ID for MAC-keyed devices.
	r2, _ := newReg(t)
	if id2 := r2.Observe(Observation{MAC: vmac}); id2 != id {
		t.Fatalf("ids differ across replicas: %s vs %s", id, id2)
	}
}

func TestObserveIPOnlyThenMACLearned(t *testing.T) {
	r, _ := newReg(t)
	id := r.Observe(Observation{Source: SourceDNS, IP: "192.0.2.20"})
	if id != "t-1" {
		t.Fatalf("id = %s", id)
	}
	if err := r.Rename(id, "Kitchen Tablet"); err != nil {
		t.Fatal(err)
	}
	id2 := r.Observe(Observation{Source: SourceNeighbor, MAC: vmac, IP: "192.0.2.20"})
	if id2 != id || r.Len() != 1 {
		t.Fatalf("MAC learned late must merge: %s vs %s, len %d", id2, id, r.Len())
	}
	d := mustDevice(t, r, id)
	eq(t, d.MACs, []string{vmac})
	eq(t, d.Alias, "Kitchen Tablet")
	eq(t, d.Vendor, "ExampleCo")
}

func TestObserveMACLearnedForOtherIPAbsorbsIPOnlyDevice(t *testing.T) {
	r, _ := newReg(t)
	macDev := r.Observe(Observation{MAC: macA, IP: "192.0.2.30"})
	ipDev := r.Observe(Observation{Source: SourceDNS, IP: "192.0.2.31"})
	if macDev == ipDev {
		t.Fatal("setup")
	}
	// The MAC device moves to .31, where an IP-only device sits.
	got := r.Observe(Observation{MAC: macA, IP: "192.0.2.31"})
	if got != macDev || r.Len() != 1 {
		t.Fatalf("IP-only device not absorbed: %s len=%d", got, r.Len())
	}
	d := mustDevice(t, r, macDev)
	eq(t, d.IPs, []string{"192.0.2.31"})
	eq(t, d.PastIPs, []string{"192.0.2.30"})
	if _, ok := r.Get(ipDev); ok {
		t.Fatal("absorbed device still live")
	}
}

func TestDHCPChurnDoesNotDuplicate(t *testing.T) {
	r, clk := newReg(t)
	id := r.Observe(Observation{MAC: macA, IP: "192.0.2.40"})
	for i, ip := range []string{"192.0.2.41", "192.0.2.42", "192.0.2.40"} {
		clk.Advance(time.Hour)
		if got := r.Observe(Observation{MAC: macA, IP: ip}); got != id {
			t.Fatalf("round %d: new device", i)
		}
	}
	d := mustDevice(t, r, id)
	eq(t, d.IPs, []string{"192.0.2.40"})
	eq(t, d.PastIPs, []string{"192.0.2.42", "192.0.2.41"})
	if r.Len() != 1 {
		t.Fatal("duplicates")
	}
	// Old addresses no longer resolve; the new one does.
	if dev, _ := r.ScopesFor("192.0.2.41"); dev != "" {
		t.Fatal("stale IP still scoped")
	}
	if dev, _ := r.ScopesFor("192.0.2.40"); dev != id {
		t.Fatal("current IP not scoped")
	}
}

func TestIPReuseByDifferentDevice(t *testing.T) {
	r, clk := newReg(t)
	first := r.Observe(Observation{MAC: vmac, IP: "192.0.2.50"})
	clk.Advance(time.Hour)
	second := r.Observe(Observation{MAC: "00:00:5e:00:53:02", IP: "192.0.2.50"})
	if first == second || r.Len() != 2 {
		t.Fatal("distinct hardware must stay distinct")
	}
	eq(t, mustDevice(t, r, first).IPs, "[]")
	eq(t, mustDevice(t, r, first).PastIPs, []string{"192.0.2.50"})
	eq(t, mustDevice(t, r, second).IPs, []string{"192.0.2.50"})
	if dev, _ := r.ScopesFor("192.0.2.50"); dev != second {
		t.Fatal("scope should follow the new holder")
	}
}

func TestRandomizedMACRotationFoldsIntoHolder(t *testing.T) {
	r, _ := newReg(t)
	id := r.Observe(Observation{MAC: macA, IP: "192.0.2.60"})
	got := r.Observe(Observation{MAC: macB, IP: "192.0.2.60"})
	if got != id || r.Len() != 1 {
		t.Fatalf("rotated randomized MAC created a new device (len %d)", r.Len())
	}
	eq(t, mustDevice(t, r, id).MACs, []string{macA, macB})
	// Both MACs resolve to the one device.
	if d, _ := r.FindByMAC(macB); d.ID != id {
		t.Fatal("new MAC not indexed")
	}
}

func TestRandomizedMACNameConflictStaysSeparate(t *testing.T) {
	r, _ := newReg(t)
	a := r.Observe(Observation{Source: SourceDHCP, MAC: macA, IP: "192.0.2.61", Hostname: "alpha-phone"})
	b := r.Observe(Observation{Source: SourceDHCP, MAC: macB, IP: "192.0.2.61", Hostname: "beta-phone"})
	if a == b {
		t.Fatal("conflicting hostnames must not merge")
	}
	// A generic hostname never conflicts or merges.
	c := r.Observe(Observation{Source: SourceDHCP, MAC: macC, IP: "192.0.2.62", Hostname: "iPhone"})
	d := r.Observe(Observation{Source: SourceDHCP, MAC: "02:00:5e:00:00:0d", IP: "192.0.2.63", Hostname: "iPhone"})
	if c == d {
		t.Fatal("generic hostnames merged unrelated devices")
	}
}

func TestRandomizedMACFoundByHostnameOnNewIP(t *testing.T) {
	r, _ := newReg(t)
	id := r.Observe(Observation{Source: SourceDHCP, MAC: macA, IP: "192.0.2.70", Hostname: "reading-lamp"})
	// New private MAC, new IP, same self-reported name: same device.
	got := r.Observe(Observation{Source: SourceDHCP, MAC: macB, IP: "192.0.2.71", Hostname: "Reading-Lamp.local"})
	if got != id || r.Len() != 1 {
		t.Fatalf("hostname match failed: len %d", r.Len())
	}
	eq(t, mustDevice(t, r, id).IPs, []string{"192.0.2.71"})
	// A hardware MAC with the same name is a different device.
	other := r.Observe(Observation{Source: SourceDHCP, MAC: vmac, IP: "192.0.2.72", Hostname: "reading-lamp"})
	if other == id {
		t.Fatal("hardware MAC merged by name")
	}
}

func TestIPOnlyObservationJoinsByMDNSName(t *testing.T) {
	r, _ := newReg(t)
	id := r.Observe(Observation{Source: SourceMDNS, MAC: macA, IP: "192.0.2.80", Hostname: "studio-mac.local"})
	// mDNS says the same host also lives at an IPv6 address.
	got := r.Observe(Observation{Source: SourceMDNS, IP: "2001:db8::80", Hostname: "studio-mac.local."})
	if got != id {
		t.Fatal("v6 address did not join the named device")
	}
	d := mustDevice(t, r, id)
	eq(t, d.IPs, []string{"192.0.2.80", "2001:db8::80"})
	eq(t, d.MDNSName, "studio-mac")
	// A DHCP renumbering of the IP-only device via its name replaces the v4.
	r2, _ := newReg(t)
	a := r2.Observe(Observation{Source: SourceMDNS, IP: "192.0.2.81", Hostname: "plug"})
	b := r2.Observe(Observation{Source: SourceMDNS, IP: "192.0.2.82", Hostname: "plug"})
	if a != b {
		t.Fatal("renumbered IP-only device duplicated")
	}
	eq(t, mustDevice(t, r2, a).IPs, []string{"192.0.2.82"})
}

func TestIPv6CapAndPastCap(t *testing.T) {
	r, clk := newReg(t)
	id := r.Observe(Observation{MAC: macA, IP: "2001:db8::1"})
	for i := 2; i <= 12; i++ {
		clk.Advance(time.Minute)
		r.Observe(Observation{MAC: macA, IP: "2001:db8::" + itoa(i)})
	}
	d := mustDevice(t, r, id)
	if len(d.IPs) != maxCurrentV6 {
		t.Fatalf("current v6 = %d", len(d.IPs))
	}
	if len(d.PastIPs) != 4 || d.PastIPs[0] != "2001:db8::4" {
		t.Fatalf("past = %v", d.PastIPs)
	}
	for i := 0; i < 30; i++ {
		clk.Advance(time.Minute)
		r.Observe(Observation{MAC: macA, IP: "198.51.100." + itoa(i+1)})
	}
	if d = mustDevice(t, r, id); len(d.PastIPs) > maxPastIPs {
		t.Fatalf("past not capped: %d", len(d.PastIPs))
	}
}

func TestNamesVendorAndTypeEvidence(t *testing.T) {
	r, _ := newReg(t)
	id := r.Observe(Observation{Source: SourceNeighbor, MAC: macA, IP: "192.0.2.90"})
	r.Observe(Observation{Source: SourceReverseDNS, IP: "192.0.2.90", Hostname: "host90.example.com."})
	eq(t, mustDevice(t, r, id).ReverseName, "host90.example.com")
	r.Observe(Observation{Source: SourceDHCP, MAC: macA, Hostname: "dhcp-name"})
	dd := mustDevice(t, r, id)
	eq(t, dd.DisplayName(), "dhcp-name")
	r.Observe(Observation{Source: SourceMDNS, IP: "192.0.2.90", Hostname: "mdns-name.local",
		Services: []string{"_ipp._tcp.local."}, Hints: []string{"Laser 4000"}, VendorHint: "ExampleCorp"})
	d := mustDevice(t, r, id)
	eq(t, d.DisplayName(), "mdns-name")
	eq(t, d.Type, TypePrinter)
	eq(t, d.Vendor, "ExampleCorp")
	eq(t, d.Services, []string{"_ipp._tcp"})
	if d.TypeReason == "" {
		t.Fatal("no type reason")
	}
	// Evidence caps.
	for i := 0; i < 50; i++ {
		r.Observe(Observation{IP: "192.0.2.90", Hints: []string{"h" + itoa(i)}, Services: []string{"_s" + itoa(i) + "._tcp"}})
	}
	d = mustDevice(t, r, id)
	if len(d.Hints) > maxHints || len(d.Services) > maxServices {
		t.Fatal("evidence not capped")
	}
}

func TestRandomizedUnknownTypeReason(t *testing.T) {
	r, _ := newReg(t)
	id := r.Observe(Observation{MAC: macA, IP: "192.0.2.91"})
	d := mustDevice(t, r, id)
	eq(t, d.Type, TypeUnknown)
	if !d.Randomized() || d.TypeReason == "" {
		t.Fatalf("want randomized reason: %+v", d)
	}
	if (&Device{}).Randomized() {
		t.Fatal("no MACs is not randomized")
	}
	if (&Device{MACs: []string{macA, vmac}}).Randomized() {
		t.Fatal("mixed MACs are not randomized")
	}
}

func TestLastSeenAndRestamp(t *testing.T) {
	r, clk := newReg(t)
	id := r.Observe(Observation{MAC: macA, IP: "192.0.2.92"})
	u1 := mustDevice(t, r, id).Updated
	clk.Advance(time.Minute)
	r.Observe(Observation{MAC: macA, IP: "192.0.2.92"})
	d := mustDevice(t, r, id)
	if d.Updated != u1 {
		t.Fatal("a mere sighting must not re-stamp within the window")
	}
	if !d.LastSeen.Equal(clk.Now()) {
		t.Fatal("LastSeen not advanced")
	}
	clk.Advance(10 * time.Minute)
	r.Observe(Observation{MAC: macA, IP: "192.0.2.92"})
	if mustDevice(t, r, id).Updated.Compare(u1) <= 0 {
		t.Fatal("stale stamp should refresh")
	}
	// Explicit timestamps move FirstSeen backwards, never LastSeen.
	early := clk.Now().Add(-48 * time.Hour)
	r.Observe(Observation{MAC: macA, Time: early})
	d = mustDevice(t, r, id)
	if !d.FirstSeen.Equal(early) || !d.LastSeen.Equal(clk.Now()) {
		t.Fatalf("timestamps wrong: %v %v", d.FirstSeen, d.LastSeen)
	}
}

func TestReverseDNSNeverCreatesDevice(t *testing.T) {
	r, _ := newReg(t)
	if id := r.Observe(Observation{Source: SourceReverseDNS, IP: "192.0.2.93", Hostname: "ghost.example.com"}); id != "" {
		t.Fatal("PTR created a device")
	}
}

func TestHLCMonotonic(t *testing.T) {
	r, _ := newReg(t)
	var last HLC
	for i := 0; i < 20; i++ {
		id := r.Observe(Observation{IP: "192.0.2." + itoa(100+i)})
		u := mustDevice(t, r, id).Updated
		if u.Compare(last) <= 0 {
			t.Fatalf("clock went backwards: %v after %v", u, last)
		}
		last = u
	}
	if (HLC{1, 2}).Compare(HLC{1, 3}) != -1 || (HLC{2, 0}).Compare(HLC{1, 9}) != 1 || (HLC{1, 1}).Compare(HLC{1, 1}) != 0 || (HLC{1, 2}).Compare(HLC{1, 1}) != 1 || (HLC{0, 5}).Compare(HLC{1, 0}) != -1 {
		t.Fatal("HLC.Compare")
	}
}

func TestNewDeviceIDCollisions(t *testing.T) {
	// A tombstoned deterministic ID is reused; a live one forces a random ID.
	r, _ := newReg(t)
	id := r.Observe(Observation{MAC: macA})
	if err := r.Delete(id); err != nil {
		t.Fatal(err)
	}
	again := r.Observe(Observation{MAC: macA})
	if again != id {
		t.Fatalf("tombstoned ID should be reused: %s vs %s", again, id)
	}
}

func TestDisplayNamePrecedence(t *testing.T) {
	d := &Device{ID: "x", IPs: []string{"2001:db8::1", "192.0.2.1"}, PastIPs: []string{"192.0.2.9"},
		Vendor: "Acme", Type: TypeCamera, ReverseName: "rev", Hostname: "host", MDNSName: "mdns", Alias: "mine"}
	for _, want := range []string{"mine", "mdns", "host", "rev", "Acme camera", "Acme device", "Camera", "192.0.2.1", "2001:db8::1", "192.0.2.9", "x"} {
		eq(t, d.DisplayName(), want)
		switch want {
		case "mine":
			d.Alias = ""
		case "mdns":
			d.MDNSName = ""
		case "host":
			d.Hostname = ""
		case "rev":
			d.ReverseName = ""
		case "Acme camera":
			d.Type = TypeUnknown
		case "Acme device":
			d.Vendor, d.Type = "", TypeCamera
		case "Camera":
			d.Type = ""
		case "192.0.2.1":
			d.IPs = []string{"2001:db8::1"}
		case "2001:db8::1":
			d.IPs = nil
		case "192.0.2.9":
			d.PastIPs = nil
		}
	}
	if d.Named() {
		t.Fatal("Named")
	}
}

func TestParseType(t *testing.T) {
	for in, want := range map[string]DeviceType{
		"Camera": TypeCamera, "game_console": TypeGameConsole, "Game Console": TypeGameConsole,
		"smart-home hub": TypeSmartHome, "router": TypeRouter, "infrastructure": TypeRouter,
		"hub": TypeSmartHome, "console": TypeGameConsole, "pc": TypeLaptop, "UNKNOWN": TypeUnknown,
	} {
		if got, ok := ParseType(in); !ok || got != want {
			t.Errorf("ParseType(%q) = %q,%v", in, got, ok)
		}
	}
	if _, ok := ParseType("toaster"); ok {
		t.Fatal("toaster is not a type")
	}
}

func TestDefaultsAndRandomIDs(t *testing.T) {
	r := New(Options{})
	a := r.Observe(Observation{IP: "192.0.2.1"})
	b := r.Observe(Observation{IP: "192.0.2.2"})
	if a == b || len(a) != 14 || a[:2] != "d-" {
		t.Fatalf("random ids: %q %q", a, b)
	}
	if r.node != "local" {
		t.Fatal("default node")
	}
	// The default vendor lookup is the embedded OUI table.
	id := r.Observe(Observation{MAC: "00:03:93:00:00:01"})
	d := mustDevice(t, r, id)
	if d.Vendor != "Apple" {
		t.Fatalf("vendor %q", d.Vendor)
	}
}

func TestNewerTieBreak(t *testing.T) {
	if !newer(HLC{1, 1}, "b", HLC{1, 1}, "a") || newer(HLC{1, 1}, "a", HLC{1, 1}, "b") || newer(HLC{1, 1}, "a", HLC{1, 1}, "a") {
		t.Fatal("node tie-break")
	}
	if !newer(HLC{2, 0}, "a", HLC{1, 9}, "z") || newer(HLC{1, 0}, "z", HLC{2, 0}, "a") {
		t.Fatal("HLC order")
	}
}

func TestMapWordsKeepsSeparators(t *testing.T) {
	eq(t, titleCaps("ACME-ROBOTICS & CO 3M"), "Acme-Robotics & CO 3M")
	eq(t, NormalizeVendor("ACME ROBOTICS"), "Acme Robotics")
}
