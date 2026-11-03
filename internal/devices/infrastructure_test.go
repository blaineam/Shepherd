// SPDX-License-Identifier: AGPL-3.0-or-later

package devices

import (
	"strings"
	"testing"
)

// The answer is a fact about the device rather than a policy of either
// feature that asks, which is why it lives here: both Watch mode's steering
// and DHCP mode's routing refuse the same devices for the same reasons.
func TestInfrastructureRecognisesWhatTheNetworkDependsOn(t *testing.T) {
	cases := []struct {
		name string
		dev  Device
		want string
	}{
		{"a router", Device{Type: TypeRouter}, "network infrastructure"},
		{"a smart-home hub", Device{Type: TypeSmartHome}, "smart-home hub"},
		{"a Thread border router", Device{Services: []string{"_meshcop._udp.local"}}, "Thread/Matter"},
		{"a Matter device", Device{Services: []string{"_matterc._udp"}}, "Thread/Matter"},
		{"a mesh vendor", Device{Vendor: "eero Inc."}, "infrastructure vendor"},
		{"another mesh vendor", Device{Vendor: "Ubiquiti Networks"}, "infrastructure vendor"},
	}
	for _, c := range cases {
		dev := c.dev
		ok, why := Infrastructure(&dev)
		if !ok {
			t.Errorf("%s should be infrastructure", c.name)
			continue
		}
		if !strings.Contains(why, c.want) {
			t.Errorf("%s: reason %q should mention %q", c.name, why, c.want)
		}
	}
}

func TestInfrastructureLeavesOrdinaryDevicesAlone(t *testing.T) {
	for _, dev := range []Device{
		{Type: TypeLaptop, Vendor: "Apple"},
		{Type: TypePhone},
		{Type: TypeGameConsole, Vendor: "Sony Interactive Entertainment"},
		{Services: []string{"_airplay._tcp", "_raop._tcp"}},
		{},
	} {
		d := dev
		if ok, why := Infrastructure(&d); ok {
			t.Errorf("%+v was called infrastructure (%s)", dev, why)
		}
	}
	if ok, why := Infrastructure(nil); ok || why != "" {
		t.Errorf("Infrastructure(nil) = %v, %q", ok, why)
	}
}

func TestRouteModeIsAThreePositionSwitchLikeWatch(t *testing.T) {
	for in, want := range map[string]RouteMode{
		"": RouteAuto, "auto": RouteAuto, " AUTO ": RouteAuto,
		"on": RouteOn, "ON": RouteOn, "off": RouteOff, " off": RouteOff,
	} {
		got, ok := ParseRouteMode(in)
		if !ok || got != want {
			t.Errorf("ParseRouteMode(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	if _, ok := ParseRouteMode("sometimes"); ok {
		t.Error("an unknown position must be refused rather than guessed")
	}
	for m, want := range map[RouteMode]string{RouteAuto: "auto", RouteOn: "on", RouteOff: "off"} {
		if got := m.String(); got != want {
			t.Errorf("%q.String() = %q, want %q", m, got, want)
		}
	}
}

func TestRouteSwitchRoundTripsThroughTheRegistry(t *testing.T) {
	r := New(Options{NodeID: "test", Vendor: func(string) string { return "" }})
	id := r.Observe(Observation{Source: SourceDHCP, MAC: "02:00:5e:01:02:03", IP: "192.0.2.100"})
	if id == "" {
		t.Fatal("the observation should have created a device")
	}
	if d, _ := r.Get(id); d.Route != RouteAuto {
		t.Errorf("a new device's Route = %q, want auto", d.Route)
	}
	if err := r.SetRoute(id, RouteOff); err != nil {
		t.Fatalf("SetRoute: %v", err)
	}
	if d, _ := r.Get(id); d.Route != RouteOff {
		t.Errorf("Route = %q, want off", d.Route)
	}
	if res := r.BulkSetRoute([]string{id}, RouteOn); res.Changed != 1 {
		t.Errorf("BulkSetRoute changed %d, want 1", res.Changed)
	}
	// Writing the same value is not a change, which is what keeps the
	// registry from emitting an event per poll.
	if res := r.BulkSetRoute([]string{id}, RouteOn); res.Changed != 0 {
		t.Errorf("an unchanged switch counted as %d changes", res.Changed)
	}
	if err := r.SetRoute("no-such-device", RouteOff); err == nil {
		t.Error("setting the switch on a device that does not exist must fail")
	}
}
