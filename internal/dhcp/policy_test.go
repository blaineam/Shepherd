// SPDX-License-Identifier: AGPL-3.0-or-later

package dhcp

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"shepherd/internal/devices"
)

func ownSet() Own {
	return Own{
		MACs:    []string{"02:00:5e:00:00:20", "02:00:5e:00:00:21"},
		IPs:     []netip.Addr{shepherdA, netip.MustParseAddr("192.0.2.21")},
		Gateway: gatewayA, GatewayMAC: macGateway,
	}
}

func TestOwnRecognisesThisHostAndTheGatewayWhateverTheSpelling(t *testing.T) {
	o := ownSet()
	if !o.HasMAC("02-00-5E-00-00-20") {
		t.Error("one of this host's own MACs, spelled differently")
	}
	if !o.HasMAC(macGateway) {
		t.Error("the gateway's MAC")
	}
	if o.HasMAC(macA) || o.HasMAC("") || o.HasMAC("nonsense") {
		t.Error("an ordinary device is not ours")
	}
	if !o.HasIP(shepherdA) || !o.HasIP(gatewayA) {
		t.Error("our own and the gateway's addresses")
	}
	if o.HasIP(poolStart) || o.HasIP(netip.Addr{}) {
		t.Error("an ordinary address is not ours")
	}
}

// Routing this host through itself is the failure Watch mode has a whole
// paragraph about, and no setting may override it.
func TestNothingCanRouteTheGatewayOrThisHostsOwnInterfaces(t *testing.T) {
	for _, d := range []devices.Device{
		{ID: "x", Route: devices.RouteOn},
		{ID: "x", Route: devices.RouteOn, Type: devices.TypeRouter},
	} {
		p := RoutePolicy{Route: true, Own: ownSet(), Lookup: func(string) (devices.Device, bool) { return d, true }}
		for _, c := range []struct {
			mac  string
			ip   netip.Addr
			want string
		}{
			{"02:00:5e:00:00:20", netip.Addr{}, ReasonOwnInterface},
			{macGateway, netip.Addr{}, ReasonGateway},
			{macA, shepherdA, ReasonOwnInterface},
			{macA, gatewayA, ReasonGateway},
		} {
			got := p.Decide(c.mac, c.ip)
			if got.Routed {
				t.Errorf("Decide(%s, %v) routed it; that can never be allowed", c.mac, c.ip)
			}
			if got.Reason != c.want {
				t.Errorf("Decide(%s, %v) reason = %q, want %q", c.mac, c.ip, got.Reason, c.want)
			}
			if !got.Hard {
				t.Errorf("Decide(%s, %v) should be a hard refusal", c.mac, c.ip)
			}
		}
	}
}

func TestRoutingOffRoutesNothingAndSaysSo(t *testing.T) {
	p := RoutePolicy{Route: false, Own: ownSet()}
	got := p.Decide(macA, poolStart)
	if got.Routed || got.Reason != ReasonRoutingOff {
		t.Fatalf("Decide = %+v, want not routed with the routing-off reason", got)
	}
	if got.Hard {
		t.Error("routing being off is not a hard refusal: turning it on changes the answer")
	}
}

// All-or-nothing: with routing on, an ordinary device is routed, and a device
// Shepherd has never seen is routed too -- refusing on missing information
// would quietly leave most of the house out of the measurement.
func TestRoutingOnRoutesEveryOrdinaryDeviceIncludingUnknownOnes(t *testing.T) {
	p := RoutePolicy{Route: true, Own: ownSet()}
	if got := p.Decide(macA, poolStart); !got.Routed {
		t.Fatalf("a device with no registry record should be routed, got %+v", got)
	}
	p.Lookup = func(string) (devices.Device, bool) {
		return devices.Device{ID: "d1", Type: devices.TypeLaptop}, true
	}
	if got := p.Decide(macA, poolStart); !got.Routed || got.Reason != "" {
		t.Fatalf("an ordinary laptop should be routed, got %+v", got)
	}
}

func TestTheSoftRefusals(t *testing.T) {
	cases := []struct {
		name string
		dev  devices.Device
		want string
	}{
		{"switch off", devices.Device{Route: devices.RouteOff}, ReasonSwitchOff},
		{"excluded", devices.Device{Excluded: true}, ReasonExcluded},
		{"a router", devices.Device{Type: devices.TypeRouter}, "network infrastructure"},
		{"a smart-home hub", devices.Device{Type: devices.TypeSmartHome}, "smart-home hub"},
		{"a Thread border router", devices.Device{Services: []string{"_meshcop._udp"}}, "Thread/Matter"},
		{"a mesh vendor", devices.Device{Vendor: "eero Inc"}, "infrastructure vendor"},
		{"a console", devices.Device{Type: devices.TypeGameConsole}, "NAT type"},
		{"an unclassified console", devices.Device{Vendor: "Sony Interactive Entertainment"}, "NAT type"},
	}
	for _, c := range cases {
		dev := c.dev
		p := RoutePolicy{Route: true, Own: ownSet(), Lookup: func(string) (devices.Device, bool) { return dev, true }}
		got := p.Decide(macA, poolStart)
		if got.Routed {
			t.Errorf("%s should not be routed", c.name)
			continue
		}
		if !strings.Contains(got.Reason, c.want) {
			t.Errorf("%s: reason %q should mention %q", c.name, got.Reason, c.want)
		}
	}
}

// "Always route" overrides the soft refusals, the way Watch mode's "Always
// watch" does -- but the switch-off and excluded checks come first, because
// those are the owner's own two ways of saying no.
func TestAlwaysRouteOverridesTheSoftRefusalsOnly(t *testing.T) {
	infra := devices.Device{Type: devices.TypeRouter, Route: devices.RouteOn}
	p := RoutePolicy{Route: true, Own: ownSet(), Lookup: func(string) (devices.Device, bool) { return infra, true }}
	if got := p.Decide(macA, poolStart); !got.Routed {
		t.Errorf("Always route should override the infrastructure refusal, got %+v", got)
	}

	excluded := devices.Device{Excluded: true, Route: devices.RouteOn}
	p.Lookup = func(string) (devices.Device, bool) { return excluded, true }
	if got := p.Decide(macA, poolStart); got.Routed {
		t.Error("an Excluded device is opted out, and this is a thing to be opted out of")
	}
}

func TestRouteConsolesTurnsTheConsoleRefusalOff(t *testing.T) {
	console := devices.Device{Type: devices.TypeGameConsole}
	p := RoutePolicy{Route: true, RouteConsoles: true, Own: ownSet(),
		Lookup: func(string) (devices.Device, bool) { return console, true }}
	if got := p.Decide(macA, poolStart); !got.Routed {
		t.Fatalf("with route_consoles on a console is routed like anything else, got %+v", got)
	}
}

func TestDeviceRouteModeParsing(t *testing.T) {
	for in, want := range map[string]devices.RouteMode{
		"": devices.RouteAuto, "auto": devices.RouteAuto, "AUTO": devices.RouteAuto,
		"on": devices.RouteOn, " off ": devices.RouteOff,
	} {
		got, ok := devices.ParseRouteMode(in)
		if !ok || got != want {
			t.Errorf("ParseRouteMode(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	if _, ok := devices.ParseRouteMode("sometimes"); ok {
		t.Error("an unknown position must be refused")
	}
	if devices.RouteAuto.String() != "auto" || devices.RouteOff.String() != "off" {
		t.Error("String should spell the position")
	}
}

func TestInfrastructureIsNilSafe(t *testing.T) {
	if ok, why := devices.Infrastructure(nil); ok || why != "" {
		t.Errorf("Infrastructure(nil) = %v, %q", ok, why)
	}
}

func TestRegistryRouteSwitchRoundTrips(t *testing.T) {
	reg := devices.New(devices.Options{NodeID: "test"})
	id := reg.Observe(devices.Observation{Source: devices.SourceDHCP, MAC: macA, IP: poolStart.String(), Time: time.Now()})
	if id == "" {
		t.Fatal("the observation should have created a device")
	}
	if err := reg.SetRoute(id, devices.RouteOff); err != nil {
		t.Fatalf("SetRoute: %v", err)
	}
	d, _ := reg.Get(id)
	if d.Route != devices.RouteOff {
		t.Errorf("Route = %q, want off", d.Route)
	}
	res := reg.BulkSetRoute([]string{id}, devices.RouteOn)
	if res.Changed != 1 {
		t.Fatalf("BulkSetRoute changed %d devices, want 1", res.Changed)
	}
	// Setting the same value again changes nothing, which is what keeps the
	// registry from emitting an event per poll.
	if res := reg.BulkSetRoute([]string{id}, devices.RouteOn); res.Changed != 0 {
		t.Errorf("an unchanged switch should not count as a change, got %+v", res.Changed)
	}
}
