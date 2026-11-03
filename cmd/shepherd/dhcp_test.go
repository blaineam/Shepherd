// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"shepherd/internal/alarms"
	"shepherd/internal/config"
	"shepherd/internal/devices"
	"shepherd/internal/dhcp"
)

// fakeHost is a hostNetwork that answers from a table, so startDHCP's own
// wiring is exercised on every platform with no interface and no /proc.
type fakeHost struct {
	iface   string
	gateway netip.Addr
	addrs   []netip.Addr
	nets    []netip.Prefix
	macs    []string
	ips     []netip.Addr

	routeErr error
	addrErr  error
	localErr error
}

func (f fakeHost) DefaultRoute() (string, netip.Addr, error) {
	return f.iface, f.gateway, f.routeErr
}

func (f fakeHost) Addrs(string) ([]netip.Addr, []netip.Prefix, error) {
	return f.addrs, f.nets, f.addrErr
}

func (f fakeHost) LocalAddrs() ([]string, []netip.Addr, error) {
	return f.macs, f.ips, f.localErr
}

func goodHost() fakeHost {
	return fakeHost{
		iface:   "eth0",
		gateway: netip.MustParseAddr("192.0.2.1"),
		addrs:   []netip.Addr{netip.MustParseAddr("192.0.2.20")},
		nets:    []netip.Prefix{netip.MustParsePrefix("192.0.2.20/24")},
		macs:    []string{"02:00:5e:00:00:20"},
		ips:     []netip.Addr{netip.MustParseAddr("192.0.2.20")},
	}
}

func withHost(t *testing.T, h hostNetwork) {
	t.Helper()
	prev := dhcpHost
	dhcpHost = func() hostNetwork { return h }
	t.Cleanup(func() { dhcpHost = prev })
}

func dhcpConfig(t *testing.T, mode string) config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.DHCP.Mode = mode
	cfg.DHCP.PoolStart = "192.0.2.100"
	cfg.DHCP.PoolEnd = "192.0.2.110"
	return cfg
}

func TestStartDHCPWithTheModeOffStillOffersReservations(t *testing.T) {
	withHost(t, goodHost())
	reg := devices.New(devices.Options{NodeID: "test"})
	srv, err := startDHCP(context.Background(), dhcpConfig(t, "off"), reg, nil)
	if err != nil {
		t.Fatalf("startDHCP: %v", err)
	}
	if srv == nil {
		t.Fatal("a server is built even with the mode off, so the portal can show and edit reservations")
	}
	if got := srv.Status().Mode; got != "off" {
		t.Errorf("Mode = %q", got)
	}
	if err := srv.SetReservation(dhcp.Reservation{MAC: "02:00:5e:01:02:03", Hostname: "printer"}); err != nil {
		t.Fatalf("SetReservation with the mode off: %v", err)
	}
	if len(srv.Reservations()) != 1 {
		t.Error("the reservation should be stored")
	}
}

func TestStartDHCPRefusesAnUnknownMode(t *testing.T) {
	withHost(t, goodHost())
	cfg := dhcpConfig(t, "maybe")
	reg := devices.New(devices.Options{NodeID: "test"})
	if _, err := startDHCP(context.Background(), cfg, reg, nil); err == nil {
		t.Fatal("an unknown mode must be refused: this one decides whether a house has DHCP")
	}
}

// Like Watch mode and the ARP monitor, DHCP mode never fails Shepherd's
// startup: a host it cannot run on gets a logged reason and everything else
// runs untouched.
func TestStartDHCPNeverFailsStartupOnAHostItCannotRunOn(t *testing.T) {
	reg := devices.New(devices.Options{NodeID: "test"})
	cases := map[string]hostNetwork{
		"no default route":   fakeHost{routeErr: errors.New("no /proc/net/route")},
		"no interface":       fakeHost{iface: "eth0", gateway: netip.MustParseAddr("192.0.2.1"), addrErr: errors.New("no such interface")},
		"no local addresses": fakeHost{iface: "eth0", gateway: netip.MustParseAddr("192.0.2.1"), addrs: goodHost().addrs, nets: goodHost().nets, localErr: errors.New("cannot list interfaces")},
	}
	for name, host := range cases {
		withHost(t, host)
		srv, err := startDHCP(context.Background(), dhcpConfig(t, "observe"), reg, nil)
		if err != nil {
			t.Errorf("%s: startDHCP = %v, want no error", name, err)
		}
		if srv != nil {
			t.Errorf("%s: want no server", name)
		}
	}
}

func TestStartDHCPRefusesToStartWithAnUnreadableReservationsFile(t *testing.T) {
	withHost(t, goodHost())
	cfg := dhcpConfig(t, "observe")
	if err := os.WriteFile(filepath.Join(cfg.DataDir, "dhcp.json"), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	reg := devices.New(devices.Options{NodeID: "test"})
	srv, err := startDHCP(context.Background(), cfg, reg, nil)
	if err != nil {
		t.Fatalf("startDHCP = %v; it must not stop Shepherd", err)
	}
	if srv != nil {
		t.Error("but it must not run either: silently dropping a reservation is how a printer changes address")
	}
}

func TestStartDHCPInObserveModeRunsAndListens(t *testing.T) {
	withHost(t, goodHost())
	cfg := dhcpConfig(t, "observe")
	reg := devices.New(devices.Options{NodeID: "test"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, err := startDHCP(ctx, cfg, reg, nil)
	if err != nil {
		t.Fatalf("startDHCP: %v", err)
	}
	if srv == nil {
		t.Fatal("observe mode should start")
	}
	set := srv.SettingsView()
	if set.Subnet != "192.0.2.0/24" || set.ServerIP != "192.0.2.20" || set.Gateway != "192.0.2.1" {
		t.Errorf("SettingsView = %+v; the empty configuration keys should be filled from the interface", set)
	}
	if len(set.DNS) != 1 || set.DNS[0] != "192.0.2.20" {
		t.Errorf("DNS = %v, want Shepherd's own address by default", set.DNS)
	}
}

func TestDhcpSettingsFillsTheGapsFromTheInterfaceAndHonoursTheFile(t *testing.T) {
	addrs := []netip.Addr{netip.MustParseAddr("192.0.2.20")}
	nets := []netip.Prefix{netip.MustParsePrefix("192.0.2.20/24")}
	gw := netip.MustParseAddr("192.0.2.1")

	// Everything empty: taken from the interface.
	got, err := dhcpSettings(config.DHCP{PoolStart: "192.0.2.100", PoolEnd: "192.0.2.110"}, gw, addrs, nets)
	if err != nil {
		t.Fatalf("dhcpSettings: %v", err)
	}
	if got.ServerIP != addrs[0] || got.Subnet.String() != "192.0.2.0/24" {
		t.Errorf("settings = %+v", got)
	}
	if got.LeaseTime != dhcp.DefaultLeaseTime {
		t.Errorf("LeaseTime = %v, want the default", got.LeaseTime)
	}

	// Everything given: the file wins.
	c := config.DHCP{
		Subnet: "192.0.2.0/25", ServerIP: "192.0.2.21", PoolStart: "192.0.2.100", PoolEnd: "192.0.2.110",
		DNS: []string{"192.0.2.20", "not an address"}, Domain: "example.test", LeaseSeconds: 1800,
	}
	got, err = dhcpSettings(c, gw, addrs, nets)
	if err != nil {
		t.Fatalf("dhcpSettings: %v", err)
	}
	if got.Subnet.String() != "192.0.2.0/25" || got.ServerIP.String() != "192.0.2.21" {
		t.Errorf("settings = %+v", got)
	}
	if got.Domain != "example.test" || got.LeaseTime.Minutes() != 30 {
		t.Errorf("settings = %+v", got)
	}
	if len(got.DNS) != 1 {
		t.Errorf("DNS = %v; an unparseable entry is dropped rather than carried as an invalid address", got.DNS)
	}

	// Settings that cannot serve come back with the reason, not as a fatal
	// error: the portal is where that belongs.
	if _, err := dhcpSettings(config.DHCP{}, netip.Addr{}, nil, nil); err == nil {
		t.Error("settings with nothing in them are not valid")
	}
}

func TestDhcpAlarmMapsEachConditionToItsType(t *testing.T) {
	if dhcpAlarm(nil) != nil {
		t.Fatal("with the alarm engine off there is nothing to raise to")
	}
	eng, err := alarms.New(alarms.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	raise := dhcpAlarm(eng)
	if raise == nil {
		t.Fatal("dhcpAlarm should return a function")
	}
	raise("critical", "Another DHCP server is answering", "from 192.0.2.2")
	raise("critical", "DHCP mode could not configure NAT", "nft refused")
	raise("warning", "DHCP lease file reset", "started with none")
	eng.Drain()

	seen := map[string]bool{}
	for _, a := range eng.List(alarms.Query{}).Alarms {
		seen[a.Type] = true
	}
	for _, want := range []string{alarms.TypeDHCPRogueServer, alarms.TypeDHCPNATFailed, alarms.TypeDHCPLeaseReset} {
		if !seen[want] {
			t.Errorf("no alarm of type %s was raised; got %v", want, seen)
		}
	}
}

// The real host reader is Linux-specific in its routing table but not in its
// interface list, so what is checked here is that it answers at all rather
// than what it answers: the values belong to whatever machine runs the tests.
func TestRealHostNetworkReadsThisMachine(t *testing.T) {
	var h hostNetwork = realHostNetwork{}
	macs, ips, err := h.LocalAddrs()
	if err != nil {
		t.Fatalf("LocalAddrs: %v", err)
	}
	if len(macs) == 0 && len(ips) == 0 {
		t.Error("a machine running tests has at least one address")
	}
	for _, m := range macs {
		if dhcp.NormalizeMAC(m) != m {
			t.Errorf("MAC %q should already be normalized", m)
		}
	}

	// A named interface that cannot exist, so the error path is covered on
	// every platform.
	if _, _, err := h.Addrs("shepherd-no-such-interface"); err == nil {
		t.Error("Addrs on a missing interface must fail")
	}

	// The default route is read from /proc, so it is only expected to work
	// on Linux; either answer is fine, and what matters is that it does not
	// panic.
	if iface, gw, err := h.DefaultRoute(); err == nil && iface == "" && !gw.IsValid() {
		t.Error("a successful DefaultRoute should name something")
	}

	// And the loopback interface has addresses but no MAC, which is the
	// case the MAC filter exists for.
	if _, _, err := h.Addrs("lo"); err != nil {
		if _, _, err2 := h.Addrs("lo0"); err2 != nil {
			t.Logf("no loopback interface named lo or lo0 here: %v / %v", err, err2)
		}
	}
}

// With the interface and the gateway both given in the file, nothing is read
// from the routing table at all -- which is what a host whose default route
// is somewhere else needs.
func TestStartDHCPSkipsTheRoutingTableWhenTheFileSaysEnough(t *testing.T) {
	host := goodHost()
	host.routeErr = errors.New("this must not be called")
	withHost(t, host)
	cfg := dhcpConfig(t, "observe")
	cfg.DHCP.Interface = "eth0"
	cfg.DHCP.Gateway = "192.0.2.1"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, err := startDHCP(ctx, cfg, devices.New(devices.Options{NodeID: "test"}), nil)
	if err != nil {
		t.Fatalf("startDHCP: %v", err)
	}
	if srv == nil {
		t.Fatal("it should start")
	}
	if got := srv.SettingsView().Gateway; got != "192.0.2.1" {
		t.Errorf("Gateway = %q", got)
	}
}

// A mode that is switched on but cannot describe the network is a
// configuration mistake, and the portal is where it should be read: the
// server still starts so the status carries the reason.
func TestStartDHCPStartsWithUnusableSettingsSoTheReasonIsVisible(t *testing.T) {
	host := goodHost()
	host.addrs = nil
	host.nets = nil
	withHost(t, host)
	cfg := dhcpConfig(t, "observe")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, err := startDHCP(ctx, cfg, devices.New(devices.Options{NodeID: "test"}), nil)
	if err != nil {
		t.Fatalf("startDHCP: %v", err)
	}
	if srv == nil {
		t.Fatal("it should still start, so the portal can say what is wrong")
	}
}

// With the mode off the screen still needs the addressing, because a
// reservation has to be refused when it lands inside the dynamic pool. The
// first live run of this had empty settings, and the form could not have
// caught that mistake.
func TestTheModeBeingOffStillCarriesTheAddressingForTheScreen(t *testing.T) {
	withHost(t, goodHost())
	cfg := dhcpConfig(t, "off")
	cfg.DHCP.Subnet = "192.0.2.0/24"
	cfg.DHCP.ServerIP = "192.0.2.20"
	cfg.DHCP.Gateway = "192.0.2.1"
	srv, err := startDHCP(context.Background(), cfg, devices.New(devices.Options{NodeID: "test"}), nil)
	if err != nil {
		t.Fatalf("startDHCP: %v", err)
	}
	set := srv.SettingsView()
	if set.Subnet != "192.0.2.0/24" || set.PoolStart != "192.0.2.100" || set.PoolSize != 11 {
		t.Fatalf("SettingsView = %+v", set)
	}
	// And the pool rule is enforced against it.
	if err := srv.SetReservation(dhcp.Reservation{MAC: "02:00:5e:01:02:03", IP: netip.MustParseAddr("192.0.2.105")}); err == nil {
		t.Error("an address inside the pool must be refused with the mode off too")
	}
}

// A host that cannot be read is only a smaller screen while the mode is off,
// not a reason to show nothing.
func TestTheModeBeingOffSurvivesAHostItCannotRead(t *testing.T) {
	withHost(t, fakeHost{routeErr: errors.New("no /proc/net/route"), addrErr: errors.New("no such interface")})
	cfg := dhcpConfig(t, "off")
	srv, err := startDHCP(context.Background(), cfg, devices.New(devices.Options{NodeID: "test"}), nil)
	if err != nil {
		t.Fatalf("startDHCP: %v", err)
	}
	if srv == nil {
		t.Fatal("the mode being off should still give the portal a handle")
	}
	// The file's own pool is still there, which is what the form needs most.
	if got := srv.SettingsView().PoolStart; got != "192.0.2.100" {
		t.Errorf("PoolStart = %q", got)
	}
}

func TestAnInterfaceThatCannotBeReadStopsAModeThatIsOn(t *testing.T) {
	host := goodHost()
	host.addrErr = errors.New("no such interface")
	withHost(t, host)
	srv, err := startDHCP(context.Background(), dhcpConfig(t, "serve"), devices.New(devices.Options{NodeID: "test"}), nil)
	if err != nil {
		t.Fatalf("startDHCP = %v; it must not stop Shepherd", err)
	}
	if srv != nil {
		t.Error("but a mode that is on cannot run without the interface")
	}
}
