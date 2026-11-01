// SPDX-License-Identifier: AGPL-3.0-or-later

package watch

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"shepherd/internal/arp"
	"shepherd/internal/devices"
)

func sprintf(format string, args ...any) string { return fmt.Sprintf(format, args...) }

func phone(now time.Time) *devices.Device {
	return &devices.Device{
		ID: "d1", MACs: []string{phoneMAC.String()}, IPs: []string{phoneIP.String()},
		IPSeen: map[string]time.Time{phoneIP.String(): now}, LastSeen: now, Type: devices.TypePhone,
	}
}

func TestDecideSteersAnOrdinaryRecentDevice(t *testing.T) {
	dec := Decide(phone(t0), PolicyConfig{}, Own{MACs: []arp.MAC{gwMAC, shepherdMAC}}, t0)
	if !dec.Eligible || dec.State != StatePending || dec.Reason != "" {
		t.Fatalf("decision = %+v", dec)
	}
}

func TestDecideStandingRefusals(t *testing.T) {
	own := Own{MACs: []arp.MAC{gwMAC, shepherdMAC}}
	cases := map[string]func(d *devices.Device){
		"excluded":        func(d *devices.Device) { d.Excluded = true },
		"watch off":       func(d *devices.Device) { d.Watch = devices.WatchOff },
		"gateway":         func(d *devices.Device) { d.MACs = []string{gwMAC.String()} },
		"shepherd":        func(d *devices.Device) { d.MACs = []string{phoneMAC.String(), shepherdMAC.String()} },
		"router type":     func(d *devices.Device) { d.Type = devices.TypeRouter },
		"hub type":        func(d *devices.Device) { d.Type = devices.TypeSmartHome },
		"thread border":   func(d *devices.Device) { d.Services = []string{"_airplay._tcp", "_meshcop._udp"} },
		"matter":          func(d *devices.Device) { d.Services = []string{"_matterc._udp"} },
		"infra vendor":    func(d *devices.Device) { d.Vendor = "eero inc" },
		"excluded and on": func(d *devices.Device) { d.Excluded = true; d.Watch = devices.WatchOn },
	}
	for name, mut := range cases {
		d := phone(t0)
		mut(d)
		dec := Decide(d, PolicyConfig{}, own, t0)
		if dec.Eligible || dec.State != StateSkipped || !dec.Policy || dec.Reason == "" {
			t.Errorf("%s: decision = %+v", name, dec)
		}
	}
}

func TestDecideWatchOnOverridesInfrastructureButNotExclusion(t *testing.T) {
	d := phone(t0)
	d.Type = devices.TypeRouter
	d.Watch = devices.WatchOn
	if dec := Decide(d, PolicyConfig{}, Own{}, t0); !dec.Eligible {
		t.Fatalf("watch=on should steer a router: %+v", dec)
	}
	d.Watch = devices.WatchAuto
	if dec := Decide(d, PolicyConfig{SteerInfrastructure: true}, Own{}, t0); !dec.Eligible {
		t.Fatalf("steer_infrastructure should steer a router: %+v", dec)
	}
}

func TestDecideTransientRefusals(t *testing.T) {
	d := phone(t0)
	d.MACs = nil
	if dec := Decide(d, PolicyConfig{}, Own{}, t0); dec.Eligible || dec.State != StateIdle || dec.Policy {
		t.Errorf("no MAC: %+v", dec)
	}
	d = phone(t0)
	d.IPs = []string{"2001:db8::10"}
	if dec := Decide(d, PolicyConfig{}, Own{}, t0); dec.Eligible || dec.State != StateIdle || !strings.Contains(dec.Reason, "IPv4") {
		t.Errorf("v6 only: %+v", dec)
	}
	d = phone(t0)
	later := t0.Add(16 * time.Minute)
	if dec := Decide(d, PolicyConfig{}, Own{}, later); dec.Eligible || dec.State != StateIdle || !strings.Contains(dec.Reason, "not seen for 16 min") {
		t.Errorf("stale: %+v", dec)
	}
	if dec := Decide(d, PolicyConfig{ActiveWindow: time.Hour}, Own{}, later); !dec.Eligible {
		t.Errorf("a longer window should keep it: %+v", dec)
	}
	d.LastSeen = time.Time{}
	if dec := Decide(d, PolicyConfig{}, Own{}, t0); dec.Eligible || !strings.Contains(dec.Reason, "ever") {
		t.Errorf("never seen: %+v", dec)
	}
}

func TestRoundAge(t *testing.T) {
	for d, want := range map[time.Duration]string{30 * time.Second: "under a minute", 5 * time.Minute: "5 min", 3 * time.Hour: "3 h", 72 * time.Hour: "3 days"} {
		if got := roundAge(d, t0); got != want {
			t.Errorf("%s: %q, want %q", d, got, want)
		}
	}
}

func TestPrimaryIPv4PrefersTheMostRecentlySeen(t *testing.T) {
	d := phone(t0)
	d.IPs = []string{"192.0.2.10", "2001:db8::10", "192.0.2.11", "224.0.0.1"}
	d.IPSeen = map[string]time.Time{"192.0.2.10": t0.Add(-time.Hour), "192.0.2.11": t0}
	if got := primaryIPv4(d); got != netip.MustParseAddr("192.0.2.11") {
		t.Fatalf("primary = %s", got)
	}
	d.IPs = []string{"2001:db8::10"}
	if got := primaryIPv4(d); got.IsValid() {
		t.Fatalf("v6 only should give no primary, got %s", got)
	}
}

func TestTargetsSingleMAC(t *testing.T) {
	ts, skipped := targets(phone(t0), nil)
	if skipped != "" || len(ts) != 1 || ts[0].MAC != phoneMAC || ts[0].IP != phoneIP {
		t.Fatalf("targets = %+v (%q)", ts, skipped)
	}
}

func TestTargetsMultiMACUsesTheNeighbourTable(t *testing.T) {
	other := mustMAC("02:00:5e:00:00:11")
	otherIP := netip.MustParseAddr("192.0.2.11")
	d := phone(t0)
	d.MACs = append(d.MACs, other.String())
	d.IPs = append(d.IPs, otherIP.String())
	d.IPSeen[otherIP.String()] = t0

	ts, skipped := targets(d, nil)
	if len(ts) != 0 || skipped == "" {
		t.Fatalf("with no table, nothing should be guessed: %+v %q", ts, skipped)
	}
	nb := map[netip.Addr]arp.MAC{phoneIP: phoneMAC, otherIP: other}
	ts, skipped = targets(d, nb)
	if skipped != "" || len(ts) != 2 || ts[0].MAC != phoneMAC || ts[0].IP != phoneIP || ts[1].MAC != other || ts[1].IP != otherIP {
		t.Fatalf("targets = %+v (%q)", ts, skipped)
	}
	// Only one MAC in the table: the other is left alone, not guessed.
	ts, skipped = targets(d, map[netip.Addr]arp.MAC{otherIP: other})
	if skipped != "" || len(ts) != 1 || ts[0].MAC != other {
		t.Fatalf("targets = %+v (%q)", ts, skipped)
	}
}

func TestParseMode(t *testing.T) {
	for s, want := range map[string]Mode{"": ModeAuto, "auto": ModeAuto, "XDP": ModeXDP, "userspace": ModeUserspace, "off": ModeOff} {
		m, err := ParseMode(s)
		if err != nil || m != want {
			t.Errorf("%q: %v %v", s, m, err)
		}
		if m.String() == "" {
			t.Errorf("%v has no name", m)
		}
	}
	if _, err := ParseMode("kernel"); err == nil {
		t.Error("unknown mode accepted")
	}
	if Mode(9).String() != "Mode(9)" {
		t.Error("unknown mode string")
	}
}

func TestBackoffDoublesAndCaps(t *testing.T) {
	if backoffFor(1) != retryBase || backoffFor(2) != 2*retryBase || backoffFor(3) != 4*retryBase {
		t.Fatalf("backoff = %s %s %s", backoffFor(1), backoffFor(2), backoffFor(3))
	}
	if backoffFor(20) != retryMax {
		t.Fatalf("cap = %s", backoffFor(20))
	}
}

// ---------------------------------------------------------------- IPv6

func TestDecideV6NeverForcedForInfrastructure(t *testing.T) {
	// Unlike Decide, the per-device "always watch" switch does not get a
	// Thread border router or a smart-home hub IPv6-steered.
	for _, mut := range []func(*devices.Device){
		func(d *devices.Device) { d.Type = devices.TypeRouter },
		func(d *devices.Device) { d.Type = devices.TypeSmartHome },
		func(d *devices.Device) { d.Services = []string{"_meshcop._udp"} },
		func(d *devices.Device) { d.Services = []string{"_matter._tcp"} },
		func(d *devices.Device) { d.Vendor = "eero" },
	} {
		d := phone(t0)
		d.IPs = append(d.IPs, phoneV6.String())
		d.Watch = devices.WatchOn
		mut(d)
		if dec := DecideV6(d, PolicyConfig{}, t0); dec.Eligible || !dec.Policy || !strings.Contains(dec.Reason, "never forced") {
			t.Errorf("decision = %+v", dec)
		}
		// The same device is still allowed for IPv4 when forced on.
		if dec := Decide(d, PolicyConfig{}, Own{}, t0); !dec.Eligible {
			t.Errorf("IPv4 should still be allowed when forced: %+v", dec)
		}
	}
}

func TestDecideV6NeedsAnIPv6Address(t *testing.T) {
	d := phone(t0)
	if dec := DecideV6(d, PolicyConfig{}, t0); dec.Eligible || dec.Policy || !strings.Contains(dec.Reason, "no IPv6 address") {
		t.Fatalf("decision = %+v", dec)
	}
	d.IPs = append(d.IPs, phoneV6.String())
	if dec := DecideV6(d, PolicyConfig{}, t0); !dec.Eligible {
		t.Fatalf("decision = %+v", dec)
	}
	// steer_infrastructure also lifts the IPv6 refusal, deliberately: it
	// is the operator saying so in the configuration file, not a switch
	// in the portal.
	d.Type = devices.TypeSmartHome
	if dec := DecideV6(d, PolicyConfig{SteerInfrastructure: true}, t0); !dec.Eligible {
		t.Fatalf("decision = %+v", dec)
	}
}

func TestDeviceIPv6PrefersTheLinkLocal(t *testing.T) {
	d := phone(t0)
	ula := uniqueLocal(0x10)
	d.IPs = []string{"192.0.2.10", "2001:db8::10", phoneV6.String(), ula.String()}
	if got := deviceIPv6(d); got != phoneV6 {
		t.Fatalf("got %s, want the link-local", got)
	}
	// Without a link-local, the most recently seen unicast address wins.
	d.IPs = []string{"2001:db8::10", ula.String()}
	d.IPSeen = map[string]time.Time{"2001:db8::10": t0.Add(-time.Hour), ula.String(): t0}
	if got := deviceIPv6(d); got != ula {
		t.Fatalf("got %s", got)
	}
	d.IPs = []string{"192.0.2.10"}
	if got := deviceIPv6(d); got.IsValid() {
		t.Fatalf("an IPv4-only device must have no IPv6 target, got %s", got)
	}
}

func TestIsGlobalV6(t *testing.T) {
	global := map[netip.Addr]bool{
		netip.MustParseAddr("2001:db8::1"): true,
		uniqueLocal(0x01):                  false,
		linkLocal(0x01):                    false,
		netip.MustParseAddr("ff02::1"):     false,
		netip.MustParseAddr("::1"):         false,
		netip.MustParseAddr("::"):          false,
		netip.MustParseAddr("192.0.2.1"):   false,
	}
	for a, want := range global {
		if got := isGlobalV6(a); got != want {
			t.Errorf("isGlobalV6(%s) = %v, want %v", a, got, want)
		}
	}
}

func TestUsableDeviceV6(t *testing.T) {
	usable := map[netip.Addr]bool{
		linkLocal(0x10):                     true,
		netip.MustParseAddr("2001:db8::10"): true,
		uniqueLocal(0x10):                   true,
		netip.MustParseAddr("ff02::1"):      false,
		netip.MustParseAddr("::1"):          false,
		netip.MustParseAddr("::"):           false,
		netip.MustParseAddr("192.0.2.10"):   false,
	}
	for a, want := range usable {
		if got := usableDeviceV6(a); got != want {
			t.Errorf("usableDeviceV6(%s) = %v, want %v", a, got, want)
		}
	}
}

func TestParseDefaultRoute6(t *testing.T) {
	// The real shape of /proc/net/ipv6_route: an on-link prefix, a
	// link-local prefix, a multicast route, then the default route.
	table := "" +
		"20010db8000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000000 00000000 00000001 eth0\n" +
		"fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000000 00000000 00000001 eth0\n" +
		"ff000000000000000000000000000000 08 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000000 00000000 00000001 eth0\n" +
		"00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000000 00000000 00000003 eth0\n"
	r, err := ParseDefaultRoute6([]byte(table))
	if err != nil {
		t.Fatal(err)
	}
	if r.Iface != "eth0" || r.NextHop != linkLocal(0x01) || r.Metric != 0x400 {
		t.Fatalf("route = %+v", r)
	}

	// The lowest metric wins.
	two := table + "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000002 00000100 00000000 00000000 00000003 eth1\n"
	if r, err = ParseDefaultRoute6([]byte(two)); err != nil || r.NextHop != linkLocal(0x02) || r.Iface != "eth1" {
		t.Fatalf("route = %+v err = %v", r, err)
	}
}

func TestParseDefaultRoute6Rejections(t *testing.T) {
	zeros := "00000000000000000000000000000000"
	line := func(dest, plen, hop, flags, iface string) string {
		return dest + " " + plen + " " + zeros + " 00 " + hop + " 00000400 00000000 00000000 " + flags + " " + iface + "\n"
	}
	ll := "fe800000000000000000000000000001"
	cases := map[string]string{
		"empty":             "",
		"no default route":  line("20010db8000000000000000000000000", "40", ll, "00000003", "eth0"),
		"not up":            line(zeros, "00", ll, "00000002", "eth0"),
		"not via a gateway": line(zeros, "00", ll, "00000001", "eth0"),
		"no next hop":       line(zeros, "00", zeros, "00000003", "eth0"),
		"short line":        "00000000 00 x\n",
		"bad hex address":   line("zzzz", "00", ll, "00000003", "eth0"),
		"bad hex flags":     line(zeros, "00", ll, "zz", "eth0"),
		"truncated address": line("0000", "00", ll, "00000003", "eth0"),
	}
	for name, table := range cases {
		if _, err := ParseDefaultRoute6([]byte(table)); !errors.Is(err, ErrNoDefaultRoute6) {
			t.Errorf("%s: err = %v, want ErrNoDefaultRoute6", name, err)
		}
	}
}
