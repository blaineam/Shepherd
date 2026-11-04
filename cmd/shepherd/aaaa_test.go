package main

import (
	"path/filepath"
	"testing"
	"time"

	"shepherd/internal/devices"
	"shepherd/internal/settings"
)

func testPrefs(t *testing.T) *settings.Store {
	t.Helper()
	s, err := settings.Open(filepath.Join(t.TempDir(), "settings.json"))
	if err != nil {
		t.Fatalf("settings.Open: %v", err)
	}
	return s
}

func TestAAAASwitchModes(t *testing.T) {
	prefs := testPrefs(t)
	a := newAAAASwitch(prefs, "off", nil)
	if a.filter("10.0.0.5") {
		t.Error(`"off" must not filter`)
	}
	a = newAAAASwitch(prefs, "on", nil)
	if !a.filter("10.0.0.5") {
		t.Error(`"on" must always filter`)
	}
	a = newAAAASwitch(prefs, "auto", nil)
	if a.filter("10.0.0.5") {
		t.Error(`"auto" starts by not filtering, until the probe finds IPv6 unreachable`)
	}
	// An unknown or empty dns.filter_aaaa falls back to "auto" rather than
	// to no filtering at all, so a typo cannot silently turn it off.
	if got := newAAAASwitch(prefs, "", nil).mode(); got != settings.AAAAAuto {
		t.Errorf("empty config mode = %q, want %q", got, settings.AAAAAuto)
	}
}

func TestAAAASwitchPortalModeWinsOverConfig(t *testing.T) {
	prefs := testPrefs(t)
	a := newAAAASwitch(prefs, "off", nil)
	if err := prefs.SetAAAAMode(settings.AAAAOn); err != nil {
		t.Fatalf("SetAAAAMode: %v", err)
	}
	if !a.filter("10.0.0.5") {
		t.Error("a mode saved in the portal must win over dns.filter_aaaa, with no restart")
	}
	if err := prefs.ClearAAAAMode(); err != nil {
		t.Fatalf("ClearAAAAMode: %v", err)
	}
	if a.filter("10.0.0.5") {
		t.Error("clearing the portal's choice must hand the decision back to dns.filter_aaaa")
	}
}

func TestAAAASwitchDeviceOverridesNetwork(t *testing.T) {
	reg := devices.New(devices.Options{NodeID: "t", AllowLoopback: true})
	id := reg.Observe(devices.Observation{Source: devices.SourceNeighbor, MAC: "02:00:5e:00:00:01", IP: "10.0.0.104", Time: time.Now()})
	if id == "" {
		t.Fatal("the observation should have registered a device")
	}
	a := newAAAASwitch(testPrefs(t), "on", reg)
	if !a.filter("10.0.0.104") {
		t.Fatal(`the network says "on", so an "auto" device is filtered`)
	}
	// This is the escape hatch the solar inverter needed: a device that does
	// not cache a NODATA asks for the same filtered AAAA without end.
	if err := reg.SetAAAA(id, devices.AAAAOff); err != nil {
		t.Fatalf("SetAAAA: %v", err)
	}
	if a.filter("10.0.0.104") {
		t.Error(`a device set to "off" must be answered in full even where the network filters`)
	}
	if !a.network() {
		t.Error("the network-wide verdict must not change with one device's switch")
	}
	if !a.filter("10.0.0.7") {
		t.Error("another device must still be filtered")
	}

	a = newAAAASwitch(testPrefs(t), "off", reg)
	if err := reg.SetAAAA(id, devices.AAAAOn); err != nil {
		t.Fatalf("SetAAAA: %v", err)
	}
	if !a.filter("10.0.0.104") {
		t.Error(`a device set to "on" must be filtered even where the network does not`)
	}
	if a.filter("10.0.0.7") {
		t.Error("another device must not be filtered")
	}
}

func TestAAAASwitchLogsOnlyInAutoMode(t *testing.T) {
	prefs := testPrefs(t)
	// Nothing to assert on the log itself; this covers the guard and proves
	// a flip in the probe's verdict cannot panic in any mode.
	for _, mode := range []string{"auto", "on", "off"} {
		a := newAAAASwitch(prefs, mode, nil)
		a.logIPv6Change(true)
		a.logIPv6Change(false)
		if got := a.ipv6Usable(); !got {
			t.Errorf("%s: the probe has not run, so IPv6 is not yet called unusable", mode)
		}
	}
}
