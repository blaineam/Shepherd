// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"path/filepath"
	"testing"

	"shepherd/internal/devices"
	"shepherd/internal/secrets"
	"shepherd/internal/traffic"
	"shepherd/internal/watch"
)

func testSecrets(t *testing.T) *secrets.Store {
	t.Helper()
	s, err := secrets.Open(filepath.Join(t.TempDir(), secrets.FileName))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestResolveByMACFindsTheDeviceTheRegistryKnows(t *testing.T) {
	reg := devices.New(devices.Options{NodeID: "test", Vendor: func(string) string { return "" }})
	resolve := resolveByMAC(reg)
	if _, ok := resolve("02:00:5e:00:00:21"); ok {
		t.Fatal("an unknown MAC resolved to a device")
	}
	reg.Observe(devices.Observation{MAC: "02:00:5e:00:00:21", IP: "192.0.2.21"})
	id, ok := resolve("02005e000021") // the reader hands over a bare MAC
	if !ok || id == "" {
		t.Fatalf("resolve = %q, %v", id, ok)
	}
	if _, ok := resolve("not a mac"); ok {
		t.Fatal("nonsense resolved to a device")
	}
	if _, ok := resolveByMAC(nil)("02:00:5e:00:00:21"); ok {
		t.Fatal("a nil registry resolved something")
	}
}

type fakeSteering map[string]watch.DeviceStatus

func (f fakeSteering) DeviceStatuses() map[string]watch.DeviceStatus { return f }

// Watch mode measures the devices it steers exactly; the router's estimate
// for those must not be added on top.
func TestSkipWatchedSkipsOnlyTheDevicesBeingSteered(t *testing.T) {
	if skipWatched(nil) != nil {
		t.Fatal("with no Watch engine nothing should be skipped")
	}
	var absent *watch.Engine
	if skipWatched(absent) != nil {
		t.Fatal("a Watch engine that was never started should skip nothing")
	}
	skip := skipWatched(fakeSteering{
		"d-steered": {State: watch.StateSteered},
		"d-pending": {State: watch.StatePending},
	})
	if !skip("d-steered") {
		t.Error("a steered device must be left to Watch mode")
	}
	for _, id := range []string{"d-pending", "d-unknown"} {
		if skip(id) {
			t.Errorf("%s is not being measured by Watch mode, so it must be counted", id)
		}
	}
}

// Nothing starts, and no stored credential is read, until the owner has
// connected a router and left the reader switched on.
func TestRouterUsageStaysIdleUntilItIsConnectedAndSwitchedOn(t *testing.T) {
	sec := testSecrets(t)
	reg := devices.New(devices.Options{NodeID: "test", Vendor: func(string) string { return "" }})
	store := traffic.NewStore(traffic.Options{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	m := startRouterUsage(ctx, sec, reg, store, nil)
	defer m.Stop()
	if st := m.Status(); st.Source != "" || st.LastError != "" {
		t.Fatalf("status with nothing connected = %+v", st)
	}

	// A session with no network chosen is still not a connection.
	if _, err := sec.SetEero(secrets.Eero{Token: "eero-token-abc", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	m.Reload()
	if st := m.Status(); st.Source != "" {
		t.Fatalf("status with no network chosen = %+v", st)
	}

	// Switched off, it still does not run.
	if _, err := sec.SetEeroNetwork("3001"); err != nil {
		t.Fatal(err)
	}
	if _, err := sec.SetEeroEnabled(false); err != nil {
		t.Fatal(err)
	}
	m.Reload()
	if st := m.Status(); st.Source != "" {
		t.Fatalf("status while switched off = %+v", st)
	}

	// Connected and on, it runs and says which router it is reading.
	if _, err := sec.SetEeroEnabled(true); err != nil {
		t.Fatal(err)
	}
	m.Reload()
	if st := m.Status(); st.Source != "eero" || !st.Estimated {
		t.Fatalf("status once connected = %+v", st)
	}

	// Forgetting the session stops it again.
	if err := sec.ClearEero(); err != nil {
		t.Fatal(err)
	}
	m.Reload()
	if st := m.Status(); st.Source != "" {
		t.Fatalf("status after forgetting = %+v", st)
	}
}

// A UniFi controller keeps real counters, so when both are connected it
// is the one that runs.
func TestAControllerWinsOverAnEeroSession(t *testing.T) {
	sec := testSecrets(t)
	reg := devices.New(devices.Options{NodeID: "test", Vendor: func(string) string { return "" }})
	store := traffic.NewStore(traffic.Options{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := startRouterUsage(ctx, sec, reg, store, nil)
	defer m.Stop()

	// eero alone.
	if _, err := sec.SetEero(secrets.Eero{Token: "eero-token-abc", NetworkID: "3001", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	m.Reload()
	if st := m.Status(); st.Source != "eero" {
		t.Fatalf("with only eero = %+v", st)
	}

	// Add a controller and it takes over, with counters rather than rates.
	if _, err := sec.SetUniFi(secrets.UniFi{BaseURL: "https://192.0.2.10", Username: "ro", Password: "pw", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	m.Reload()
	st := m.Status()
	if st.Source != "unifi" || st.Estimated {
		t.Fatalf("with both connected = %+v, want unifi and not estimated", st)
	}

	// Switched off, eero takes over again.
	if _, err := sec.SetUniFiEnabled(false); err != nil {
		t.Fatal(err)
	}
	m.Reload()
	if st := m.Status(); st.Source != "eero" {
		t.Fatalf("with the controller off = %+v", st)
	}
}

func TestAControllerAddressThatCannotBeUsedIsReported(t *testing.T) {
	sec := testSecrets(t)
	// Stored directly, since the portal would have refused it.
	if _, err := sec.SetUniFi(secrets.UniFi{BaseURL: "https://192.0.2.10", Username: "ro", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := sec.SetEeroNetwork("x"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := startRouterUsage(ctx, sec, testRegistry(), traffic.NewStore(traffic.Options{}), nil)
	defer m.Stop()
	if st := m.Status(); st.Source != "unifi" {
		t.Fatalf("a usable controller did not start: %+v", st)
	}
}

func testRegistry() *devices.Registry {
	return devices.New(devices.Options{NodeID: "test", Vendor: func(string) string { return "" }})
}
