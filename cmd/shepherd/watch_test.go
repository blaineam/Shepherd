// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"shepherd/internal/arp"
	"shepherd/internal/config"
	"shepherd/internal/devices"
	"shepherd/internal/intercept"
	"shepherd/internal/watch"
)

// refusingPlatform is a watch.Platform that cannot do anything, which is
// what a host without the capabilities (or not Linux at all) looks like.
type refusingPlatform struct{ err error }

func (p refusingPlatform) DefaultRoute() (string, netip.Addr, error) { return "", netip.Addr{}, p.err }
func (p refusingPlatform) DefaultRoute6() (watch.Route6, error)      { return watch.Route6{}, p.err }
func (p refusingPlatform) Link(string) (watch.Link, error)           { return watch.Link{}, p.err }
func (p refusingPlatform) GatewayMAC(context.Context, string, netip.Addr) (arp.MAC, error) {
	return arp.MAC{}, p.err
}
func (p refusingPlatform) Neighbors(string) ([]watch.Neighbor, error) { return nil, p.err }
func (p refusingPlatform) OpenSender(string) (intercept.Sender, func() error, error) {
	return nil, nil, p.err
}
func (p refusingPlatform) AttachXDP(context.Context, *intercept.Controller, string, intercept.XDPOptions) error {
	return p.err
}
func (p refusingPlatform) ParallelRelay(context.Context, *intercept.Controller, string, int) error {
	return p.err
}
func (p refusingPlatform) GRO(string) (bool, error)  { return false, p.err }
func (p refusingPlatform) SetGRO(string, bool) error { return p.err }

func watchConfig(t *testing.T, w config.Watch) config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.Watch = w
	return cfg
}

func TestStartWatchOffDoesNothing(t *testing.T) {
	for _, w := range []config.Watch{
		{Enabled: false, Mode: "auto", ActiveWindowSeconds: 900},
		{Enabled: true, Mode: "off", ActiveWindowSeconds: 900},
	} {
		eng, err := startWatch(context.Background(), watchConfig(t, w), devices.New(devices.Options{}))
		if err != nil || eng != nil {
			t.Fatalf("%+v: engine %v err %v", w, eng, err)
		}
	}
}

func TestStartWatchRejectsABadMode(t *testing.T) {
	_, err := startWatch(context.Background(), watchConfig(t, config.Watch{Enabled: true, Mode: "kernel"}), devices.New(devices.Options{}))
	if err == nil || !strings.Contains(err.Error(), "kernel") {
		t.Fatalf("err = %v", err)
	}
}

// A host that cannot run Watch mode must not fail Shepherd's startup: the
// engine comes back, says why in its own status, and the rest of Shepherd
// is untouched.
func TestStartWatchWithoutCapabilitiesStartsAnyway(t *testing.T) {
	old := watchPlatform
	watchPlatform = func() watch.Platform { return refusingPlatform{err: errors.New("operation not permitted")} }
	t.Cleanup(func() { watchPlatform = old })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	eng, err := startWatch(ctx, watchConfig(t, config.Watch{Enabled: true, Mode: "auto", ActiveWindowSeconds: 900}), devices.New(devices.Options{}))
	if err != nil || eng == nil {
		t.Fatalf("engine %v err %v", eng, err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		snap := eng.Snapshot()
		if snap.Phase == watch.PhaseUnavailable && strings.Contains(snap.Reason, "not permitted") {
			if !snap.Enabled || !snap.Armed {
				t.Fatalf("snapshot = %+v", snap)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("engine never reported why it is unavailable: %+v", eng.Snapshot())
}

// The gateway-mac-changed event from the passive ARP monitor must reach the
// engine, and nothing else about the ARP wiring may change.
func TestARPGatewayEventReachesWatch(t *testing.T) {
	oldPlat, oldOpen := watchPlatform, arpOpen
	watchPlatform = func() watch.Platform { return refusingPlatform{err: errors.New("nope")} }
	src := arp.NewFakeSource()
	arpOpen = func(string) (arp.Source, string, error) { return src, "test0", nil }
	t.Cleanup(func() { watchPlatform, arpOpen = oldPlat, oldOpen })

	cfg := watchConfig(t, config.Watch{Enabled: true, Mode: "auto", ActiveWindowSeconds: 900})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := devices.New(devices.Options{})
	eng, err := startWatch(ctx, cfg, reg)
	if err != nil || eng == nil {
		t.Fatalf("engine %v err %v", eng, err)
	}
	// Exactly the callback main.go builds.
	var seen int
	onEvent := func(e arp.Event) {
		if e.Type == arp.EventGatewayMACChanged {
			seen++
			eng.GatewayChanged()
		}
	}
	mon, err := startARP(ctx, cfg, reg, onEvent)
	if err != nil || mon == nil {
		t.Fatalf("monitor %v err %v", mon, err)
	}
	onEvent(arp.Event{Type: arp.EventGatewayMACChanged, Summary: "the gateway moved"})
	onEvent(arp.Event{Type: arp.EventNewMAC, Summary: "a new device"})
	if seen != 1 {
		t.Fatalf("gateway events seen = %d, want 1", seen)
	}
}

// The [watch] ipv6 switch has to reach the engine; everything it then
// gates on is the network's, and is tested in internal/watch.
func TestStartWatchPassesTheIPv6Switch(t *testing.T) {
	old := watchPlatform
	watchPlatform = func() watch.Platform { return refusingPlatform{err: errors.New("nope")} }
	t.Cleanup(func() { watchPlatform = old })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for _, on := range []bool{false, true} {
		cfg := watchConfig(t, config.Watch{Enabled: true, Mode: "auto", ActiveWindowSeconds: 900, IPv6: on})
		eng, err := startWatch(ctx, cfg, devices.New(devices.Options{}))
		if err != nil || eng == nil {
			t.Fatalf("ipv6=%v: engine %v err %v", on, eng, err)
		}
		if got := eng.Snapshot().IPv6Wanted; got != on {
			t.Errorf("ipv6=%v: IPv6Wanted = %v", on, got)
		}
	}
}
