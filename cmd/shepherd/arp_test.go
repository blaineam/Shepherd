// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"shepherd/internal/arp"
	"shepherd/internal/config"
)

func TestStartARPDisabledDoesNothing(t *testing.T) {
	old := arpOpen
	called := false
	arpOpen = func(string) (arp.Source, string, error) { called = true; return nil, "", nil }
	t.Cleanup(func() { arpOpen = old })

	cfg := config.Default()
	cfg.ARP.Enabled = false
	_, reg := testEngineAndRegistry(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mon, err := startARP(ctx, cfg, reg, nil)
	if err != nil || mon != nil {
		t.Fatalf("disabled arp: mon=%v err=%v", mon, err)
	}
	if called {
		t.Error("arp.Open must not be called when disabled")
	}
}

func TestStartARPOpenFailureIsAWarningNotAStartupError(t *testing.T) {
	old := arpOpen
	arpOpen = func(string) (arp.Source, string, error) { return nil, "", arp.ErrUnsupported }
	t.Cleanup(func() { arpOpen = old })

	cfg := config.Default()
	_, reg := testEngineAndRegistry(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mon, err := startARP(ctx, cfg, reg, nil)
	if err != nil {
		t.Fatalf("arp.Open failing must never fail startup, got err=%v", err)
	}
	if mon != nil {
		t.Errorf("mon = %v, want nil when the source could not be opened", mon)
	}
}

func TestStartARPFeedsTheRegistryAndTheEventCallback(t *testing.T) {
	src := arp.NewFakeSource()
	old := arpOpen
	arpOpen = func(iface string) (arp.Source, string, error) { return src, "test0", nil }
	t.Cleanup(func() { arpOpen = old })

	cfg := config.Default()
	_, reg := testEngineAndRegistry(t)

	var events []arp.Event
	done := make(chan struct{})
	onEvent := func(e arp.Event) {
		events = append(events, e)
		close(done)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mon, err := startARP(ctx, cfg, reg, onEvent)
	if err != nil {
		t.Fatal(err)
	}
	if mon == nil {
		t.Fatal("mon must not be nil when the source opens cleanly")
	}

	mac, err := arp.ParseMAC("02:00:00:00:00:02")
	if err != nil {
		t.Fatal(err)
	}
	src.Push(arp.NewRequest(mac, netip.MustParseAddr("192.0.2.20"), netip.MustParseAddr("192.0.2.1")))

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("onEvent was never called for a new MAC")
	}
	if len(events) != 1 || events[0].Type != arp.EventNewMAC {
		t.Errorf("events = %+v, want exactly one new-mac-seen", events)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if mon.Stats().Observations > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the registry never received an observation from the ARP monitor")
}

func TestStartARPWithoutAnEventCallbackJustLogs(t *testing.T) {
	src := arp.NewFakeSource()
	old := arpOpen
	arpOpen = func(string) (arp.Source, string, error) { return src, "test0", nil }
	t.Cleanup(func() { arpOpen = old })

	cfg := config.Default()
	_, reg := testEngineAndRegistry(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mon, err := startARP(ctx, cfg, reg, nil)
	if err != nil {
		t.Fatal(err)
	}
	mac, _ := arp.ParseMAC("02:00:00:00:00:03")
	src.Push(arp.NewRequest(mac, netip.MustParseAddr("192.0.2.30"), netip.MustParseAddr("192.0.2.1")))

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if mon.Stats().Events[arp.EventNewMAC] > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the monitor never recorded the new-mac event")
}

func TestStartARPStopsOnContextCancel(t *testing.T) {
	src := arp.NewFakeSource()
	old := arpOpen
	arpOpen = func(string) (arp.Source, string, error) { return src, "test0", nil }
	t.Cleanup(func() { arpOpen = old })

	cfg := config.Default()
	_, reg := testEngineAndRegistry(t)
	ctx, cancel := context.WithCancel(context.Background())
	mon, err := startARP(ctx, cfg, reg, nil)
	if err != nil {
		t.Fatal(err)
	}
	cancel()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if src.Closed() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("the ARP source was never closed after ctx was cancelled; mon=%v", mon)
}

func TestStartARPUsesTheConfiguredInterface(t *testing.T) {
	var got string
	old := arpOpen
	arpOpen = func(iface string) (arp.Source, string, error) {
		got = iface
		return nil, "", errors.New("not opening a real socket in this test")
	}
	t.Cleanup(func() { arpOpen = old })

	cfg := config.Default()
	cfg.ARP.Interface = "eth7"
	_, reg := testEngineAndRegistry(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := startARP(ctx, cfg, reg, nil); err != nil {
		t.Fatal(err)
	}
	if got != "eth7" {
		t.Errorf("arpOpen called with interface %q, want %q", got, "eth7")
	}
}
