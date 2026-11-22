// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"shepherd/internal/secrets"
	"shepherd/internal/wanrate"
)

func withWAN(t *testing.T, iface string, ifaceErr error, read wanrate.Reader) {
	t.Helper()
	oldIface, oldReader := wanInterface, wanReader
	t.Cleanup(func() { wanInterface, wanReader = oldIface, oldReader })
	wanInterface = func() (string, error) { return iface, ifaceErr }
	wanReader = func(string) wanrate.Reader { return read }
}

func TestTheWANRateIsOfferedOnlyOnTheRouterItself(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// No default route, no interface name, or counters that cannot be
	// read: there is nothing to measure.
	withWAN(t, "", errors.New("no route"), nil)
	if startWANRate(ctx, nil) != nil {
		t.Fatal("a meter with no default route")
	}
	withWAN(t, "", nil, nil)
	if startWANRate(ctx, nil) != nil {
		t.Fatal("a meter with no interface")
	}
	withWAN(t, "eth9", nil, func() (uint64, uint64, error) { return 0, 0, errors.New("no counters") })
	if startWANRate(ctx, nil) != nil {
		t.Fatal("a meter over counters that cannot be read")
	}

	var mu sync.Mutex
	var rx uint64
	withWAN(t, "eth9", nil, func() (uint64, uint64, error) {
		mu.Lock()
		defer mu.Unlock()
		rx += 5000
		return rx, rx / 2, nil
	})
	// Not on the router: the interface carries only this machine's traffic.
	if rate := startWANRate(ctx, nil); rate == nil {
		t.Fatal("no meter")
	} else if _, _, ok := rate(); ok {
		t.Fatal("offered with no backend")
	}
	sec := testSecrets(t)
	if _, err := sec.SetFirewalla(secrets.Firewalla{BaseURL: "https://home.firewalla.net", Token: "tok", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	msp := &liveMSP{}
	viaMSP := &backendManager{parent: ctx, sec: sec, dataDir: t.TempDir(), transport: msp.transport(t)}
	t.Cleanup(viaMSP.Stop)
	viaMSP.Reload()
	if viaMSP.onBox() {
		t.Fatal("a Firewalla read through MSP is not this machine")
	}
	if _, _, ok := startWANRate(ctx, viaMSP)(); ok {
		t.Fatal("offered for a Firewalla somewhere else")
	}
	if viaMSP.interval() != 30*time.Second {
		t.Fatalf("an MSP account is read every %s", viaMSP.interval())
	}
	if (&backendManager{}).interval() != 30*time.Second {
		t.Fatal("no default interval")
	}

	// On the box: offered, once two readings have made a rate.
	sec2 := testSecrets(t)
	if _, err := sec2.SetFirewalla(secrets.Firewalla{BaseURL: "http://127.0.0.1:8834", Local: true, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	var writes []string
	onBox := &backendManager{parent: ctx, sec: sec2, dataDir: t.TempDir(), transport: boxAPI(t, &writes)}
	t.Cleanup(onBox.Stop)
	onBox.Reload()
	if !onBox.onBox() || onBox.interval() != localInterval {
		t.Fatalf("onBox %v, read every %s", onBox.onBox(), onBox.interval())
	}
	rate := startWANRate(ctx, onBox)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if down, up, ok := rate(); ok && down > 0 && up > 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("no rate on the box")
}
