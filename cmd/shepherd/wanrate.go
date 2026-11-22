// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"log"
	"os"

	"shepherd/internal/arp"
	"shepherd/internal/wanrate"
)

// wanInterface names the interface the default route leaves by. A seam,
// so the wiring is tested the same way on every platform.
var wanInterface = func() (string, error) {
	r, err := arp.DefaultRoute(os.ReadFile)
	return r.Iface, err
}

// wanReader reads an interface's byte counters. A seam for tests.
var wanReader = wanrate.SysReader

// startWANRate measures the whole network's throughput at the WAN port,
// every second, and returns how to read it. That is only the network's
// throughput where this machine is the router: anywhere else the default
// route's interface carries this machine's own traffic and nothing more.
// So the reading is offered only while Shepherd is reading a Firewalla it
// runs on (backendManager.onBox). It returns nil when the interface cannot
// be found, which is every platform but Linux.
func startWANRate(ctx context.Context, backend *backendManager) func() (down, up float64, ok bool) {
	iface, err := wanInterface()
	if err != nil || iface == "" {
		return nil
	}
	read := wanReader(iface)
	if _, _, err := read(); err != nil {
		return nil
	}
	m := wanrate.New(read, nil)
	go m.Run(ctx, wanrate.DefaultEvery)
	log.Printf("bandwidth: measuring the network's throughput at %s every %s", iface, wanrate.DefaultEvery)
	return func() (float64, float64, bool) {
		if backend == nil || !backend.onBox() {
			return 0, 0, false
		}
		return m.Rate()
	}
}
