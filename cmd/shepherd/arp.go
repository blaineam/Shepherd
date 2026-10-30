// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"log"
	"os"

	"shepherd/internal/arp"
	"shepherd/internal/config"
	"shepherd/internal/devices"
)

// arpOpen is a test seam over arp.Open: production opens the real Linux raw
// socket (needs CAP_NET_RAW); tests inject a FakeSource so startARP can be
// exercised on every platform.
var arpOpen = arp.Open

// startARP builds the passive ARP monitor (internal/arp) and starts it in a
// goroutine that runs until ctx is cancelled. It never fails Shepherd's
// startup: when ARP monitoring is turned off, or arp.Open cannot get a read
// socket (wrong platform, no CAP_NET_RAW), it logs a clear warning and
// returns a nil Monitor. onEvent receives every arp.Event; it may be nil, in
// which case events are just logged until something consumes them (the
// alarm engine, once wired).
func startARP(ctx context.Context, cfg config.Config, reg *devices.Registry, onEvent func(arp.Event)) (*arp.Monitor, error) {
	if !cfg.ARP.Enabled {
		return nil, nil
	}
	src, iface, err := arpOpen(cfg.ARP.Interface)
	if err != nil {
		log.Printf("arp: passive monitoring is off: %v", err)
		return nil, nil
	}
	acfg := arp.DefaultConfig()
	acfg.Sink = reg
	acfg.GatewayFunc = arp.DefaultGatewayFunc(os.ReadFile)
	acfg.OnEvent = func(e arp.Event) {
		if onEvent != nil {
			onEvent(e)
			return
		}
		log.Printf("arp: %s (%s): %s", e.Type, e.Severity, e.Summary)
	}
	acfg.OnError = func(err error) { log.Printf("arp: %v", err) }
	mon := arp.NewMonitor(src, acfg)
	go func() {
		if err := mon.Run(ctx); err != nil {
			log.Printf("arp: monitor stopped: %v", err)
		}
	}()
	log.Printf("arp: passive monitor listening on %s", iface)
	return mon, nil
}
