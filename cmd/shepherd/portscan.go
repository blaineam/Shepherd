// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"time"

	"shepherd/internal/config"
	"shepherd/internal/devices"
	"shepherd/internal/portscan"
	"shepherd/internal/upnpigd"
)

// Test seams. Production leaves them at their defaults: portscanEvery zero
// (use the configuration), portscanDial nil (a real net.Dialer), and
// portscanExposure nil (build a real upnpigd.Checker when the
// configuration enables it, or leave WAN-exposure checking off entirely
// when it does not) — so tests never need a real socket, or a real
// router, to exercise this wiring.
var (
	portscanEvery    time.Duration
	portscanDial     portscan.DialFunc
	portscanExposure portscan.ExposureChecker
)

// startPortscan builds the port scanner, restores its saved history from
// <data>/portscan.json, and starts its periodic scan of every known device's
// common ports (docs/PORTSCAN.md). History is saved after every scan,
// scheduled or manual, so the portal's "scan now" persists too.
func startPortscan(ctx context.Context, cfg config.Config, reg *devices.Registry) (*portscan.Scanner, error) {
	exposure := portscanExposure
	if exposure == nil && cfg.Portscan.WANExposure.Enabled {
		every := time.Duration(cfg.Portscan.WANExposure.RefreshIntervalSeconds) * time.Second
		exposure = upnpigd.NewChecker(upnpigd.NewClient(), every)
	}
	s := portscan.New(portscan.Options{Dial: portscanDial, Exposure: exposure})
	path := filepath.Join(cfg.DataDir, "portscan.json")
	if err := s.Load(path); err != nil && !os.IsNotExist(err) {
		log.Printf("portscan: ignoring unreadable history %s: %v", path, err)
	}
	s.OnScan = func([]portscan.DeviceScan) {
		if err := s.Save(path); err != nil {
			log.Printf("portscan: saving history: %v", err)
		}
	}
	every := time.Duration(cfg.Portscan.IntervalSeconds) * time.Second
	if portscanEvery > 0 {
		every = portscanEvery
	}
	lister := func() []portscan.Target { return portscan.TargetsFromDevices(reg.List()) }
	go s.Run(ctx, lister, every)
	return s, nil
}
