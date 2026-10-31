// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"log"
	"path/filepath"
	"time"

	"shepherd/internal/config"
	"shepherd/internal/devices"
	"shepherd/internal/watch"
)

// watchPlatform is a test seam over watch.RealPlatform: production talks to
// the real kernel (raw sockets, XDP, the ethtool ioctl, /proc); tests inject
// a fake so startWatch's own wiring is exercised on every platform without
// any capability.
var watchPlatform = func() watch.Platform { return watch.RealPlatform{} }

// startWatch builds Watch mode's engine (internal/watch, docs/WATCH.md) and
// runs it in a goroutine until ctx is cancelled. It is on by default and
// steers every eligible device's outbound IPv4 traffic through Shepherd.
//
// Like startARP, it never fails Shepherd's startup: a host that cannot run
// it (not Linux, no CAP_NET_RAW/CAP_NET_ADMIN/CAP_BPF, no usable interface)
// gets a logged reason and an engine that reports itself unavailable in the
// portal, with DNS filtering and everything else untouched. A nil Engine
// means the feature is switched off in the configuration.
//
// The returned engine is the portal's handle on Watch mode (status, the
// per-device state, the kill switch) and the sink for the ARP monitor's
// gateway-changed events.
func startWatch(ctx context.Context, cfg config.Config, reg *devices.Registry) (*watch.Engine, error) {
	mode, err := watch.ParseMode(cfg.Watch.Mode)
	if err != nil {
		return nil, err
	}
	if !cfg.Watch.Enabled || mode == watch.ModeOff {
		log.Print("watch: Watch mode is off (watch.enabled = false or watch.mode = \"off\"); no device traffic is steered")
		return nil, nil
	}
	secs := func(n int) time.Duration { return time.Duration(n) * time.Second }
	eng, err := watch.New(watch.Config{
		Enabled:   true,
		Interface: cfg.Watch.Interface,
		Mode:      mode,
		Workers:   cfg.Watch.Workers,
		IPv6:      cfg.Watch.IPv6,
		Policy: watch.PolicyConfig{
			SteerInfrastructure: cfg.Watch.SteerInfrastructure,
			ActiveWindow:        secs(cfg.Watch.ActiveWindowSeconds),
		},
		HealthInterval: secs(cfg.Watch.HealthIntervalSeconds),
		IdleGrace:      secs(cfg.Watch.IdleGraceSeconds),
		StartupGrace:   secs(cfg.Watch.StartupGraceSeconds),
		Registry:       reg,
		StatePath:      filepath.Join(cfg.DataDir, "watch.json"),
		Platform:       watchPlatform(),
	})
	if err != nil {
		return nil, err
	}
	go func() {
		if err := eng.Run(ctx); err != nil {
			log.Printf("watch: engine stopped: %v", err)
		}
	}()
	return eng, nil
}
