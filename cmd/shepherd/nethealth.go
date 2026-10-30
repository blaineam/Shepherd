// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"shepherd/internal/alarms"
	"shepherd/internal/arp"
	"shepherd/internal/config"
	"shepherd/internal/nethealth"
)

// Test seams, in the same style as portscanEvery/portscanDial
// (cmd/shepherd/portscan.go). Production leaves them at their defaults.
var (
	nethealthEvery               time.Duration
	nethealthDial                nethealth.DialFunc
	nethealthBufferbloatEvery    time.Duration
	nethealthLoad                nethealth.LoadFunc
	nethealthBufferbloatDuration time.Duration
	// nethealthGateway learns the default gateway for the reachability
	// target list; production reads the real routing table. Tests inject a
	// fake so startNethealth is exercised the same way on every platform,
	// without needing a real route table (the same pattern
	// cmd/shepherd/arp.go's arpOpen uses for its own platform-specific call).
	nethealthGateway = arp.DefaultGatewayFunc(os.ReadFile)
)

// startNethealth builds the network-health prober, restores its saved
// history from <data>/nethealth.json, and starts its periodic
// latency/jitter/loss/reachability probe and, if configured, its separate
// bufferbloat check (docs/NETHEALTH.md). eng may be nil (the alarm engine
// is disabled); samples are still probed, persisted and logged either way,
// just never raised as alarms.
func startNethealth(ctx context.Context, cfg config.Config, eng *alarms.Engine) (*nethealth.Prober, error) {
	p := nethealth.New(nethealth.Options{Dial: nethealthDial, Load: nethealthLoad, BufferbloatDuration: nethealthBufferbloatDuration})
	path := filepath.Join(cfg.DataDir, "nethealth.json")
	if err := p.Load(path); err != nil && !os.IsNotExist(err) {
		log.Printf("nethealth: ignoring unreadable history %s: %v", path, err)
	}

	targets := nethealth.DefaultTargets(cfg.DNS.Upstreams)
	if gw, err := nethealthGateway(); err == nil && gw.IsValid() {
		targets = append(targets, gw.String())
	}

	tracker := nethealth.NewDegradationTracker(nethealth.DegradationOptions{})
	p.OnSample = func(s nethealth.Sample) {
		if err := p.Save(path); err != nil {
			log.Printf("nethealth: saving history: %v", err)
		}
		reportNethealthSample(eng, tracker, s)
	}

	every := time.Duration(cfg.Nethealth.IntervalSeconds) * time.Second
	if nethealthEvery > 0 {
		every = nethealthEvery
	}
	lister := func() []string { return targets }
	go p.Run(ctx, lister, every)

	if cfg.Nethealth.BufferbloatEnabled {
		bevery := time.Duration(cfg.Nethealth.BufferbloatIntervalSeconds) * time.Second
		if nethealthBufferbloatEvery > 0 {
			bevery = nethealthBufferbloatEvery
		}
		p.OnBufferbloat = func(b nethealth.Bufferbloat) {
			if err := p.Save(path); err != nil {
				log.Printf("nethealth: saving history: %v", err)
			}
			log.Printf("nethealth: bufferbloat check against %s: idle %.0fms, loaded %.0fms, grade %s", b.PingTarget, b.IdleMS, b.LoadedMS, b.Grade)
		}
		pingTarget := func() string {
			if len(targets) == 0 {
				return ""
			}
			return targets[0]
		}
		go p.RunBufferbloat(ctx, pingTarget, bevery, nethealth.BufferbloatOptions{})
	}

	return p, nil
}

// reportNethealthSample logs the sample's own headline numbers, feeds it
// to tracker, and raises or resolves alarms.TypeNetworkDegraded on the
// resulting Transition (docs/NETHEALTH.md's "Alerting" section). Logging
// happens unconditionally, the same convention cmd/shepherd/vulnscan.go's
// reportVulnscanFindings uses, so there is always a plain server-log
// record even with [alarms] disabled.
func reportNethealthSample(eng *alarms.Engine, tracker *nethealth.DegradationTracker, s nethealth.Sample) {
	log.Printf("nethealth: latency %.1fms jitter %.1fms loss %.1f%% reachable %d/%d", s.LatencyMS, s.JitterMS, s.LossPct, s.ReachableTargets, s.TotalTargets)
	if eng == nil {
		return
	}
	switch tracker.Update(s) {
	case nethealth.TransitionDegraded:
		eng.Raise(alarms.Event{
			Type:   alarms.TypeNetworkDegraded,
			Source: "nethealth",
			Title:  "Network latency, loss or reachability has been sustained bad",
			Key:    "network-degraded|",
			Evidence: []alarms.Evidence{
				{Label: "Latency", Value: fmt.Sprintf("%.0fms", s.LatencyMS)},
				{Label: "Loss", Value: fmt.Sprintf("%.0f%%", s.LossPct)},
				{Label: "Reachable", Value: fmt.Sprintf("%d/%d", s.ReachableTargets, s.TotalTargets)},
			},
		})
	case nethealth.TransitionRecovered:
		resolveNethealthAlarm(eng)
	}
}

// resolveNethealthAlarm closes the open network-degraded alarm, if any,
// mirroring cmd/shepherd/vulnscan.go's resolveVulnscanAlarm: there is one
// ongoing "is the network currently degraded" condition, not one alarm per
// bad sample, so resolving it is exactly internal/alarms.Engine.Resolve's
// existing primitive, not a second alarm type.
func resolveNethealthAlarm(eng *alarms.Engine) {
	const key = "network-degraded|"
	page := eng.List(alarms.Query{Filter: alarms.Filter{Types: []string{alarms.TypeNetworkDegraded}, Text: key}, Limit: 50})
	var ids []string
	for _, a := range page.Alarms {
		if a.Key == key && a.State != alarms.StateResolved {
			ids = append(ids, a.ID)
		}
	}
	if len(ids) == 0 {
		return
	}
	if _, err := eng.Resolve(alarms.Selector{IDs: ids}); err != nil {
		log.Printf("nethealth: resolving alarm: %v", err)
	}
}
