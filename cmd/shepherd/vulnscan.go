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
	"shepherd/internal/config"
	"shepherd/internal/devices"
	"shepherd/internal/portscan"
	"shepherd/internal/vulnscan"
)

// Test seams, in the same style as portscanEvery/portscanDial. Production
// leaves them at their defaults.
var (
	vulnscanEvery time.Duration
	vulnscanDial  vulnscan.DialFunc
)

// startVulnscan builds the vulnerability scanner, restores its saved
// history from <data>/vulnscan.json, and starts its periodic probe of every
// port internal/portscan currently has open (docs/VULNSCAN.md). It needs ps
// (the already-running portscan.Scanner) to know which ports to probe —
// this feature never scans for open ports on its own. eng may be nil (the
// alarm engine is disabled); findings are still probed, persisted and
// logged either way, just never raised as alarms.
func startVulnscan(ctx context.Context, cfg config.Config, reg *devices.Registry, ps *portscan.Scanner, eng *alarms.Engine) (*vulnscan.Scanner, error) {
	s := vulnscan.New(vulnscan.Options{Dial: vulnscanDial})
	path := filepath.Join(cfg.DataDir, "vulnscan.json")
	if err := s.Load(path); err != nil && !os.IsNotExist(err) {
		log.Printf("vulnscan: ignoring unreadable history %s: %v", path, err)
	}
	s.OnScan = func(scans []vulnscan.DeviceFindings, resolved []vulnscan.ResolvedFinding) {
		if err := s.Save(path); err != nil {
			log.Printf("vulnscan: saving history: %v", err)
		}
		reportVulnscanFindings(eng, reg, scans, resolved)
	}
	every := time.Duration(cfg.Vulnscan.IntervalSeconds) * time.Second
	if vulnscanEvery > 0 {
		every = vulnscanEvery
	}
	lister := func() []vulnscan.Target { return vulnscan.TargetsFromPortscan(ps.Results()) }
	go s.Run(ctx, lister, every)
	return s, nil
}

// vulnscanDeviceName looks up a device's display name for a log line or
// alarm title; a device the registry no longer has (deleted since its last
// scan) just falls back to its ID, the same convention
// internal/portal/api_portscan.go's deviceName helper uses.
func vulnscanDeviceName(reg *devices.Registry, id string) string {
	if reg != nil {
		if d, ok := reg.Get(id); ok {
			return d.DisplayName()
		}
	}
	return id
}

// reportVulnscanFindings logs every newly active and newly resolved finding
// from one scan and, when an alarm engine is wired in, raises
// alarms.TypeVulnerabilityFound for each new one (once; internal/alarms'
// own dedupe keeps a steady repeat from paging again) and resolves the
// matching open alarm for each one that just cleared. Logging happens
// unconditionally, so there is always a plain server-log record of both
// transitions even with [alarms] disabled.
func reportVulnscanFindings(eng *alarms.Engine, reg *devices.Registry, scans []vulnscan.DeviceFindings, resolved []vulnscan.ResolvedFinding) {
	for _, ds := range scans {
		for _, f := range ds.Findings {
			if !f.NewlyFound {
				continue
			}
			name := vulnscanDeviceName(reg, ds.DeviceID)
			log.Printf("vulnscan: %s found on %s (%s), port %d: %s", f.Severity, name, ds.DeviceID, f.Port, f.Name)
			if eng != nil {
				eng.Raise(alarms.Event{
					Type:     alarms.TypeVulnerabilityFound,
					Severity: alarms.Severity(f.Severity),
					Source:   "vulnscan",
					Title:    fmt.Sprintf("%s: %s", name, f.Name),
					Body:     f.Description,
					Key:      vulnscanAlarmKey(ds.DeviceID, f.SignatureID, f.Port),
					DeviceID: ds.DeviceID,
					Evidence: []alarms.Evidence{
						{Label: "Port", Value: fmt.Sprintf("%d", f.Port)},
						{Label: "Evidence", Value: f.Evidence},
					},
				})
			}
		}
	}
	for _, r := range resolved {
		name := vulnscanDeviceName(reg, r.DeviceID)
		log.Printf("vulnscan: resolved on %s (%s), port %d: %s", name, r.DeviceID, r.Finding.Port, r.Finding.Name)
		if eng == nil {
			continue
		}
		resolveVulnscanAlarm(eng, r.DeviceID, r.Finding.SignatureID, r.Finding.Port)
	}
}

func vulnscanAlarmKey(deviceID, signatureID string, port int) string {
	return fmt.Sprintf("vulnerability-found|%s|%s|%d|", deviceID, signatureID, port)
}

// resolveVulnscanAlarm closes the alarm this exact finding raised, if it is
// still open, rather than leaving it to linger as "new" or "acknowledged"
// once the underlying vulnerability is actually gone. There is no separate
// "resolved" alarm type: Resolve is exactly the primitive internal/alarms
// already has for this (see docs/VULNSCAN.md's "Alerting" section).
func resolveVulnscanAlarm(eng *alarms.Engine, deviceID, signatureID string, port int) {
	key := vulnscanAlarmKey(deviceID, signatureID, port)
	page := eng.List(alarms.Query{Filter: alarms.Filter{
		Types: []string{alarms.TypeVulnerabilityFound}, DeviceID: deviceID, Text: key,
	}, Limit: 500})
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
		log.Printf("vulnscan: resolving alarm for %s: %v", deviceID, err)
	}
}
