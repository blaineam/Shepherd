// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"log"
	"path/filepath"
	"time"

	"shepherd/internal/alarms"
	"shepherd/internal/config"
	"shepherd/internal/devices"
	"shepherd/internal/dnsengine"
	"shepherd/internal/threats"
)

// threatsEvery overrides the refresh interval in tests; production leaves
// it at zero, meaning "use the configuration".
var threatsEvery time.Duration

// startThreats builds the threat-feed matcher (docs/THREATS.md), hooks it
// onto every recorded DNS query, raises a threat-match alarm for each hit
// and runs the periodic feed refresh. eng may be nil (alarms disabled):
// matches are still recorded and logged. Returns (nil, nil) when [threats]
// is off.
func startThreats(ctx context.Context, cfg config.Config, engine *dnsengine.Engine, reg *devices.Registry, eng *alarms.Engine) (*threats.Engine, error) {
	if !cfg.Threats.Enabled {
		return nil, nil
	}
	var th *threats.Engine
	th = threats.New(threats.Options{
		Dir: filepath.Join(cfg.DataDir, "threats"),
		OnMatch: func(m threats.Match) {
			reportThreatMatch(eng, reg, th, m)
		},
	})
	engine.OnEntry = th.Observe
	every := time.Duration(cfg.Threats.IntervalHours) * time.Hour
	if threatsEvery > 0 {
		every = threatsEvery
	}
	go th.Run(ctx, every)
	return th, nil
}

// reportThreatMatch logs a match and raises it as an alarm attributed to
// the device, keyed by device and indicator so a beacon folds into one
// open alarm rather than one per query.
func reportThreatMatch(eng *alarms.Engine, reg *devices.Registry, th *threats.Engine, m threats.Match) {
	who := m.Device
	deviceID := m.DeviceID
	var groups []string
	if deviceID == "" && reg != nil {
		if d, ok := reg.FindByIP(m.Client); ok {
			deviceID, who, groups = d.ID, d.DisplayName(), d.Groups
		}
	} else if reg != nil && deviceID != "" {
		if d, ok := reg.Get(deviceID); ok {
			groups = d.Groups
		}
	}
	if who == "" {
		who = m.Client
	}
	what := th.Describe(m.FeedID)
	log.Printf("threats: %s reached for %s (%s), %s on the %s feed, query %s", who, m.Name, m.Indicator, what, m.FeedID, m.Action)
	if eng == nil {
		return
	}
	subject := deviceID
	if subject == "" {
		subject = m.Client
	}
	eng.Raise(alarms.Event{
		Type:     alarms.TypeThreatMatch,
		Source:   "threats",
		Title:    who + " reached for " + what,
		Body:     m.Name + " is " + what + " (" + m.Indicator + " on " + m.FeedID + "); the lookup was " + m.Action + ".",
		Key:      "threat-match|" + subject + "|" + m.Indicator + "|",
		DeviceID: deviceID,
		GroupIDs: groups,
		Domain:   m.Name,
		Time:     m.Time,
		Evidence: []alarms.Evidence{
			{Label: "Looked up", Value: m.Name},
			{Label: "Matched", Value: m.Indicator},
			{Label: "Feed", Value: m.FeedID},
			{Label: "Query was", Value: m.Action},
			{Label: "Client", Value: m.Client},
		},
	})
}
