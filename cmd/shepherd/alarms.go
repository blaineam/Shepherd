// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"path/filepath"

	"shepherd/internal/alarms"
	"shepherd/internal/config"
	"shepherd/internal/dnsengine"
	"shepherd/internal/ntfy"
)

// startAlarms builds the alarm engine and its delivery Router, wires ntfy
// into the Router when configured, subscribes the Router to the engine and
// starts it, and connects the DNS engine's upstream pool so a total outage
// and its recovery raise alarms. The returned engine is also handed to the
// portal (cmd/shepherd/main.go). The Router itself is not returned: nothing
// outside this file needs to drive it directly, only the engine it delivers
// for. Web Push is not wired in; see docs/ALARMS.md.
func startAlarms(ctx context.Context, cfg config.Config, pool *dnsengine.Pool) (*alarms.Engine, error) {
	dir := filepath.Join(cfg.DataDir, "alarms")
	eng, err := alarms.New(alarms.Options{Dir: dir})
	if err != nil {
		return nil, err
	}
	rt := alarms.NewRouter(alarms.RouterOptions{Source: eng, Ntfy: ntfyPublisherFor(cfg.Alarms.Ntfy), Path: alarms.DefaultRouterPath(dir)})
	if err := rt.Load(); err != nil {
		eng.Close()
		return nil, err
	}
	eng.Subscribe(rt.Handle)
	go rt.Run(ctx)
	wireUpstreamAlarms(eng, pool)
	return eng, nil
}

// ntfyPublisherFor adapts the ntfy config section to the Router's
// NtfyPublisher, or nil when ntfy delivery is off.
func ntfyPublisherFor(c config.AlarmsNtfy) alarms.NtfyPublisher {
	if !c.Enabled {
		return nil
	}
	return alarms.NewNtfyPublisher(&ntfy.Client{
		Server: c.Server, Token: c.Token, Username: c.Username, Password: c.Password,
	}, c.Topic)
}

// wireUpstreamAlarms hooks the pool's health-change callback (see
// dnsengine.Pool.OnHealthChange) to raise alarms.TypeUpstreamDown when every
// configured upstream has gone unhealthy (a total outage, matching the
// type's description) and alarms.TypeUpstreamRecovered whenever any one
// upstream answers again (low severity, so it is fine to report each
// resolver's own recovery rather than waiting for the whole pool). This is
// the DNS engine's only existing upstream-health signal (internal/dnsengine's
// automatic failover and probing); nothing new was added to track health
// twice.
func wireUpstreamAlarms(eng *alarms.Engine, pool *dnsengine.Pool) {
	pool.OnHealthChange = func(addr string, healthy bool) {
		if healthy {
			eng.Raise(alarms.Event{
				Type:     alarms.TypeUpstreamRecovered,
				Source:   "dnsengine",
				Title:    "Upstream DNS recovered: " + addr,
				Evidence: []alarms.Evidence{{Label: "Upstream", Value: addr}},
			})
			return
		}
		for _, s := range pool.Status() {
			if s.Healthy {
				return // at least one upstream still answers: not a total outage
			}
		}
		eng.Raise(alarms.Event{
			Type:     alarms.TypeUpstreamDown,
			Source:   "dnsengine",
			Title:    "Every upstream DNS resolver stopped answering",
			Evidence: []alarms.Evidence{{Label: "Last to fail", Value: addr}},
		})
	}
}
