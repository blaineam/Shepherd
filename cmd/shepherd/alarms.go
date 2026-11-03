// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"path/filepath"
	"sync"

	"shepherd/internal/alarms"
	"shepherd/internal/config"
	"shepherd/internal/dnsengine"
	"shepherd/internal/ntfy"
	"shepherd/internal/secrets"
)

// startAlarms builds the alarm engine and its delivery Router, wires ntfy
// into the Router when configured, subscribes the Router to the engine and
// starts it, and connects the DNS engine's upstream pool so a total outage
// and its recovery raise alarms. The returned engine is also handed to the
// portal (cmd/shepherd/main.go). The Router itself is not returned: nothing
// outside this file needs to drive it directly, only the engine it delivers
// for. Web Push is wired through startPush (push.go) when [alarms.push] is
// on, and the returned pushService is the portal's handle on subscriptions.
//
// The returned stop func cancels the Router's own context (derived from ctx,
// but independently cancelable) and waits for its goroutine to actually
// exit before closing the engine. It must not rely on ctx having already
// been cancelled by the caller: run's own defer order can close the alarm
// engine before its outer ctx is cancelled, and waiting on a goroutine
// that is still being told to keep running would deadlock. Calling stop
// before that goroutine has a chance to save its state is exactly the bug
// that let main.go's own ctx cancellation race the Router's final
// Router.Save, intermittently leaving <data_dir>/alarms mid-write when a
// test's early failure tore the directory down immediately after.
func startAlarms(ctx context.Context, cfg config.Config, pool *dnsengine.Pool, sec *secrets.Store) (eng *alarms.Engine, push *pushService, rt *alarms.Router, stop func(), err error) {
	dir := filepath.Join(cfg.DataDir, "alarms")
	eng, err = alarms.New(alarms.Options{Dir: dir})
	if err != nil {
		return nil, nil, nil, nil, err
	}
	push, pusher, err := startPush(cfg)
	if err != nil {
		eng.Close()
		return nil, nil, nil, nil, err
	}
	rt = alarms.NewRouter(alarms.RouterOptions{Source: eng, Pusher: pusher, Ntfy: ntfyPublisherFor(sec), Path: alarms.DefaultRouterPath(dir)})
	if err := rt.Load(); err != nil {
		eng.Close()
		return nil, nil, nil, nil, err
	}
	eng.Subscribe(rt.Handle)
	rctx, rcancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); rt.Run(rctx) }()
	wireUpstreamAlarms(eng, pool)
	stop = func() {
		rcancel()
		wg.Wait()
		eng.Close()
	}
	return eng, push, rt, stop, nil
}

// ntfyPublisherFor adapts the ntfy server the portal holds to the Router's
// NtfyPublisher, or nil when none is set or the owner has switched delivery
// off. The store is the single source of truth: shepherd.toml's
// [alarms.ntfy] is imported into it once at startup (seedNtfy) and ignored
// from then on, exactly like the mail relay.
func ntfyPublisherFor(sec *secrets.Store) alarms.NtfyPublisher {
	n, ok := sec.Ntfy()
	if !ok || !n.Enabled {
		return nil
	}
	return alarms.NewNtfyPublisher(ntfyClient(n), n.Topic)
}

// ntfyClient is the publishing client for a stored server. It is also what
// the portal's "send a test notification" action uses, so a test and a real
// alarm go out over exactly the same path.
func ntfyClient(n secrets.Ntfy) *ntfy.Client {
	return &ntfy.Client{Server: n.Server, Token: n.Token, Username: n.Username, Password: n.Password}
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
