// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"log"
	"reflect"

	"shepherd/internal/devices"
	"shepherd/internal/importers"
	"shepherd/internal/routerusage"
	"shepherd/internal/secrets"
	"shepherd/internal/traffic"
	"shepherd/internal/watch"
)

// startRouterUsage wires the passive bandwidth reader (docs/TRAFFIC.md):
// per-device numbers read from the router the owner already has, for
// networks where Watch mode cannot run. Nothing starts, and no stored
// credential is touched, until the owner connects a router in the portal;
// the Manager is returned so the portal can restart it when they do.
func startRouterUsage(ctx context.Context, sec *secrets.Store, reg *devices.Registry, store *traffic.Store, watchEngine *watch.Engine) *routerusage.Manager {
	build := func() (*routerusage.Collector, bool, error) {
		e, ok := sec.Eero()
		if !ok || !e.Enabled || e.NetworkID == "" {
			return nil, false, nil
		}
		client, err := importers.NewClient(importers.ClientOptions{
			TokenStore: secrets.EeroTokenStore{S: sec},
		})
		if err != nil {
			return nil, false, err
		}
		resumed, err := client.Resume()
		if err != nil {
			return nil, false, fmt.Errorf("reading the stored eero session: %w", err)
		}
		if !resumed {
			return nil, false, nil // the token was cleared from under us
		}
		return routerusage.New(routerusage.Options{
			Source:      routerusage.NewEero(client, e.NetworkID),
			Recorder:    store,
			Resolve:     resolveByMAC(reg),
			Skip:        skipWatched(watchEngine),
			NeedsSignIn: routerusage.EeroNeedsSignIn,
			Logf:        log.Printf,
		}), true, nil
	}
	m := routerusage.NewManager(ctx, build, log.Printf)
	m.Reload()
	return m
}

// resolveByMAC turns a router's MAC into the device the registry knows by
// it. A MAC the registry has never seen counts towards nothing until the
// registry learns it, which it does by itself.
func resolveByMAC(reg *devices.Registry) routerusage.Resolver {
	return func(mac string) (string, bool) {
		if reg == nil {
			return "", false
		}
		d, ok := reg.FindByMAC(mac)
		if !ok {
			return "", false
		}
		return d.ID, true
	}
}

// steeringReporter is the part of Watch mode's engine this needs, so the
// rule below can be tested without starting one.
type steeringReporter interface {
	DeviceStatuses() map[string]watch.DeviceStatus
}

// skipWatched leaves out every device Watch mode is steering, because
// Watch mode is measuring those exactly and the two must not be added
// together. With Watch mode off, nothing is skipped.
func skipWatched(e steeringReporter) func(string) bool {
	if e == nil || reflect.ValueOf(e).IsNil() {
		return nil
	}
	return func(deviceID string) bool {
		st, ok := e.DeviceStatuses()[deviceID]
		return ok && st.State == watch.StateSteered
	}
}
