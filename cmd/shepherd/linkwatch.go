// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"

	"shepherd/internal/alarms"
	"shepherd/internal/config"
	"shepherd/internal/linkwatch"
)

// startLinkwatch watches the addresses Shepherd serves DNS on and reports
// every time one of them goes away, however briefly (docs/LINKWATCH.md).
// It returns the watcher, or nil when there is nothing it can watch (an
// install that listens only on loopback).
func startLinkwatch(ctx context.Context, cfg config.Config, eng *alarms.Engine) *linkwatch.Watcher {
	var addrs []netip.Addr
	for _, hp := range cfg.DNS.ListenAddrs() {
		host, _, err := net.SplitHostPort(hp)
		if err != nil {
			continue
		}
		if a, err := netip.ParseAddr(host); err == nil {
			addrs = append(addrs, a)
		}
	}
	w := linkwatch.New(linkwatch.Options{
		Addrs: addrs,
		OnLost: func(e linkwatch.Episode) {
			// Logged at once. An alarm cannot leave the machine while its
			// own link is down, so it is raised when the link returns.
			log.Printf("linkwatch: %s lost: %s", e.Addr, e.Reason)
		},
		OnRestored: func(e linkwatch.Episode) {
			log.Printf("linkwatch: %s is back after %s", e.Addr, e.Duration(e.End))
			raiseLinkLost(eng, e)
		},
	})
	if w.Watching() == 0 {
		return nil
	}
	go w.Run(ctx)
	return w
}

// raiseLinkLost reports one finished outage. The key is per address, so a
// link that flaps repeatedly shows up as one alarm with a count, not a flood.
func raiseLinkLost(eng *alarms.Engine, e linkwatch.Episode) {
	if eng == nil {
		return
	}
	iface := e.Iface
	if iface == "" {
		iface = "unknown"
	}
	eng.Raise(alarms.Event{
		Type:   alarms.TypeNetworkLinkLost,
		Source: "linkwatch",
		Title:  fmt.Sprintf("Network link lost for %s on %s (%s)", e.Duration(e.End), iface, e.Addr),
		Key:    "network-link-lost|" + e.Addr.String(),
		Evidence: []alarms.Evidence{
			{Label: "Address", Value: e.Addr.String()},
			{Label: "Interface", Value: iface},
			{Label: "Cause", Value: e.Reason},
			{Label: "Down for", Value: e.Duration(e.End).String()},
			{Label: "Started", Value: e.Start.UTC().Format(time.RFC3339)},
		},
	})
}
