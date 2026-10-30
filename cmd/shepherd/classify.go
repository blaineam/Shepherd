// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"net/netip"
	"time"

	"shepherd/internal/classify"
	"shepherd/internal/config"
	"shepherd/internal/devices"
	"shepherd/internal/dnsengine"
	"shepherd/internal/geo"
)

// startClassify builds the automatic device classifier, feeds it from the DNS
// engine and the device registry, and starts its periodic Apply pass. asnLoc
// is the shared ASN locator (nil when the map, and so ASN evidence, is off);
// the ASN family simply contributes nothing without it.
func startClassify(ctx context.Context, cfg config.Config, engine *dnsengine.Engine, reg *devices.Registry, asnLoc *geo.ASNLocator) (*classify.Classifier, error) {
	c, err := classify.New(classify.Options{NonBlocking: true})
	if err != nil {
		return nil, err
	}
	c.UseRegistry(reg)
	if asnLoc != nil {
		c.SetASN(func(addr netip.Addr) (classify.ASNInfo, bool) {
			a, ok := asnLoc.LookupAddr(addr)
			return classify.ASNInfo{Number: a.Number, Org: a.Org}, ok
		})
	}
	engine.Observe = c.Observe
	every := time.Duration(cfg.Classify.IntervalSeconds) * time.Second
	if classifyEvery > 0 {
		every = classifyEvery
	}
	go c.Run(ctx, reg, every)
	return c, nil
}

// classifyEvery overrides the Apply interval in tests. Production leaves it
// at its default, zero, meaning "use the configuration".
var classifyEvery time.Duration
