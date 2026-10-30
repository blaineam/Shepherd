// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"log"
	"sync"

	"shepherd/internal/dnsengine"
	"shepherd/internal/geo"
)

// startGeoBlock wires the engine's additive country-block check (see
// dnsengine.Engine.CountryBlock): it runs only after a query would
// otherwise be allowed, and never reaches into the Filter's own policy
// decision. locator is nil when [map] is disabled; the check then simply
// never blocks, since no answer is ever geolocated either. It logs once,
// and only when a scope actually has countries configured, so an install
// that never uses this feature stays silent.
func startGeoBlock(engine *dnsengine.Engine, store *dnsengine.GeoBlockStore, cs dnsengine.ClientScopes, locator *geo.Locator) {
	var warnOnce sync.Once
	engine.CountryBlock = func(clientIP string, dests []dnsengine.Dest) (string, bool) {
		blocked := store.BlockedFor(clientIP, cs)
		if len(blocked) == 0 {
			return "", false
		}
		if locator == nil || !locator.Ready() {
			warnOnce.Do(func() {
				log.Print("geo-block: countries are configured but [map] is disabled or the GeoIP database has not loaded yet; country blocking is inactive until then")
			})
			return "", false
		}
		for _, d := range dests {
			if blocked[d.Country] {
				return d.Country, true
			}
		}
		return "", false
	}
}
