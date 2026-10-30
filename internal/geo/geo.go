// SPDX-License-Identifier: AGPL-3.0-or-later

// Package geo places IP addresses on the globe using a keyless, locally stored
// GeoIP database. Nothing about your traffic is sent anywhere to do this: the
// database is downloaded once a month and every lookup happens on your machine.
package geo

import (
	"net"
	"net/netip"
	"sync"

	"github.com/oschwald/maxminddb-golang/v2"

	"shepherd/internal/dnsengine"
)

// Attribution is the credit the database's license (CC BY 4.0) requires us to show.
const Attribution = "IP geolocation by DB-IP.com (CC BY 4.0)"

type record struct {
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	Location struct {
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
}

// Locator answers lookups from a memory-mapped GeoIP database. The zero value
// is usable and simply finds nothing until a database is opened.
type Locator struct {
	mu sync.RWMutex
	db *maxminddb.Reader
}

// Open loads the database at path, replacing any previous one. On error the
// previous database stays in use.
func (l *Locator) Open(path string) error {
	r, err := maxminddb.Open(path)
	if err != nil {
		return err
	}
	l.mu.Lock()
	old := l.db
	l.db = r
	l.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	return nil
}

// Ready reports whether a database is loaded.
func (l *Locator) Ready() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.db != nil
}

// Locate implements dnsengine.Geo.
func (l *Locator) Locate(ip net.IP) (dnsengine.Dest, bool) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return dnsengine.Dest{}, false
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.db == nil {
		return dnsengine.Dest{}, false
	}
	var rec record
	res := l.db.Lookup(addr.Unmap())
	if !res.Found() || res.Decode(&rec) != nil {
		return dnsengine.Dest{}, false
	}
	if rec.Location.Latitude == 0 && rec.Location.Longitude == 0 {
		return dnsengine.Dest{}, false // no usable coordinates
	}
	return dnsengine.Dest{
		Lat:     rec.Location.Latitude,
		Lon:     rec.Location.Longitude,
		City:    rec.City.Names["en"],
		Country: rec.Country.ISOCode,
	}, true
}
