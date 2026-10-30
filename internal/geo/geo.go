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

// reader holds a replaceable MaxMind-format database. The zero value is
// usable and finds nothing until a database is opened. Locator and ASNLocator
// share it so both keep the same swap-on-success guarantee.
type reader struct {
	mu sync.RWMutex
	db *maxminddb.Reader
}

// open loads the database at path, replacing any previous one. On error the
// previous database stays in use.
func (r *reader) open(path string) error {
	db, err := maxminddb.Open(path)
	if err != nil {
		return err
	}
	r.mu.Lock()
	old := r.db
	r.db = db
	r.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	return nil
}

func (r *reader) ready() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.db != nil
}

// decode looks addr up and decodes the record into v. It reports false when
// no database is loaded, the address is absent or the record cannot be read.
func (r *reader) decode(addr netip.Addr, v any) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.db == nil {
		return false
	}
	res := r.db.Lookup(addr.Unmap())
	return res.Found() && res.Decode(v) == nil
}

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
type Locator struct{ reader }

// Open loads the database at path, replacing any previous one. On error the
// previous database stays in use.
func (l *Locator) Open(path string) error { return l.open(path) }

// Ready reports whether a database is loaded.
func (l *Locator) Ready() bool { return l.ready() }

// Locate implements dnsengine.Geo.
func (l *Locator) Locate(ip net.IP) (dnsengine.Dest, bool) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return dnsengine.Dest{}, false
	}
	var rec record
	if !l.decode(addr, &rec) {
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
