// SPDX-License-Identifier: AGPL-3.0-or-later

package geo

import (
	"net"
	"net/netip"
)

// ASNAttribution is the credit the ASN database's license (CC BY 4.0) requires.
const ASNAttribution = "IP to ASN data by DB-IP.com (CC BY 4.0)"

// ASN identifies the network that announces an address: its autonomous system
// number and the organization that holds it.
type ASN struct {
	Number uint   `json:"number"`
	Org    string `json:"org,omitempty"`
}

type asnRecord struct {
	Number uint   `maxminddb:"autonomous_system_number"`
	Org    string `maxminddb:"autonomous_system_organization"`
}

// ASNLocator answers "which network is this address on" from a memory-mapped
// MaxMind-format ASN database. Like Locator, the zero value is usable and
// finds nothing until a database is opened, and every lookup is local.
type ASNLocator struct{ reader }

// Open loads the database at path, replacing any previous one. On error the
// previous database stays in use.
func (l *ASNLocator) Open(path string) error { return l.open(path) }

// Ready reports whether a database is loaded.
func (l *ASNLocator) Ready() bool { return l.ready() }

// Lookup returns the network for ip.
func (l *ASNLocator) Lookup(ip net.IP) (ASN, bool) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return ASN{}, false
	}
	return l.LookupAddr(addr)
}

// LookupAddr is Lookup for a netip.Addr (IPv4-mapped IPv6 addresses are
// treated as IPv4).
func (l *ASNLocator) LookupAddr(addr netip.Addr) (ASN, bool) {
	var rec asnRecord
	if !l.decode(addr, &rec) || rec.Number == 0 {
		return ASN{}, false
	}
	return ASN{Number: rec.Number, Org: rec.Org}, true
}
