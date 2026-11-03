// SPDX-License-Identifier: AGPL-3.0-or-later

package devices

import "strings"

// mdns service labels that mark a Thread border router or a Matter device:
// their IPv6 neighbour discovery must never be disturbed (docs/IPV6.md), and
// neither Watch mode's steering nor DHCP mode's routing is worth the risk of
// confusing a device the whole smart home hangs off.
var threadMatterServices = []string{"_meshcop", "_matter", "_matterc", "_matterd", "_thread"}

// Vendors that only make network infrastructure. A device from one of these
// is treated like a router even before the classifier has typed it; the owner
// can still flip its per-device switch on.
var infrastructureVendors = []string{"eero", "ubiquiti", "mikrotik", "aruba", "ruckus"}

// Infrastructure reports whether d looks like something the network itself
// depends on: a router, mesh node, access point or switch (the registry's
// router/infrastructure type covers all of these), a smart-home hub or
// bridge, a Thread border router or a Matter device. The second result is the
// plain-language reason, for the portal.
//
// It lives here rather than in one of the features because both Watch mode
// (internal/watch) and DHCP mode (internal/dhcp) need the same answer, and
// the answer is a fact about the device rather than a policy of either.
func Infrastructure(d *Device) (bool, string) {
	if d == nil {
		return false, ""
	}
	switch d.Type {
	case TypeRouter:
		return true, "network infrastructure (" + string(d.Type) + ")"
	case TypeSmartHome:
		return true, "smart-home hub or bridge"
	}
	for _, s := range d.Services {
		l := strings.ToLower(s)
		for _, want := range threadMatterServices {
			if strings.HasPrefix(l, want) {
				return true, "advertises Thread/Matter services (" + s + ")"
			}
		}
	}
	v := strings.ToLower(d.Vendor)
	for _, want := range infrastructureVendors {
		if strings.Contains(v, want) {
			return true, "network infrastructure vendor (" + d.Vendor + ")"
		}
	}
	return false, ""
}
