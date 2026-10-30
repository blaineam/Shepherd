// SPDX-License-Identifier: AGPL-3.0-or-later

package portscan

import (
	"net/netip"

	"shepherd/internal/devices"
)

// TargetsFromDevices turns registry devices into scan targets: one address
// per device, preferring its current IPv4 address (home-network exposure is
// almost always about the address other devices on the LAN actually use). A
// device with no current address at all is left out.
func TargetsFromDevices(devs []devices.Device) []Target {
	out := make([]Target, 0, len(devs))
	for _, d := range devs {
		ip := primaryIP(d.IPs)
		if ip == "" {
			continue
		}
		out = append(out, Target{DeviceID: d.ID, IP: ip})
	}
	return out
}

// primaryIP picks the address a scan should dial: the first current IPv4
// address, or else the first current address of any family.
func primaryIP(ips []string) string {
	for _, s := range ips {
		if a, err := netip.ParseAddr(s); err == nil && a.Is4() {
			return s
		}
	}
	if len(ips) > 0 {
		return ips[0]
	}
	return ""
}
