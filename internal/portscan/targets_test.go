// SPDX-License-Identifier: AGPL-3.0-or-later

package portscan

import (
	"testing"

	"shepherd/internal/devices"
)

func TestTargetsFromDevicesPrefersIPv4(t *testing.T) {
	devs := []devices.Device{
		{ID: "d1", IPs: []string{"2001:db8::1", "192.0.2.5"}},
		{ID: "d2", IPs: []string{"2001:db8::2"}},
		{ID: "d3", IPs: nil},
	}
	got := TargetsFromDevices(devs)
	if len(got) != 2 {
		t.Fatalf("TargetsFromDevices() = %+v, want 2 targets (d3 has no address)", got)
	}
	if got[0] != (Target{DeviceID: "d1", IP: "192.0.2.5"}) {
		t.Fatalf("got[0] = %+v, want d1 to prefer its IPv4 address", got[0])
	}
	if got[1] != (Target{DeviceID: "d2", IP: "2001:db8::2"}) {
		t.Fatalf("got[1] = %+v, want d2's only (IPv6) address", got[1])
	}
}

func TestTargetsFromDevicesEmpty(t *testing.T) {
	if got := TargetsFromDevices(nil); len(got) != 0 {
		t.Fatalf("TargetsFromDevices(nil) = %+v, want none", got)
	}
}
