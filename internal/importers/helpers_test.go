// SPDX-License-Identifier: AGPL-3.0-or-later

package importers

import (
	"fmt"
	"testing"
	"time"

	"shepherd/internal/devices"
)

func newReg(t testing.TB) *devices.Registry {
	t.Helper()
	n := 0
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	return devices.New(devices.Options{
		NodeID: "node-a",
		Now:    func() time.Time { return now },
		NewID:  func() string { n++; return fmt.Sprintf("t-%d", n) },
		Vendor: func(string) string { return "" },
	})
}

func mustApply(t testing.TB, p Plan, reg *devices.Registry, o Options) Report {
	t.Helper()
	r, err := Apply(p, reg, o)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func byMAC(t testing.TB, reg *devices.Registry, mac string) devices.Device {
	t.Helper()
	d, ok := reg.FindByMAC(mac)
	if !ok {
		t.Fatalf("no device with MAC %s", mac)
	}
	return d
}

func groupNames(reg *devices.Registry, d devices.Device) []string {
	var out []string
	for _, id := range d.Groups {
		if g, ok := reg.GetGroup(id); ok {
			out = append(out, g.Name)
		}
	}
	return out
}

func samplePlan() Plan {
	return Plan{
		Source: "test",
		Groups: []PlanGroup{{Name: "Kids", Color: "#3366cc"}},
		Devices: []PlanDevice{
			{MAC: "02:00:5E:00:00:01", IPs: []string{"192.0.2.10"}, Name: "Kids Tablet", Hostname: "tab-1", Vendor: "ExampleCo", Groups: []string{"Kids"}, Tags: []string{"Child"}},
			{MAC: "00:00:5e:00:00:02", IPs: []string{"192.0.2.11"}, Name: "Living Room TV", Type: "tv", Notes: "by the window"},
			{MAC: "00:00:5e:00:00:03", IPs: []string{"192.0.2.1"}, Name: "Hall eero", Infrastructure: true},
		},
	}
}
