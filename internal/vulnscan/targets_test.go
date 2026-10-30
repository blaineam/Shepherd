// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnscan

import (
	"testing"

	"shepherd/internal/portscan"
)

func TestTargetsFromPortscan(t *testing.T) {
	scans := []portscan.DeviceScan{
		{
			DeviceID: "d1", IP: "192.0.2.10",
			Ports: []portscan.PortRecord{{Port: 21, Open: true}, {Port: 22, Open: false}, {Port: 80, Open: true}},
		},
		{DeviceID: "d2", IP: ""}, // no address: skipped
		// Nothing open right now: still included (with no ports), so a
		// finding that was active on an earlier scan gets the chance to
		// resolve rather than being left stuck active forever.
		{DeviceID: "d3", IP: "192.0.2.11", Ports: []portscan.PortRecord{{Port: 22, Open: false}}},
	}
	got := TargetsFromPortscan(scans)
	if len(got) != 2 {
		t.Fatalf("TargetsFromPortscan() = %+v, want 2 targets", got)
	}
	if got[0].DeviceID != "d1" || got[0].IP != "192.0.2.10" || len(got[0].Ports) != 2 {
		t.Fatalf("target = %+v", got[0])
	}
	want := map[int]bool{21: true, 80: true}
	for _, p := range got[0].Ports {
		if !want[p] {
			t.Fatalf("unexpected port %d in %+v", p, got[0].Ports)
		}
	}
	if got[1].DeviceID != "d3" || len(got[1].Ports) != 0 {
		t.Fatalf("target for a device with nothing open = %+v, want zero ports but still present", got[1])
	}
}
