// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnscan

import "shepherd/internal/portscan"

// TargetsFromPortscan turns internal/portscan's own scan results into
// vulnscan targets: every port it found open, on every device that has an
// address. This package never independently decides a port is open —
// portscan already owns that (docs/PORTSCAN.md) — so nothing here
// duplicates its TCP connect scanning.
func TargetsFromPortscan(scans []portscan.DeviceScan) []Target {
	out := make([]Target, 0, len(scans))
	for _, ds := range scans {
		if ds.IP == "" {
			continue
		}
		var ports []int
		for _, p := range ds.Ports {
			if p.Open {
				ports = append(ports, p.Port)
			}
		}
		if len(ports) == 0 {
			continue
		}
		out = append(out, Target{DeviceID: ds.DeviceID, IP: ds.IP, Ports: ports})
	}
	return out
}
