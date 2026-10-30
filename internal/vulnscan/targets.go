// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnscan

import "shepherd/internal/portscan"

// TargetsFromPortscan turns internal/portscan's own scan results into
// vulnscan targets: every port it found open, on every device that has an
// address. This package never independently decides a port is open —
// portscan already owns that (docs/PORTSCAN.md) — so nothing here
// duplicates its TCP connect scanning.
//
// A device with no open ports right now is still included, with an empty
// Ports list: Scanner.Scan still needs to see it to resolve any finding
// that was active on an earlier scan (a port that closed, or stopped
// matching a signature) — a target this function dropped entirely would
// never get the chance to resolve.
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
		out = append(out, Target{DeviceID: ds.DeviceID, IP: ds.IP, Ports: ports})
	}
	return out
}
