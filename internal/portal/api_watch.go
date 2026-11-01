// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"net/http"

	"shepherd/internal/watch"
)

// watchJSON is the Watch-mode status the portal's Watch panel reads: what
// the engine is doing, which relay is in effect, the live relayed rates,
// every device's state and why, and the recent unsteer history. Watch mode
// that is switched off or not wired at all answers the same shape with
// enabled false, so the panel always has something honest to show.
func watchJSON(snap watch.Snapshot) map[string]any {
	devs := make([]watch.DeviceStatus, 0, len(snap.Devices))
	devs = append(devs, snap.Devices...)
	return map[string]any{
		"enabled": snap.Enabled, "phase": snap.Phase, "reason": snap.Reason, "relay": snap.Relay,
		"armed": snap.Armed, "interface": snap.Interface, "since": snap.Since,
		"ipv6": snap.IPv6, "ipv6_wanted": snap.IPv6Wanted, "ipv6_reason": snap.IPv6Reason,
		"gateway_link_local": snap.GatewayLinkLocal,
		"gateway_ip":         snap.GatewayIP, "gateway_mac": snap.GatewayMAC,
		"shepherd_mac": snap.ShepherdMAC, "shepherd_ips": orEmpty(snap.ShepherdIPs),
		"steered": snap.Steered, "stats": snap.Stats, "devices": devs, "history": snap.History,
	}
}

func (s *Server) getWatch(w http.ResponseWriter, r *http.Request) {
	if s.Watch == nil {
		// Armed is true deliberately, even though nothing is running:
		// "armed" means the kill switch is not holding steering down, and
		// reporting false here would say someone had pressed it when the
		// truth is that Watch mode is switched off. The live install hit
		// exactly that reading.
		writeJSON(w, watchJSON(watch.Snapshot{Phase: watch.PhaseDisabled, Armed: true,
			Reason:  "Watch mode is turned off in the configuration",
			Devices: []watch.DeviceStatus{}, History: []watch.HistoryRecord{}}))
		return
	}
	writeJSON(w, watchJSON(s.Watch.Snapshot()))
}

// killWatch is the global kill switch: every steered device is unsteered at
// once (each with its corrective ARP reply) and nothing is steered again
// until it is re-armed, across restarts.
func (s *Server) killWatch(w http.ResponseWriter, r *http.Request) {
	if s.Watch == nil {
		notFound(w, "Watch mode is not running")
		return
	}
	if err := s.Watch.Kill(); err != nil {
		// The steering stopped either way; only persisting it failed.
		serverFault(w, "steering stopped, but the kill switch could not be saved")
		return
	}
	writeJSON(w, watchJSON(s.Watch.Snapshot()))
}

func (s *Server) rearmWatch(w http.ResponseWriter, r *http.Request) {
	if s.Watch == nil {
		notFound(w, "Watch mode is not running")
		return
	}
	if err := s.Watch.Rearm(); err != nil {
		serverFault(w, "steering resumed, but the kill switch could not be saved")
		return
	}
	writeJSON(w, watchJSON(s.Watch.Snapshot()))
}
