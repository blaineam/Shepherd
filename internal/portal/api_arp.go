// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import "net/http"

// arpStats reports the passive ARP monitor's counters, or that it is not
// running (disabled, unsupported on this platform, or missing CAP_NET_RAW).
func (s *Server) arpStats(w http.ResponseWriter, r *http.Request) {
	if s.ARP == nil {
		writeJSON(w, map[string]any{"enabled": false})
		return
	}
	writeJSON(w, map[string]any{"enabled": true, "stats": s.ARP.Stats()})
}
