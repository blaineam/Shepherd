// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"net/http"

	"shepherd/internal/decoy"
	"shepherd/internal/detect"
)

// getDetect reports the behaviour checks' state and recent findings, and
// the decoy ports with what has touched them, newest first
// (docs/DETECT.md). Off in the configuration answers enabled false with
// empty lists, so the screen can say so.
func (s *Server) getDetect(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{
		"enabled":  s.DetectEnabled,
		"findings": []detect.Finding{},
		"decoy":    map[string]any{"enabled": false, "ports": []decoy.PortStatus{}, "touches": []decoy.Touch{}},
	}
	if s.Detect != nil {
		out["status"] = s.Detect.Status()
		out["findings"] = s.Detect.Recent()
	}
	if s.Decoy != nil {
		out["decoy"] = map[string]any{"enabled": true, "ports": s.Decoy.Status(), "touches": s.Decoy.Recent()}
	}
	writeJSON(w, out)
}
