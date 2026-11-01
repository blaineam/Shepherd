// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"context"
	"net/http"
	"time"

	"shepherd/internal/threats"
)

// threatsRefreshTimeout bounds a manual "refresh now" from the portal.
const threatsRefreshTimeout = 90 * time.Second

// getThreats reports every feed's state and the recent matches, newest
// first (docs/THREATS.md). Off in the configuration answers enabled false
// with empty lists.
func (s *Server) getThreats(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{"enabled": s.ThreatsEnabled, "feeds": []threats.FeedStatus{}, "matches": []threats.Match{}, "loaded": 0}
	if s.Threats != nil {
		out["feeds"] = s.Threats.Status()
		out["matches"] = s.Threats.Recent()
		out["loaded"] = s.Threats.Loaded()
	}
	writeJSON(w, out)
}

// refreshThreats re-downloads every feed now.
func (s *Server) refreshThreats(w http.ResponseWriter, r *http.Request) {
	if s.Threats == nil {
		notFound(w, "threat feeds are turned off in the configuration")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), threatsRefreshTimeout)
	defer cancel()
	s.Threats.Refresh(ctx)
	writeJSON(w, map[string]any{"feeds": s.Threats.Status()})
}
