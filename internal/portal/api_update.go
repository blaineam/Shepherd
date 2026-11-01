// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"context"
	"net/http"
	"time"
)

// Updater is what the portal needs from cmd/shepherd's self-update
// service (docs/UPDATE.md). Nil Deps.Update means the checker is off.
type Updater interface {
	// Status is the current picture: version, latest release, whether an
	// update can be applied here and why not, the data directory's size.
	Status() any
	// CheckNow looks for a newer release at once and returns Status.
	CheckNow(ctx context.Context) any
	// Apply downloads, verifies and installs the latest release, then
	// restarts shortly after returning. An error says why it could not.
	Apply(ctx context.Context) error
}

const updateApplyTimeout = 10 * time.Minute

func (s *Server) getUpdate(w http.ResponseWriter, r *http.Request) {
	if s.Update == nil {
		writeJSON(w, map[string]any{"enabled": false, "current": s.Version})
		return
	}
	writeJSON(w, map[string]any{"enabled": true, "status": s.Update.Status()})
}

func (s *Server) checkUpdate(w http.ResponseWriter, r *http.Request) {
	if s.Update == nil {
		notFound(w, "the update checker is turned off in the configuration")
		return
	}
	writeJSON(w, map[string]any{"enabled": true, "status": s.Update.CheckNow(r.Context())})
}

func (s *Server) applyUpdate(w http.ResponseWriter, r *http.Request) {
	if s.Update == nil {
		notFound(w, "the update checker is turned off in the configuration")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), updateApplyTimeout)
	defer cancel()
	if err := s.Update.Apply(ctx); err != nil {
		conflict(w, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true, "restarting": true})
}
