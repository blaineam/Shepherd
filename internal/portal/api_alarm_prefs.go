// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"errors"
	"net/http"

	"shepherd/internal/alarms"
)

// The alarm preferences (docs/ALARMS.md "Preferences"): what is delivered
// at once, what waits for the digest and when the digest goes out. The
// portal's Notifications tab edits the delivery part; the whole structure
// is readable and writable here so the rest can be tuned over the API.

func (s *Server) getAlarmPrefs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"preferences": s.Alarms.Preferences()})
}

// putAlarmPrefs replaces the preferences. The body is a whole Preferences;
// a client that wants to change one field reads, edits and writes back.
func (s *Server) putAlarmPrefs(w http.ResponseWriter, r *http.Request) {
	var p alarms.Preferences
	if !decode(w, r, &p, 64<<10) {
		return
	}
	if err := s.Alarms.SetPreferences(p); err != nil {
		if errors.Is(err, alarms.ErrBadPreferences) {
			bad(w, err.Error())
			return
		}
		serverFault(w, "saving alarm preferences")
		return
	}
	writeJSON(w, map[string]any{"preferences": s.Alarms.Preferences()})
}
