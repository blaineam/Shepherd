// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"context"
	"errors"
	"net/http"
	"time"

	"shepherd/internal/namesync"
)

// Every connection at once, and the device-name sync across them
// (docs/BACKENDS.md). The Router screen reads these. Connecting and
// disconnecting keep their own endpoints (api_routerusage.go,
// api_backend.go); nothing here returns a credential.

// connectionsJSON lists each kind of connection and whether it is stored,
// so the screen can show them side by side: an eero account and a
// Firewalla are both useful at once, one for names and one for everything
// else.
func (s *Server) connectionsJSON() map[string]any {
	conn := func(ok bool, fields map[string]any) map[string]any {
		if !ok {
			return map[string]any{"connected": false}
		}
		fields["connected"] = true
		return fields
	}
	e, eok := s.Secrets.Eero()
	f, fok := s.Secrets.Firewalla()
	u, uok := s.Secrets.UniFi()
	a, aok := s.Secrets.UniFiAPI()
	out := map[string]any{
		"available": s.RouterUsage != nil && s.Backend != nil,
		"eero":      conn(eok, map[string]any{"enabled": e.Enabled, "network": e.NetworkID}),
		"firewalla": conn(fok, map[string]any{"enabled": f.Enabled, "address": f.BaseURL, "box": f.Box, "writes": f.Writes}),
		"unifi":     conn(uok, map[string]any{"enabled": u.Enabled, "address": u.BaseURL, "site": u.Site}),
		"unifi_api": conn(aok, map[string]any{"enabled": a.Enabled, "address": a.BaseURL, "site": a.Site, "writes": a.Writes}),
	}
	// What each reader is doing right now, which is not always what is
	// stored: with two connected, one of them supplies the bandwidth.
	if s.RouterUsage != nil {
		out["bandwidth"] = s.RouterUsage.Status()
	}
	if s.Backend != nil {
		if snap, ok := s.Backend.Snapshot(); ok {
			out["dashboard"] = map[string]any{"name": snap.Name, "status": snap.Status, "read_only": snap.ReadOnly}
		}
		if msg := s.Backend.LastError(); msg != "" {
			out["dashboard_error"] = msg
		}
	}
	return out
}

func (s *Server) getConnections(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.connectionsJSON())
}

// ---- device names -----------------------------------------------------------

const namesPreviewTimeout = 45 * time.Second

func (s *Server) namesJSON() map[string]any {
	if s.Names == nil {
		return map[string]any{"available": false}
	}
	st := s.Names.Status()
	return map[string]any{"available": true, "auto": st.Auto, "running": st.Running, "last": st.Last, "log": st.Log}
}

func (s *Server) haveNames(w http.ResponseWriter) bool {
	if s.Names == nil {
		notFound(w, "this build cannot sync device names")
		return false
	}
	return true
}

func (s *Server) getNames(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.namesJSON())
}

// previewNames reads every connected place and says what a sync would
// write. Nothing is changed.
func (s *Server) previewNames(w http.ResponseWriter, r *http.Request) {
	if !s.haveNames(w) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), namesPreviewTimeout)
	defer cancel()
	rep, err := s.Names.Preview(ctx)
	if err != nil {
		namesError(w, err)
		return
	}
	writeJSON(w, rep)
}

// syncNames starts a sync. Renaming a house full of devices takes longer
// than a request should, so it runs in the background and the screen reads
// the outcome from GET /api/names.
func (s *Server) syncNames(w http.ResponseWriter, r *http.Request) {
	var b confirmBody
	if !decode(w, r, &b, smallBody) || !s.haveNames(w) || !confirmed(w, b.Confirm) {
		return
	}
	// The run must outlive this request.
	if !s.Names.Start(context.WithoutCancel(r.Context())) {
		http.Error(w, "a name sync is already running", http.StatusConflict)
		return
	}
	out := s.namesJSON()
	out["running"] = true
	writeJSON(w, out)
}

// setNamesAuto turns the automatic sync on or off. On, a name edited in
// any one place is written to the others without being asked, which is why
// it needs confirm:true like any other write.
func (s *Server) setNamesAuto(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Enabled bool `json:"enabled"`
		Confirm bool `json:"confirm"`
	}
	if !decode(w, r, &b, smallBody) || !s.haveNames(w) {
		return
	}
	if b.Enabled && !confirmed(w, b.Confirm) {
		return
	}
	if err := s.Names.SetAuto(b.Enabled); err != nil {
		serverFault(w, "the setting could not be saved")
		return
	}
	writeJSON(w, s.namesJSON())
}

func namesError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, namesync.ErrNothingToSync):
		http.Error(w, "Connect a router or firewall first: there is nothing to sync names with yet.", http.StatusConflict)
	case errors.Is(err, context.DeadlineExceeded):
		http.Error(w, "reading the names took too long; try again", http.StatusGatewayTimeout)
	default:
		http.Error(w, "the names could not be read: "+err.Error(), http.StatusBadGateway)
	}
}
