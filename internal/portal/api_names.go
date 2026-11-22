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
		"firewalla": conn(fok, map[string]any{"enabled": f.Enabled, "address": f.BaseURL, "box": f.Box, "writes": f.Writes, "local": f.Local}),
		"unifi":     conn(uok, map[string]any{"enabled": u.Enabled, "address": u.BaseURL, "site": u.Site}),
		"unifi_api": conn(aok, map[string]any{"enabled": a.Enabled, "address": a.BaseURL, "site": a.Site, "writes": a.Writes}),
	}
	// Whether this Shepherd is running on a Firewalla box, in which case
	// the box can be read directly, with no MSP account.
	if s.Backend != nil {
		out["local_firewalla"] = s.onFirewalla()
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

// ---- device names and device groups ------------------------------------------

// One engine keeps device names the same everywhere and a second keeps
// device groups the same (cmd/shepherd/names.go, groups.go). They answer
// the same four calls, so the handlers are written once over syncKind.

const syncPreviewTimeout = 45 * time.Second

// syncKind is one of the two syncs as the API words it.
type syncKind struct {
	engine func(*Server) NameSync
	// what is the thing synced, in the plural, for messages.
	what string
}

var (
	namesKind  = syncKind{func(s *Server) NameSync { return s.Names }, "device names"}
	groupsKind = syncKind{func(s *Server) NameSync { return s.Groups }, "device groups"}
)

func (s *Server) syncJSON(k syncKind) map[string]any {
	e := k.engine(s)
	if e == nil {
		return map[string]any{"available": false}
	}
	st := e.Status()
	return map[string]any{"available": true, "auto": st.Auto, "running": st.Running, "last": st.Last, "log": st.Log}
}

func (s *Server) haveSync(w http.ResponseWriter, k syncKind) (NameSync, bool) {
	e := k.engine(s)
	if e == nil {
		notFound(w, "this build cannot sync "+k.what)
		return nil, false
	}
	return e, true
}

// previewSync reads every connected place and says what a sync would
// write. Nothing is changed.
func (s *Server) previewSync(w http.ResponseWriter, r *http.Request, k syncKind) {
	e, ok := s.haveSync(w, k)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), syncPreviewTimeout)
	defer cancel()
	rep, err := e.Preview(ctx)
	if err != nil {
		syncError(w, k, err)
		return
	}
	writeJSON(w, rep)
}

// startSync starts a sync. Changing a house full of devices takes longer
// than a request should, so it runs in the background and the screen reads
// the outcome from the status call.
func (s *Server) startSync(w http.ResponseWriter, r *http.Request, k syncKind) {
	var b confirmBody
	if !decode(w, r, &b, smallBody) {
		return
	}
	e, ok := s.haveSync(w, k)
	if !ok || !confirmed(w, b.Confirm) {
		return
	}
	// The run must outlive this request.
	if !e.Start(context.WithoutCancel(r.Context())) {
		http.Error(w, "a sync of "+k.what+" is already running", http.StatusConflict)
		return
	}
	out := s.syncJSON(k)
	out["running"] = true
	writeJSON(w, out)
}

// setSyncAuto turns the automatic sync on or off. On, a change made in
// any one place is written to the others without being asked, which is why
// it needs confirm:true like any other write.
func (s *Server) setSyncAuto(w http.ResponseWriter, r *http.Request, k syncKind) {
	var b struct {
		Enabled bool `json:"enabled"`
		Confirm bool `json:"confirm"`
	}
	if !decode(w, r, &b, smallBody) {
		return
	}
	e, ok := s.haveSync(w, k)
	if !ok {
		return
	}
	if b.Enabled && !confirmed(w, b.Confirm) {
		return
	}
	if err := e.SetAuto(b.Enabled); err != nil {
		serverFault(w, "the setting could not be saved")
		return
	}
	writeJSON(w, s.syncJSON(k))
}

func syncError(w http.ResponseWriter, k syncKind, err error) {
	switch {
	case errors.Is(err, namesync.ErrNothingToSync):
		http.Error(w, "Connect a router or firewall first: there is nothing to sync "+k.what+" with yet.", http.StatusConflict)
	case errors.Is(err, context.DeadlineExceeded):
		http.Error(w, "reading the "+k.what+" took too long; try again", http.StatusGatewayTimeout)
	default:
		http.Error(w, "the "+k.what+" could not be read: "+err.Error(), http.StatusBadGateway)
	}
}

func (s *Server) getNames(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.syncJSON(namesKind))
}
func (s *Server) previewNames(w http.ResponseWriter, r *http.Request) { s.previewSync(w, r, namesKind) }
func (s *Server) syncNames(w http.ResponseWriter, r *http.Request)    { s.startSync(w, r, namesKind) }
func (s *Server) setNamesAuto(w http.ResponseWriter, r *http.Request) { s.setSyncAuto(w, r, namesKind) }

func (s *Server) getGroupSync(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.syncJSON(groupsKind))
}
func (s *Server) previewGroupSync(w http.ResponseWriter, r *http.Request) {
	s.previewSync(w, r, groupsKind)
}
func (s *Server) syncGroupSync(w http.ResponseWriter, r *http.Request) { s.startSync(w, r, groupsKind) }
func (s *Server) setGroupSyncAuto(w http.ResponseWriter, r *http.Request) {
	s.setSyncAuto(w, r, groupsKind)
}
