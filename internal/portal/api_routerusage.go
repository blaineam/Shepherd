// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"net/http"
	"strings"

	"shepherd/internal/importers"
	"shepherd/internal/routerusage"
	"shepherd/internal/secrets"
)

// The passive bandwidth reader's API (docs/TRAFFIC.md). Where Watch mode
// cannot run, Shepherd can instead ask the owner's own router what each
// device has moved. The owner signs in through the import flow they
// already have (POST /api/import/eero/start and /verify), then hands that
// verified session here to keep.
//
// The session token is never returned, and never passes through this file:
// the eero client writes it straight into the secrets store.

// routerUsageJSON is the Bandwidth screen's view of the reader.
func (s *Server) routerUsageJSON() map[string]any {
	out := map[string]any{
		"available": s.RouterUsage != nil,
		"connected": false,
		"source":    "",
		"network":   "",
		"status":    routerusage.Status{},
	}
	if e, ok := s.Secrets.Eero(); ok {
		out["connected"] = true
		out["source"] = "eero"
		out["network"] = e.NetworkID
		out["enabled"] = e.Enabled
	}
	if s.RouterUsage != nil {
		out["status"] = s.RouterUsage.Status()
	}
	return out
}

func (s *Server) getRouterUsage(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.routerUsageJSON())
}

// connectRouterUsage keeps a verified import session as the lasting
// connection: the token is persisted, the network recorded, the reader
// switched on and restarted. The import session is discarded either way,
// so a half-finished sign-in never lingers.
func (s *Server) connectRouterUsage(w http.ResponseWriter, r *http.Request) {
	var b struct {
		SessionID string `json:"session_id"`
		NetworkID string `json:"network_id"`
	}
	if !decode(w, r, &b, smallBody) {
		return
	}
	if s.RouterUsage == nil {
		notFound(w, "this build cannot read bandwidth from a router")
		return
	}
	sess, ok := s.importSessions.get(b.SessionID)
	if !ok {
		eeroSessionNotFound(w)
		return
	}
	if !sess.client.HasSession() {
		http.Error(w, "verify the code eero sent before connecting", http.StatusUnauthorized)
		return
	}
	networkID := strings.TrimSpace(b.NetworkID)
	if !knownNetwork(sess.getNetworks(), networkID) {
		bad(w, "choose one of the networks on this eero account")
		return
	}
	// PersistTo hands the token straight to the store; the portal never
	// holds it. The session was checked above, so the only way this fails
	// is the store refusing the write, which is ours to own, not the
	// owner's to correct.
	if err := sess.client.PersistTo(secrets.EeroTokenStore{S: s.Secrets}); err != nil {
		serverFault(w, "the sign-in could not be saved")
		return
	}
	s.importSessions.discard(b.SessionID)
	if _, err := s.Secrets.SetEeroNetwork(networkID); err != nil {
		serverFault(w, "the connection could not be saved")
		return
	}
	if _, err := s.Secrets.SetEeroEnabled(true); err != nil {
		serverFault(w, "the connection could not be saved")
		return
	}
	s.RouterUsage.Reload()
	writeJSON(w, s.routerUsageJSON())
}

func knownNetwork(nets []importers.Network, id string) bool {
	if id == "" {
		return false
	}
	for _, n := range nets {
		if n.ID == id {
			return true
		}
	}
	return false
}

// setRouterUsageEnabled turns the reader on or off without forgetting the
// sign-in, so turning it back on costs no new verification code.
func (s *Server) setRouterUsageEnabled(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Enabled bool `json:"enabled"`
	}
	if !decode(w, r, &b, smallBody) {
		return
	}
	if s.RouterUsage == nil {
		notFound(w, "this build cannot read bandwidth from a router")
		return
	}
	ok, err := s.Secrets.SetEeroEnabled(b.Enabled)
	if err != nil {
		serverFault(w, "the setting could not be saved")
		return
	}
	if !ok {
		notFound(w, "no router is connected")
		return
	}
	s.RouterUsage.Reload()
	writeJSON(w, s.routerUsageJSON())
}

// forgetRouterUsage drops the stored session entirely and stops reading.
func (s *Server) forgetRouterUsage(w http.ResponseWriter, r *http.Request) {
	if s.RouterUsage == nil {
		notFound(w, "this build cannot read bandwidth from a router")
		return
	}
	if err := s.Secrets.ClearEero(); err != nil {
		serverFault(w, "the connection could not be forgotten")
		return
	}
	s.RouterUsage.Reload()
	writeJSON(w, s.routerUsageJSON())
}

// ---- names ------------------------------------------------------------------

// Syncing names reuses the kept sign-in: eero already knows what the
// household calls each device, and the importer already maps those names
// to aliases and eero's profiles to groups (internal/importers). What is
// new here is that it needs no fresh verification code, so it can be run
// whenever the owner adds a device.
//
// The owner's own names win by default. Overwriting them is a deliberate
// choice, asked for per request, never a default and never automatic.

// storedEeroClient opens a client on the kept sign-in, with the network
// the owner chose.
func (s *Server) storedEeroClient() (*importers.Client, importers.Network, error) {
	e, ok := s.Secrets.Eero()
	if !ok || e.NetworkID == "" {
		return nil, importers.Network{}, importers.ErrEeroNoSession
	}
	store := secrets.EeroTokenStore{S: s.Secrets}
	var (
		c   *importers.Client
		err error
	)
	if s.NewStoredEeroClient != nil {
		c, err = s.NewStoredEeroClient(store)
	} else {
		c, err = importers.NewClient(importers.ClientOptions{TokenStore: store})
	}
	if err != nil {
		return nil, importers.Network{}, err
	}
	resumed, err := c.Resume()
	if err != nil {
		return nil, importers.Network{}, err
	}
	if !resumed {
		return nil, importers.Network{}, importers.ErrEeroNoSession
	}
	return c, importers.Network{ID: e.NetworkID}, nil
}

// syncRouterNames previews or applies eero's device names and profiles.
// dry_run is the preview the portal shows before anything is written.
func (s *Server) syncRouterNames(w http.ResponseWriter, r *http.Request) {
	var b struct {
		OverwriteNames bool `json:"overwrite_names"`
		DryRun         bool `json:"dry_run"`
	}
	if !decode(w, r, &b, smallBody) {
		return
	}
	c, net, err := s.storedEeroClient()
	if err != nil {
		eeroError(w, err)
		return
	}
	// The client is for this request only; the token stays in the store.
	defer c.Discard()
	snap, err := c.Snapshot(r.Context(), net)
	if err != nil {
		eeroError(w, err)
		return
	}
	plan := importers.MapEero(snap)
	opts := importers.Options{OverwriteNames: b.OverwriteNames}
	var rep importers.Report
	if b.DryRun {
		rep, err = importers.PreviewWith(plan, s.Devices, opts)
	} else {
		rep, err = importers.Apply(plan, s.Devices, opts)
	}
	if err != nil {
		bad(w, err.Error())
		return
	}
	writeJSON(w, toImportReport(rep))
}
