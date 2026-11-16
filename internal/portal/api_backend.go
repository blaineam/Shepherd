// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"shepherd/internal/backends"
	"shepherd/internal/backends/hub"
)

// The dashboard over a connected router or firewall (docs/BACKENDS.md).
// Reading is open to any signed-in portal user. Writing is a separate
// switch the owner turns on, and every write must carry confirm:true, so a
// stray request can never change a firewall.
//
// The credential never passes through this file: it was stored by the
// connect endpoint in api_routerusage.go and is only ever read by the hub.

const backendWriteTimeout = 20 * time.Second

func (s *Server) backendJSON() map[string]any {
	out := map[string]any{
		"available": s.Backend != nil,
		"connected": false,
		"running":   false,
	}
	if w, ok := s.Secrets.Firewalla(); ok {
		out["connected"] = true
		out["name"] = "firewalla"
		out["address"] = w.BaseURL
		out["box"] = w.Box
		out["enabled"] = w.Enabled
		out["writes"] = w.Writes
	}
	if s.Backend == nil {
		return out
	}
	if e := s.Backend.LastError(); e != "" {
		out["error"] = e
	}
	if snap, ok := s.Backend.Snapshot(); ok {
		out["running"] = true
		out["read_only"] = snap.ReadOnly
		out["capabilities"] = snap.Capabilities
		out["status"] = snap.Status
		out["devices"] = nonNil(snap.Devices)
		out["rules"] = nonNil(snap.Rules)
		out["alarms"] = nonNil(snap.Alarms)
		out["flows"] = nonNil(snap.Flows)
		out["audit"] = nonNil(snap.Audit)
		out["schedules"] = nonNil(snap.Schedules)
		out["target_types"] = backends.TargetTypes
		out["scope_types"] = backends.ScopeTypes
	}
	return out
}

// nonNil makes a nil slice encode as [] rather than null.
func nonNil[T any](v []T) []T {
	if v == nil {
		return []T{}
	}
	return v
}

func (s *Server) getBackend(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.backendJSON())
}

func (s *Server) refreshBackend(w http.ResponseWriter, r *http.Request) {
	if s.Backend == nil {
		notFound(w, "this build has no router dashboard")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), backendWriteTimeout)
	defer cancel()
	s.Backend.Refresh(ctx)
	writeJSON(w, s.backendJSON())
}

func (s *Server) setBackendWrites(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Enabled bool `json:"enabled"`
	}
	if !decode(w, r, &b, smallBody) {
		return
	}
	if s.Backend == nil {
		notFound(w, "this build has no router dashboard")
		return
	}
	ok, err := s.Secrets.SetFirewallaWrites(b.Enabled)
	if err != nil {
		serverFault(w, "the setting could not be saved")
		return
	}
	if !ok {
		notFound(w, "no Firewalla account is connected")
		return
	}
	s.Backend.Reload()
	writeJSON(w, s.backendJSON())
}

// backendRuleBody is a rule as the portal sends it.
type backendRuleBody struct {
	Action           string `json:"action"`
	TargetType       string `json:"target_type"`
	Target           string `json:"target"`
	BlockConnections bool   `json:"block_connections"`
	ScopeType        string `json:"scope_type"`
	Scope            string `json:"scope"`
	Notes            string `json:"notes"`
	Box              string `json:"box"`
	Confirm          bool   `json:"confirm"`
}

func (b backendRuleBody) spec() backends.RuleSpec {
	return backends.RuleSpec{
		Action: b.Action, TargetType: b.TargetType, Target: b.Target, BlockConnections: b.BlockConnections,
		ScopeType: b.ScopeType, Scope: b.Scope, Notes: b.Notes, Box: b.Box,
	}
}

func (s *Server) previewBackendRule(w http.ResponseWriter, r *http.Request) {
	var b backendRuleBody
	if !decode(w, r, &b, smallBody) || !s.haveBackend(w) {
		return
	}
	p, err := s.Backend.PreviewRule(b.spec())
	if err != nil {
		backendError(w, err)
		return
	}
	writeJSON(w, p)
}

func (s *Server) createBackendRule(w http.ResponseWriter, r *http.Request) {
	var b backendRuleBody
	if !decode(w, r, &b, smallBody) || !s.haveBackend(w) || !confirmed(w, b.Confirm) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), backendWriteTimeout)
	defer cancel()
	rule, err := s.Backend.CreateRule(ctx, b.spec())
	if err != nil {
		backendError(w, err)
		return
	}
	writeJSON(w, rule)
}

type confirmBody struct {
	Confirm bool `json:"confirm"`
}

func (s *Server) pauseBackendRule(w http.ResponseWriter, r *http.Request) {
	s.ruleAction(w, r, func(ctx context.Context, id string) error { return s.Backend.SetRulePaused(ctx, id, true) })
}

func (s *Server) resumeBackendRule(w http.ResponseWriter, r *http.Request) {
	s.ruleAction(w, r, func(ctx context.Context, id string) error { return s.Backend.SetRulePaused(ctx, id, false) })
}

func (s *Server) deleteBackendRule(w http.ResponseWriter, r *http.Request) {
	s.ruleAction(w, r, func(ctx context.Context, id string) error { return s.Backend.DeleteRule(ctx, id) })
}

func (s *Server) ruleAction(w http.ResponseWriter, r *http.Request, do func(context.Context, string) error) {
	var b confirmBody
	if !decode(w, r, &b, smallBody) || !s.haveBackend(w) || !confirmed(w, b.Confirm) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), backendWriteTimeout)
	defer cancel()
	if err := do(ctx, r.PathValue("id")); err != nil {
		backendError(w, err)
		return
	}
	writeJSON(w, s.backendJSON())
}

func (s *Server) renameBackendDevice(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Box     string `json:"box"`
		Native  string `json:"native"`
		Name    string `json:"name"`
		Confirm bool   `json:"confirm"`
	}
	if !decode(w, r, &b, smallBody) || !s.haveBackend(w) || !confirmed(w, b.Confirm) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), backendWriteTimeout)
	defer cancel()
	if err := s.Backend.RenameDevice(ctx, backends.DeviceRef{Box: b.Box, Native: b.Native}, b.Name); err != nil {
		backendError(w, err)
		return
	}
	writeJSON(w, s.backendJSON())
}

func (s *Server) dismissBackendAlarm(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Box     string `json:"box"`
		ID      string `json:"id"`
		Confirm bool   `json:"confirm"`
	}
	if !decode(w, r, &b, smallBody) || !s.haveBackend(w) || !confirmed(w, b.Confirm) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), backendWriteTimeout)
	defer cancel()
	if err := s.Backend.DismissAlarm(ctx, backends.AlarmRef{Box: b.Box, ID: b.ID}); err != nil {
		backendError(w, err)
		return
	}
	writeJSON(w, s.backendJSON())
}

func (s *Server) haveBackend(w http.ResponseWriter) bool {
	if s.Backend == nil {
		notFound(w, "this build has no router dashboard")
		return false
	}
	return true
}

// confirmed refuses a write that did not say it was meant.
func confirmed(w http.ResponseWriter, ok bool) bool {
	if !ok {
		bad(w, "this changes your router or firewall: send confirm:true once you have seen what it will do")
	}
	return ok
}

// backendError maps a backend failure onto the status the owner should see.
func backendError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, backends.ErrReadOnly):
		http.Error(w, "writes are switched off: turn on \"Allow changes\" first", http.StatusForbidden)
	case errors.Is(err, backends.ErrInvalid):
		bad(w, strings.TrimPrefix(err.Error(), backends.ErrInvalid.Error()+": "))
	case errors.Is(err, backends.ErrNotFound):
		notFound(w, "the router no longer has that")
	case errors.Is(err, backends.ErrRateLimited):
		http.Error(w, err.Error(), http.StatusTooManyRequests)
	case errors.Is(err, backends.ErrAuth):
		http.Error(w, "the router refused the token: it may be Read Only or revoked", http.StatusBadGateway)
	default:
		http.Error(w, "the router could not do that: "+err.Error(), http.StatusBadGateway)
	}
}

// backendFlows reads requests straight from the backend, for a filter the
// polled list does not cover: ?device=<mac>&limit=<n>&cursor=<c>.
func (s *Server) backendFlows(w http.ResponseWriter, r *http.Request) {
	if !s.haveBackend(w) {
		return
	}
	q := backends.FlowQuery{DeviceMAC: r.URL.Query().Get("device"), Cursor: r.URL.Query().Get("cursor"), Limit: 100}
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 500 {
		q.Limit = n
	}
	ctx, cancel := context.WithTimeout(r.Context(), backendWriteTimeout)
	defer cancel()
	page, err := s.Backend.QueryFlows(ctx, q)
	if err != nil {
		backendError(w, err)
		return
	}
	writeJSON(w, map[string]any{"flows": nonNil(page.Flows), "next": page.Next})
}

type scheduleBody struct {
	RuleID  string `json:"rule_id"`
	Days    []int  `json:"days"`
	Start   string `json:"start"`
	End     string `json:"end"`
	TZ      string `json:"tz"`
	Confirm bool   `json:"confirm"`
}

func (s *Server) addBackendSchedule(w http.ResponseWriter, r *http.Request) {
	var b scheduleBody
	if !decode(w, r, &b, smallBody) || !s.haveBackend(w) || !confirmed(w, b.Confirm) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), backendWriteTimeout)
	defer cancel()
	if _, err := s.Backend.AddSchedule(ctx, hub.Schedule{RuleID: b.RuleID, Days: b.Days, Start: b.Start, End: b.End, TZ: b.TZ}); err != nil {
		backendError(w, err)
		return
	}
	writeJSON(w, s.backendJSON())
}

func (s *Server) deleteBackendSchedule(w http.ResponseWriter, r *http.Request) {
	var b confirmBody
	if !decode(w, r, &b, smallBody) || !s.haveBackend(w) || !confirmed(w, b.Confirm) {
		return
	}
	if err := s.Backend.DeleteSchedule(r.PathValue("id")); err != nil {
		backendError(w, err)
		return
	}
	writeJSON(w, s.backendJSON())
}
