// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"shepherd/internal/importers"
)

// This file wires internal/importers (a one-time, optional import of device
// names and groups, from eero or a CSV file) into the portal. See
// docs/IMPORT.md.
//
// The eero flow is multi-step (start login, verify a code, pick a network,
// preview, apply) and needs an eero session token in between steps. That
// token is never written to disk: it lives only inside the *importers.Client
// held by an eeroSession, in memory, for at most importSessionTTL, keyed by a
// random ID the browser holds instead of the token itself. Apply discards it
// immediately, whether or not the import succeeded, and so does an explicit
// cancel or a session that is never touched again until it expires.

const (
	importSessionTTL = 15 * time.Minute
	maxEeroLoginLen  = 256
	maxEeroCodeLen   = 32
	// importCSVBody allows for importers.MaxCSVBytes of CSV text plus the
	// JSON request's framing and string-escaping overhead.
	importCSVBody = importers.MaxCSVBytes + (importers.MaxCSVBytes / 2) + 4096
)

// eeroSession is one in-progress (or just-previewed) eero import. expires is
// owned by the eeroSessions map's own mutex, not sess.mu, since only the map
// methods ever read or write it.
type eeroSession struct {
	client  *importers.Client
	expires time.Time

	mu       sync.Mutex
	networks []importers.Network
	plan     *importers.Plan
	opts     importers.Options
}

func (s *eeroSession) setNetworks(nets []importers.Network) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.networks = nets
}

func (s *eeroSession) getNetworks() []importers.Network {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.networks
}

func (s *eeroSession) setPlan(p importers.Plan, opts importers.Options) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.plan, s.opts = &p, opts
}

func (s *eeroSession) getPlan() (importers.Plan, importers.Options, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.plan == nil {
		return importers.Plan{}, importers.Options{}, false
	}
	return *s.plan, s.opts, true
}

type eeroSessions struct {
	mu   sync.Mutex
	byID map[string]*eeroSession
}

func newEeroSessions() *eeroSessions { return &eeroSessions{byID: map[string]*eeroSession{}} }

func randomSessionID() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// sweep discards every expired session's client and token. Callers hold ss.mu.
func (ss *eeroSessions) sweep() {
	now := time.Now()
	for id, s := range ss.byID {
		if s.expires.Before(now) {
			s.client.Discard()
			delete(ss.byID, id)
		}
	}
}

func (ss *eeroSessions) create(c *importers.Client) (string, error) {
	id, err := randomSessionID()
	if err != nil {
		return "", err
	}
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.sweep()
	ss.byID[id] = &eeroSession{client: c, expires: time.Now().Add(importSessionTTL)}
	return id, nil
}

// get returns the session for id, renewing its TTL. Nothing it returns
// should be cached past one request.
func (ss *eeroSessions) get(id string) (*eeroSession, bool) {
	if id == "" {
		return nil, false
	}
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.sweep()
	s, ok := ss.byID[id]
	if !ok {
		return nil, false
	}
	s.expires = time.Now().Add(importSessionTTL)
	return s, true
}

// discard drops the session and its client, including the eero token held in
// memory. Safe to call more than once or with an unknown ID.
func (ss *eeroSessions) discard(id string) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if s, ok := ss.byID[id]; ok {
		s.client.Discard()
		delete(ss.byID, id)
	}
}

// ---- eero -------------------------------------------------------------------

func (s *Server) newEeroClient() (*importers.Client, error) {
	if s.NewEeroClient != nil {
		return s.NewEeroClient()
	}
	return importers.NewClient(importers.ClientOptions{})
}

// eeroError maps an error from the importers eero client to a response.
// Client.scrub has already removed every credential from it.
func eeroError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, importers.ErrEeroInvalidCode), errors.Is(err, importers.ErrEeroCodeExpired):
		bad(w, err.Error())
	case errors.Is(err, importers.ErrEeroRateLimited):
		http.Error(w, err.Error(), http.StatusTooManyRequests)
	case errors.Is(err, importers.ErrEeroUnauthorized), errors.Is(err, importers.ErrEeroSessionExpire), errors.Is(err, importers.ErrEeroNoSession):
		http.Error(w, err.Error(), http.StatusUnauthorized)
	default:
		bad(w, err.Error())
	}
}

func validShortText(s string, max int) bool {
	s = strings.TrimSpace(s)
	return s != "" && len(s) <= max && !hasControl(s)
}

func (s *Server) importEeroStart(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Login string `json:"login"`
	}
	if !decode(w, r, &b, smallBody) {
		return
	}
	login := strings.TrimSpace(b.Login)
	if !validShortText(login, maxEeroLoginLen) {
		bad(w, "enter the eero account's email address or phone number")
		return
	}
	c, err := s.newEeroClient()
	if err != nil {
		serverFault(w, "could not reach eero")
		return
	}
	if err := c.StartLogin(r.Context(), login); err != nil {
		eeroError(w, err)
		return
	}
	id, err := s.importSessions.create(c)
	if err != nil {
		serverFault(w, "could not start the import")
		return
	}
	writeJSON(w, map[string]string{"session_id": id})
}

func eeroSessionNotFound(w http.ResponseWriter) {
	notFound(w, "the import session was not found or has expired; start again")
}

func (s *Server) importEeroVerify(w http.ResponseWriter, r *http.Request) {
	var b struct {
		SessionID string `json:"session_id"`
		Code      string `json:"code"`
	}
	if !decode(w, r, &b, smallBody) {
		return
	}
	sess, ok := s.importSessions.get(b.SessionID)
	if !ok {
		eeroSessionNotFound(w)
		return
	}
	code := strings.TrimSpace(b.Code)
	if !validShortText(code, maxEeroCodeLen) {
		bad(w, "enter the verification code eero sent")
		return
	}
	if err := sess.client.Verify(r.Context(), code); err != nil {
		eeroError(w, err)
		return
	}
	nets, err := sess.client.Networks(r.Context())
	if err != nil {
		eeroError(w, err)
		return
	}
	sess.setNetworks(nets)
	out := make([]eeroNetworkJSON, len(nets))
	for i, n := range nets {
		out[i] = eeroNetworkJSON{ID: n.ID, Name: n.Name}
	}
	writeJSON(w, map[string]any{"session_id": b.SessionID, "networks": out})
}

type eeroNetworkJSON struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (s *Server) importEeroPreview(w http.ResponseWriter, r *http.Request) {
	var b struct {
		SessionID      string `json:"session_id"`
		NetworkID      string `json:"network_id"`
		OverwriteNames bool   `json:"overwrite_names"`
	}
	if !decode(w, r, &b, smallBody) {
		return
	}
	sess, ok := s.importSessions.get(b.SessionID)
	if !ok {
		eeroSessionNotFound(w)
		return
	}
	nets := sess.getNetworks()
	if len(nets) == 0 {
		bad(w, "verify the code before previewing")
		return
	}
	var net importers.Network
	found := false
	for _, n := range nets {
		if n.ID == b.NetworkID {
			net, found = n, true
			break
		}
	}
	if !found {
		bad(w, "unknown network")
		return
	}
	snap, err := sess.client.Snapshot(r.Context(), net)
	if err != nil {
		eeroError(w, err)
		return
	}
	plan := importers.MapEero(snap)
	opts := importers.Options{OverwriteNames: b.OverwriteNames}
	rep, err := importers.PreviewWith(plan, s.Devices, opts)
	if err != nil {
		bad(w, err.Error())
		return
	}
	sess.setPlan(plan, opts)
	writeJSON(w, toImportReport(rep))
}

func (s *Server) importEeroApply(w http.ResponseWriter, r *http.Request) {
	var b struct {
		SessionID string `json:"session_id"`
	}
	if !decode(w, r, &b, smallBody) {
		return
	}
	sess, ok := s.importSessions.get(b.SessionID)
	if !ok {
		eeroSessionNotFound(w)
		return
	}
	plan, opts, ok := sess.getPlan()
	if !ok {
		bad(w, "preview the import before applying it")
		return
	}
	rep, err := importers.Apply(plan, s.Devices, opts)
	s.importSessions.discard(b.SessionID) // one-time import: drop the token as soon as it has done its job
	if err != nil {
		bad(w, err.Error())
		return
	}
	writeJSON(w, toImportReport(rep))
}

func (s *Server) importEeroCancel(w http.ResponseWriter, r *http.Request) {
	var b struct {
		SessionID string `json:"session_id"`
	}
	if !decode(w, r, &b, smallBody) {
		return
	}
	s.importSessions.discard(b.SessionID)
	writeJSON(w, map[string]bool{"ok": true})
}

// ---- CSV ----------------------------------------------------------------

type csvImportRequest struct {
	CSV            string `json:"csv"`
	OverwriteNames bool   `json:"overwrite_names"`
}

func (s *Server) parseCSVPlan(w http.ResponseWriter, r *http.Request) (importers.Plan, []importers.RowError, importers.Options, bool) {
	var b csvImportRequest
	if !decode(w, r, &b, importCSVBody) {
		return importers.Plan{}, nil, importers.Options{}, false
	}
	if strings.TrimSpace(b.CSV) == "" {
		bad(w, "choose a CSV file to import")
		return importers.Plan{}, nil, importers.Options{}, false
	}
	plan, rowErrs, err := importers.ImportCSV(strings.NewReader(b.CSV))
	if err != nil {
		bad(w, err.Error())
		return importers.Plan{}, nil, importers.Options{}, false
	}
	return plan, rowErrs, importers.Options{OverwriteNames: b.OverwriteNames}, true
}

func rowErrorStrings(rowErrs []importers.RowError) []string {
	out := make([]string, len(rowErrs))
	for i, e := range rowErrs {
		out[i] = e.Error()
	}
	return out
}

func (s *Server) importCSVPreview(w http.ResponseWriter, r *http.Request) {
	plan, rowErrs, opts, ok := s.parseCSVPlan(w, r)
	if !ok {
		return
	}
	rep, err := importers.PreviewWith(plan, s.Devices, opts)
	if err != nil {
		bad(w, err.Error())
		return
	}
	out := toImportReport(rep)
	out.RowErrors = orEmpty(rowErrorStrings(rowErrs))
	writeJSON(w, out)
}

func (s *Server) importCSVApply(w http.ResponseWriter, r *http.Request) {
	plan, rowErrs, opts, ok := s.parseCSVPlan(w, r)
	if !ok {
		return
	}
	rep, err := importers.Apply(plan, s.Devices, opts)
	if err != nil {
		bad(w, err.Error())
		return
	}
	out := toImportReport(rep)
	out.RowErrors = orEmpty(rowErrorStrings(rowErrs))
	writeJSON(w, out)
}

// ---- shared report shape --------------------------------------------------

type importReportJSON struct {
	DryRun  bool   `json:"dry_run"`
	Source  string `json:"source"`
	Changed bool   `json:"changed"`

	Created      int `json:"created"`
	MatchedByMAC int `json:"matched_by_mac"`
	MatchedByIP  int `json:"matched_by_ip"`
	Updated      int `json:"updated"`
	Named        int `json:"named"`
	Renamed      int `json:"renamed"`
	Skipped      int `json:"skipped"`
	Unchanged    int `json:"unchanged"`

	GroupsCreated    int `json:"groups_created"`
	MembershipsAdded int `json:"memberships_added"`
	TagsAdded        int `json:"tags_added"`
	MarkedExcluded   int `json:"marked_excluded"`
	NotesSet         int `json:"notes_set"`
	TypesSet         int `json:"types_set"`

	Lines     []string `json:"lines"`
	Conflicts []string `json:"conflicts"`
	Warnings  []string `json:"warnings"`
	RowErrors []string `json:"row_errors,omitempty"`
}

func toImportReport(r importers.Report) importReportJSON {
	return importReportJSON{
		DryRun: r.DryRun, Source: r.Source, Changed: r.Changed(),
		Created: r.Created, MatchedByMAC: r.MatchedByMAC, MatchedByIP: r.MatchedByIP,
		Updated: r.Updated, Named: r.Named, Renamed: r.Renamed, Skipped: r.Skipped, Unchanged: r.Unchanged,
		GroupsCreated: r.GroupsCreated, MembershipsAdded: r.MembershipsAdded, TagsAdded: r.TagsAdded,
		MarkedExcluded: r.MarkedExcluded, NotesSet: r.NotesSet, TypesSet: r.TypesSet,
		Lines: orEmpty(r.Lines), Conflicts: orEmpty(r.Conflicts), Warnings: orEmpty(r.Warnings),
	}
}
