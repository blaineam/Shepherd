// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"errors"
	"net/http"
	"time"

	"shepherd/internal/accountability"
)

// acctEngine returns the accountability engine, or answers 404 and reports
// false when the feature is not wired up (cmd/shepherd's startAccountability
// returns nil when no SMTP relay is configured, or the feature is off): the
// same "not available on this version" shape the frontend already recognises
// via mgmt.js's unavailable(), rather than a 500 or a panic.
func (s *Server) acctEngine(w http.ResponseWriter) (*accountability.Engine, bool) {
	if s.Accountability == nil {
		notFound(w, "accountability is not configured on this server")
		return nil, false
	}
	return s.Accountability, true
}

// acctError maps an accountability package error to a status: ErrNotFound is
// 404, ErrInvalid (and anything else from validation) is 400, and a failed
// save is a server fault, matching policyError's precedent for the other
// scoped stores.
func acctError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, accountability.ErrNotFound):
		notFound(w, err.Error())
	case isIOError(err):
		serverFault(w, "could not save accountability settings")
	default:
		bad(w, err.Error())
	}
}

type contactJSON struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

func toContact(c accountability.Contact) contactJSON {
	return contactJSON{ID: c.ID, Name: c.Name, Email: c.Email, CreatedAt: c.CreatedAt}
}

func (s *Server) listContacts(w http.ResponseWriter, r *http.Request) {
	eng, ok := s.acctEngine(w)
	if !ok {
		return
	}
	cs := eng.Contacts()
	out := make([]contactJSON, len(cs))
	for i, c := range cs {
		out[i] = toContact(c)
	}
	writeJSON(w, map[string]any{"contacts": out})
}

func (s *Server) addContact(w http.ResponseWriter, r *http.Request) {
	eng, ok := s.acctEngine(w)
	if !ok {
		return
	}
	var b struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if !decode(w, r, &b, smallBody) {
		return
	}
	c, err := eng.AddContact(b.Name, b.Email)
	if err != nil {
		acctError(w, err)
		return
	}
	writeJSON(w, toContact(c))
}

func (s *Server) deleteContact(w http.ResponseWriter, r *http.Request) {
	eng, ok := s.acctEngine(w)
	if !ok {
		return
	}
	if err := eng.RemoveContact(r.PathValue("id")); err != nil {
		acctError(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

type subscriptionJSON struct {
	ID                    string    `json:"id"`
	ContactID             string    `json:"contact_id"`
	Scope                 scopeJSON `json:"scope"`
	Items                 []string  `json:"items"`
	Detail                string    `json:"detail"`
	Mode                  string    `json:"mode"`
	Trigger               string    `json:"trigger"`
	DigestIntervalSeconds int       `json:"digest_interval_seconds,omitempty"`
	CreatedAt             time.Time `json:"created_at"`
}

func toSubscription(sub accountability.Subscription) subscriptionJSON {
	return subscriptionJSON{
		ID: sub.ID, ContactID: sub.ContactID,
		Scope:                 scopeJSON{Kind: string(sub.Scope.Kind), ID: sub.Scope.ID},
		Items:                 orEmpty(sub.Items),
		Detail:                string(sub.Detail),
		Mode:                  string(sub.Mode),
		Trigger:               string(sub.Trigger),
		DigestIntervalSeconds: int(sub.DigestInterval / time.Second),
		CreatedAt:             sub.CreatedAt,
	}
}

// resolveAccountabilityScope accepts only "group" and "device" (unlike the
// blocking policy's resolveScope): accountability has no network-wide scope
// by design (docs/ACCOUNTABILITY.md design rule 4).
func (s *Server) resolveAccountabilityScope(w http.ResponseWriter, kind, id string) (accountability.Scope, bool) {
	switch accountability.ScopeKind(kind) {
	case accountability.ScopeGroup:
		if _, ok := s.Devices.GetGroup(id); !ok {
			notFound(w, "unknown group")
			return accountability.Scope{}, false
		}
		return accountability.GroupScope(id), true
	case accountability.ScopeDevice:
		if _, ok := s.Devices.Get(id); !ok {
			notFound(w, "unknown device")
			return accountability.Scope{}, false
		}
		return accountability.DeviceScope(id), true
	}
	bad(w, `scope kind must be "group" or "device"`)
	return accountability.Scope{}, false
}

func (s *Server) listSubscriptions(w http.ResponseWriter, r *http.Request) {
	eng, ok := s.acctEngine(w)
	if !ok {
		return
	}
	var subs []accountability.Subscription
	if cid := r.URL.Query().Get("contact_id"); cid != "" {
		subs = eng.SubscriptionsFor(cid)
	} else {
		subs = eng.Subscriptions()
	}
	out := make([]subscriptionJSON, len(subs))
	for i, sub := range subs {
		out[i] = toSubscription(sub)
	}
	writeJSON(w, map[string]any{"subscriptions": out})
}

func (s *Server) addSubscription(w http.ResponseWriter, r *http.Request) {
	eng, ok := s.acctEngine(w)
	if !ok {
		return
	}
	var b struct {
		ContactID             string    `json:"contact_id"`
		Scope                 scopeJSON `json:"scope"`
		Items                 []string  `json:"items"`
		Detail                string    `json:"detail"`
		Mode                  string    `json:"mode"`
		Trigger               string    `json:"trigger"`
		DigestIntervalSeconds int       `json:"digest_interval_seconds"`
	}
	if !decode(w, r, &b, smallBody) {
		return
	}
	sc, ok := s.resolveAccountabilityScope(w, b.Scope.Kind, b.Scope.ID)
	if !ok {
		return
	}
	if len(b.Items) == 0 {
		bad(w, `items must list at least one catalog, list or app id, or "*" for any`)
		return
	}
	for _, it := range b.Items {
		if it != accountability.Wildcard && !s.knownItem(it) {
			notFound(w, "unknown item "+it)
			return
		}
	}
	if b.DigestIntervalSeconds < 0 {
		bad(w, "digest_interval_seconds must not be negative")
		return
	}
	detail := accountability.Detail(b.Detail)
	if detail == "" {
		detail = accountability.DetailSummary
	}
	mode := accountability.Mode(b.Mode)
	if mode == "" {
		mode = accountability.ModeDigest
	}
	trigger := accountability.TriggerOn(b.Trigger)
	if trigger == "" {
		trigger = accountability.TriggerAny
	}
	sub, err := eng.AddSubscription(accountability.Subscription{
		ContactID: b.ContactID, Scope: sc, Items: b.Items,
		Detail: detail, Mode: mode, Trigger: trigger,
		DigestInterval: time.Duration(b.DigestIntervalSeconds) * time.Second,
	})
	if err != nil {
		acctError(w, err)
		return
	}
	writeJSON(w, toSubscription(sub))
}

func (s *Server) deleteSubscription(w http.ResponseWriter, r *http.Request) {
	eng, ok := s.acctEngine(w)
	if !ok {
		return
	}
	if err := eng.RemoveSubscription(r.PathValue("id")); err != nil {
		acctError(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}
