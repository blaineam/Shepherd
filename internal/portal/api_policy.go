// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"

	"shepherd/internal/dnsengine"
)

// switchInfo describes a built-in policy switch for the UI.
var switchInfo = map[string][2]string{
	dnsengine.PolicyPrivateRelay: {
		"Block Apple iCloud Private Relay",
		"Answers NXDOMAIN for the hostnames Apple devices use to reach iCloud Private Relay, which is Apple's documented way for a network to say it does not allow the relay. Devices show a notice that the relay is unavailable here.",
	},
}

type scopeJSON struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// resolveScope validates a scope from a request and checks that a group or
// device scope names something that exists.
func (s *Server) resolveScope(w http.ResponseWriter, kind, id string) (dnsengine.Scope, bool) {
	switch dnsengine.ScopeKind(kind) {
	case dnsengine.ScopeNetwork:
		if id != "" {
			bad(w, "a network scope has no id")
			return dnsengine.Scope{}, false
		}
		return dnsengine.NetworkScope(), true
	case dnsengine.ScopeGroup:
		if _, ok := s.Devices.GetGroup(id); !ok {
			notFound(w, "unknown group")
			return dnsengine.Scope{}, false
		}
		return dnsengine.GroupScope(id), true
	case dnsengine.ScopeDevice:
		if _, ok := s.Devices.Get(id); !ok {
			notFound(w, "unknown device")
			return dnsengine.Scope{}, false
		}
		return dnsengine.DeviceScope(id), true
	}
	bad(w, `scope kind must be "network", "group" or "device"`)
	return dnsengine.Scope{}, false
}

type catalogEntryJSON struct {
	ID            string   `json:"id"`
	Kind          string   `json:"kind"`
	Name          string   `json:"name"`
	Category      string   `json:"category"`
	Description   string   `json:"description"`
	License       string   `json:"license"`
	Homepage      string   `json:"homepage"`
	ApproxEntries int      `json:"approx_entries"`
	Recommended   bool     `json:"recommended"`
	Includes      []string `json:"includes,omitempty"`
}

func (s *Server) getCatalog(w http.ResponseWriter, r *http.Request) {
	cat := s.Policy.Catalog()
	entries := cat.Entries()
	out := make([]catalogEntryJSON, 0, len(entries))
	cats := []string{}
	for _, e := range entries {
		category := ""
		if e.Kind == dnsengine.KindCategory {
			category = e.Name
			cats = append(cats, e.Name)
		} else if c, ok := cat.ByID(e.Category); ok {
			category = c.Name
		}
		out = append(out, catalogEntryJSON{
			ID: e.ID, Kind: string(e.Kind), Name: e.Name, Category: category, Description: e.Description,
			License: e.License, Homepage: e.Homepage, ApproxEntries: e.ApproxEntries,
			Recommended: e.Recommended, Includes: e.Includes,
		})
	}
	writeJSON(w, map[string]any{"entries": out, "categories": cats})
}

func isEmptyScope(ss dnsengine.ScopeSettings) bool {
	return len(ss.Items) == 0 && len(ss.Policies) == 0 && len(ss.Allow) == 0 && len(ss.Block) == 0
}

func scopeView(kind, id string, ss dnsengine.ScopeSettings) map[string]any {
	items := map[string]bool{}
	for k, v := range ss.Items {
		items[k] = v
	}
	switches := map[string]bool{}
	for k, v := range ss.Policies {
		switches[k] = v
	}
	return map[string]any{
		"scope":    scopeJSON{Kind: kind, ID: id},
		"items":    items,
		"rules":    map[string][]string{"allow": orEmpty(ss.Allow), "block": orEmpty(ss.Block)},
		"switches": switches,
	}
}

func (s *Server) itemCount(id string, c dnsengine.CustomList) int {
	if n, ok := s.Engine.Filter.ItemSize(id); ok {
		return n
	}
	if c.Inline != "" {
		if set, err := dnsengine.ParseList(strings.NewReader(c.Inline)); err == nil {
			return len(set)
		}
	}
	return 0
}

func (s *Server) customView(c dnsengine.CustomList) map[string]any {
	m := map[string]any{"id": c.ID, "name": c.Name, "category": c.Category, "count": s.itemCount(c.ID, c)}
	if c.URL != "" {
		m["url"] = c.URL
	}
	if c.Inline != "" {
		m["inline"] = true
	}
	return m
}

func (s *Server) policyView() map[string]any {
	snap := s.Policy.Snapshot()
	scopes := []map[string]any{scopeView("network", "", snap.Network)}
	for _, kind := range []struct {
		name string
		m    map[string]dnsengine.ScopeSettings
	}{{"group", snap.Groups}, {"device", snap.Devices}} {
		ids := make([]string, 0, len(kind.m))
		for id, ss := range kind.m {
			if !isEmptyScope(ss) {
				ids = append(ids, id)
			}
		}
		slices.Sort(ids)
		for _, id := range ids {
			scopes = append(scopes, scopeView(kind.name, id, kind.m[id]))
		}
	}
	custom := make([]map[string]any, 0, len(snap.Custom))
	for _, c := range snap.Custom {
		custom = append(custom, s.customView(c))
	}
	type listJSON struct {
		ID      string     `json:"id"`
		Name    string     `json:"name"`
		Count   int        `json:"count"`
		Size    int64      `json:"size_bytes"`
		Updated *time.Time `json:"updated"`
		Error   string     `json:"error,omitempty"`
	}
	statuses := s.Lists.Status()
	lists := make([]listJSON, 0, len(statuses))
	for _, st := range statuses {
		l := listJSON{ID: st.ID, Name: st.Name, Count: st.Count, Size: st.Size, Error: st.Error}
		if !st.Updated.IsZero() {
			u := st.Updated
			l.Updated = &u
		}
		lists = append(lists, l)
	}
	switches := []map[string]string{}
	for _, name := range snap.Policies {
		info := switchInfo[name]
		switches = append(switches, map[string]string{"name": name, "title": info[0], "description": info[1]})
	}
	return map[string]any{"scopes": scopes, "custom_lists": custom, "lists": lists, "switches": switches}
}

func (s *Server) getPolicy(w http.ResponseWriter, r *http.Request) { writeJSON(w, s.policyView()) }

// policyError maps a store error to a status: a failed save is a server fault,
// anything else is the caller's input.
func policyError(w http.ResponseWriter, err error) {
	if isIOError(err) {
		serverFault(w, "could not save the policy")
		return
	}
	bad(w, err.Error())
}

// enabledField is a request's "enabled": true, false or null (clear). Absent
// is distinct from null so a forgotten field is an error, not a silent clear.
type enabledField struct {
	present bool
	value   *bool
}

func (e *enabledField) UnmarshalJSON(b []byte) error {
	e.present = true
	if string(b) == "null" {
		e.value = nil
		return nil
	}
	var v bool
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	e.value = &v
	return nil
}

func (s *Server) setPolicyItem(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Scope   scopeJSON    `json:"scope"`
		Item    string       `json:"item"`
		Enabled enabledField `json:"enabled"`
	}
	if !decode(w, r, &b, smallBody) {
		return
	}
	sc, ok := s.resolveScope(w, b.Scope.Kind, b.Scope.ID)
	if !ok {
		return
	}
	if !b.Enabled.present {
		bad(w, "enabled is required (true, false or null)")
		return
	}
	if !s.knownItem(b.Item) {
		notFound(w, "unknown item")
		return
	}
	var err error
	if b.Enabled.value == nil {
		err = s.Policy.ClearItem(sc, b.Item)
	} else {
		err = s.Policy.SetItem(sc, b.Item, *b.Enabled.value)
	}
	if err != nil {
		policyError(w, err)
		return
	}
	s.getPolicy(w, r)
}

func (s *Server) knownItem(id string) bool {
	if _, ok := s.Policy.Catalog().ByID(id); ok {
		return true
	}
	return slices.ContainsFunc(s.Policy.Snapshot().Custom, func(c dnsengine.CustomList) bool { return c.ID == id })
}

func (s *Server) setPolicySwitch(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Scope   scopeJSON    `json:"scope"`
		Name    string       `json:"name"`
		Enabled enabledField `json:"enabled"`
	}
	if !decode(w, r, &b, smallBody) {
		return
	}
	sc, ok := s.resolveScope(w, b.Scope.Kind, b.Scope.ID)
	if !ok {
		return
	}
	if !b.Enabled.present {
		bad(w, "enabled is required (true, false or null)")
		return
	}
	if !slices.Contains(dnsengine.KnownPolicies(), b.Name) {
		notFound(w, "unknown switch")
		return
	}
	var err error
	if b.Enabled.value == nil {
		err = s.Policy.ClearPolicy(sc, b.Name)
	} else {
		err = s.Policy.SetPolicy(sc, b.Name, *b.Enabled.value)
	}
	if err != nil {
		policyError(w, err)
		return
	}
	s.getPolicy(w, r)
}

func (s *Server) addPolicyRule(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Scope  scopeJSON `json:"scope"`
		Kind   string    `json:"kind"`
		Domain string    `json:"domain"`
	}
	if !decode(w, r, &b, smallBody) {
		return
	}
	sc, ok := s.resolveScope(w, b.Scope.Kind, b.Scope.ID)
	if !ok {
		return
	}
	if err := s.Policy.AddRule(sc, b.Kind, b.Domain); err != nil {
		policyError(w, err)
		return
	}
	s.getPolicy(w, r)
}

func (s *Server) deletePolicyRule(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	sc, ok := s.resolveScope(w, q.Get("scope_kind"), q.Get("scope_id"))
	if !ok {
		return
	}
	if err := s.Policy.RemoveRule(sc, q.Get("kind"), q.Get("domain")); err != nil {
		policyError(w, err)
		return
	}
	s.getPolicy(w, r)
}

func (s *Server) addCustomList(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Name     string `json:"name"`
		Category string `json:"category"`
		URL      string `json:"url"`
		Inline   string `json:"inline"`
	}
	if !decode(w, r, &b, listBody) {
		return
	}
	c, err := s.Policy.AddCustomList(dnsengine.CustomListInput{Name: b.Name, Category: b.Category, URL: b.URL, Inline: b.Inline})
	if err != nil {
		policyError(w, err)
		return
	}
	writeJSON(w, s.customView(c))
}

func (s *Server) deleteCustomList(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !slices.ContainsFunc(s.Policy.Snapshot().Custom, func(c dnsengine.CustomList) bool { return c.ID == id }) {
		notFound(w, "unknown custom list")
		return
	}
	if err := s.Policy.RemoveCustomList(id); err != nil {
		policyError(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// refreshTimeout bounds a background list refresh started from the API.
const refreshTimeout = 10 * time.Minute

func (s *Server) refreshPolicy(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Item string `json:"item"`
	}
	if r.ContentLength != 0 {
		if !decode(w, r, &b, smallBody) {
			return
		}
	}
	if b.Item != "" && !s.knownItem(b.Item) {
		notFound(w, "unknown item")
		return
	}
	s.refreshAsync(b.Item)
	w.WriteHeader(http.StatusAccepted)
}

// refreshAsync refreshes in the background, outliving the request.
func (s *Server) refreshAsync(item string) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), refreshTimeout)
		defer cancel()
		if item == "" {
			s.Lists.Refresh(ctx)
		} else {
			s.Lists.RefreshItem(ctx, item)
		}
	}()
}
