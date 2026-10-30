// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"errors"
	"net/http"
	"regexp"
	"time"

	"shepherd/internal/devices"
	"shepherd/internal/dnsengine"
)

type deviceNames struct {
	MDNS     string `json:"mdns"`
	Hostname string `json:"hostname"`
	RDNS     string `json:"rdns"`
}

type deviceJSON struct {
	ID             string      `json:"id"`
	Name           string      `json:"name"`
	Alias          string      `json:"alias"`
	Names          deviceNames `json:"names"`
	Vendor         string      `json:"vendor"`
	Type           string      `json:"type"`
	TypeReason     string      `json:"type_reason"`
	MACs           []string    `json:"macs"`
	IPs            []string    `json:"ips"`
	FirstSeen      time.Time   `json:"first_seen"`
	LastSeen       time.Time   `json:"last_seen"`
	Groups         []string    `json:"groups"`
	Tags           []string    `json:"tags"`
	Excluded       bool        `json:"excluded"`
	Wandering      bool        `json:"wandering"`
	WanderingUntil *time.Time  `json:"wandering_until,omitempty"`
	Notes          string      `json:"notes"`
}

func toDevice(d devices.Device) deviceJSON {
	wandering := d.Wandering && (d.WanderingUntil.IsZero() || d.WanderingUntil.After(time.Now()))
	var until *time.Time
	if wandering && !d.WanderingUntil.IsZero() {
		u := d.WanderingUntil
		until = &u
	}
	typ := string(d.Type)
	if typ == "" {
		typ = string(devices.TypeUnknown)
	}
	return deviceJSON{
		ID: d.ID, Name: d.DisplayName(), Alias: d.Alias,
		Names:  deviceNames{MDNS: d.MDNSName, Hostname: d.Hostname, RDNS: d.ReverseName},
		Vendor: d.Vendor, Type: typ, TypeReason: d.TypeReason,
		MACs: orEmpty(d.MACs), IPs: orEmpty(d.IPs), FirstSeen: d.FirstSeen, LastSeen: d.LastSeen,
		Groups: orEmpty(d.Groups), Tags: orEmpty(d.Tags), Excluded: d.Excluded, Wandering: wandering, WanderingUntil: until, Notes: d.Notes,
	}
}

type groupJSON struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Color string `json:"color"`
	Count int    `json:"count"`
}

func toGroup(g devices.Group) groupJSON {
	return groupJSON{ID: g.ID, Name: g.Name, Color: g.Color, Count: len(g.Members)}
}

const (
	maxNotes    = 2000
	maxAlias    = 128
	maxTagLen   = 32
	maxTags     = 20
	maxBulkIDs  = 2000
	maxMergeSrc = 100
)

var colorRE = regexp.MustCompile(`^(#[0-9a-fA-F]{3,8}|[a-zA-Z]{3,20})$`)

func (s *Server) listDevices(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	offset, ok1 := intParam(r, "offset", 0)
	limit, ok2 := intParam(r, "limit", 100)
	if !ok1 || !ok2 {
		bad(w, "offset and limit must be non-negative integers")
		return
	}
	sort := devices.SortRecent
	switch q.Get("sort") {
	case "", "recent":
	case "name":
		sort = devices.SortName
	default:
		bad(w, `sort must be "recent" or "name"`)
		return
	}
	if limit == 0 {
		limit = 100
	}
	page := s.Devices.Search(q.Get("q"), devices.SearchOptions{Sort: sort, Offset: offset, Limit: limit})
	out := make([]deviceJSON, len(page.Items))
	for i, d := range page.Items {
		out[i] = toDevice(d)
	}
	writeJSON(w, map[string]any{"devices": out, "total": page.Total, "offset": page.Offset, "limit": page.Limit})
}

func (s *Server) getDevice(w http.ResponseWriter, r *http.Request) {
	d, ok := s.Devices.Get(r.PathValue("id"))
	if !ok {
		notFound(w, "unknown device")
		return
	}
	writeJSON(w, toDevice(d))
}

func validTags(tags []string) bool {
	if len(tags) > maxTags {
		return false
	}
	for _, t := range tags {
		if len(t) > maxTagLen || hasControl(t) {
			return false
		}
	}
	return true
}

func (s *Server) patchDevice(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var b struct {
		Alias            *string   `json:"alias"`
		Notes            *string   `json:"notes"`
		Type             *string   `json:"type"`
		Excluded         *bool     `json:"excluded"`
		Tags             *[]string `json:"tags"`
		Wandering        *bool     `json:"wandering"`
		WanderingMinutes int       `json:"wandering_minutes"`
	}
	if !decode(w, r, &b, smallBody) {
		return
	}
	if _, ok := s.Devices.Get(id); !ok {
		notFound(w, "unknown device")
		return
	}
	switch {
	case b.Alias != nil && (len(*b.Alias) > maxAlias || hasControl(*b.Alias)):
		bad(w, "alias must be at most 128 characters without control characters")
		return
	case b.Notes != nil && len(*b.Notes) > maxNotes:
		bad(w, "notes must be at most 2000 characters")
		return
	case b.Type != nil && *b.Type != "" && !validType(*b.Type):
		bad(w, `type must be "auto" or a known device type`)
		return
	case b.Tags != nil && !validTags(*b.Tags):
		bad(w, "at most 20 tags of at most 32 characters each")
		return
	case b.WanderingMinutes < 0 || b.WanderingMinutes > maxWanderMinutes:
		bad(w, "wandering_minutes must be between 0 (until turned off) and 43200 (30 days)")
		return
	}
	var err error
	if b.Alias != nil {
		err = s.Devices.Rename(id, *b.Alias)
	}
	if err == nil && b.Notes != nil {
		err = s.Devices.SetNotes(id, *b.Notes)
	}
	if err == nil && b.Type != nil {
		err = s.Devices.SetType(id, *b.Type)
	}
	if err == nil && b.Excluded != nil {
		err = s.Devices.SetExcluded(id, *b.Excluded)
	}
	if err == nil && b.Tags != nil {
		err = s.Devices.SetTags(id, *b.Tags)
	}
	if err == nil && b.Wandering != nil {
		err = s.Devices.SetWandering(id, *b.Wandering, wanderUntil(*b.Wandering, b.WanderingMinutes))
	}
	if errors.Is(err, devices.ErrNotFound) { // deleted by someone else meanwhile
		notFound(w, "unknown device")
		return
	}
	if err != nil {
		bad(w, err.Error())
		return
	}
	s.getDevice(w, r)
}

func validType(t string) bool {
	if t == "auto" {
		return true
	}
	_, ok := devices.ParseType(t)
	return ok
}

// forgetDeviceScopes drops policy kept for devices that no longer exist.
func (s *Server) forgetDeviceScopes(ids ...string) {
	snap := s.Policy.Snapshot()
	for _, id := range ids {
		if _, has := snap.Devices[id]; has {
			_ = s.Policy.DeleteScope(dnsengine.DeviceScope(id))
		}
	}
}

func (s *Server) deleteDevice(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.Devices.Delete(id); err != nil {
		notFound(w, "unknown device")
		return
	}
	s.forgetDeviceScopes(id)
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) bulkDevices(w http.ResponseWriter, r *http.Request) {
	var b struct {
		IDs              []string `json:"ids"`
		Op               string   `json:"op"`
		GroupID          string   `json:"group_id"`
		Excluded         *bool    `json:"excluded"`
		AddTags          []string `json:"add_tags"`
		RemoveTags       []string `json:"remove_tags"`
		Wandering        *bool    `json:"wandering"`
		WanderingMinutes int      `json:"wandering_minutes"`
	}
	if !decode(w, r, &b, smallBody) {
		return
	}
	if len(b.IDs) == 0 || len(b.IDs) > maxBulkIDs {
		bad(w, "ids must list between 1 and 2000 devices")
		return
	}
	var res devices.BulkResult
	var err error
	switch b.Op {
	case "assign_group", "remove_group":
		if b.GroupID == "" {
			bad(w, "group_id is required")
			return
		}
		if b.Op == "assign_group" {
			res, err = s.Devices.BulkAssignGroup(b.IDs, b.GroupID)
		} else {
			res, err = s.Devices.BulkRemoveGroup(b.IDs, b.GroupID)
		}
		if errors.Is(err, devices.ErrGroupNotFound) {
			notFound(w, "unknown group")
			return
		}
	case "set_excluded":
		if b.Excluded == nil {
			bad(w, "excluded is required")
			return
		}
		res = s.Devices.BulkSetExcluded(b.IDs, *b.Excluded)
	case "set_wandering":
		if b.Wandering == nil {
			bad(w, "wandering is required")
			return
		}
		if b.WanderingMinutes < 0 || b.WanderingMinutes > maxWanderMinutes {
			bad(w, "wandering_minutes must be between 0 (until turned off) and 43200 (30 days)")
			return
		}
		res = s.Devices.BulkSetWandering(b.IDs, *b.Wandering, wanderUntil(*b.Wandering, b.WanderingMinutes))
	case "set_tags":
		if len(b.AddTags)+len(b.RemoveTags) == 0 {
			bad(w, "give add_tags or remove_tags")
			return
		}
		if !validTags(b.AddTags) || !validTags(b.RemoveTags) {
			bad(w, "at most 20 tags of at most 32 characters each")
			return
		}
		res = s.Devices.BulkSetTags(b.IDs, b.AddTags, b.RemoveTags)
	case "delete":
		res = s.Devices.BulkDelete(b.IDs)
		s.forgetDeviceScopes(b.IDs...)
	default:
		bad(w, `op must be "assign_group", "remove_group", "set_excluded", "set_wandering", "set_tags" or "delete"`)
		return
	}
	if err != nil {
		bad(w, err.Error())
		return
	}
	writeJSON(w, map[string]any{"changed": res.Changed, "missing": orEmpty(res.Missing)})
}

func (s *Server) mergeDevices(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Target  string   `json:"target"`
		Sources []string `json:"sources"`
	}
	if !decode(w, r, &b, smallBody) {
		return
	}
	if b.Target == "" || len(b.Sources) == 0 || len(b.Sources) > maxMergeSrc {
		bad(w, "target and between 1 and 100 sources are required")
		return
	}
	switch err := s.Devices.Merge(b.Target, b.Sources...); {
	case errors.Is(err, devices.ErrNotFound):
		notFound(w, "unknown device")
		return
	case err != nil:
		bad(w, "sources must include at least one device other than the target")
		return
	}
	s.forgetDeviceScopes(b.Sources...) // what was configured on a merged-away device goes with it
	d, _ := s.Devices.Get(b.Target)
	writeJSON(w, toDevice(d))
}

func (s *Server) listGroups(w http.ResponseWriter, r *http.Request) {
	gs := s.Devices.Groups()
	out := make([]groupJSON, len(gs))
	for i, g := range gs {
		out[i] = toGroup(g)
	}
	writeJSON(w, map[string]any{"groups": out})
}

func validGroupText(name string, color *string) bool {
	if name != "" && (len(name) > 64 || hasControl(name)) {
		return false
	}
	return color == nil || *color == "" || colorRE.MatchString(*color)
}

func (s *Server) createGroup(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Name  string  `json:"name"`
		Color *string `json:"color"`
	}
	if !decode(w, r, &b, smallBody) {
		return
	}
	if b.Name == "" || !validGroupText(b.Name, b.Color) {
		bad(w, "name is required (at most 64 characters); color must be #hex or a color name")
		return
	}
	color := ""
	if b.Color != nil {
		color = *b.Color
	}
	g, err := s.Devices.CreateGroup(b.Name, color)
	switch {
	case errors.Is(err, devices.ErrDuplicateName):
		conflict(w, "a group with that name already exists")
	case err != nil:
		bad(w, "invalid group")
	default:
		g, _ = s.Devices.GetGroup(g.ID)
		writeJSON(w, toGroup(g))
	}
}

func (s *Server) patchGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var b struct {
		Name  *string `json:"name"`
		Color *string `json:"color"`
	}
	if !decode(w, r, &b, smallBody) {
		return
	}
	if _, ok := s.Devices.GetGroup(id); !ok {
		notFound(w, "unknown group")
		return
	}
	if (b.Name != nil && *b.Name == "") || !validGroupText(derefOr(b.Name), b.Color) {
		bad(w, "name must be 1 to 64 characters; color must be #hex or a color name")
		return
	}
	var err error
	if b.Name != nil {
		err = s.Devices.RenameGroup(id, *b.Name)
	}
	if err == nil && b.Color != nil {
		err = s.Devices.SetGroupColor(id, *b.Color)
	}
	switch {
	case errors.Is(err, devices.ErrDuplicateName):
		conflict(w, "a group with that name already exists")
	case errors.Is(err, devices.ErrGroupNotFound):
		notFound(w, "unknown group")
	case err != nil:
		bad(w, "invalid group")
	default:
		g, _ := s.Devices.GetGroup(id)
		writeJSON(w, toGroup(g))
	}
}

func derefOr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func (s *Server) deleteGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.Devices.DeleteGroup(id); err != nil {
		notFound(w, "unknown group")
		return
	}
	if _, has := s.Policy.Snapshot().Groups[id]; has {
		_ = s.Policy.DeleteScope(dnsengine.GroupScope(id))
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// maxWanderMinutes caps a wandering timer at 30 days.
const maxWanderMinutes = 30 * 24 * 60

// wanderUntil turns a requested number of minutes into the end time of wandering
// mode. Zero minutes means until it is turned off (the zero time).
func wanderUntil(on bool, minutes int) time.Time {
	if !on || minutes <= 0 {
		return time.Time{}
	}
	return time.Now().Add(time.Duration(minutes) * time.Minute)
}
