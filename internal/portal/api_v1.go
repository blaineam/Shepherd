// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"shepherd/internal/backends"
	"shepherd/internal/routerusage"
)

// The router API (docs/API.md): one small REST API over whatever router or
// firewall is connected, the same for every product. A Firewalla read on
// the box, a Firewalla through MSP and a UniFi console all answer these
// calls; what differs is which of them each can do, which GET
// /api/v1/router reports as capabilities and every call checks.
//
// It is described by an OpenAPI document served at /api/v1/openapi.json.
// The document is built from the same table the routes are registered
// from (v1Routes), so the two cannot drift apart.
//
// It sits beside the portal's own /api/backend endpoints, which stay as
// they are: those return the product's records as the hub holds them and
// serve the screens. This one has its own stable, lower-case shapes.

// v1Route is one call: how it is routed, and how it is described.
type v1Route struct {
	method, path string
	summary      string
	// needs is the capability the connected product must have, "" for none.
	needs backends.Capability
	// body and reply name schemas in v1Schemas; "" for none.
	body, reply string
	// list marks reply as an array of that schema, under this key.
	list    string
	params  []v1Param
	handler func(*Server, http.ResponseWriter, *http.Request)
}

type v1Param struct {
	name, in, description string
	required              bool
}

var macParam = v1Param{"mac", "path", "The device's MAC address, with or without separators.", true}

func v1Routes() []v1Route {
	return []v1Route{
		{method: "GET", path: "/api/v1/router", summary: "The connected router or firewall and what it can do", reply: "Router", handler: (*Server).v1Router},
		{method: "GET", path: "/api/v1/devices", summary: "Every device the router knows", needs: backends.CapDevices, reply: "Device", list: "devices", handler: (*Server).v1Devices},
		{method: "GET", path: "/api/v1/devices/{mac}", summary: "One device", needs: backends.CapDevices, reply: "Device", params: []v1Param{macParam}, handler: (*Server).v1Device},
		{method: "PATCH", path: "/api/v1/devices/{mac}", summary: "Rename a device, move it to a group, or block it", needs: backends.CapDevices, body: "DevicePatch", reply: "Device", params: []v1Param{macParam}, handler: (*Server).v1PatchDevice},
		{method: "GET", path: "/api/v1/groups", summary: "The router's device groups", needs: backends.CapGroups, reply: "Group", list: "groups", handler: (*Server).v1Groups},
		{method: "GET", path: "/api/v1/rules", summary: "The router's access rules", needs: backends.CapRules, reply: "Rule", list: "rules", handler: (*Server).v1Rules},
		{method: "POST", path: "/api/v1/rules", summary: "Create a block or allow rule", needs: backends.CapRuleCreate, body: "RuleCreate", reply: "Rule", handler: (*Server).v1CreateRule},
		{method: "PATCH", path: "/api/v1/rules/{id}", summary: "Pause or resume a rule", needs: backends.CapRuleWrite, body: "RulePatch", reply: "Ok", params: []v1Param{{"id", "path", "The rule's ID.", true}}, handler: (*Server).v1PatchRule},
		{method: "DELETE", path: "/api/v1/rules/{id}", summary: "Delete a rule", needs: backends.CapRuleWrite, reply: "Ok", params: []v1Param{{"id", "path", "The rule's ID.", true}}, handler: (*Server).v1DeleteRule},
		{method: "GET", path: "/api/v1/alarms", summary: "The router's active alarms", needs: backends.CapAlarms, reply: "Alarm", list: "alarms", handler: (*Server).v1Alarms},
		{method: "DELETE", path: "/api/v1/alarms/{id}", summary: "Dismiss an alarm", needs: backends.CapAlarmDismiss, reply: "Ok", params: []v1Param{
			{"id", "path", "The alarm's ID.", true},
			{"box", "query", "The box the alarm is on, for a product with several (a Firewalla MSP account).", false},
		}, handler: (*Server).v1DismissAlarm},
		{method: "GET", path: "/api/v1/flows", summary: "Recent network requests, newest first", needs: backends.CapFlows, reply: "Flow", list: "flows", params: []v1Param{
			{"device", "query", "Only this device's requests: its MAC address.", false},
			{"limit", "query", "At most this many, 1 to 500 (default 100).", false},
			{"cursor", "query", "The next value from the previous page.", false},
		}, handler: (*Server).v1Flows},
	}
}

// routesV1 registers the router API and its description.
func (s *Server) routesV1() {
	for _, rt := range v1Routes() {
		rt := rt
		s.mux.Handle(rt.method+" "+rt.path, s.auth(func(w http.ResponseWriter, r *http.Request) {
			if !s.v1Can(w, rt.needs) {
				return
			}
			rt.handler(s, w, r)
		}))
	}
	s.mux.Handle("GET /api/v1/openapi.json", s.auth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, v1OpenAPI(s.Version))
	}))
}

// ---- errors -----------------------------------------------------------------

// v1Fail answers with the API's one error shape.
func v1Fail(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	writeJSONBody(w, map[string]string{"error": msg, "code": code})
}

// v1Error maps a backend failure onto the API's error shape.
func v1Error(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, backends.ErrReadOnly):
		v1Fail(w, http.StatusForbidden, "read_only", "changes are switched off: turn on Allow changes on the Router screen")
	case errors.Is(err, backends.ErrInvalid):
		v1Fail(w, http.StatusBadRequest, "invalid", strings.TrimPrefix(err.Error(), backends.ErrInvalid.Error()+": "))
	case errors.Is(err, backends.ErrNotFound):
		v1Fail(w, http.StatusNotFound, "not_found", "the router has nothing by that ID")
	case errors.Is(err, backends.ErrRateLimited):
		v1Fail(w, http.StatusTooManyRequests, "rate_limited", "the router's service is limiting requests; try again shortly")
	case errors.Is(err, backends.ErrAuth):
		v1Fail(w, http.StatusBadGateway, "credential_refused", "the router refused Shepherd's credential")
	default:
		v1Fail(w, http.StatusBadGateway, "router_error", err.Error())
	}
}

// v1Can refuses a call the connected product cannot serve, saying whether
// nothing is connected, the product lacks the ability, or changes are off.
func (s *Server) v1Can(w http.ResponseWriter, need backends.Capability) bool {
	if need == "" {
		return true
	}
	if s.Backend == nil {
		v1Fail(w, http.StatusNotFound, "not_connected", "no router or firewall is connected")
		return false
	}
	snap, ok := s.Backend.Snapshot()
	if !ok {
		v1Fail(w, http.StatusNotFound, "not_connected", "no router or firewall is connected")
		return false
	}
	for _, c := range snap.Capabilities {
		if c == need {
			return true
		}
	}
	if snap.ReadOnly && strings.Contains(string(need), ":") {
		v1Fail(w, http.StatusForbidden, "read_only", "changes are switched off: turn on Allow changes on the Router screen")
		return false
	}
	v1Fail(w, http.StatusNotImplemented, "unsupported", "the connected "+snap.Name+" cannot do this ("+string(need)+")")
	return false
}

// ---- shapes -----------------------------------------------------------------

type v1Device struct {
	MAC     string `json:"mac"`
	Name    string `json:"name"`
	IP      string `json:"ip,omitempty"`
	Vendor  string `json:"vendor,omitempty"`
	Online  bool   `json:"online"`
	Group   string `json:"group,omitempty"`
	Network string `json:"network,omitempty"`
	Blocked bool   `json:"blocked"`
	// NameFrom is "typed", "learned" or "" when the product cannot say.
	NameFrom string `json:"name_from,omitempty"`
}

func toV1Device(d backends.Device) v1Device {
	return v1Device{MAC: d.MAC, Name: d.Name, IP: d.IP, Vendor: d.Vendor, Online: d.Online && !d.Blocked,
		Group: d.Group, Network: d.Network, Blocked: d.Blocked, NameFrom: d.NameFrom}
}

type v1Rule struct {
	ID         string     `json:"id"`
	Action     string     `json:"action"`
	TargetType string     `json:"target_type"`
	Target     string     `json:"target"`
	DNSOnly    bool       `json:"dns_only"`
	ScopeType  string     `json:"scope_type,omitempty"`
	Scope      string     `json:"scope,omitempty"`
	Name       string     `json:"name,omitempty"`
	Paused     bool       `json:"paused"`
	Notes      string     `json:"notes,omitempty"`
	Schedule   string     `json:"schedule,omitempty"`
	Created    *time.Time `json:"created,omitempty"`
}

func toV1Rule(r backends.Rule) v1Rule {
	out := v1Rule{ID: r.ID, Action: r.Action, TargetType: r.TargetType, Target: r.Target, DNSOnly: r.DNSOnly,
		ScopeType: r.ScopeType, Scope: r.Scope, Name: r.Name, Paused: r.Paused, Notes: r.Notes, Schedule: r.Schedule}
	if !r.Created.IsZero() {
		out.Created = &r.Created
	}
	return out
}

type v1Alarm struct {
	ID      string     `json:"id"`
	Box     string     `json:"box,omitempty"`
	Type    string     `json:"type"`
	Message string     `json:"message"`
	Time    *time.Time `json:"time,omitempty"`
	MAC     string     `json:"mac,omitempty"`
	Device  string     `json:"device,omitempty"`
	Domain  string     `json:"domain,omitempty"`
}

type v1Flow struct {
	Time      time.Time `json:"time"`
	MAC       string    `json:"mac,omitempty"`
	Device    string    `json:"device,omitempty"`
	DeviceIP  string    `json:"device_ip,omitempty"`
	Domain    string    `json:"domain,omitempty"`
	RemoteIP  string    `json:"remote_ip,omitempty"`
	Protocol  string    `json:"protocol,omitempty"`
	Outbound  bool      `json:"outbound"`
	Blocked   bool      `json:"blocked"`
	Download  uint64    `json:"download_bytes"`
	Upload    uint64    `json:"upload_bytes"`
	Country   string    `json:"country,omitempty"`
	Category  string    `json:"category,omitempty"`
	FlowCount int       `json:"count,omitempty"`
}

// ---- handlers ---------------------------------------------------------------

func (s *Server) v1Router(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{"connected": false, "capabilities": []string{}}
	if s.Backend != nil {
		if snap, ok := s.Backend.Snapshot(); ok {
			out["connected"] = true
			out["product"] = snap.Name
			out["read_only"] = snap.ReadOnly
			out["capabilities"] = snap.Capabilities
			out["last_read"] = snap.Status.LastPoll
			if len(snap.Status.Errors) > 0 {
				out["errors"] = snap.Status.Errors
			}
		}
	}
	writeJSON(w, out)
}

// v1Find looks a device up by MAC in the hub's latest list.
func (s *Server) v1Find(w http.ResponseWriter, r *http.Request) (backends.Device, bool) {
	mac := routerusage.NormalizeMAC(r.PathValue("mac"))
	if mac == "" {
		v1Fail(w, http.StatusBadRequest, "invalid", "that is not a MAC address")
		return backends.Device{}, false
	}
	snap, _ := s.Backend.Snapshot()
	for _, d := range snap.Devices {
		if d.MAC == mac {
			return d, true
		}
	}
	v1Fail(w, http.StatusNotFound, "not_found", "the router knows no device with that MAC address")
	return backends.Device{}, false
}

func (s *Server) v1Devices(w http.ResponseWriter, r *http.Request) {
	snap, _ := s.Backend.Snapshot()
	out := make([]v1Device, 0, len(snap.Devices))
	for _, d := range snap.Devices {
		out = append(out, toV1Device(d))
	}
	sort.SliceStable(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	writeJSON(w, map[string]any{"devices": out})
}

func (s *Server) v1Device(w http.ResponseWriter, r *http.Request) {
	if d, ok := s.v1Find(w, r); ok {
		writeJSON(w, toV1Device(d))
	}
}

// v1PatchDevice applies whichever of name, group and blocked the body
// carries, in that order, and stops at the first that fails. Each needs
// its own capability, checked here because one call can ask for several.
func (s *Server) v1PatchDevice(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Name    *string `json:"name"`
		Group   *string `json:"group"`
		Blocked *bool   `json:"blocked"`
	}
	if !decode(w, r, &b, smallBody) {
		return
	}
	if b.Name == nil && b.Group == nil && b.Blocked == nil {
		v1Fail(w, http.StatusBadRequest, "invalid", "send at least one of name, group or blocked")
		return
	}
	d, ok := s.v1Find(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), backendWriteTimeout)
	defer cancel()
	if b.Name != nil {
		if !s.v1Can(w, backends.CapDeviceRename) {
			return
		}
		if err := s.Backend.RenameDevice(ctx, d.Ref(), *b.Name); err != nil {
			v1Error(w, err)
			return
		}
	}
	if b.Group != nil {
		if !s.v1Can(w, backends.CapGroupWrite) {
			return
		}
		if err := s.Backend.SetDeviceGroup(ctx, d.Ref(), *b.Group); err != nil {
			v1Error(w, err)
			return
		}
	}
	if b.Blocked != nil {
		if !s.v1Can(w, backends.CapDeviceBlock) {
			return
		}
		if err := s.Backend.BlockClient(ctx, d.Ref(), *b.Blocked); err != nil {
			v1Error(w, err)
			return
		}
	}
	// Answer with the device as the hub now has it.
	snap, _ := s.Backend.Snapshot()
	for _, now := range snap.Devices {
		if now.MAC == d.MAC {
			d = now
		}
	}
	writeJSON(w, toV1Device(d))
}

func (s *Server) v1Groups(w http.ResponseWriter, r *http.Request) {
	snap, _ := s.Backend.Snapshot()
	members := map[string]int{}
	for _, d := range snap.Devices {
		if d.Group != "" {
			members[strings.ToLower(d.Group)]++
		}
	}
	out := make([]map[string]any, 0, len(snap.Groups))
	for _, g := range snap.Groups {
		out = append(out, map[string]any{"id": g.ID, "name": g.Name, "devices": members[strings.ToLower(g.Name)]})
	}
	writeJSON(w, map[string]any{"groups": out})
}

func (s *Server) v1Rules(w http.ResponseWriter, r *http.Request) {
	snap, _ := s.Backend.Snapshot()
	out := make([]v1Rule, 0, len(snap.Rules))
	for _, rule := range snap.Rules {
		out = append(out, toV1Rule(rule))
	}
	writeJSON(w, map[string]any{"rules": out})
}

func (s *Server) v1CreateRule(w http.ResponseWriter, r *http.Request) {
	var b backendRuleBody
	if !decode(w, r, &b, smallBody) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), backendWriteTimeout)
	defer cancel()
	rule, err := s.Backend.CreateRule(ctx, b.spec())
	if err != nil {
		v1Error(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	writeJSONBody(w, toV1Rule(rule))
}

func (s *Server) v1PatchRule(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Paused *bool `json:"paused"`
	}
	if !decode(w, r, &b, smallBody) {
		return
	}
	if b.Paused == nil {
		v1Fail(w, http.StatusBadRequest, "invalid", "send paused: true or false")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), backendWriteTimeout)
	defer cancel()
	if err := s.Backend.SetRulePaused(ctx, r.PathValue("id"), *b.Paused); err != nil {
		v1Error(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) v1DeleteRule(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), backendWriteTimeout)
	defer cancel()
	if err := s.Backend.DeleteRule(ctx, r.PathValue("id")); err != nil {
		v1Error(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) v1Alarms(w http.ResponseWriter, r *http.Request) {
	snap, _ := s.Backend.Snapshot()
	out := make([]v1Alarm, 0, len(snap.Alarms))
	for _, a := range snap.Alarms {
		v := v1Alarm{ID: a.ID, Box: a.Box, Type: a.Type, Message: a.Message, MAC: a.DeviceMAC, Device: a.Device, Domain: a.Domain}
		if !a.Time.IsZero() {
			t := a.Time
			v.Time = &t
		}
		out = append(out, v)
	}
	writeJSON(w, map[string]any{"alarms": out})
}

func (s *Server) v1DismissAlarm(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), backendWriteTimeout)
	defer cancel()
	ref := backends.AlarmRef{Box: r.URL.Query().Get("box"), ID: r.PathValue("id")}
	// A product with one box need not be told which: take it from the alarm.
	if ref.Box == "" {
		snap, _ := s.Backend.Snapshot()
		for _, a := range snap.Alarms {
			if a.ID == ref.ID {
				ref.Box = a.Box
				break
			}
		}
	}
	if err := s.Backend.DismissAlarm(ctx, ref); err != nil {
		v1Error(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) v1Flows(w http.ResponseWriter, r *http.Request) {
	q := backends.FlowQuery{DeviceMAC: r.URL.Query().Get("device"), Cursor: r.URL.Query().Get("cursor"), Limit: 100}
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 500 {
			v1Fail(w, http.StatusBadRequest, "invalid", "limit is a number from 1 to 500")
			return
		}
		q.Limit = n
	}
	ctx, cancel := context.WithTimeout(r.Context(), backendWriteTimeout)
	defer cancel()
	page, err := s.Backend.QueryFlows(ctx, q)
	if err != nil {
		v1Error(w, err)
		return
	}
	out := make([]v1Flow, 0, len(page.Flows))
	for _, f := range page.Flows {
		out = append(out, v1Flow{Time: f.Time, MAC: f.DeviceMAC, Device: f.Device, DeviceIP: f.DeviceIP, Domain: f.Domain,
			RemoteIP: f.RemoteIP, Protocol: f.Protocol, Outbound: f.Outbound, Blocked: f.Blocked, Download: f.Download,
			Upload: f.Upload, Country: f.Country, Category: f.Category, FlowCount: f.Count})
	}
	if len(out) > q.Limit {
		out = out[:q.Limit]
	}
	writeJSON(w, map[string]any{"flows": out, "next": page.Next})
}
