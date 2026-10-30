// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"shepherd/internal/alarms"
)

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseBool(s string) bool { return s == "1" || s == "true" }

// parseAlarmQuery turns the list endpoint's query string into an alarms.Query.
func parseAlarmQuery(r *http.Request) (alarms.Query, error) {
	var q alarms.Query
	offset, ok1 := intParam(r, "offset", 0)
	limit, ok2 := intParam(r, "limit", 50)
	if !ok1 || !ok2 {
		return q, errors.New("offset and limit must be non-negative integers")
	}
	q.Offset, q.Limit = offset, limit
	v := r.URL.Query()
	switch s := v.Get("sort"); s {
	case "", "last_seen":
		q.Sort = alarms.SortLastSeen
	case "first_seen":
		q.Sort = alarms.SortFirstSeen
	case "severity":
		q.Sort = alarms.SortSeverity
	case "count":
		q.Sort = alarms.SortCount
	case "title":
		q.Sort = alarms.SortTitle
	default:
		return q, fmt.Errorf("unknown sort %q", s)
	}
	q.Asc = parseBool(v.Get("asc"))
	q.Types = splitCSV(v.Get("types"))
	for _, s := range splitCSV(v.Get("severities")) {
		sev, ok := alarms.ParseSeverity(s)
		if !ok {
			return q, fmt.Errorf("unknown severity %q", s)
		}
		q.Severities = append(q.Severities, sev)
	}
	if s := v.Get("min_severity"); s != "" {
		sev, ok := alarms.ParseSeverity(s)
		if !ok {
			return q, fmt.Errorf("unknown min_severity %q", s)
		}
		q.MinSeverity = sev
	}
	for _, s := range splitCSV(v.Get("states")) {
		st := alarms.State(strings.ToLower(strings.TrimSpace(s)))
		if !st.Valid() {
			return q, fmt.Errorf("unknown state %q", s)
		}
		q.States = append(q.States, st)
	}
	q.DeviceID = v.Get("device_id")
	q.GroupID = v.Get("group_id")
	q.Text = v.Get("text")
	q.IncludeChildren = parseBool(v.Get("include_children"))
	if s := v.Get("since"); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return q, fmt.Errorf("since must be RFC3339, got %q", s)
		}
		q.Since = t
	}
	if s := v.Get("until"); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return q, fmt.Errorf("until must be RFC3339, got %q", s)
		}
		q.Until = t
	}
	return q, nil
}

func (s *Server) listAlarms(w http.ResponseWriter, r *http.Request) {
	q, err := parseAlarmQuery(r)
	if err != nil {
		bad(w, err.Error())
		return
	}
	writeJSON(w, s.Alarms.List(q))
}

func (s *Server) getAlarm(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a, ok := s.Alarms.Get(id)
	if !ok {
		notFound(w, "unknown alarm")
		return
	}
	out := map[string]any{"alarm": a}
	if a.Bundle {
		out["children"] = orEmptyAlarms(s.Alarms.Children(id))
	}
	writeJSON(w, out)
}

func orEmptyAlarms(a []alarms.Alarm) []alarms.Alarm {
	if a == nil {
		return []alarms.Alarm{}
	}
	return a
}

// alarmError maps an engine error to the response it deserves. Anything it
// does not recognize is treated as a bad request: every error these handlers
// can produce comes from validating the caller's input.
func alarmError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, alarms.ErrNotFound), errors.Is(err, alarms.ErrRuleNotFound), errors.Is(err, alarms.ErrUndoNotFound):
		notFound(w, err.Error())
	case errors.Is(err, alarms.ErrUndoExpired):
		conflict(w, err.Error())
	default:
		bad(w, err.Error())
	}
}

func (s *Server) patchAlarm(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var b struct {
		State string `json:"state"`
	}
	if !decode(w, r, &b, smallBody) {
		return
	}
	if _, ok := s.Alarms.Get(id); !ok {
		notFound(w, "unknown alarm")
		return
	}
	var err error
	switch b.State {
	case "acknowledged":
		_, err = s.Alarms.Acknowledge(alarms.Selector{IDs: []string{id}})
	case "resolved":
		_, err = s.Alarms.Resolve(alarms.Selector{IDs: []string{id}})
	default:
		bad(w, `state must be "acknowledged" or "resolved"`)
		return
	}
	if err != nil {
		alarmError(w, err)
		return
	}
	s.getAlarm(w, r)
}

func (s *Server) deleteAlarm(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.Alarms.Get(id); !ok {
		notFound(w, "unknown alarm")
		return
	}
	if _, err := s.Alarms.Delete(alarms.Selector{IDs: []string{id}}); err != nil {
		alarmError(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) muteAlarm(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.Alarms.Get(id); !ok {
		notFound(w, "unknown alarm")
		return
	}
	var spec alarms.MuteSpec
	if !decode(w, r, &spec, smallBody) {
		return
	}
	if _, err := s.Alarms.Snooze(id, spec); err != nil {
		alarmError(w, err)
		return
	}
	s.getAlarm(w, r)
}

// muteBody is alarms.MuteRequest's JSON shape: MuteRequest itself carries no
// json tags, so a bulk mute decodes into this instead.
type muteBody struct {
	By       alarms.MuteBy   `json:"by"`
	Duration alarms.MuteSpec `json:"duration"`
	Reason   string          `json:"reason"`
}

func (s *Server) alarmsBulk(w http.ResponseWriter, r *http.Request) {
	var b struct {
		alarms.Selector
		Op   string    `json:"op"`
		Mute *muteBody `json:"mute,omitempty"`
	}
	if !decode(w, r, &b, smallBody) {
		return
	}
	var res alarms.BatchResult
	var err error
	switch b.Op {
	case "acknowledge":
		res, err = s.Alarms.Acknowledge(b.Selector)
	case "resolve":
		res, err = s.Alarms.Resolve(b.Selector)
	case "delete":
		res, err = s.Alarms.Delete(b.Selector)
	case "mute":
		if b.Mute == nil {
			bad(w, `op "mute" requires "mute"`)
			return
		}
		res, err = s.Alarms.Mute(b.Selector, alarms.MuteRequest{By: b.Mute.By, Duration: b.Mute.Duration, Reason: b.Mute.Reason})
	default:
		bad(w, `op must be "acknowledge", "resolve", "delete" or "mute"`)
		return
	}
	if err != nil {
		alarmError(w, err)
		return
	}
	writeJSON(w, res)
}

func (s *Server) undoAlarms(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Handle string `json:"handle"`
	}
	if !decode(w, r, &b, smallBody) {
		return
	}
	res, err := s.Alarms.Undo(b.Handle)
	if err != nil {
		alarmError(w, err)
		return
	}
	writeJSON(w, res)
}

func (s *Server) alarmsSummary(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.Alarms.Summary())
}

func (s *Server) alarmTypes(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"types": s.Alarms.Types()})
}

func (s *Server) listAlarmRules(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"rules": orEmptyRules(s.Alarms.ListRules(parseBool(r.URL.Query().Get("all"))))})
}

func orEmptyRules(r []alarms.Rule) []alarms.Rule {
	if r == nil {
		return []alarms.Rule{}
	}
	return r
}

func (s *Server) createAlarmRule(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Name     string           `json:"name"`
		Match    alarms.RuleMatch `json:"match"`
		Duration alarms.MuteSpec  `json:"duration"`
		Reason   string           `json:"reason"`
	}
	if !decode(w, r, &b, smallBody) {
		return
	}
	rule, res, err := s.Alarms.CreateRule(alarms.RuleSpec{Name: b.Name, Match: b.Match, Duration: b.Duration, Reason: b.Reason})
	if err != nil {
		alarmError(w, err)
		return
	}
	writeJSON(w, map[string]any{"rule": rule, "result": res})
}

func (s *Server) deleteAlarmRule(w http.ResponseWriter, r *http.Request) {
	res, err := s.Alarms.RemoveRule(r.PathValue("id"))
	if err != nil {
		alarmError(w, err)
		return
	}
	writeJSON(w, res)
}
