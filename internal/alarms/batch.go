// SPDX-License-Identifier: AGPL-3.0-or-later

package alarms

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Errors from batch operations.
var (
	ErrEmptySelector = errors.New("alarms: selector selects nothing (give IDs, a filter, or All)")
	ErrNothingToMute = errors.New("alarms: the selected alarms have nothing to build a mute rule from")
	ErrBadMuteBy     = errors.New("alarms: unknown mute scope")
	ErrUndoNotFound  = errors.New("alarms: undo handle not found or already used")
	ErrUndoExpired   = errors.New("alarms: undo handle expired")
)

// Filter narrows a list or a batch. Empty fields match everything.
type Filter struct {
	Types      []string   `json:"types,omitempty"`
	Severities []Severity `json:"severities,omitempty"`
	// MinSeverity matches alarms at or above this severity.
	MinSeverity Severity `json:"min_severity,omitempty"`
	States      []State  `json:"states,omitempty"`
	DeviceID    string   `json:"device_id,omitempty"`
	GroupID     string   `json:"group_id,omitempty"`
	// Since and Until match alarms whose first-to-last sighting overlaps the
	// range.
	Since time.Time `json:"since,omitzero"`
	Until time.Time `json:"until,omitzero"`
	// Text is a case-insensitive substring over the title, body, key, source,
	// domain, device ID and evidence.
	Text string `json:"text,omitempty"`
	// IncludeChildren also matches storm-bundle members, which lists hide
	// while their bundle exists.
	IncludeChildren bool `json:"include_children,omitempty"`
	// IncludeArchived also matches archived alarms, which the default list
	// and Summary hide the same way IncludeChildren reveals bundle members.
	IncludeArchived bool `json:"include_archived,omitempty"`
}

func (f *Filter) matches(e *Engine, a *Alarm) bool {
	if a.Deleted {
		return false
	}
	if f == nil {
		return !e.hidden(a)
	}
	if !f.IncludeChildren && e.hidden(a) {
		return false
	}
	if a.Archived && !f.IncludeArchived {
		return false
	}
	if len(f.Types) > 0 && !anyOf(f.Types, func(s string) bool { return s == a.Type }) {
		return false
	}
	if len(f.Severities) > 0 {
		ok := false
		for _, s := range f.Severities {
			ok = ok || s == a.Severity
		}
		if !ok {
			return false
		}
	}
	if f.MinSeverity != "" && !a.Severity.AtLeast(f.MinSeverity) {
		return false
	}
	if len(f.States) > 0 {
		ok := false
		for _, s := range f.States {
			ok = ok || s == a.State
		}
		if !ok {
			return false
		}
	}
	if f.DeviceID != "" && a.DeviceID != f.DeviceID {
		return false
	}
	if f.GroupID != "" && !anyOf(a.GroupIDs, func(g string) bool { return g == f.GroupID }) {
		return false
	}
	if !f.Since.IsZero() && a.LastSeen.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && a.FirstSeen.After(f.Until) {
		return false
	}
	if f.Text != "" && !textMatch(a, strings.ToLower(f.Text)) {
		return false
	}
	return true
}

func textMatch(a *Alarm, needle string) bool {
	has := func(s string) bool { return strings.Contains(strings.ToLower(s), needle) }
	if has(a.Title) || has(a.Body) || has(a.Key) || has(a.Source) || has(a.Domain) || has(a.DeviceID) || has(a.Type) {
		return true
	}
	for _, ev := range a.Evidence {
		if has(ev.Label) || has(ev.Value) {
			return true
		}
	}
	return false
}

// SortField orders a list.
type SortField string

// Sort fields.
const (
	SortLastSeen  SortField = "last_seen" // default
	SortFirstSeen SortField = "first_seen"
	SortSeverity  SortField = "severity"
	SortCount     SortField = "count"
	SortTitle     SortField = "title"
)

// Query is a filtered, sorted, paged list request.
type Query struct {
	Filter
	Sort SortField // default SortLastSeen
	// Asc reverses the default newest/highest/largest-first order.
	Asc    bool
	Offset int
	Limit  int // default 50, at most 500
}

// Page is one page of a list.
type Page struct {
	Alarms []Alarm `json:"alarms"`
	Total  int     `json:"total"` // matches before paging
	Offset int     `json:"offset"`
	Limit  int     `json:"limit"`
}

// List returns one page of alarms.
func (e *Engine) List(q Query) Page {
	e.mu.Lock()
	var sweep []Change
	now := e.clock.Now()
	sweep = e.sweepLocked(now)
	var hits []*Alarm
	for _, a := range e.alarms {
		if q.Filter.matches(e, a) {
			hits = append(hits, a)
		}
	}
	less := func(x, y *Alarm) bool { return x.LastSeen.After(y.LastSeen) }
	switch q.Sort {
	case SortFirstSeen:
		less = func(x, y *Alarm) bool { return x.FirstSeen.After(y.FirstSeen) }
	case SortSeverity:
		less = func(x, y *Alarm) bool {
			if x.Severity.Rank() != y.Severity.Rank() {
				return x.Severity.Rank() > y.Severity.Rank()
			}
			return x.LastSeen.After(y.LastSeen)
		}
	case SortCount:
		less = func(x, y *Alarm) bool {
			if x.Count != y.Count {
				return x.Count > y.Count
			}
			return x.LastSeen.After(y.LastSeen)
		}
	case SortTitle:
		less = func(x, y *Alarm) bool { return strings.ToLower(x.Title) > strings.ToLower(y.Title) }
	}
	sort.Slice(hits, func(i, j int) bool {
		a, b := hits[i], hits[j]
		if less(a, b) != less(b, a) {
			return less(a, b) != q.Asc
		}
		return a.ID < b.ID
	})
	limit := q.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	off := q.Offset
	if off < 0 {
		off = 0
	}
	p := Page{Total: len(hits), Offset: off, Limit: limit, Alarms: []Alarm{}}
	for i := off; i < len(hits) && i < off+limit; i++ {
		p.Alarms = append(p.Alarms, hits[i].clone())
	}
	if len(sweep) > 0 {
		e.dirty = true
	}
	e.mu.Unlock()
	e.emit(sweep)
	return p
}

// Get returns one alarm (including storm-bundle members).
func (e *Engine) Get(id string) (Alarm, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if a := e.live(id); a != nil {
		return a.clone(), true
	}
	return Alarm{}, false
}

// Children returns the members of a storm bundle, oldest first.
func (e *Engine) Children(id string) []Alarm {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []Alarm
	for _, cid := range e.children[id] {
		if c := e.live(cid); c != nil {
			out = append(out, c.clone())
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FirstSeen.Before(out[j].FirstSeen) })
	return out
}

// Summary is the cheap overview for badges.
type Summary struct {
	// Total counts visible alarms (storm-bundle members are folded into
	// their bundle).
	Total int `json:"total"`
	// ByState counts every state.
	ByState map[State]int `json:"by_state"`
	// BySeverity counts the alarms in the new state, which is what an
	// unread badge shows.
	BySeverity map[Severity]int `json:"by_severity"`
	// Highest is the highest severity among new alarms ("" when none).
	Highest Severity `json:"highest,omitempty"`
	// Dropped is how many events Raise discarded under load.
	Dropped     uint64 `json:"dropped"`
	ActiveRules int    `json:"active_rules"`
}

// Summary counts alarms by state and severity.
func (e *Engine) Summary() Summary {
	e.mu.Lock()
	now := e.clock.Now()
	sweep := e.sweepLocked(now)
	s := Summary{ByState: map[State]int{}, BySeverity: map[Severity]int{}, Dropped: e.dropped.Load()}
	for _, st := range []State{StateNew, StateAcknowledged, StateMuted, StateResolved} {
		s.ByState[st] = 0
	}
	for _, sv := range Severities() {
		s.BySeverity[sv] = 0
	}
	for _, a := range e.alarms {
		if a.Deleted || e.hidden(a) || a.Archived {
			continue
		}
		s.Total++
		s.ByState[a.State]++
		if a.State == StateNew {
			s.BySeverity[a.Severity]++
			if a.Severity.Rank() > s.Highest.Rank() {
				s.Highest = a.Severity
			}
		}
	}
	for _, r := range e.rules {
		if r.Active(now) {
			s.ActiveRules++
		}
	}
	if len(sweep) > 0 {
		e.dirty = true
	}
	e.mu.Unlock()
	e.emit(sweep)
	return s
}

// ---- batch operations --------------------------------------------------------------

// Selector picks the alarms a batch operation applies to: explicit IDs, a
// filter, or both (an alarm must be in the IDs and match the filter). An empty
// selector is an error; set All to select everything visible.
type Selector struct {
	IDs    []string `json:"ids,omitempty"`
	Filter *Filter  `json:"filter,omitempty"`
	All    bool     `json:"all,omitempty"`
}

// BatchResult reports what a batch did.
type BatchResult struct {
	// Matched is how many alarms the selector chose; Changed is how many of
	// those the operation actually changed; Skipped are IDs that were not
	// found.
	Matched int `json:"matched"`
	Changed int `json:"changed"`
	Skipped int `json:"skipped"`
	// Rules lists mute rules the operation created.
	Rules []string `json:"rules,omitempty"`
	// Handle undoes a mute or resolve (or acknowledge) via Undo.
	Handle string `json:"handle,omitempty"`
}

func (e *Engine) selectLocked(sel Selector) ([]*Alarm, int, error) {
	if len(sel.IDs) == 0 && sel.Filter == nil && !sel.All {
		return nil, 0, ErrEmptySelector
	}
	var out []*Alarm
	missing := 0
	if len(sel.IDs) > 0 {
		seen := map[string]bool{}
		for _, id := range sel.IDs {
			if seen[id] {
				continue
			}
			seen[id] = true
			a := e.live(id)
			if a == nil {
				missing++
				continue
			}
			if sel.Filter != nil {
				c := *sel.Filter
				c.IncludeChildren = true
				if !c.matches(e, a) {
					continue
				}
			}
			out = append(out, a)
		}
	} else {
		for _, a := range e.sortedAlarms() {
			if sel.Filter.matches(e, a) {
				out = append(out, a)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, missing, nil
}

// undoEntry remembers enough to reverse one batch.
type undoEntry struct {
	kind    string
	created time.Time
	prev    map[string]stateSnap
	post    map[string]stateSnap
	rules   []string
}

type stateSnap struct {
	State      State
	AckedAt    time.Time
	ResolvedAt time.Time
	MutedBy    string
	MutedUntil time.Time
	Archived   bool
	ArchivedAt time.Time
}

func snapOf(a *Alarm) stateSnap {
	return stateSnap{a.State, a.AckedAt, a.ResolvedAt, a.MutedBy, a.MutedUntil, a.Archived, a.ArchivedAt}
}

func newUndo(kind string, now time.Time) *undoEntry {
	return &undoEntry{kind: kind, created: now, prev: map[string]stateSnap{}, post: map[string]stateSnap{}}
}

func (u *undoEntry) record(a *Alarm) {
	if _, ok := u.prev[a.ID]; !ok {
		u.prev[a.ID] = snapOf(a)
	}
}

const maxUndos = 50

func (e *Engine) keepUndo(u *undoEntry) string {
	id := "u" + e.newID()
	e.undos[id] = u
	e.undoOrder = append(e.undoOrder, id)
	for len(e.undoOrder) > maxUndos {
		delete(e.undos, e.undoOrder[0])
		e.undoOrder = e.undoOrder[1:]
	}
	return id
}

func (e *Engine) expireUndoLocked(now time.Time) {
	keep := e.undoOrder[:0]
	for _, id := range e.undoOrder {
		if u := e.undos[id]; u != nil && now.Sub(u.created) <= e.undoTTL {
			keep = append(keep, id)
		} else {
			delete(e.undos, id)
		}
	}
	e.undoOrder = keep
}

// emitBatch turns per-alarm changes into one bulk change when the batch is
// large, so a stream consumer is not flooded.
func emitBatch(changes []Change) []Change {
	const bulk = 100
	n := 0
	for _, c := range changes {
		if c.Kind == ChangeState || c.Kind == ChangeDeleted {
			n++
		}
	}
	if n <= bulk {
		return changes
	}
	var out []Change
	for _, c := range changes {
		if c.Kind != ChangeState && c.Kind != ChangeDeleted {
			out = append(out, c)
		}
	}
	return append(out, Change{Kind: ChangeBulk, Count: n})
}

// setState moves every alarm in sel to a state, skipping those already there.
func (e *Engine) setStateLocked(sel []*Alarm, to State, now time.Time, u *undoEntry) (changed int, changes []Change) {
	for _, a := range sel {
		did := false
		e.family(a, func(x *Alarm) {
			if x.State == to || x.State == StateResolved || (to == StateAcknowledged && x.State != StateNew) {
				return
			}
			u.record(x)
			x.State = to
			switch to {
			case StateResolved:
				x.ResolvedAt, x.MutedBy, x.MutedUntil = now, "", time.Time{}
			case StateAcknowledged:
				x.AckedAt = now
			}
			e.touch(x)
			u.post[x.ID] = snapOf(x)
			changes = append(changes, Change{Kind: ChangeState, Alarm: x.clone()})
			if x == a {
				did = true
			}
		})
		if did {
			changed++
		}
	}
	return changed, emitBatch(changes)
}

func (e *Engine) simpleBatch(sel Selector, to State, kind string) (BatchResult, error) {
	var res BatchResult
	err := e.mutate(func(now time.Time) ([]Change, error) {
		hits, missing, err := e.selectLocked(sel)
		if err != nil {
			return nil, err
		}
		u := newUndo(kind, now)
		changed, changes := e.setStateLocked(hits, to, now, u)
		res = BatchResult{Matched: len(hits), Changed: changed, Skipped: missing}
		if changed > 0 {
			res.Handle = e.keepUndo(u)
		}
		return changes, nil
	})
	return res, err
}

// Acknowledge marks the selected new alarms as seen. Undo reverses it.
func (e *Engine) Acknowledge(sel Selector) (BatchResult, error) {
	return e.simpleBatch(sel, StateAcknowledged, "acknowledge")
}

// Resolve closes the selected alarms: a resolved alarm can fire again, as a
// new alarm, the next time its key is raised. Undo reverses it.
func (e *Engine) Resolve(sel Selector) (BatchResult, error) {
	return e.simpleBatch(sel, StateResolved, "resolve")
}

// archiveSetLocked sets Archived on every alarm in sel (and, for a bundle,
// its live members), skipping those already at that value.
func (e *Engine) archiveSetLocked(sel []*Alarm, archived bool, now time.Time, u *undoEntry) (changed int, changes []Change) {
	for _, a := range sel {
		did := false
		e.family(a, func(x *Alarm) {
			if x.Archived == archived {
				return
			}
			u.record(x)
			x.Archived = archived
			if archived {
				x.ArchivedAt = now
			} else {
				x.ArchivedAt = time.Time{}
			}
			e.touch(x)
			u.post[x.ID] = snapOf(x)
			changes = append(changes, Change{Kind: ChangeState, Alarm: x.clone()})
			if x == a {
				did = true
			}
		})
		if did {
			changed++
		}
	}
	return changed, emitBatch(changes)
}

func (e *Engine) archiveBatch(sel Selector, archived bool, kind string) (BatchResult, error) {
	var res BatchResult
	err := e.mutate(func(now time.Time) ([]Change, error) {
		hits, missing, err := e.selectLocked(sel)
		if err != nil {
			return nil, err
		}
		u := newUndo(kind, now)
		changed, changes := e.archiveSetLocked(hits, archived, now, u)
		res = BatchResult{Matched: len(hits), Changed: changed, Skipped: missing}
		if changed > 0 {
			res.Handle = e.keepUndo(u)
		}
		return changes, nil
	})
	return res, err
}

// Archive hides the selected alarms from the default list and Summary
// without changing their State: it can be applied to an alarm in any state,
// including a New one nobody intends to act on. Undo reverses it.
func (e *Engine) Archive(sel Selector) (BatchResult, error) {
	return e.archiveBatch(sel, true, "archive")
}

// Unarchive returns the selected alarms to the default list. Undo reverses
// it.
func (e *Engine) Unarchive(sel Selector) (BatchResult, error) {
	return e.archiveBatch(sel, false, "unarchive")
}

// MuteBy says what a batch mute builds its rules from.
type MuteBy string

// Mute scopes.
const (
	// MuteByAlarm snoozes each selected alarm individually (no rule).
	MuteByAlarm MuteBy = "alarm"
	// MuteByKey makes one rule per distinct dedupe key (key prefix match).
	MuteByKey MuteBy = "key"
	// MuteByType makes one rule covering the selected alarms' types.
	MuteByType MuteBy = "type"
	// MuteByDevice makes one rule covering the selected alarms' devices.
	MuteByDevice MuteBy = "device"
	// MuteByTypeDevice makes one rule per distinct (type, device) pair.
	MuteByTypeDevice MuteBy = "type+device"
	// MuteByDomain makes one rule covering the selected alarms' domains.
	MuteByDomain MuteBy = "domain"
)

// MuteRequest describes a batch mute.
type MuteRequest struct {
	By       MuteBy
	Duration MuteSpec
	Reason   string
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// Mute mutes the selected alarms. Except for MuteByAlarm it creates mute rules
// from the selection (so the same thing stays quiet next time) and mutes every
// other new alarm those rules match. Muted alarms are still recorded. Undo
// removes the rules and restores the alarms.
func (e *Engine) Mute(sel Selector, req MuteRequest) (BatchResult, error) {
	var res BatchResult
	err := e.mutate(func(now time.Time) ([]Change, error) {
		hits, missing, err := e.selectLocked(sel)
		if err != nil {
			return nil, err
		}
		loc := e.locLocked()
		until, err := req.Duration.Resolve(now, loc, e.prefs.MorningHour)
		if err != nil {
			return nil, err
		}
		u := newUndo("mute", now)
		res = BatchResult{Matched: len(hits), Skipped: missing}
		var changes []Change
		if req.By == MuteByAlarm {
			for _, a := range hits {
				if a.State == StateResolved {
					continue
				}
				changes = append(changes, e.muteAlarm(a, snoozeMarker, until, now, u)...)
				res.Changed++
			}
			res.Handle = e.keepUndo(u)
			changes = emitBatch(changes)
			return changes, nil
		}
		var matches []RuleMatch
		var keys, types, devs, doms []string
		pairs := map[[2]string]bool{}
		for _, a := range hits {
			keys = append(keys, a.Key)
			types = append(types, a.Type)
			devs = append(devs, a.DeviceID)
			doms = append(doms, a.Domain)
			if a.DeviceID != "" {
				pairs[[2]string{a.Type, a.DeviceID}] = true
			}
		}
		switch req.By {
		case MuteByKey:
			for _, k := range uniq(keys) {
				matches = append(matches, RuleMatch{KeyPrefixes: []string{k}})
			}
		case MuteByType:
			if t := uniq(types); len(t) > 0 {
				matches = append(matches, RuleMatch{Types: t})
			}
		case MuteByDevice:
			if d := uniq(devs); len(d) > 0 {
				matches = append(matches, RuleMatch{DeviceIDs: d})
			}
		case MuteByTypeDevice:
			var ps [][2]string
			for p := range pairs {
				ps = append(ps, p)
			}
			sort.Slice(ps, func(i, j int) bool {
				if ps[i][0] != ps[j][0] {
					return ps[i][0] < ps[j][0]
				}
				return ps[i][1] < ps[j][1]
			})
			for _, p := range ps {
				matches = append(matches, RuleMatch{Types: []string{p[0]}, DeviceIDs: []string{p[1]}})
			}
		case MuteByDomain:
			if d := uniq(doms); len(d) > 0 {
				matches = append(matches, RuleMatch{Domains: d})
			}
		default:
			return nil, fmt.Errorf("%w: %q", ErrBadMuteBy, req.By)
		}
		if len(matches) == 0 {
			return nil, ErrNothingToMute
		}
		var rules []*Rule
		for _, m := range matches {
			r, err := e.ruleCreateLocked(RuleSpec{Match: m, Duration: req.Duration, Reason: req.Reason}, now)
			if err != nil {
				for _, c := range rules {
					delete(e.rules, c.ID)
				}
				return nil, err
			}
			rules = append(rules, r)
			u.rules = append(u.rules, r.ID)
			res.Rules = append(res.Rules, r.ID)
			changes = append(changes, Change{Kind: ChangeRule, RuleID: r.ID})
		}
		selected := map[string]bool{}
		for _, a := range hits {
			selected[a.ID] = true
		}
		for _, a := range e.sortedAlarms() {
			if a.Deleted || (a.State != StateNew && !(selected[a.ID] && a.State == StateAcknowledged)) {
				continue
			}
			for _, r := range rules {
				if r.Match.Matches(a) {
					changes = append(changes, e.muteAlarm(a, r.ID, time.Time{}, now, u)...)
					if selected[a.ID] {
						res.Changed++
					}
					break
				}
			}
		}
		res.Handle = e.keepUndo(u)
		return emitBatch(changes), nil
	})
	return res, err
}

// Snooze mutes one alarm for a while without creating a rule.
func (e *Engine) Snooze(id string, d MuteSpec) (BatchResult, error) {
	return e.Mute(Selector{IDs: []string{id}}, MuteRequest{By: MuteByAlarm, Duration: d})
}

// Delete removes the selected alarms (tombstones, so the deletion replicates;
// retention purges them later). Deleting a bundle deletes its members. It
// cannot be undone.
func (e *Engine) Delete(sel Selector) (BatchResult, error) {
	var res BatchResult
	err := e.mutate(func(now time.Time) ([]Change, error) {
		hits, missing, err := e.selectLocked(sel)
		if err != nil {
			return nil, err
		}
		res = BatchResult{Matched: len(hits), Skipped: missing}
		var changes []Change
		for _, a := range hits {
			e.family(a, func(x *Alarm) {
				if x.Deleted {
					return
				}
				x.Deleted = true
				e.touch(x)
				changes = append(changes, Change{Kind: ChangeDeleted, Alarm: x.clone()})
				if x == a {
					res.Changed++
				}
			})
		}
		e.reindex()
		return emitBatch(changes), nil
	})
	return res, err
}

// Undo reverses the batch behind a handle returned by Acknowledge, Resolve,
// Mute, Snooze or CreateRule. Alarms changed again since (by another batch or
// a new state) are left alone and counted as skipped. A handle works once and
// lives for Options.UndoTTL.
func (e *Engine) Undo(handle string) (BatchResult, error) {
	var res BatchResult
	err := e.mutate(func(now time.Time) ([]Change, error) {
		u := e.undos[handle]
		if u == nil {
			return nil, ErrUndoNotFound
		}
		delete(e.undos, handle)
		for i, id := range e.undoOrder {
			if id == handle {
				e.undoOrder = append(e.undoOrder[:i], e.undoOrder[i+1:]...)
				break
			}
		}
		if now.Sub(u.created) > e.undoTTL {
			return nil, ErrUndoExpired
		}
		var changes []Change
		for _, id := range u.rules {
			if r := e.rules[id]; r != nil && !r.Deleted {
				r.Deleted = true
				e.stamp(&r.Updated, &r.Node)
				changes = append(changes, Change{Kind: ChangeRule, RuleID: id})
			}
		}
		ids := make([]string, 0, len(u.prev))
		for id := range u.prev {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			res.Matched++
			a := e.live(id)
			if a == nil || snapOf(a) != u.post[id] {
				res.Skipped++
				continue
			}
			p := u.prev[id]
			a.State, a.AckedAt, a.ResolvedAt, a.MutedBy, a.MutedUntil = p.State, p.AckedAt, p.ResolvedAt, p.MutedBy, p.MutedUntil
			a.Archived, a.ArchivedAt = p.Archived, p.ArchivedAt
			e.touch(a)
			res.Changed++
			changes = append(changes, Change{Kind: ChangeState, Alarm: a.clone()})
		}
		return emitBatch(changes), nil
	})
	return res, err
}

// ---- retention --------------------------------------------------------------------------

// PruneResult counts what retention removed.
type PruneResult struct {
	Aged       int // dropped for age
	Overflow   int // dropped for the count cap
	Tombstones int // purged tombstones
	Rules      int // purged expired or removed rules
}

// Prune applies retention now (the worker also does so on every tick).
func (e *Engine) Prune() PruneResult {
	e.mu.Lock()
	defer e.mu.Unlock()
	r := e.pruneLocked(e.clock.Now())
	if r != (PruneResult{}) {
		e.dirty = true
	}
	return r
}

func (e *Engine) pruneLocked(now time.Time) PruneResult {
	var r PruneResult
	rm := func(id string) {
		delete(e.alarms, id)
	}
	tomb := now.Add(-e.retention.TombstoneAge).UnixMilli()
	cutoff := now.Add(-e.retention.MaxAge)
	for id, a := range e.alarms {
		switch {
		case a.Deleted && a.Updated.Wall < tomb:
			rm(id)
			r.Tombstones++
		case !a.Deleted && a.State != StateNew && a.LastSeen.Before(cutoff):
			rm(id)
			r.Aged++
		case !a.Deleted && a.State == StateNew && a.LastSeen.Before(now.Add(-2*e.retention.MaxAge)):
			rm(id)
			r.Aged++
		}
	}
	if live := e.liveCount(); live > e.retention.MaxCount {
		order := map[State]int{StateResolved: 0, StateAcknowledged: 1, StateMuted: 2, StateNew: 3}
		var all []*Alarm
		for _, a := range e.alarms {
			if !a.Deleted {
				all = append(all, a)
			}
		}
		sort.Slice(all, func(i, j int) bool {
			if order[all[i].State] != order[all[j].State] {
				return order[all[i].State] < order[all[j].State]
			}
			if !all[i].LastSeen.Equal(all[j].LastSeen) {
				return all[i].LastSeen.Before(all[j].LastSeen)
			}
			return all[i].ID < all[j].ID
		})
		for _, a := range all[:live-e.retention.MaxCount] {
			rm(a.ID)
			r.Overflow++
		}
	}
	for id, ru := range e.rules {
		gone := (ru.Deleted && ru.Updated.Wall < tomb) || (!ru.ExpiresAt.IsZero() && ru.ExpiresAt.Before(cutoff))
		if gone {
			delete(e.rules, id)
			r.Rules++
		}
	}
	if r.Aged+r.Overflow+r.Tombstones > 0 {
		e.reindex()
	}
	return r
}

func (e *Engine) liveCount() int {
	n := 0
	for _, a := range e.alarms {
		if !a.Deleted {
			n++
		}
	}
	return n
}
