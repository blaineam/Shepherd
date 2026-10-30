// SPDX-License-Identifier: AGPL-3.0-or-later

package alarms

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// snoozeMarker is the MutedBy value of a single-alarm snooze.
const snoozeMarker = "snooze"

// RuleMatch selects alarms. Within one field the entries are alternatives;
// every non-empty field must match. At least one field must be set.
type RuleMatch struct {
	DeviceIDs []string `json:"device_ids,omitempty"`
	GroupIDs  []string `json:"group_ids,omitempty"` // matches if the alarm is in any of them
	Types     []string `json:"types,omitempty"`
	// Domains match the alarm's domain exactly or as a parent: "example.com"
	// matches "tracker.example.com".
	Domains []string `json:"domains,omitempty"`
	// KeyPrefixes match the start of the alarm's dedupe key.
	KeyPrefixes []string `json:"key_prefixes,omitempty"`
}

func (m RuleMatch) empty() bool {
	return len(m.DeviceIDs)+len(m.GroupIDs)+len(m.Types)+len(m.Domains)+len(m.KeyPrefixes) == 0
}

func anyOf(list []string, f func(string) bool) bool {
	for _, s := range list {
		if f(s) {
			return true
		}
	}
	return false
}

// Matches reports whether the alarm satisfies every non-empty field.
func (m RuleMatch) Matches(a *Alarm) bool {
	if m.empty() {
		return false
	}
	if len(m.DeviceIDs) > 0 && !anyOf(m.DeviceIDs, func(s string) bool { return a.DeviceID != "" && s == a.DeviceID }) {
		return false
	}
	if len(m.GroupIDs) > 0 && !anyOf(m.GroupIDs, func(g string) bool { return anyOf(a.GroupIDs, func(x string) bool { return x == g }) }) {
		return false
	}
	if len(m.Types) > 0 && !anyOf(m.Types, func(s string) bool { return s == a.Type }) {
		return false
	}
	if len(m.Domains) > 0 && !anyOf(m.Domains, func(d string) bool {
		return a.Domain != "" && (a.Domain == d || strings.HasSuffix(a.Domain, "."+d))
	}) {
		return false
	}
	if len(m.KeyPrefixes) > 0 && !anyOf(m.KeyPrefixes, func(p string) bool { return strings.HasPrefix(a.Key, p) }) {
		return false
	}
	return true
}

// Rule is a mute rule. Alarms matching an active rule are recorded as muted
// and never notified.
type Rule struct {
	ID        string    `json:"id"`
	Name      string    `json:"name,omitempty"`
	Match     RuleMatch `json:"match"`
	Reason    string    `json:"reason,omitempty"`
	Created   time.Time `json:"created"`
	ExpiresAt time.Time `json:"expires_at,omitzero"` // zero means forever

	Updated HLC    `json:"updated"`
	Node    string `json:"node"`
	Deleted bool   `json:"deleted,omitempty"`
}

func (r *Rule) clone() Rule {
	c := *r
	m := &c.Match
	m.DeviceIDs = append([]string(nil), r.Match.DeviceIDs...)
	m.GroupIDs = append([]string(nil), r.Match.GroupIDs...)
	m.Types = append([]string(nil), r.Match.Types...)
	m.Domains = append([]string(nil), r.Match.Domains...)
	m.KeyPrefixes = append([]string(nil), r.Match.KeyPrefixes...)
	return c
}

// Active reports whether the rule is in force at now.
func (r *Rule) Active(now time.Time) bool {
	return !r.Deleted && (r.ExpiresAt.IsZero() || now.Before(r.ExpiresAt))
}

// RuleSpec describes a rule to create.
type RuleSpec struct {
	Name     string
	Match    RuleMatch
	Duration MuteSpec
	Reason   string
}

// Errors from rule operations.
var (
	ErrInvalidRule  = errors.New("alarms: invalid mute rule")
	ErrRuleNotFound = errors.New("alarms: mute rule not found")
)

const maxMatchEntries = 50

func normList(in []string, lower bool) ([]string, error) {
	if len(in) > maxMatchEntries {
		return nil, fmt.Errorf("%w: at most %d entries per field", ErrInvalidRule, maxMatchEntries)
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if lower {
			s = strings.ToLower(strings.TrimSuffix(s, "."))
		}
		if s == "" || len(s) > 200 {
			return nil, fmt.Errorf("%w: empty or oversized entry", ErrInvalidRule)
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out, nil
}

func normalizeMatch(m RuleMatch) (RuleMatch, error) {
	var err error
	var out RuleMatch
	if out.DeviceIDs, err = normList(m.DeviceIDs, false); err != nil {
		return out, err
	}
	if out.GroupIDs, err = normList(m.GroupIDs, false); err != nil {
		return out, err
	}
	if out.Types, err = normList(m.Types, false); err != nil {
		return out, err
	}
	if out.Domains, err = normList(m.Domains, true); err != nil {
		return out, err
	}
	if out.KeyPrefixes, err = normList(m.KeyPrefixes, false); err != nil {
		return out, err
	}
	if out.empty() {
		return out, fmt.Errorf("%w: a rule needs at least one criterion (use quiet hours to silence everything)", ErrInvalidRule)
	}
	return out, nil
}

// ruleCreateLocked builds, stores and applies a rule. Callers hold e.mu.
func (e *Engine) ruleCreateLocked(spec RuleSpec, now time.Time) (*Rule, error) {
	m, err := normalizeMatch(spec.Match)
	if err != nil {
		return nil, err
	}
	loc := e.locLocked()
	until, err := spec.Duration.Resolve(now, loc, e.prefs.MorningHour)
	if err != nil {
		return nil, err
	}
	r := &Rule{ID: "r" + e.newID(), Name: clip(spec.Name, 80), Match: m, Reason: clip(spec.Reason, 200), Created: now, ExpiresAt: until}
	e.stamp(&r.Updated, &r.Node)
	e.rules[r.ID] = r
	return r, nil
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		s = strings.ToValidUTF8(s[:n], "")
	}
	return s
}

// matchRule returns the active rule that mutes a, preferring the oldest.
func (e *Engine) matchRule(a *Alarm, now time.Time) *Rule {
	var best *Rule
	for _, r := range e.rules {
		if !r.Active(now) || !r.Match.Matches(a) {
			continue
		}
		if best == nil || r.Created.Before(best.Created) || (r.Created.Equal(best.Created) && r.ID < best.ID) {
			best = r
		}
	}
	return best
}

// CreateRule creates a mute rule and mutes the matching alarms that are still
// new. The BatchResult carries an undo handle that removes the rule and
// restores those alarms.
func (e *Engine) CreateRule(spec RuleSpec) (Rule, BatchResult, error) {
	var rule Rule
	var res BatchResult
	err := e.mutate(func(now time.Time) ([]Change, error) {
		r, err := e.ruleCreateLocked(spec, now)
		if err != nil {
			return nil, err
		}
		u := newUndo("mute", now)
		u.rules = []string{r.ID}
		changes := []Change{{Kind: ChangeRule, RuleID: r.ID}}
		for _, a := range e.sortedAlarms() {
			if a.Deleted || a.State != StateNew || !r.Match.Matches(a) {
				continue
			}
			res.Matched++
			changes = append(changes, e.muteAlarm(a, r.ID, time.Time{}, now, u)...)
			res.Changed++
		}
		res.Rules = []string{r.ID}
		res.Handle = e.keepUndo(u)
		rule = r.clone()
		return changes, nil
	})
	return rule, res, err
}

// ListRules returns the mute rules, oldest first. Expired and removed rules
// are left out unless includeInactive is set.
func (e *Engine) ListRules(includeInactive bool) []Rule {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.clock.Now()
	var out []Rule
	for _, r := range e.rules {
		if includeInactive || r.Active(now) {
			out = append(out, r.clone())
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Created.Equal(out[j].Created) {
			return out[i].Created.Before(out[j].Created)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// RemoveRule ends a mute rule (a tombstone, so the removal replicates) and
// returns the alarms it muted to the new state.
func (e *Engine) RemoveRule(id string) (BatchResult, error) {
	var res BatchResult
	err := e.mutate(func(now time.Time) ([]Change, error) {
		r := e.rules[id]
		if r == nil || r.Deleted {
			return nil, ErrRuleNotFound
		}
		r.Deleted = true
		e.stamp(&r.Updated, &r.Node)
		changes := []Change{{Kind: ChangeRule, RuleID: id}}
		for _, a := range e.sortedAlarms() {
			if !a.Deleted && a.State == StateMuted && a.MutedBy == id {
				res.Matched++
				res.Changed++
				changes = append(changes, e.unmute(a)...)
			}
		}
		return changes, nil
	})
	return res, err
}
