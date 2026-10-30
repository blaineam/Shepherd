// SPDX-License-Identifier: AGPL-3.0-or-later

package dnsengine

import (
	"errors"
	"fmt"
	"slices"
	"time"
)

// Schedule limits an allow or block rule to a window of days and times, in
// the server's own local time zone (there is no per-network time zone
// setting; see docs/POLICY.md's "Scheduled access"). StartMin and EndMin are
// minutes after local midnight; the window is [StartMin, EndMin) and must
// not cross midnight (StartMin < EndMin <= 1440). A block that must span
// midnight needs two Schedules, one on each side of it.
type Schedule struct {
	Days     []time.Weekday `json:"days"`
	StartMin int            `json:"start_min"`
	EndMin   int            `json:"end_min"`
}

// Validate checks that s is well formed: at least one day, no day repeated,
// and a same-day, non-empty window.
func (s Schedule) Validate() error {
	if len(s.Days) == 0 {
		return errors.New("schedule needs at least one day")
	}
	seen := make(map[time.Weekday]bool, len(s.Days))
	for _, d := range s.Days {
		if d < time.Sunday || d > time.Saturday {
			return fmt.Errorf("invalid weekday %d", d)
		}
		if seen[d] {
			return fmt.Errorf("weekday %s repeated", d)
		}
		seen[d] = true
	}
	if s.StartMin < 0 || s.EndMin > 24*60 || s.StartMin >= s.EndMin {
		return errors.New("start_min must be >= 0, end_min <= 1440, and start_min < end_min " +
			"(a schedule cannot cross midnight; use two schedules for an overnight window)")
	}
	return nil
}

// Active reports whether t falls inside the schedule's days and minute-of-day
// window, using t's own time zone (callers pass the server's local now).
func (s Schedule) Active(t time.Time) bool {
	if !slices.Contains(s.Days, t.Weekday()) {
		return false
	}
	min := t.Hour()*60 + t.Minute()
	return min >= s.StartMin && min < s.EndMin
}

// ruleSet is one scope's own allow or block domains (not those of less
// specific scopes), with the schedules of any that are not always active.
type ruleSet struct {
	domains   map[string]struct{}
	schedules map[string]Schedule // subset of domains; absent means always active
}

// newRuleSet builds a ruleSet from a scope's rule domains and their optional
// schedules, or nil when there are no domains.
func newRuleSet(domains []string, schedules map[string]Schedule) *ruleSet {
	if len(domains) == 0 {
		return nil
	}
	rs := &ruleSet{domains: make(map[string]struct{}, len(domains))}
	for _, d := range domains {
		rs.domains[normalize(d)] = struct{}{}
	}
	if len(schedules) > 0 {
		rs.schedules = make(map[string]Schedule, len(schedules))
		for d, sch := range schedules {
			rs.schedules[normalize(d)] = sch
		}
	}
	return rs
}

// activeRuleMatch reports whether name or one of its parent domains is in rs
// and currently active. It checks the most specific ancestor first, but an
// ancestor whose own schedule is not active right now is treated as if it
// were not configured at all: checking continues to less specific ancestors,
// which may still match unconditionally or on a different schedule.
//
// rs is nil for a scope this package never tracks per-domain rules for (the
// legacy, pre-scopes filter mode, which has no schedules at all): callers
// only reach activeRuleMatch after the coarse index already matched, so a
// nil rs defers to that and reports active, keeping legacy behavior exactly
// as it was before Schedule existed.
func activeRuleMatch(rs *ruleSet, name string, now time.Time) bool {
	if rs == nil {
		return true
	}
	active := false
	walk(name, func(d string) {
		if active {
			return
		}
		if _, ok := rs.domains[d]; !ok {
			return
		}
		if sch, has := rs.schedules[d]; has && !sch.Active(now) {
			return // configured here, but inert right now
		}
		active = true
	})
	return active
}
