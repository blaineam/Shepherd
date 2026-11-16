// SPDX-License-Identifier: AGPL-3.0-or-later

package hub

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"shepherd/internal/backends"
)

// Schedules give a rule a time window. Neither product lets Shepherd
// create its native time-limit rules over the API (Firewalla's POST
// /v2/rules takes block and allow only), but both let it pause and resume a
// rule. So Shepherd holds the window itself and does exactly that: the rule
// enforces inside the window and is paused outside it. "Block games on
// school nights, 21:00 to 07:00" is a block rule plus a schedule.
//
// A scheduled rule follows its schedule. If someone resumes it by hand
// outside the window, the next tick pauses it again; remove the schedule to
// take the rule back.

const (
	maxSchedules = 50
	// scheduleEvery is how often schedules are applied. A minute is the
	// granularity of the windows, so this keeps a rule within half a
	// minute of its window.
	scheduleEvery = 30 * time.Second
	// retryAfter is how long to leave a rule alone after a change failed,
	// so a refused write is not repeated and audited every tick.
	retryAfter = 5 * time.Minute
)

// Schedule is when a rule enforces.
type Schedule struct {
	ID     string `json:"id"`
	RuleID string `json:"rule_id"`
	// Days the window starts on, 0 (Sunday) to 6.
	Days []int `json:"days"`
	// Start and End are "15:04" in TZ. An End at or before Start means the
	// window runs past midnight into the next day.
	Start string `json:"start"`
	End   string `json:"end"`
	// TZ is an IANA zone name. The owner's browser supplies it, because a
	// container's own clock is usually UTC.
	TZ string `json:"tz"`
}

func parseClock(s string) (int, bool) {
	t, err := time.Parse("15:04", s)
	if err != nil {
		return 0, false
	}
	return t.Hour()*60 + t.Minute(), true
}

// Validate refuses a schedule that could not be applied, naming why.
func (s Schedule) Validate() error {
	if strings.TrimSpace(s.RuleID) == "" {
		return fmt.Errorf("%w: a schedule needs a rule", backends.ErrInvalid)
	}
	if len(s.Days) == 0 {
		return fmt.Errorf("%w: choose at least one day", backends.ErrInvalid)
	}
	seen := map[int]bool{}
	for _, d := range s.Days {
		if d < 0 || d > 6 || seen[d] {
			return fmt.Errorf("%w: days are 0 (Sunday) to 6, each once", backends.ErrInvalid)
		}
		seen[d] = true
	}
	a, aok := parseClock(s.Start)
	b, bok := parseClock(s.End)
	if !aok || !bok {
		return fmt.Errorf("%w: times are written like 21:00", backends.ErrInvalid)
	}
	if a == b {
		return fmt.Errorf("%w: the start and end must differ", backends.ErrInvalid)
	}
	if _, err := time.LoadLocation(s.TZ); err != nil || s.TZ == "" {
		return fmt.Errorf("%w: unknown time zone %q", backends.ErrInvalid, s.TZ)
	}
	return nil
}

// Active reports whether t falls inside the window.
func (s Schedule) Active(t time.Time) bool {
	loc, err := time.LoadLocation(s.TZ)
	if err != nil {
		return false
	}
	t = t.In(loc)
	start, _ := parseClock(s.Start)
	end, _ := parseClock(s.End)
	now := t.Hour()*60 + t.Minute()
	has := func(d time.Weekday) bool {
		for _, x := range s.Days {
			if x == int(d) {
				return true
			}
		}
		return false
	}
	if start < end { // within one day
		return has(t.Weekday()) && now >= start && now < end
	}
	// Past midnight: the evening part belongs to the starting day, the
	// morning part to the day before it.
	if now >= start {
		return has(t.Weekday())
	}
	if now < end {
		return has((t.Weekday() + 6) % 7)
	}
	return false
}

func newID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (h *Hub) loadSchedules() {
	if h.o.SchedulePath == "" {
		return
	}
	b, err := os.ReadFile(h.o.SchedulePath)
	if err != nil {
		return
	}
	var list []Schedule
	if json.Unmarshal(b, &list) == nil {
		kept := list[:0]
		for _, s := range list {
			if s.Validate() == nil {
				kept = append(kept, s)
			}
		}
		h.schedules = kept
	}
}

// saveSchedules must be called with h.mu held.
func (h *Hub) saveSchedulesLocked() error {
	if h.o.SchedulePath == "" {
		return nil
	}
	b, _ := json.Marshal(h.schedules)
	tmp := h.o.SchedulePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, h.o.SchedulePath)
}

// Schedules returns the schedules, oldest first.
func (h *Hub) Schedules() []Schedule {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := append([]Schedule(nil), h.schedules...)
	return out
}

// AddSchedule validates and keeps a schedule, then applies it at once. It
// is refused for a read-only connection, because a schedule would change
// rules later, and for a rule that is not on the backend.
func (h *Hub) AddSchedule(ctx context.Context, s Schedule) (Schedule, error) {
	if _, ok := h.o.Backend.(backends.RuleManager); !ok {
		return Schedule{}, errUnsupported
	}
	if h.o.Backend.ReadOnly() {
		return Schedule{}, backends.ErrReadOnly
	}
	s.ID, s.RuleID = newID(), strings.TrimSpace(s.RuleID)
	sort.Ints(s.Days)
	if err := s.Validate(); err != nil {
		return Schedule{}, err
	}
	h.mu.Lock()
	known := false
	for _, r := range h.rules {
		if r.ID == s.RuleID {
			known = true
		}
	}
	if !known {
		h.mu.Unlock()
		return Schedule{}, fmt.Errorf("%w: that rule is not on the %s", backends.ErrInvalid, h.o.Backend.Name())
	}
	for _, x := range h.schedules {
		if x.RuleID == s.RuleID {
			h.mu.Unlock()
			return Schedule{}, fmt.Errorf("%w: that rule already has a schedule; remove it first", backends.ErrInvalid)
		}
	}
	if len(h.schedules) >= maxSchedules {
		h.mu.Unlock()
		return Schedule{}, fmt.Errorf("%w: at most %d schedules", backends.ErrInvalid, maxSchedules)
	}
	h.schedules = append(h.schedules, s)
	err := h.saveSchedulesLocked()
	h.mu.Unlock()
	h.record("add schedule", s.RuleID+" "+s.Start+"-"+s.End, err)
	if err != nil {
		return s, err
	}
	h.ApplySchedules(ctx)
	return s, nil
}

// DeleteSchedule removes a schedule. The rule keeps whatever state it is
// in; the owner takes it from there.
func (h *Hub) DeleteSchedule(id string) error {
	h.mu.Lock()
	idx := -1
	for i, s := range h.schedules {
		if s.ID == id {
			idx = i
		}
	}
	if idx < 0 {
		h.mu.Unlock()
		return backends.ErrNotFound
	}
	rule := h.schedules[idx].RuleID
	h.schedules = append(h.schedules[:idx:idx], h.schedules[idx+1:]...)
	err := h.saveSchedulesLocked()
	h.mu.Unlock()
	h.record("remove schedule", rule, err)
	return err
}

// ApplySchedules brings each scheduled rule in line with its window. It
// only changes a rule that disagrees, and leaves a rule alone for a while
// after a change failed.
func (h *Hub) ApplySchedules(ctx context.Context) {
	rm, ok := h.o.Backend.(backends.RuleManager)
	if !ok || h.o.Backend.ReadOnly() {
		return
	}
	now := h.o.Now()
	h.mu.Lock()
	type job struct {
		ruleID string
		pause  bool
	}
	var jobs []job
	for _, s := range h.schedules {
		var rule *backends.Rule
		for i := range h.rules {
			if h.rules[i].ID == s.RuleID {
				rule = &h.rules[i]
			}
		}
		if rule == nil {
			continue
		}
		wantPaused := !s.Active(now)
		if rule.Paused == wantPaused {
			delete(h.schedRetry, s.RuleID)
			continue
		}
		if t, tried := h.schedRetry[s.RuleID]; tried && now.Sub(t) < retryAfter {
			continue
		}
		h.schedRetry[s.RuleID] = now
		jobs = append(jobs, job{s.RuleID, wantPaused})
	}
	h.mu.Unlock()
	for _, j := range jobs {
		err := rm.SetRulePaused(ctx, j.ruleID, j.pause)
		verb := "schedule resumes rule"
		if j.pause {
			verb = "schedule pauses rule"
		}
		h.record(verb, j.ruleID, err)
		if err == nil {
			h.mu.Lock()
			for i := range h.rules {
				if h.rules[i].ID == j.ruleID {
					h.rules[i].Paused = j.pause
				}
			}
			delete(h.schedRetry, j.ruleID)
			h.mu.Unlock()
		}
	}
}
