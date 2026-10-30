// SPDX-License-Identifier: AGPL-3.0-or-later

package alarms

import (
	"strings"
	"time"
)

// Severity ranks an alarm. The order is info < low < medium < high < critical.
type Severity string

// Severities.
const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Severities lists every severity from lowest to highest.
func Severities() []Severity {
	return []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
}

// Rank is 0 (info) to 4 (critical), or -1 for an unknown value.
func (s Severity) Rank() int {
	for i, v := range Severities() {
		if v == s {
			return i
		}
	}
	return -1
}

// Valid reports whether s is one of the five severities.
func (s Severity) Valid() bool { return s.Rank() >= 0 }

// AtLeast reports whether s ranks at or above o. Unknown values are never at
// least anything.
func (s Severity) AtLeast(o Severity) bool { return s.Valid() && o.Valid() && s.Rank() >= o.Rank() }

// ParseSeverity parses a severity name, ignoring case and space.
func ParseSeverity(v string) (Severity, bool) {
	s := Severity(strings.ToLower(strings.TrimSpace(v)))
	return s, s.Valid()
}

// State is where an alarm is in its life.
type State string

// States.
const (
	StateNew          State = "new"
	StateAcknowledged State = "acknowledged"
	StateMuted        State = "muted"
	StateResolved     State = "resolved"
)

// Valid reports whether s is a known state.
func (s State) Valid() bool {
	switch s {
	case StateNew, StateAcknowledged, StateMuted, StateResolved:
		return true
	}
	return false
}

// HLC is a hybrid logical clock stamp, wire-compatible with the one in
// internal/devices: wall-clock milliseconds plus a counter that orders events
// within the same millisecond.
type HLC struct {
	Wall    int64  `json:"w"`
	Counter uint32 `json:"c"`
}

// Compare orders two stamps (-1, 0, +1).
func (a HLC) Compare(b HLC) int {
	switch {
	case a.Wall < b.Wall:
		return -1
	case a.Wall > b.Wall:
		return 1
	case a.Counter < b.Counter:
		return -1
	case a.Counter > b.Counter:
		return 1
	}
	return 0
}

// Evidence is one labeled fact attached to an alarm ("Client": "192.0.2.10").
type Evidence struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// Alarm is one recorded alarm. Alarms are values: the engine returns copies,
// so callers may keep or modify them freely.
type Alarm struct {
	ID       string   `json:"id"`
	Type     string   `json:"type"`
	Severity Severity `json:"severity"`
	// RawSeverity is the severity before learning mode recorded the alarm as
	// info; empty when it was not downgraded.
	RawSeverity Severity `json:"raw_severity,omitempty"`
	Title       string   `json:"title"`
	Body        string   `json:"body,omitempty"`
	// Key is the dedupe key: the same key within the dedupe window folds
	// into one alarm.
	Key         string     `json:"key"`
	Source      string     `json:"source,omitempty"` // the feature that raised it
	DeviceID    string     `json:"device_id,omitempty"`
	DeviceClass string     `json:"device_class,omitempty"` // e.g. "camera", for per-class switches
	GroupIDs    []string   `json:"group_ids,omitempty"`
	Domain      string     `json:"domain,omitempty"`
	Evidence    []Evidence `json:"evidence,omitempty"`
	// URL is the portal route to open, for example "/alarms/a1b2".
	URL string `json:"url"`

	State      State     `json:"state"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Count      int       `json:"count"`
	AckedAt    time.Time `json:"acked_at,omitzero"`
	ResolvedAt time.Time `json:"resolved_at,omitzero"`
	// MutedBy is the mute rule ID, or "snooze" for a single-alarm snooze.
	MutedBy string `json:"muted_by,omitempty"`
	// MutedUntil is when a snooze ends (zero for a forever snooze or a rule).
	MutedUntil time.Time `json:"muted_until,omitzero"`
	// Learning marks an alarm recorded as info during learning mode.
	Learning bool `json:"learning,omitempty"`
	// Bundle marks a storm-control bundle; its members carry ParentID.
	Bundle   bool   `json:"bundle,omitempty"`
	ParentID string `json:"parent_id,omitempty"`
	// Notified is when the engine last decided to notify for this alarm.
	Notified time.Time `json:"notified,omitzero"`
	// Archived hides the alarm from the default list and summary counts
	// without changing its State: unlike Resolve ("this is fixed"), Archive
	// says "I don't want to see this," so a New alarm can be archived without
	// claiming the underlying problem went away. ArchivedAt is when it was
	// archived (zero when it is not). An escalated repeat (see
	// Engine.foldLocked) clears it, since a bigger version of the same
	// problem deserves to resurface.
	Archived   bool      `json:"archived,omitempty"`
	ArchivedAt time.Time `json:"archived_at,omitzero"`

	// Sync-ready fields, as in the device registry.
	Updated HLC    `json:"updated"`
	Node    string `json:"node"`
	Deleted bool   `json:"deleted,omitempty"`
}

func (a *Alarm) clone() Alarm {
	c := *a
	c.GroupIDs = append([]string(nil), a.GroupIDs...)
	c.Evidence = append([]Evidence(nil), a.Evidence...)
	return c
}

// Event is what the rest of Shepherd hands to Engine.Raise. Only Type is
// required.
type Event struct {
	Type string
	// Severity overrides the type's default when valid.
	Severity Severity
	Title    string // defaults to the type's title
	Body     string
	// Key is the dedupe key. Empty means "<type>|<device>|<domain>". Make
	// keys end in a delimiter ("new-device|dev1|") if prefix muting must not
	// catch longer keys.
	Key         string
	Source      string
	DeviceID    string
	DeviceClass string
	GroupIDs    []string
	Domain      string
	Evidence    []Evidence
	URL         string
	// Count is how many occurrences this event stands for (default 1).
	Count int
	// Time is when it happened (default: now).
	Time time.Time
}

// ChangeKind classifies a stream Change.
type ChangeKind string

// Change kinds.
const (
	ChangeRaised    ChangeKind = "raised"    // a new alarm
	ChangeUpdated   ChangeKind = "updated"   // dedupe hit or bundle growth
	ChangeEscalated ChangeKind = "escalated" // a repeat with a higher severity
	ChangeState     ChangeKind = "state"     // acknowledge, resolve, mute, unmute, undo
	ChangeDeleted   ChangeKind = "deleted"
	ChangeBulk      ChangeKind = "bulk" // a large batch; re-fetch the list
	ChangeRule      ChangeKind = "rule" // a mute rule was created, removed or expired
	ChangePrefs     ChangeKind = "prefs"
)

// Notify is the engine's decision about notifying for a change.
type Notify struct {
	// Send is true when channels should be told about this alarm.
	Send bool `json:"send"`
	// HoldUntil is set when the alarm arrived in quiet hours: deliver it
	// (with the digest) no earlier than this.
	HoldUntil time.Time `json:"hold_until,omitzero"`
	// Reason explains Send=false ("muted", "learning") or a hold
	// ("quiet-hours").
	Reason string `json:"reason,omitempty"`
}

// Change is one entry in the engine's change stream, for the portal's live
// updates and for the delivery Router.
type Change struct {
	Kind   ChangeKind `json:"kind"`
	Alarm  Alarm      `json:"alarm"`
	Notify Notify     `json:"notify"`
	RuleID string     `json:"rule_id,omitempty"`
	// Count is the number of alarms affected by a ChangeBulk.
	Count int `json:"count,omitempty"`
}
