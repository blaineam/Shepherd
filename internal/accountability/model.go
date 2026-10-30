// SPDX-License-Identifier: AGPL-3.0-or-later

package accountability

import (
	"errors"
	"fmt"
	"net/mail"
	"slices"
	"strings"
	"time"
)

// Wildcard, used as the sole entry of Subscription.Items, means "any item
// this scope was evaluated against" rather than one specific catalog, list
// or app ID.
const Wildcard = "*"

// Detail is how much a subscription's email says about what happened.
//
// DetailSummary is the default: it names the category and roughly when and
// where, and nothing more specific. DetailDetailed additionally names the
// exact domain. Summary-by-default is design rule 1 in docs/ACCOUNTABILITY.md:
// this feature exists to invite a conversation, not to hand over a browsing
// log, so the person setting it up has to actively choose more detail.
type Detail string

// Detail levels.
const (
	DetailSummary  Detail = "summary"
	DetailDetailed Detail = "detailed"
)

// Valid reports whether d is a known detail level.
func (d Detail) Valid() bool { return d == DetailSummary || d == DetailDetailed }

// Mode is when a subscription's matching events are emailed.
//
// ModeDigest is the default: matching events accumulate and are sent as one
// periodic rollup (see Subscription.DigestInterval). ModeImmediate sends
// sooner, but still coalesces a burst within a short window into one email
// (see Engine.Options.ImmediateWindow) — design rule 2: a running tally of
// every attempt, sent instantly, reads as surveillance, not an invitation to
// talk.
type Mode string

// Modes.
const (
	ModeDigest    Mode = "digest"
	ModeImmediate Mode = "immediate"
)

// Valid reports whether m is a known mode.
func (m Mode) Valid() bool { return m == ModeDigest || m == ModeImmediate }

// TriggerOn decides which accesses a subscription cares about.
//
// TriggerAny (the default) matches every access the scope and items select,
// whether or not the policy engine also blocked it: a trusted-contact alert
// is disclosure, not enforcement, and the maintainer's own motivating
// example — alerting a friend that a watched category was *accessed* — is
// an allowed access, not a blocked one. TriggerBlockedOnly matches only
// accesses the caller reports as blocked, for whoever wants the alert tied
// to an actual block.
type TriggerOn string

// Trigger modes.
const (
	TriggerAny         TriggerOn = "any"
	TriggerBlockedOnly TriggerOn = "blocked_only"
)

// Valid reports whether t is a known trigger mode.
func (t TriggerOn) Valid() bool { return t == TriggerAny || t == TriggerBlockedOnly }

// ScopeKind says whether a Scope names a group or a single device. It is
// shaped like internal/dnsengine's ScopeKind (group and device only: there is
// deliberately no network-wide scope here — see design rule 4, "scoped and
// explicit, never silent").
type ScopeKind string

// Scope kinds.
const (
	ScopeGroup  ScopeKind = "group"
	ScopeDevice ScopeKind = "device"
)

// Valid reports whether k is a known scope kind.
func (k ScopeKind) Valid() bool { return k == ScopeGroup || k == ScopeDevice }

// Scope names the group or device a subscription watches.
type Scope struct {
	Kind ScopeKind `json:"kind"`
	ID   string    `json:"id"`
}

// GroupScope returns a group scope.
func GroupScope(id string) Scope { return Scope{Kind: ScopeGroup, ID: id} }

// DeviceScope returns a device scope.
func DeviceScope(id string) Scope { return Scope{Kind: ScopeDevice, ID: id} }

// String renders the scope as "group:<id>" or "device:<id>".
func (s Scope) String() string { return string(s.Kind) + ":" + s.ID }

func (s Scope) validate() error {
	if !s.Kind.Valid() {
		return fmt.Errorf("%w: scope kind %q", ErrInvalid, s.Kind)
	}
	if s.ID == "" {
		return fmt.Errorf("%w: scope id is required", ErrInvalid)
	}
	return nil
}

// Contact is a person who can be emailed: a name, an address, nothing more.
// Shepherd never asks a contact to sign in to anything (design rule 5).
type Contact struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

func (c Contact) clone() Contact { return c }

func (c Contact) validate() error {
	if strings.TrimSpace(c.Name) == "" {
		return fmt.Errorf("%w: contact name is required", ErrInvalid)
	}
	if len(c.Name) > 200 {
		return fmt.Errorf("%w: contact name is too long", ErrInvalid)
	}
	addr, err := mail.ParseAddress(c.Email)
	if err != nil || addr.Address != c.Email {
		return fmt.Errorf("%w: contact email %q is not a valid address", ErrInvalid, c.Email)
	}
	return nil
}

// Subscription is one contact's subscription to one scope's accesses to a
// set of catalog items (or Wildcard for all of them).
type Subscription struct {
	ID        string   `json:"id"`
	ContactID string   `json:"contact_id"`
	Scope     Scope    `json:"scope"`
	Items     []string `json:"items"`

	Detail  Detail    `json:"detail"`
	Mode    Mode      `json:"mode"`
	Trigger TriggerOn `json:"trigger_on"`
	// DigestInterval is how often a digest-mode subscription is sent:
	// a day by default, a week, or any custom duration. Ignored in
	// immediate mode.
	DigestInterval time.Duration `json:"digest_interval"`

	CreatedAt time.Time `json:"created_at"`
}

func (s Subscription) clone() Subscription {
	c := s
	c.Items = append([]string(nil), s.Items...)
	return c
}

func (s Subscription) validate() error {
	if s.ContactID == "" {
		return fmt.Errorf("%w: subscription needs a contact", ErrInvalid)
	}
	if err := s.Scope.validate(); err != nil {
		return err
	}
	if len(s.Items) == 0 {
		return fmt.Errorf("%w: subscription needs at least one item, or %q for any", ErrInvalid, Wildcard)
	}
	for _, it := range s.Items {
		if strings.TrimSpace(it) == "" {
			return fmt.Errorf("%w: subscription has a blank item", ErrInvalid)
		}
	}
	if !s.Detail.Valid() {
		return fmt.Errorf("%w: detail %q", ErrInvalid, s.Detail)
	}
	if !s.Mode.Valid() {
		return fmt.Errorf("%w: mode %q", ErrInvalid, s.Mode)
	}
	if !s.Trigger.Valid() {
		return fmt.Errorf("%w: trigger %q", ErrInvalid, s.Trigger)
	}
	if s.DigestInterval < 0 {
		return fmt.Errorf("%w: digest interval must not be negative", ErrInvalid)
	}
	return nil
}

// watchesItem reports whether the subscription watches item, honoring
// Wildcard.
func (s Subscription) watchesItem(item string) bool {
	return slices.Contains(s.Items, Wildcard) || slices.Contains(s.Items, item)
}

// matchesScope reports whether ev's device or any of its groups is the
// subscription's scope.
func (s Subscription) matchesScope(ev AccessEvent) bool {
	switch s.Scope.Kind {
	case ScopeDevice:
		return ev.ClientID != "" && ev.ClientID == s.Scope.ID
	case ScopeGroup:
		return slices.Contains(ev.GroupIDs, s.Scope.ID)
	default:
		return false
	}
}

// matchesTrigger reports whether ev's action satisfies the subscription's
// trigger mode.
func (s Subscription) matchesTrigger(ev AccessEvent) bool {
	if s.Trigger == TriggerBlockedOnly {
		return strings.EqualFold(ev.Action, "blocked")
	}
	return true // TriggerAny, and the empty value defaults to it
}

// Matches reports whether ev should be recorded for this subscription: its
// scope, its watched items and its trigger mode all agree.
func (s Subscription) Matches(ev AccessEvent) bool {
	return s.matchesScope(ev) && s.watchesItem(ev.Item) && s.matchesTrigger(ev)
}

// AccessEvent is one DNS decision the caller has chosen to report because it
// matched something being watched. It is deliberately not tied to blocking:
// Action carries whatever the policy engine actually decided ("blocked",
// "allowed", or any other label internal/dnsengine's Entry.Action uses), and
// TriggerBlockedOnly subscriptions filter on it. The caller — Shepherd's
// wiring, not this package — builds one of these from a dnsengine.Entry (or
// equivalent) for every query that matches a watched item; this package
// never reaches into the DNS engine itself.
type AccessEvent struct {
	Time time.Time
	// ClientID is the device ID the access came from, when known.
	ClientID string
	// GroupIDs are the groups that device belongs to.
	GroupIDs []string
	// Item is the catalog, list or app ID the caller matched this access
	// against (for example "gaming" or "roblox"), or a domain-derived
	// label when no catalog item applies.
	Item string
	// Domain is the exact name queried. Carried on every event regardless
	// of any subscription's detail level; Detail controls what the
	// rendered email says, not what Record is told.
	Domain string
	// Action is what the policy engine decided: typically "blocked" or
	// "allowed" (internal/dnsengine's Entry also uses "cached" and
	// "error", which TriggerAny treats like "allowed" and
	// TriggerBlockedOnly ignores).
	Action string
}

func (ev AccessEvent) validate() error {
	if ev.Item == "" {
		return fmt.Errorf("%w: access event needs an item", ErrInvalid)
	}
	return nil
}

// Intake is implemented by anything that accepts access events. Engine
// implements it; the DNS-engine wiring (built later, not by this package)
// calls Record for every query that matches a watched item.
type Intake interface {
	Record(ev AccessEvent)
}

// ErrInvalid wraps every validation error this package returns.
var ErrInvalid = errors.New("accountability: invalid value")

// ErrNotFound is returned when a contact or subscription ID is unknown.
var ErrNotFound = errors.New("accountability: not found")
