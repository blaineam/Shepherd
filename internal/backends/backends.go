// SPDX-License-Identifier: AGPL-3.0-or-later

// Package backends lets Shepherd be a dashboard over a router or firewall
// the owner already runs, instead of only over its own DNS server.
//
// A Backend is one product's management API: Firewalla MSP, a UniFi
// controller. Products differ in what they will tell you and what they
// will let you change, so nothing here assumes a Backend does everything.
// Each ability is its own small interface, and a Backend implements the
// ones its API really supports. The portal asks what a Backend can do
// (Capabilities) and shows only that. Firewalla can report flows and
// alarms; UniFi cannot report requests at all, and Shepherd's own DNS
// history fills that gap beside it.
//
// Reading is always safe. Writing is separate, is switched on by the owner
// per backend, and is refused outright for a read-only credential before
// any request leaves the machine.
package backends

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Capability is one thing a Backend can do right now.
type Capability string

// The capabilities. A write capability is present only when the backend
// implements it and the owner has not made the credential read-only.
const (
	CapDevices      Capability = "devices"
	CapFlows        Capability = "flows"
	CapAlarms       Capability = "alarms"
	CapRules        Capability = "rules"
	CapRuleWrite    Capability = "rules:write"
	CapDeviceRename Capability = "devices:rename"
	CapAlarmDismiss Capability = "alarms:dismiss"
)

// Errors every backend maps its failures onto. Use errors.Is.
var (
	ErrAuth        = errors.New("backend: the credential was refused")
	ErrRateLimited = errors.New("backend: the service is rate limiting requests")
	ErrRefused     = errors.New("backend: the service refused the request")
	ErrNotFound    = errors.New("backend: not found")
	// ErrReadOnly is returned, before any network call, for a write
	// through a backend the owner marked read-only.
	ErrReadOnly = errors.New("backend: this connection is read-only")
	// ErrInvalid is a request Shepherd would not send: a rule with no
	// target, an empty name. The message says which.
	ErrInvalid = errors.New("backend: invalid request")
)

// Backend is the part every product has.
type Backend interface {
	// Name is lowercase and stable ("firewalla"). It appears in the portal,
	// in alarms and in logs.
	Name() string
	// ReadOnly reports whether writes are refused.
	ReadOnly() bool
}

// DeviceReader lists the devices the product knows.
type DeviceReader interface {
	Devices(ctx context.Context) ([]Device, error)
}

// FlowReader reads network requests, newest first.
type FlowReader interface {
	Flows(ctx context.Context, q FlowQuery) (FlowPage, error)
}

// AlarmReader reads what the product flagged.
type AlarmReader interface {
	Alarms(ctx context.Context, q AlarmQuery) (AlarmPage, error)
}

// RuleManager lists and changes access rules.
type RuleManager interface {
	Rules(ctx context.Context) ([]Rule, error)
	CreateRule(ctx context.Context, spec RuleSpec) (Rule, error)
	SetRulePaused(ctx context.Context, id string, paused bool) error
	DeleteRule(ctx context.Context, id string) error
}

// DeviceRenamer gives a device a new name on the product.
type DeviceRenamer interface {
	RenameDevice(ctx context.Context, d DeviceRef, name string) error
}

// AlarmDismisser removes an alarm on the product.
type AlarmDismisser interface {
	DismissAlarm(ctx context.Context, a AlarmRef) error
}

// Capabilities reports what b can do, in a stable order. Write abilities
// are left out for a read-only backend, so the portal never offers a
// button that is certain to fail.
func Capabilities(b Backend) []Capability {
	var out []Capability
	writable := !b.ReadOnly()
	if _, ok := b.(DeviceReader); ok {
		out = append(out, CapDevices)
	}
	if _, ok := b.(FlowReader); ok {
		out = append(out, CapFlows)
	}
	if _, ok := b.(AlarmReader); ok {
		out = append(out, CapAlarms)
	}
	if _, ok := b.(RuleManager); ok {
		out = append(out, CapRules)
		if writable {
			out = append(out, CapRuleWrite)
		}
	}
	if _, ok := b.(DeviceRenamer); ok && writable {
		out = append(out, CapDeviceRename)
	}
	if _, ok := b.(AlarmDismisser); ok && writable {
		out = append(out, CapAlarmDismiss)
	}
	return out
}

// Has reports whether c is among b's capabilities.
func Has(b Backend, c Capability) bool {
	for _, have := range Capabilities(b) {
		if have == c {
			return true
		}
	}
	return false
}

// ---- normalized records -----------------------------------------------------

// Device is a device as a product lists it. MAC is lowercase hex with no
// separators, which is what Shepherd's registry keys on; it is empty for
// something that is not a hardware device, such as a VPN profile.
type Device struct {
	MAC      string
	Name     string
	IP       string
	Vendor   string
	Online   bool
	Group    string
	Network  string
	Download uint64 // bytes, as the product counts them
	Upload   uint64
	// Box names where the product keeps it (Firewalla's box ID), which a
	// rename needs. Opaque to everything else.
	Box string
	// Native is the product's own identifier, which a rename needs.
	Native string
}

// DeviceRef identifies a device for a write.
type DeviceRef struct {
	Box    string
	Native string
}

// Ref is the reference to use when changing d.
func (d Device) Ref() DeviceRef { return DeviceRef{Box: d.Box, Native: d.Native} }

// Flow is one network request. Domain is the name the device asked for
// when the product knows it; RemoteIP is where the traffic went.
type Flow struct {
	Time      time.Time
	DeviceMAC string
	Device    string
	DeviceIP  string
	Domain    string
	RemoteIP  string
	Protocol  string
	Outbound  bool
	Blocked   bool
	Download  uint64
	Upload    uint64
	Category  string
	Country   string
	Box       string
}

// FlowQuery selects flows. From and To bound the time range; a zero From
// leaves the product's default window (Firewalla's is the last 24 hours).
type FlowQuery struct {
	From, To time.Time
	Limit    int    // at most 500
	Cursor   string // from a previous page's Next
}

// FlowPage is one page, newest first. Next is empty on the last page.
type FlowPage struct {
	Flows []Flow
	Next  string
}

// Alarm is something the product flagged.
type Alarm struct {
	ID        string
	Time      time.Time
	Type      string
	Message   string
	DeviceMAC string
	Device    string
	Box       string
}

// AlarmRef identifies an alarm for a write.
type AlarmRef struct {
	Box string
	ID  string
}

// Ref is the reference to use when dismissing a.
func (a Alarm) Ref() AlarmRef { return AlarmRef{Box: a.Box, ID: a.ID} }

// AlarmQuery selects alarms. ActiveOnly leaves out the ones already
// dealt with.
type AlarmQuery struct {
	ActiveOnly bool
	Limit      int
	Cursor     string
}

// AlarmPage is one page of alarms.
type AlarmPage struct {
	Alarms []Alarm
	Next   string
}

// Rule is an access rule as a product holds it.
type Rule struct {
	ID         string
	Action     string // "block" or "allow"
	TargetType string // "domain", "ip", "category"
	Target     string
	// ScopeType is "device" for one device, "" for the whole network.
	ScopeType string
	Scope     string // the device's MAC when ScopeType is "device"
	Paused    bool
	Notes     string
	Created   time.Time
	Box       string
}

// RuleSpec is a rule to create.
type RuleSpec struct {
	Action     string
	TargetType string
	Target     string
	// DNSOnly limits a domain rule to name lookups, which is what a DNS
	// block means. Left false it also blocks the connection.
	DNSOnly   bool
	ScopeType string
	Scope     string
	Notes     string
	// Box says which box gets the rule when the account has several.
	Box string
}

// Validate refuses a spec Shepherd would not send, naming the problem.
func (s RuleSpec) Validate() error {
	switch s.Action {
	case "block", "allow":
	default:
		return invalid("the action must be block or allow")
	}
	switch s.TargetType {
	case "domain", "ip", "category":
	default:
		return invalid("the target type must be domain, ip or category")
	}
	if strings.TrimSpace(s.Target) == "" {
		return invalid("a rule needs a target")
	}
	switch s.ScopeType {
	case "":
		if s.Scope != "" {
			return invalid("a scope value needs a scope type")
		}
	case "device":
		if strings.TrimSpace(s.Scope) == "" {
			return invalid("a device rule needs the device")
		}
	default:
		return invalid("the scope must be a device or the whole network")
	}
	return nil
}

func invalid(msg string) error { return fmt.Errorf("%w: %s", ErrInvalid, msg) }
