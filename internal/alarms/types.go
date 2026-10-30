// SPDX-License-Identifier: AGPL-3.0-or-later

package alarms

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Delivery channel names. Every alarm is recorded for the portal; Push and
// Ntfy are the outbound channels the Router drives.
const (
	ChannelPortal = "portal"
	ChannelPush   = "push"
	ChannelNtfy   = "ntfy"
)

// Built-in alarm type IDs.
const (
	TypeNewDevice          = "new-device"
	TypeDeviceLeft         = "device-left"
	TypeUpstreamDown       = "upstream-down"
	TypeUpstreamRecovered  = "upstream-recovered"
	TypeListUpdateRejected = "list-update-rejected"
	TypeHistoryLocked      = "history-locked"
	TypeHistoryError       = "history-error"
	TypeMapDataFailed      = "map-data-failed"
	TypeDNSErrorSpike      = "dns-error-spike"
	TypeBlockedSpike       = "blocked-spike"
	TypePrivateRelay       = "private-relay-attempt"
	TypePortOpened         = "port-opened"          // for the ports feature
	TypeNewInboundExposure = "new-inbound-exposure" // for the ports feature
	TypeThreatMatch        = "threat-match"         // for threat intelligence
	TypeSelfUpdate         = "self-update"          // for self-update
	TypeTest               = "test"
)

// AlarmType describes a kind of alarm: how it reads, how severe it is by
// default, where it goes by default and how learning mode treats it.
type AlarmType struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	// DefaultSeverity applies when an Event does not choose one.
	DefaultSeverity Severity `json:"default_severity"`
	// Channels are the channels the type uses unless preferences override
	// them: any of ChannelPortal, ChannelPush and ChannelNtfy.
	Channels []string `json:"channels"`
	// LearningSuppresses records the type as info, without notifying, during
	// the install learning period.
	LearningSuppresses bool `json:"learning_suppresses"`
	// DeviceLearning additionally suppresses it for a device that was first
	// seen recently (the device's own learning period).
	DeviceLearning bool `json:"device_learning,omitempty"`
	// Bypass makes the type ignore mute rules, quiet hours and learning mode
	// (used by "send a test notification").
	Bypass  bool `json:"bypass,omitempty"`
	Builtin bool `json:"builtin,omitempty"`
}

var allChannels = []string{ChannelPortal, ChannelPush, ChannelNtfy}

// BuiltinTypes returns the built-in alarm type table.
func BuiltinTypes() []AlarmType {
	all := func(id, title, desc string, sev Severity, learn, devLearn bool) AlarmType {
		return AlarmType{ID: id, Title: title, Description: desc, DefaultSeverity: sev, Channels: append([]string(nil), allChannels...),
			LearningSuppresses: learn, DeviceLearning: devLearn, Builtin: true}
	}
	portal := func(t AlarmType) AlarmType { t.Channels = []string{ChannelPortal}; return t }
	return []AlarmType{
		all(TypeNewDevice, "New device", "A device appeared on the network that Shepherd has not seen before.", SeverityHigh, true, false),
		portal(all(TypeDeviceLeft, "Device left", "A known device has not been seen for a while.", SeverityLow, true, false)),
		all(TypeUpstreamDown, "Upstream DNS down", "Every upstream resolver in a pool stopped answering.", SeverityHigh, false, false),
		all(TypeUpstreamRecovered, "Upstream DNS recovered", "An upstream resolver is answering again.", SeverityLow, false, false),
		all(TypeListUpdateRejected, "List update rejected", "A blocklist update failed its safety checks and was not applied.", SeverityMedium, false, false),
		all(TypeHistoryLocked, "History locked", "Encrypted history is locked and queries are not being stored.", SeverityMedium, false, false),
		all(TypeHistoryError, "History error", "Query history could not be written or read.", SeverityMedium, false, false),
		portal(all(TypeMapDataFailed, "Map data failed", "The globe's map or GeoIP data could not be loaded.", SeverityLow, false, false)),
		all(TypeDNSErrorSpike, "DNS error spike", "A burst of failed DNS lookups.", SeverityMedium, true, true),
		portal(all(TypeBlockedSpike, "Blocked-query spike", "A burst of blocked queries from one device.", SeverityLow, true, true)),
		portal(all(TypePrivateRelay, "Private Relay attempt", "A device tried to use iCloud Private Relay, which this network blocks.", SeverityInfo, false, false)),
		all(TypePortOpened, "Port opened", "A device started listening on a new port.", SeverityHigh, true, true),
		all(TypeNewInboundExposure, "New inbound exposure", "A service became reachable from outside the network.", SeverityCritical, false, false),
		all(TypeThreatMatch, "Threat match", "A device contacted an address or name on a threat list.", SeverityCritical, false, false),
		all(TypeSelfUpdate, "Shepherd update", "Shepherd updated itself, or an update needs attention.", SeverityLow, false, false),
		func() AlarmType {
			t := all(TypeTest, "Test notification", "Sent on request to check that notifications arrive.", SeverityHigh, false, false)
			t.Bypass = true
			return t
		}(),
	}
}

var typeIDRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// Errors from type registration.
var (
	ErrInvalidType = errors.New("alarms: invalid alarm type")
	ErrTypeExists  = errors.New("alarms: alarm type already registered")
	ErrUnknownType = errors.New("alarms: unknown alarm type")
	ErrBuiltinType = errors.New("alarms: cannot replace a built-in alarm type")
)

func validateType(t AlarmType) error {
	if !typeIDRE.MatchString(t.ID) {
		return fmt.Errorf("%w: id %q must be lowercase letters, digits, . _ -", ErrInvalidType, t.ID)
	}
	if strings.TrimSpace(t.Title) == "" || len(t.Title) > 120 {
		return fmt.Errorf("%w: title", ErrInvalidType)
	}
	if !t.DefaultSeverity.Valid() {
		return fmt.Errorf("%w: default severity %q", ErrInvalidType, t.DefaultSeverity)
	}
	for _, c := range t.Channels {
		if c != ChannelPortal && c != ChannelPush && c != ChannelNtfy {
			return fmt.Errorf("%w: channel %q", ErrInvalidType, c)
		}
	}
	return nil
}

// Register adds a third-party alarm type. The ID must be new: a registered
// type is never silently replaced. An empty Channels list means all three.
func (e *Engine) Register(t AlarmType) error {
	if err := validateType(t); err != nil {
		return err
	}
	t.Builtin = false
	if len(t.Channels) == 0 {
		t.Channels = append([]string(nil), allChannels...)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if old, ok := e.types[t.ID]; ok {
		if old.Builtin {
			return fmt.Errorf("%w: %s", ErrBuiltinType, t.ID)
		}
		return fmt.Errorf("%w: %s", ErrTypeExists, t.ID)
	}
	e.types[t.ID] = t
	return nil
}

// Types lists every registered alarm type, sorted by ID.
func (e *Engine) Types() []AlarmType {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]AlarmType, 0, len(e.types))
	for _, t := range e.types {
		t.Channels = append([]string(nil), t.Channels...)
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Type returns one registered type.
func (e *Engine) Type(id string) (AlarmType, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	t, ok := e.types[id]
	t.Channels = append([]string(nil), t.Channels...)
	return t, ok
}

// typeOf returns the registered type, or a synthesized default for an
// unregistered ID so that a typo never loses an alarm. Callers hold e.mu.
func (e *Engine) typeOf(id string) AlarmType {
	if t, ok := e.types[id]; ok {
		return t
	}
	return AlarmType{ID: id, Title: id, DefaultSeverity: SeverityMedium, Channels: allChannels}
}
