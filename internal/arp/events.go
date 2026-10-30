// SPDX-License-Identifier: AGPL-3.0-or-later

package arp

import "time"

// EventType names an ARP-layer event.
type EventType string

// Event types. docs/ARP.md describes each rule and its thresholds.
const (
	EventNewMAC            EventType = "new-mac-seen"
	EventIPMoved           EventType = "ip-moved-to-new-mac"
	EventManyIPs           EventType = "mac-claims-many-ips"
	EventDuplicateIP       EventType = "duplicate-ip"
	EventGatewayMACChanged EventType = "gateway-mac-changed"
	EventGratuitousFlood   EventType = "gratuitous-arp-flood"
	EventUnsolicitedStorm  EventType = "arp-reply-without-request-storm"
	EventSpoofingSuspected EventType = "arp-spoofing-suspected"
)

// AllEventTypes lists every type, for pickers and counters.
func AllEventTypes() []EventType {
	return []EventType{EventNewMAC, EventIPMoved, EventManyIPs, EventDuplicateIP,
		EventGatewayMACChanged, EventGratuitousFlood, EventUnsolicitedStorm, EventSpoofingSuspected}
}

// Severity is a hint for the alarm engine, not a verdict.
type Severity string

// Severities.
const (
	SeverityInfo   Severity = "info"
	SeverityLow    Severity = "low"
	SeverityMedium Severity = "medium"
	SeverityHigh   Severity = "high"
)

// Event is one finding about the ARP layer.
type Event struct {
	Type     EventType
	Severity Severity
	// Key is stable for the same finding (type plus subject), so a consumer
	// can dedupe. The Monitor also suppresses repeats of a Key for a cooldown.
	Key  string
	Time time.Time
	// MAC is the suspect or subject hardware address; OtherMAC is the
	// previous owner or the second claimant, when there is one.
	MAC      string
	OtherMAC string
	IP       string
	Summary  string
	Evidence map[string]string
	// Baseline is true while the Monitor is still in its learning period
	// after start, when every device looks new.
	Baseline bool
}
