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
	TypeThreatMatch        = "threat-match"         // internal/threats
	TypeSelfUpdate         = "self-update"          // for self-update
	TypeStorageOverBudget  = "storage-over-budget"  // cmd/shepherd's retention budget
	TypeVulnerabilityFound = "vulnerability-found"  // internal/vulnscan
	TypeNetworkDegraded    = "network-degraded"     // internal/nethealth
	// The passive ARP monitor's findings (internal/arp, docs/ARP.md), one
	// type per event type that raises an alarm; cmd/shepherd/arpalarms.go
	// is the mapping.
	TypeARPGatewayChanged = "arp-gateway-changed"
	TypeARPSpoofing       = "arp-spoofing"
	TypeARPIPMoved        = "arp-ip-moved"
	TypeARPDuplicateIP    = "arp-duplicate-ip"
	TypeARPManyIPs        = "arp-many-ips"
	TypeARPFlood          = "arp-flood"
	TypeARPReplyStorm     = "arp-reply-storm"
	// The built-in DNS self-test's findings (internal/selftest, docs/DNS-QA.md).
	TypeDNSListenerDown     = "dns-listener-down"
	TypeDNSCanaryFailed     = "dns-canary-failed"
	TypeDNSLANUncovered     = "dns-lan-uncovered"
	TypeDNSUpstreamDegraded = "dns-upstream-degraded"
	// DHCP mode's findings (internal/dhcp, docs/DHCP.md). All three are
	// about the two ways this mode can hurt: another server answering on
	// the same segment, and a kernel that will not take the rules that
	// make routed devices work.
	TypeDHCPRogueServer = "dhcp-rogue-server"
	TypeDHCPNATFailed   = "dhcp-nat-failed"
	TypeDHCPLeaseReset  = "dhcp-lease-reset"
	// The behaviour checks and decoy ports (internal/detect, internal/decoy,
	// docs/DETECT.md); cmd/shepherd/detect.go is the mapping.
	TypeEncryptedDNSLookup = "encrypted-dns-lookup"
	TypeDNSBypass          = "dns-bypass"
	TypeDNSRandomNames     = "dns-random-names"
	TypeDNSTunnel          = "dns-tunnel"
	TypeDNSBeacon          = "dns-beacon"
	TypeNewCountry         = "new-destination-country"
	TypeUploadSpike        = "upload-spike"
	TypeDecoyTouched       = "decoy-touched"
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
		portal(all(TypeStorageOverBudget, "Storage over budget", "Shepherd's data directory has grown past the retention budget in shepherd.toml.", SeverityLow, false, false)),
		all(TypeVulnerabilityFound, "Vulnerability found", "internal/vulnscan matched a device's open port against a known vulnerability signature.", SeverityHigh, false, false),
		all(TypeNetworkDegraded, "Network degraded", "Latency, packet loss or reachability has been sustained bad for several probe cycles in a row.", SeverityMedium, true, false),
		all(TypeARPGatewayChanged, "Gateway MAC changed", "The router's address is being claimed by a different hardware address: the classic ARP spoofing signature, or a replaced router.", SeverityHigh, false, false),
		all(TypeARPSpoofing, "ARP spoofing suspected", "One device shows several independent signs of ARP poisoning within a few minutes.", SeverityCritical, false, false),
		all(TypeARPIPMoved, "IP moved to another device", "An address is now claimed by a different device; medium when the previous owner was still active.", SeverityLow, true, true),
		all(TypeARPDuplicateIP, "Duplicate IP", "Two devices are claiming one address, usually a static address clashing with DHCP.", SeverityMedium, true, false),
		all(TypeARPManyIPs, "One device claims many IPs", "One hardware address claimed many addresses in a few minutes: a scanner, a poisoner, or a host running virtual machines.", SeverityMedium, true, true),
		portal(all(TypeARPFlood, "Gratuitous ARP flood", "A stream of unsolicited address announcements from one device.", SeverityLow, true, true)),
		all(TypeARPReplyStorm, "ARP reply storm", "Many ARP replies from one device that answered no request: poisoning replies, or a bridge Shepherd cannot see requests through.", SeverityMedium, true, true),
		all(TypeDNSListenerDown, "DNS listener not answering", "Shepherd says it listens on an address, but a test query to it over UDP or TCP got no answer.", SeverityCritical, false, false),
		all(TypeDNSCanaryFailed, "DNS self-test failed", "A listener answers, but a known-good name did not resolve or a known-blocked name was not blocked.", SeverityHigh, false, false),
		all(TypeDNSLANUncovered, "LAN address has no DNS listener", "This host has a LAN address Shepherd does not serve DNS on. Devices pointed at it get \"host not found\".", SeverityMedium, false, false),
		all(TypeDHCPRogueServer, "Another DHCP server is answering", "A DHCP reply came from something other than Shepherd. Two servers on one segment hand out addresses unpredictably, so Shepherd has stopped serving.", SeverityCritical, false, false),
		all(TypeDHCPNATFailed, "DHCP mode could not configure NAT", "Shepherd could not install the forwarding rules routed devices need, so it has stopped routing them. They move back to the router at their next renewal.", SeverityCritical, false, false),
		portal(all(TypeDHCPLeaseReset, "DHCP lease file reset", "Shepherd could not read its DHCP lease file and started with none. Addresses are re-learned as devices renew.", SeverityMedium, false, false)),
		all(TypeDNSUpstreamDegraded, "Upstream DNS degraded", "An upstream resolver is failing more than a few percent of its queries, or is far slower than the others.", SeverityMedium, false, false),
		all(TypeEncryptedDNSLookup, "Encrypted-DNS resolver looked up", "A device looked up a public DNS-over-HTTPS or DNS-over-TLS resolver. One that uses it sends its lookups where Shepherd cannot filter or see them.", SeverityMedium, true, true),
		all(TypeDNSBypass, "Device is not using Shepherd for DNS", "A device moved real traffic for a day without one lookup reaching Shepherd, so nothing it does is filtered.", SeverityMedium, true, true),
		all(TypeDNSRandomNames, "Burst of machine-made names", "One device asked for many domains that do not exist and look generated, the way malware hunts for its controller.", SeverityHigh, false, false),
		all(TypeDNSTunnel, "Data carried in DNS", "One device asked for many long, distinct names under one domain, which can carry data out through DNS.", SeverityMedium, true, false),
		all(TypeDNSBeacon, "Regular check-in to a new name", "One device looks up a name on a fixed interval that no other device asks for and the network had never seen.", SeverityMedium, true, true),
		all(TypeNewCountry, "Device reached a new country", "A single-purpose device's lookup resolved to a country none of its lookups ever had.", SeverityMedium, true, true),
		all(TypeUploadSpike, "Unusually large upload", "A device uploaded far more in an hour than it ever has.", SeverityHigh, true, false),
		all(TypeDecoyTouched, "Decoy port touched", "Something connected to a port Shepherd listens on and serves nothing from: a device probing its neighbours.", SeverityHigh, false, false),
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
