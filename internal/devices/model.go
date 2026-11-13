// SPDX-License-Identifier: AGPL-3.0-or-later

package devices

import (
	"net/netip"
	"strings"
	"time"
)

// DeviceType is the guessed kind of device.
type DeviceType string

const (
	TypeUnknown     DeviceType = "unknown"
	TypePhone       DeviceType = "phone"
	TypeTablet      DeviceType = "tablet"
	TypeLaptop      DeviceType = "laptop"
	TypeTV          DeviceType = "tv"
	TypeSpeaker     DeviceType = "speaker"
	TypeCamera      DeviceType = "camera"
	TypePrinter     DeviceType = "printer"
	TypeGameConsole DeviceType = "game console"
	TypeSmartHome   DeviceType = "smart-home hub"
	TypeRouter      DeviceType = "router/infrastructure"

	// Finer classes the automatic classifier (internal/classify) can tell
	// apart from the original set.
	TypeStreamingBox DeviceType = "streaming box"
	TypeSmartPlug    DeviceType = "smart plug/sensor"
	TypeDoorbell     DeviceType = "doorbell"
	TypeThermostat   DeviceType = "thermostat"
	TypeEReader      DeviceType = "e-reader"
	TypeWearable     DeviceType = "wearable"
	TypeNAS          DeviceType = "NAS/server"
)

// AllTypes lists every device type, for pickers.
func AllTypes() []DeviceType {
	return []DeviceType{TypePhone, TypeTablet, TypeLaptop, TypeTV, TypeStreamingBox, TypeSpeaker, TypeCamera,
		TypeDoorbell, TypePrinter, TypeGameConsole, TypeSmartHome, TypeSmartPlug, TypeThermostat, TypeEReader,
		TypeWearable, TypeNAS, TypeRouter, TypeUnknown}
}

// ParseType maps user input ("camera", "game_console", "Smart Home") to a
// DeviceType.
func ParseType(s string) (DeviceType, bool) {
	n := normType(s)
	for _, t := range AllTypes() {
		if normType(string(t)) == n {
			return t, true
		}
	}
	switch n {
	case "router", "infrastructure", "infra", "ap", "network":
		return TypeRouter, true
	case "hub", "smarthome", "iot":
		return TypeSmartHome, true
	case "console", "game", "gaming":
		return TypeGameConsole, true
	case "computer", "pc", "desktop", "mac":
		return TypeLaptop, true
	case "plug", "smartplug", "sensor", "smartsensor":
		return TypeSmartPlug, true
	case "nas", "server", "storage":
		return TypeNAS, true
	case "stream", "streamer", "streamingdevice", "firestick":
		return TypeStreamingBox, true
	case "thermo":
		return TypeThermostat, true
	case "ebook", "ebookreader":
		return TypeEReader, true
	case "watch", "smartwatch", "fitnesstracker":
		return TypeWearable, true
	case "videodoorbell":
		return TypeDoorbell, true
	}
	return "", false
}

func normType(s string) string {
	s = strings.ToLower(s)
	return strings.NewReplacer(" ", "", "_", "", "-", "", "/", "").Replace(s)
}

// WatchMode is a device's Watch-mode switch. See Device.Watch.
type WatchMode string

// Watch switch positions.
const (
	WatchAuto WatchMode = ""    // the engine's policy decides (the default)
	WatchOn   WatchMode = "on"  // steer, even a device the policy would skip
	WatchOff  WatchMode = "off" // never steer
)

// ParseWatchMode reads "auto", "on" or "off".
func ParseWatchMode(s string) (WatchMode, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "auto":
		return WatchAuto, true
	case "on":
		return WatchOn, true
	case "off":
		return WatchOff, true
	}
	return "", false
}

// String returns "auto", "on" or "off".
func (m WatchMode) String() string {
	if m == WatchAuto {
		return "auto"
	}
	return string(m)
}

// AAAAMode is a device's own AAAA-filtering switch. See Device.AAAA.
type AAAAMode string

// AAAA switch positions.
const (
	AAAAAuto AAAAMode = ""    // follow the network's AAAA setting (the default)
	AAAAOn   AAAAMode = "on"  // withhold AAAA answers from this device, whatever the network does
	AAAAOff  AAAAMode = "off" // always answer this device's AAAA queries in full
)

// ParseAAAAMode reads "auto", "on" or "off".
func ParseAAAAMode(s string) (AAAAMode, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "auto":
		return AAAAAuto, true
	case "on":
		return AAAAOn, true
	case "off":
		return AAAAOff, true
	}
	return "", false
}

// String returns "auto", "on" or "off".
func (m AAAAMode) String() string {
	if m == AAAAAuto {
		return "auto"
	}
	return string(m)
}

// RouteMode is a device's DHCP-mode routing switch. See Device.Route.
type RouteMode string

// Route switch positions.
const (
	RouteAuto RouteMode = ""    // the mode's own policy decides (the default)
	RouteOn   RouteMode = "on"  // route it, even one the policy would skip
	RouteOff  RouteMode = "off" // never route it
)

// ParseRouteMode reads "auto", "on" or "off".
func ParseRouteMode(s string) (RouteMode, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "auto":
		return RouteAuto, true
	case "on":
		return RouteOn, true
	case "off":
		return RouteOff, true
	}
	return "", false
}

// String returns "auto", "on" or "off".
func (m RouteMode) String() string {
	if m == RouteAuto {
		return "auto"
	}
	return string(m)
}

// HLC is a hybrid logical clock stamp: wall-clock milliseconds plus a counter
// that orders events within the same millisecond.
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

// Device is one identified machine on the network.
type Device struct {
	ID string `json:"id"`

	MACs    []string             `json:"macs,omitempty"`
	IPs     []string             `json:"ips,omitempty"`      // current addresses (v4 and v6)
	PastIPs []string             `json:"past_ips,omitempty"` // addresses it used to hold, newest first
	IPSeen  map[string]time.Time `json:"ip_seen,omitempty"`

	Alias       string `json:"alias,omitempty"`        // set by the user
	MDNSName    string `json:"mdns_name,omitempty"`    // from mDNS
	Hostname    string `json:"hostname,omitempty"`     // DHCP or other self-reported hostname
	ReverseName string `json:"reverse_name,omitempty"` // from reverse DNS

	Vendor     string     `json:"vendor,omitempty"`
	Type       DeviceType `json:"type,omitempty"`
	TypeReason string     `json:"type_reason,omitempty"`
	TypeUser   bool       `json:"type_user,omitempty"` // type set by the user, never overwritten by guesses
	// TypeAuto marks a type chosen by the automatic classifier (see
	// SetGuessedType); TypeConfidence is how sure it was, 0 to 1. Both are
	// cleared when the user sets a type and ignored while TypeUser is set.
	TypeAuto       bool     `json:"type_auto,omitempty"`
	TypeConfidence float64  `json:"type_confidence,omitempty"`
	Services       []string `json:"services,omitempty"` // mDNS service types seen
	Hints          []string `json:"hints,omitempty"`    // model strings and friendly names

	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`

	Groups   []string `json:"groups,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Excluded bool     `json:"excluded,omitempty"` // opted out of protection and traffic steering
	// Watch is the device's own Watch-mode switch (docs/WATCH.md): WatchAuto
	// (the empty string, the default) lets the engine's policy decide, which
	// steers ordinary devices and leaves infrastructure alone; WatchOn
	// steers it even when the policy would not (never an Excluded device);
	// WatchOff never steers it.
	Watch WatchMode `json:"watch,omitempty"`
	// Route is the device's DHCP-mode routing switch (docs/DHCP.md):
	// RouteAuto (the empty string, the default) lets the mode decide, which
	// routes every eligible device while routing is on and nothing while it
	// is off; RouteOn routes it even when the eligibility rules would not,
	// except for the refusals that exist to stop Shepherd routing itself or
	// the gateway, which no device record can override; RouteOff never
	// routes it, which is the escape hatch for a device that turns out to
	// mind double NAT.
	Route RouteMode `json:"route,omitempty"`
	// AAAA is the device's own AAAA-filtering switch (docs/IPV6.md):
	// AAAAAuto (the empty string, the default) follows the network's
	// setting; AAAAOn withholds AAAA answers from this device even when
	// the network hands them out; AAAAOff always answers it in full, which
	// is the escape hatch for a device that does not cache a NODATA and
	// asks again without end instead of falling back to IPv4.
	AAAA AAAAMode `json:"aaaa,omitempty"`
	// Wandering devices are not filtered at all, but every request they make is
	// still logged and watched. WanderingUntil ends it automatically; zero means
	// until it is turned off.
	Wandering      bool      `json:"wandering,omitempty"`
	WanderingUntil time.Time `json:"wandering_until,omitempty"`
	Notes          string    `json:"notes,omitempty"`

	MergedInto string `json:"merged_into,omitempty"` // set on the tombstone of a merged device

	Updated HLC    `json:"updated"`
	Node    string `json:"node"`
	Deleted bool   `json:"deleted,omitempty"`
}

// Randomized reports whether every known MAC is locally administered.
func (d *Device) Randomized() bool {
	if len(d.MACs) == 0 {
		return false
	}
	for _, m := range d.MACs {
		if !IsLocallyAdministered(m) {
			return false
		}
	}
	return true
}

// Named reports whether any real name (alias, mDNS, hostname or reverse DNS)
// is known.
func (d *Device) Named() bool {
	return d.Alias != "" || d.MDNSName != "" || d.Hostname != "" || d.ReverseName != ""
}

// DisplayName picks the best label: user alias, then mDNS/hostname, then
// reverse DNS, then a "Vendor Type" guess, then the IP address.
func (d *Device) DisplayName() string {
	for _, n := range []string{d.Alias, d.MDNSName, d.Hostname, d.ReverseName} {
		if n != "" {
			return n
		}
	}
	if d.Vendor != "" {
		if d.Type != "" && d.Type != TypeUnknown {
			return d.Vendor + " " + string(d.Type)
		}
		return d.Vendor + " device"
	}
	if d.Type != "" && d.Type != TypeUnknown {
		return strings.ToUpper(string(d.Type[:1])) + string(d.Type[1:])
	}
	if ip := d.primaryIP(); ip != "" {
		return ip
	}
	return d.ID
}

// primaryIP prefers a current IPv4 address, then any current address, then
// the most recent past one.
func (d *Device) primaryIP() string {
	for _, s := range d.IPs {
		if a, err := netip.ParseAddr(s); err == nil && a.Is4() {
			return s
		}
	}
	if len(d.IPs) > 0 {
		return d.IPs[0]
	}
	if len(d.PastIPs) > 0 {
		return d.PastIPs[0]
	}
	return ""
}

func (d *Device) clone() *Device {
	c := *d
	c.MACs = append([]string(nil), d.MACs...)
	c.IPs = append([]string(nil), d.IPs...)
	c.PastIPs = append([]string(nil), d.PastIPs...)
	c.Services = append([]string(nil), d.Services...)
	c.Hints = append([]string(nil), d.Hints...)
	c.Groups = append([]string(nil), d.Groups...)
	c.Tags = append([]string(nil), d.Tags...)
	if d.IPSeen != nil {
		c.IPSeen = make(map[string]time.Time, len(d.IPSeen))
		for k, v := range d.IPSeen {
			c.IPSeen[k] = v
		}
	}
	return &c
}

// Group is a named, colored set of devices.
type Group struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Color string `json:"color,omitempty"`
	// Members is derived from the devices' group lists; it is filled on reads
	// and never persisted.
	Members []string `json:"members,omitempty"`

	Updated HLC    `json:"updated"`
	Node    string `json:"node"`
	Deleted bool   `json:"deleted,omitempty"`
}

// SourceKind says where an observation came from.
type SourceKind string

const (
	SourceNeighbor   SourceKind = "neighbor"
	SourceARP        SourceKind = "arp" // Watch-mode interception
	SourceMDNS       SourceKind = "mdns"
	SourceReverseDNS SourceKind = "rdns"
	SourceDHCP       SourceKind = "dhcp"
	SourceDNS        SourceKind = "dns"       // a DNS query came from this IP
	SourceTailscale  SourceKind = "tailscale" // a name from the local tailscaled
	SourceManual     SourceKind = "manual"
)

// Observation is one piece of identity evidence.
type Observation struct {
	Source     SourceKind
	MAC        string // optional
	IP         string // optional
	Hostname   string // meaning depends on Source (mDNS name, DHCP hostname, PTR name)
	Services   []string
	VendorHint string
	Hints      []string
	Time       time.Time // zero means now
}

// Sink consumes observations. *Registry implements it, and so will the ARP
// interceptor's feed.
type Sink interface {
	Observe(Observation) string
}
