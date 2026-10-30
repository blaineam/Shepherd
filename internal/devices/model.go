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
)

// AllTypes lists every device type, for pickers.
func AllTypes() []DeviceType {
	return []DeviceType{TypePhone, TypeTablet, TypeLaptop, TypeTV, TypeSpeaker, TypeCamera,
		TypePrinter, TypeGameConsole, TypeSmartHome, TypeRouter, TypeUnknown}
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
	}
	return "", false
}

func normType(s string) string {
	s = strings.ToLower(s)
	return strings.NewReplacer(" ", "", "_", "", "-", "", "/", "").Replace(s)
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
	Services   []string   `json:"services,omitempty"`  // mDNS service types seen
	Hints      []string   `json:"hints,omitempty"`     // model strings and friendly names

	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`

	Groups   []string `json:"groups,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Excluded bool     `json:"excluded,omitempty"` // opted out of protection and traffic steering
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
	SourceDNS        SourceKind = "dns" // a DNS query came from this IP
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
