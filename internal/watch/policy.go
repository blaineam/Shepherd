// SPDX-License-Identifier: AGPL-3.0-or-later

package watch

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"shepherd/internal/arp"
	"shepherd/internal/devices"
)

// Device states reported in a Snapshot. The portal shows them as badges.
const (
	// StateSteered: the Controller is steering at least one of the device's
	// MACs right now. Healthy says whether relayed traffic has been seen
	// within the health loop's grace.
	StateSteered = "steered"
	// StatePending: eligible, but not steered yet — the engine is starting,
	// a health failure put the device on a retry backoff (NextRetry says
	// when), or Steer was refused (Reason says why).
	StatePending = "pending"
	// StateIdle: eligible by policy, but not seen recently enough (the
	// active window) or without a usable IPv4 address, so there is nothing
	// to steer yet. Becomes pending/steered on its own once it shows up.
	StateIdle = "idle"
	// StateSkipped: policy says never steer this device (excluded, its own
	// Watch switch is off, infrastructure, the gateway, Shepherd itself).
	StateSkipped = "skipped"
	// StateUnavailable: eligible, but Watch mode is not running at all
	// (disabled, unsupported, missing capabilities, or killed).
	StateUnavailable = "unavailable"
)

// PolicyConfig is the part of Config that decides eligibility.
type PolicyConfig struct {
	// SteerInfrastructure steers router/infrastructure and smart-home hub
	// devices too. Off by default.
	SteerInfrastructure bool
	// ActiveWindow is how recently a device must have been seen to be
	// steered; zero means DefaultActiveWindow.
	ActiveWindow time.Duration
}

// DefaultActiveWindow is how long a device may go unseen before the engine
// stops steering it (and stops trying to): long enough that a phone asleep
// in a pocket is not flapped, short enough that a device that left for the
// day is not chased with ARP replies all day.
const DefaultActiveWindow = 15 * time.Minute

// Decision is what the policy says about one device.
type Decision struct {
	// Eligible is true when the device should be steered now.
	Eligible bool
	// State is the Snapshot state the decision maps to when the device is
	// not steered: StateSkipped for a policy refusal, StateIdle for a
	// transient one (not seen lately, no IPv4 yet), StatePending when
	// eligible.
	State string
	// Reason is the plain-language explanation, empty when eligible.
	Reason string
	// Policy is true when the refusal is a standing one (StateSkipped), the
	// kind the Controller's Excluder must also enforce.
	Policy bool
}

// mdns service labels that mark a Thread border router or a Matter device:
// their IPv6 neighbour discovery must never be disturbed (docs/IPV6.md), and
// steering even their IPv4 side is not worth the risk of confusing a device
// the whole smart home hangs off.
var threadMatterServices = []string{"_meshcop", "_matter", "_matterc", "_matterd", "_thread"}

// Vendors that only make network infrastructure. A device from one of these
// is treated like a router even before the classifier has typed it; the
// owner can still flip its Watch switch on.
var infrastructureVendors = []string{"eero", "ubiquiti", "mikrotik", "aruba", "ruckus"}

// isInfrastructure reports whether d looks like something the network
// itself depends on: a router, mesh node, access point or switch (the
// registry's router/infrastructure type covers all of these), a
// smart-home hub or bridge, a Thread border router or a Matter device.
func isInfrastructure(d *devices.Device) (bool, string) {
	switch d.Type {
	case devices.TypeRouter:
		return true, "network infrastructure (" + string(d.Type) + ")"
	case devices.TypeSmartHome:
		return true, "smart-home hub or bridge"
	}
	for _, s := range d.Services {
		l := strings.ToLower(s)
		for _, want := range threadMatterServices {
			if strings.HasPrefix(l, want) {
				return true, "advertises Thread/Matter services (" + s + ")"
			}
		}
	}
	v := strings.ToLower(d.Vendor)
	for _, want := range infrastructureVendors {
		if strings.Contains(v, want) {
			return true, "network infrastructure vendor (" + d.Vendor + ")"
		}
	}
	return false, ""
}

// Decide applies the policy to one device as of now. own lists the MACs
// that are never steered whatever the registry says: the gateway's and
// Shepherd's own. It never consults the Controller; it only says what the
// engine should ask of it.
func Decide(d *devices.Device, cfg PolicyConfig, own []arp.MAC, now time.Time) Decision {
	skip := func(reason string) Decision { return Decision{State: StateSkipped, Reason: reason, Policy: true} }
	idle := func(reason string) Decision { return Decision{State: StateIdle, Reason: reason} }

	if len(d.MACs) == 0 {
		return idle("no MAC address known yet")
	}
	for _, m := range d.MACs {
		mac, err := arp.ParseMAC(m)
		if err != nil {
			continue
		}
		for _, o := range own {
			if mac == o {
				return skip("the gateway or Shepherd's own interface")
			}
		}
	}
	if d.Excluded {
		return skip("excluded from protection")
	}
	switch d.Watch {
	case devices.WatchOff:
		return skip("Watch switched off for this device")
	case devices.WatchOn:
		// Steered even where the policy below would skip it.
	default:
		if !cfg.SteerInfrastructure {
			if infra, why := isInfrastructure(d); infra {
				return skip(why)
			}
		}
	}
	window := cfg.ActiveWindow
	if window <= 0 {
		window = DefaultActiveWindow
	}
	if d.LastSeen.IsZero() || now.Sub(d.LastSeen) > window {
		return idle("not seen for " + roundAge(now.Sub(d.LastSeen), d.LastSeen))
	}
	if primaryIPv4(d) == (netip.Addr{}) {
		return idle("no IPv4 address known")
	}
	return Decision{Eligible: true, State: StatePending}
}

func roundAge(age time.Duration, seen time.Time) string {
	if seen.IsZero() {
		return "ever"
	}
	switch {
	case age < time.Minute:
		return "under a minute"
	case age < time.Hour:
		return fmt.Sprintf("%d min", int(age.Minutes()))
	case age < 48*time.Hour:
		return fmt.Sprintf("%d h", int(age.Hours()))
	}
	return fmt.Sprintf("%d days", int(age.Hours()/24))
}

// primaryIPv4 is the device's most recently seen current IPv4 address, or
// the zero Addr when it has none.
func primaryIPv4(d *devices.Device) netip.Addr {
	var best netip.Addr
	var bestSeen time.Time
	for _, s := range d.IPs {
		a, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		a = a.Unmap()
		if !a.Is4() || a.IsUnspecified() || a.IsMulticast() || a.IsLoopback() {
			continue
		}
		seen := d.IPSeen[s]
		if !best.IsValid() || seen.After(bestSeen) {
			best, bestSeen = a, seen
		}
	}
	return best
}

// DecideV6 says whether d may additionally have its IPv6 traffic steered.
// It is deliberately stricter than Decide and is never reached unless
// Decide already said yes:
//
//   - the per-device "always watch" override does NOT apply. For IPv4 an
//     owner can insist on steering something that looks like
//     infrastructure; for IPv6 they cannot, because the failure docs/IPV6.md
//     exists to prevent — disturbing a Thread border router's or a Matter
//     device's neighbor discovery — is silent and breaks a whole smart
//     home, and no per-device switch should be able to reach it.
//   - the device must hold a unicast IPv6 address to advertise to.
//
// This is also what the Controller's own V6Excluder enforces, so an IPv6
// steer is refused at the call even if something asked for it.
func DecideV6(d *devices.Device, cfg PolicyConfig, now time.Time) Decision {
	skip := func(reason string) Decision { return Decision{State: StateSkipped, Reason: reason, Policy: true} }
	if !cfg.SteerInfrastructure {
		if infra, why := isInfrastructure(d); infra {
			return skip(why + "; IPv6 steering is never forced for this kind of device")
		}
	}
	if !deviceIPv6(d).IsValid() {
		return Decision{State: StateIdle, Reason: "no IPv6 address known for this device"}
	}
	return Decision{Eligible: true, State: StatePending}
}

// deviceIPv6 is the address a Neighbor Advertisement is sent to. A
// link-local address is preferred and is what the design calls for: every
// IPv6 device has one, it never changes with a prefix or a privacy
// rotation, and the device's own default route is resolved over it. A
// global or unique-local address is the fallback when the registry has
// not seen a link-local one.
func deviceIPv6(d *devices.Device) netip.Addr {
	var fallback netip.Addr
	var fallbackSeen time.Time
	for _, s := range d.IPs {
		a, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		a = a.Unmap().WithZone("")
		if !usableDeviceV6(a) {
			continue
		}
		if a.IsLinkLocalUnicast() {
			return a
		}
		if seen := d.IPSeen[s]; !fallback.IsValid() || seen.After(fallbackSeen) {
			fallback, fallbackSeen = a, seen
		}
	}
	return fallback
}

// deviceIPv4s is every current IPv4 address of d, as netip.Addr.
func deviceIPv4s(d *devices.Device) []netip.Addr {
	var out []netip.Addr
	for _, s := range d.IPs {
		a, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		if a = a.Unmap(); a.Is4() {
			out = append(out, a)
		}
	}
	return out
}

// deviceMACs parses d's MACs, dropping anything unparsable.
func deviceMACs(d *devices.Device) []arp.MAC {
	out := make([]arp.MAC, 0, len(d.MACs))
	for _, m := range d.MACs {
		if mac, err := arp.ParseMAC(m); err == nil && !mac.IsZero() {
			out = append(out, mac)
		}
	}
	return out
}

// target is one steerable (MAC, address) pair: the IPv4 address always,
// and the IPv6 address to advertise to when IPv6 steering applies.
type target struct {
	MAC arp.MAC
	IP  netip.Addr
	IP6 netip.Addr
}

// targets works out which (MAC, IPv4) pairs to steer for an eligible
// device. A device with one MAC gets its primary IPv4. A device the
// registry merged from several MACs (a phone seen on Wi-Fi and through a
// dock, say) does not record which of its addresses belongs to which MAC,
// so the host's own neighbour table (neighbors, keyed by IP) is what pairs
// them; a MAC the table has no entry for is left alone, with the reason
// returned in skipped, rather than steered with a guessed address. The
// Controller is keyed by MAC, so each pair is its own steered entry.
func targets(d *devices.Device, neighbors map[netip.Addr]arp.MAC) (out []target, skipped string) {
	macs := deviceMACs(d)
	if len(macs) == 1 {
		if ip := primaryIPv4(d); ip.IsValid() {
			return []target{{MAC: macs[0], IP: ip}}, ""
		}
		return nil, "no IPv4 address known"
	}
	byMAC := map[arp.MAC]netip.Addr{}
	for _, ip := range deviceIPv4s(d) {
		mac, ok := neighbors[ip]
		if !ok {
			continue
		}
		for _, m := range macs {
			if m == mac {
				if prev, has := byMAC[m]; !has || d.IPSeen[ip.String()].After(d.IPSeen[prev.String()]) {
					byMAC[m] = ip
				}
			}
		}
	}
	for _, m := range macs {
		if ip, ok := byMAC[m]; ok {
			out = append(out, target{MAC: m, IP: ip})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MAC.String() < out[j].MAC.String() })
	if len(out) == 0 {
		return nil, "this device has several MACs and the neighbour table does not say which address belongs to which"
	}
	return out, ""
}
