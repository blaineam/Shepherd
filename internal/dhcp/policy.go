// SPDX-License-Identifier: AGPL-3.0-or-later

package dhcp

import (
	"net/netip"
	"slices"
	"strings"

	"shepherd/internal/devices"
)

// Own is everything that belongs to this host, plus the gateway: the things
// that must never be routed through Shepherd whatever any setting says.
//
// All of this host's interfaces, not just the LAN one. A NAS with wired and
// wireless on the same segment has a second interface that looks exactly like
// a LAN device — own MAC, own address, typed by the classifier — and handing
// it Shepherd's own address as its gateway makes Shepherd NAT its own traffic
// to itself. Watch mode has the same refusal for the same reason, with
// measurements attached (internal/watch.Own).
type Own struct {
	MACs    []string
	IPs     []netip.Addr
	Gateway netip.Addr
	// GatewayMAC is the router's own MAC, which catches the case where the
	// router appears under an address Shepherd has not learned yet.
	GatewayMAC string
}

// HasMAC reports whether mac belongs to this host or the gateway.
func (o Own) HasMAC(mac string) bool {
	mac = NormalizeMAC(mac)
	if mac == "" {
		return false
	}
	if NormalizeMAC(o.GatewayMAC) == mac {
		return true
	}
	for _, m := range o.MACs {
		if NormalizeMAC(m) == mac {
			return true
		}
	}
	return false
}

// HasIP reports whether ip belongs to this host or the gateway.
func (o Own) HasIP(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	return ip == o.Gateway || slices.Contains(o.IPs, ip)
}

// Decision is why one device is or is not routed through Shepherd.
type Decision struct {
	// Routed is the answer: true puts Shepherd's own address in option 3.
	Routed bool
	// Reason is the plain-language explanation of a refusal, empty when
	// routed. The portal shows it next to the lease, because "why is this
	// device not going through Shepherd" is the question an operator will
	// actually have.
	Reason string
	// Hard marks a refusal no device switch can override, because
	// overriding it would break the network or make Shepherd route itself.
	Hard bool
}

// RoutePolicy decides which devices get Shepherd's address in option 3.
//
// Routing is all-or-nothing by the maintainer's decision of 2026-11-03
// (docs/DHCP.md): when Route is on, every eligible device is routed, and
// "eligible" is every device minus the refusals below minus the per-device
// opt-out. There is deliberately no per-device opt-in, because a bandwidth
// picture assembled from whichever devices someone remembered to tick is a
// half-truth presented as a number, which is the exact failure this work
// exists to end.
type RoutePolicy struct {
	// Route is the one switch. False routes nothing, which is a complete
	// and safe resting place: Shepherd still serves every lease, with the
	// gateway's own address in option 3, so nothing is on Shepherd's path.
	Route bool
	// RouteConsoles routes game consoles too. Off by default because
	// double NAT is what makes a console's NAT type worse, and the
	// household this was designed for has a PS5 that would notice within
	// one match.
	RouteConsoles bool
	// Own is the set that can never be routed.
	Own Own
	// Lookup resolves a MAC to a device record. Nil means the registry is
	// not available, in which case a device with no record is still routed:
	// refusing on missing information would quietly leave most of the house
	// out of the picture, and the Own checks above do not need the registry.
	Lookup func(mac string) (devices.Device, bool)
}

// Refusal reasons, as constants so the portal and the tests agree on them.
const (
	ReasonRoutingOff   = "routing is off; the gateway is handing out its own address"
	ReasonOwnInterface = "this is one of Shepherd's own interfaces"
	ReasonGateway      = "this is the gateway itself"
	ReasonSwitchOff    = "this device's routing switch is off"
	ReasonExcluded     = "this device is excluded from protection"
	ReasonConsole      = "game consoles are left on the gateway: double NAT makes a console's NAT type worse"
)

// Decide answers for one device, identified by MAC and, when known, address.
func (p RoutePolicy) Decide(mac string, ip netip.Addr) Decision {
	// The hard refusals come first and are checked whether or not routing
	// is on, so the reason an operator reads is the real one rather than
	// "routing is off".
	if p.Own.HasMAC(mac) {
		if NormalizeMAC(p.Own.GatewayMAC) == NormalizeMAC(mac) {
			return Decision{Reason: ReasonGateway, Hard: true}
		}
		return Decision{Reason: ReasonOwnInterface, Hard: true}
	}
	if p.Own.HasIP(ip) {
		if ip == p.Own.Gateway {
			return Decision{Reason: ReasonGateway, Hard: true}
		}
		return Decision{Reason: ReasonOwnInterface, Hard: true}
	}

	var d devices.Device
	var known bool
	if p.Lookup != nil {
		d, known = p.Lookup(mac)
	}
	if known {
		if d.Route == devices.RouteOff {
			return Decision{Reason: ReasonSwitchOff}
		}
		if d.Excluded {
			return Decision{Reason: ReasonExcluded}
		}
	}

	if !p.Route {
		return Decision{Reason: ReasonRoutingOff}
	}

	if known && d.Route == devices.RouteOn {
		// "Always route" overrides the soft refusals below, the way
		// Watch mode's "Always watch" does. It cannot override the hard
		// ones above, which have already returned.
		return Decision{Routed: true}
	}

	if known {
		if infra, why := devices.Infrastructure(&d); infra {
			return Decision{Reason: why}
		}
		if !p.RouteConsoles && isConsole(&d) {
			return Decision{Reason: ReasonConsole}
		}
	}
	return Decision{Routed: true}
}

// isConsole reports whether d is a game console, by type or by a vendor that
// only makes them. The vendor check matters because a console that has not
// been classified yet is exactly the case where getting this wrong is most
// annoying: somebody is mid-match.
func isConsole(d *devices.Device) bool {
	if d.Type == devices.TypeGameConsole {
		return true
	}
	v := strings.ToLower(d.Vendor)
	for _, want := range []string{"sony interactive", "nintendo", "microsoft xbox"} {
		if strings.Contains(v, want) {
			return true
		}
	}
	return false
}
