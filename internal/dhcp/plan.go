// SPDX-License-Identifier: AGPL-3.0-or-later

package dhcp

import (
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
)

// Range is the addressing an operator has chosen to serve: which private
// range the LAN should use, where Shepherd and the router sit in it, and
// which part of it is handed out dynamically.
//
// It exists because the range is a preference, not a fact. Somebody who
// wants their LAN on 192.0.2.0/24 rather than 198.51.100.0/24 should be able
// to say so here and be told, in plain language, exactly what has to change
// on the router before it can happen — rather than having Shepherd quietly
// hand out addresses nothing can route.
//
// An empty Range means "whatever the interface and the configuration file
// already say", which is the default and needs no decision.
type Range struct {
	Subnet   netip.Prefix `json:"subnet,omitempty"`
	ServerIP netip.Addr   `json:"server_ip,omitempty"`
	Gateway  netip.Addr   `json:"gateway,omitempty"`
	Pool     Pool         `json:"pool,omitempty"`
}

// Set reports whether the operator has chosen a range at all.
func (r Range) Set() bool { return r.Subnet.IsValid() }

// Apply overlays the chosen range on the settings taken from the
// configuration file and the interface. Anything the range leaves unset
// keeps what was there.
func (r Range) Apply(s Settings) Settings {
	if !r.Set() {
		return s
	}
	s.Subnet = r.Subnet
	if r.ServerIP.IsValid() {
		s.ServerIP = r.ServerIP
	}
	if r.Gateway.IsValid() {
		s.Gateway = r.Gateway
	}
	if r.Pool.Valid() {
		s.Pool = r.Pool
	}
	// The resolvers follow Shepherd's own address unless they were set to
	// something else entirely: handing out an address in a range nobody
	// uses any more is the commonest way this goes wrong.
	if len(s.DNS) == 1 && r.ServerIP.IsValid() {
		s.DNS = []netip.Addr{r.ServerIP}
	}
	return s
}

// Validate normalizes a chosen range and reports what is wrong with it on
// its own terms, before anything about the live network is considered.
func (r *Range) Validate() error {
	if !r.Subnet.IsValid() || !r.Subnet.Addr().Is4() {
		return fmt.Errorf("%w: choose an IPv4 range in CIDR form, like 192.0.2.0/24", ErrRange)
	}
	r.Subnet = r.Subnet.Masked()
	if bits := r.Subnet.Bits(); bits < 16 || bits > 30 {
		return fmt.Errorf("%w: the prefix must be between /16 and /30; %s is %s", ErrRange, r.Subnet, prefixSize(bits))
	}
	if !r.Subnet.Addr().IsPrivate() {
		return fmt.Errorf("%w: %s is not a private range. A LAN uses %s", ErrRange, r.Subnet, rfc1918)
	}
	for _, f := range []struct {
		name string
		addr netip.Addr
	}{{"Shepherd's own address", r.ServerIP}, {"the router's address", r.Gateway}} {
		if !f.addr.IsValid() {
			return fmt.Errorf("%w: %s in the new range is required", ErrRange, f.name)
		}
		if !f.addr.Is4() {
			return fmt.Errorf("%w: %s must be IPv4", ErrRange, f.name)
		}
		if !r.Subnet.Contains(f.addr) {
			return fmt.Errorf("%w: %s (%s) is not inside %s", ErrRange, f.name, f.addr, r.Subnet)
		}
		if f.addr == r.Subnet.Addr() || f.addr == broadcastOf(r.Subnet) {
			return fmt.Errorf("%w: %s cannot be the network or broadcast address of %s", ErrRange, f.name, r.Subnet)
		}
	}
	if r.ServerIP == r.Gateway {
		return fmt.Errorf("%w: Shepherd and the router cannot share the address %s", ErrRange, r.ServerIP)
	}
	if !r.Pool.Valid() {
		return fmt.Errorf("%w: a pool to hand out from is required, as a start and an end address", ErrRange)
	}
	if !r.Subnet.Contains(r.Pool.Start) || !r.Subnet.Contains(r.Pool.End) {
		return fmt.Errorf("%w: the pool %s-%s is not inside %s", ErrRange, r.Pool.Start, r.Pool.End, r.Subnet)
	}
	if r.Pool.Contains(r.ServerIP) {
		return fmt.Errorf("%w: Shepherd's own address %s is inside the pool, so it could be handed to a device", ErrRange, r.ServerIP)
	}
	if r.Pool.Contains(r.Gateway) {
		return fmt.Errorf("%w: the router's address %s is inside the pool, so it could be handed to a device", ErrRange, r.Gateway)
	}
	return nil
}

func prefixSize(bits int) string {
	if bits < 16 {
		return "larger than a /16, which is more addresses than a household segment should be"
	}
	return "smaller than a /30, which leaves no usable addresses"
}

// rfc1918 names the three ranges a LAN may use, for the message somebody
// reads when they have typed a public one by mistake. These are RFC 1918's
// own prefixes rather than anybody's network.
const rfc1918 = "10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16" // leakcheck:allow

// ErrRange is the base for every rejected range.
var ErrRange = fmt.Errorf("dhcp: range")

// Holder is one address Shepherd can see in use on the network right now,
// and who has it. It comes from the device registry, which learns addresses
// from DNS queries, the neighbour table, mDNS and — once this mode is
// watching — from DHCP itself.
type Holder struct {
	IP   netip.Addr
	MAC  string
	Name string
	// Leased marks an address Shepherd itself handed out, which is the one
	// kind that moves on its own at the next renewal.
	Leased bool
}

// Observed is the network as Shepherd can see it now: this host's own
// addresses and prefixes, the gateway the default route points at, and every
// address the registry knows is in use.
type Observed struct {
	HostNets  []netip.Prefix
	HostAddrs []netip.Addr
	Gateway   netip.Addr
	Holders   []Holder
}

// Severity says whether a conflict stops Shepherd serving or is only
// something to know.
type Severity string

// The two severities.
const (
	// Blocking means Shepherd will not serve while it stands. Every one of
	// these would either hand an address out twice or leave devices with
	// no way off the segment.
	Blocking Severity = "blocking"
	// Warning means it will serve, and the operator should know anyway.
	Warning Severity = "warning"
)

// Conflict is one reason a chosen range does not fit the network as it is.
// Detail is written to be read by the person who has to fix it, and it says
// what to change rather than only what is wrong.
type Conflict struct {
	Severity Severity `json:"severity"`
	Kind     string   `json:"kind"`
	Detail   string   `json:"detail"`
}

// Conflict kinds, as constants so the portal and the tests agree.
const (
	ConflictNoHostAddress   = "no-host-address"
	ConflictRouterElsewhere = "router-elsewhere"
	ConflictStaticInPool    = "static-in-pool"
	ConflictDevicesMoving   = "devices-moving"
	ConflictReservation     = "reservation-outside"
	ConflictRangeInvalid    = "range-invalid"
)

// Check compares a chosen range against the network as it is and returns
// every reason it does not fit, blocking ones first.
//
// The rule it enforces is the one that makes this mode safe to offer at all:
// **Shepherd is not the router.** It serves the leases and masquerades what
// it forwards, but the router is still the way off the segment for every
// device Shepherd does not route, and it is still the next hop for the ones
// it does. So a range the router does not itself use cannot be served, and
// saying so plainly — with the address the router would have to move to — is
// more useful than letting somebody discover it at two in the morning.
//
// res is the stored reservations, which are checked against the new range
// too: a reservation outside it cannot be honoured.
func Check(r Range, o Observed, res []Reservation) []Conflict {
	var out []Conflict
	add := func(sev Severity, kind, detail string) {
		out = append(out, Conflict{Severity: sev, Kind: kind, Detail: detail})
	}

	check := r
	if err := check.Validate(); err != nil {
		add(Blocking, ConflictRangeInvalid, strings.TrimPrefix(err.Error(), "dhcp: range: "))
		return out
	}
	r = check

	// Shepherd has to hold an address in the range it serves, or its own
	// replies cannot reach the clients it is addressing.
	if !slices.ContainsFunc(o.HostAddrs, func(a netip.Addr) bool { return a == r.ServerIP }) {
		if hasAddrIn(o.HostAddrs, r.Subnet) {
			add(Blocking, ConflictNoHostAddress, fmt.Sprintf(
				"This host has an address in %s but not %s. Give the LAN interface %s, or choose the address it already has.",
				r.Subnet, r.ServerIP, r.ServerIP))
		} else {
			add(Blocking, ConflictNoHostAddress, fmt.Sprintf(
				"This host has no address in %s, so Shepherd could not answer a client it had addressed. Add %s to the LAN interface first — usually by changing the router's LAN to %s and letting this host pick up a new address.",
				r.Subnet, r.ServerIP, r.Subnet))
		}
	}

	// And the router has to be where the leases say it is, because it is
	// the way off the segment for everything Shepherd does not route and
	// the next hop for everything it does.
	if o.Gateway.IsValid() && o.Gateway != r.Gateway {
		add(Blocking, ConflictRouterElsewhere, fmt.Sprintf(
			"The router answers at %s today, not %s. Change its LAN address to %s (and its own subnet to %s) before serving this range: until then every device Shepherd does not route would be handed a gateway that does not exist.",
			o.Gateway, r.Gateway, r.Gateway, r.Subnet))
	}

	// An address somebody is holding statically inside the pool is the
	// collision that matters most: the pool would hand it out a second
	// time, and both devices would then be wrong.
	var static, moving []Holder
	for _, h := range o.Holders {
		if !h.IP.IsValid() || !h.IP.Is4() {
			continue
		}
		if h.IP == r.ServerIP || h.IP == r.Gateway || h.IP == o.Gateway {
			continue
		}
		if hostHas(o.HostAddrs, h.IP) {
			continue
		}
		switch {
		case r.Pool.Contains(h.IP) && !h.Leased:
			static = append(static, h)
		case !r.Subnet.Contains(h.IP):
			moving = append(moving, h)
		}
	}
	if len(static) > 0 {
		add(Blocking, ConflictStaticInPool, fmt.Sprintf(
			"%s already in use inside the pool %s-%s, and Shepherd did not hand %s out: %s. Shrink the pool past %s, or give %s a reservation outside it.",
			plural(len(static), "address is", "addresses are"), r.Pool.Start, r.Pool.End,
			pick(len(static) == 1, "it", "them"), holderList(static),
			pick(len(static) == 1, "that address", "those addresses"),
			pick(len(static) == 1, "that device", "those devices")))
	}
	if len(moving) > 0 {
		add(Warning, ConflictDevicesMoving, fmt.Sprintf(
			"%s outside %s and will move into it at the next renewal: %s. Anything with a hand-configured address will not move on its own and has to be changed by hand.",
			plural(len(moving), "device is", "devices are"), r.Subnet, holderList(moving)))
	}

	var outside []string
	for _, rr := range res {
		if rr.IP.IsValid() && !r.Subnet.Contains(rr.IP) {
			outside = append(outside, rr.IP.String()+" ("+rr.MAC+")")
		}
	}
	if len(outside) > 0 {
		sort.Strings(outside)
		add(Warning, ConflictReservation, fmt.Sprintf(
			"%s outside %s and cannot be honoured there: %s. Change or remove %s.",
			plural(len(outside), "reservation is", "reservations are"), r.Subnet, strings.Join(outside, ", "),
			pick(len(outside) == 1, "it", "them")))
	}

	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Severity == Blocking && out[j].Severity != Blocking
	})
	return out
}

// Blocked reports the first blocking conflict, which is what the serve gate
// refuses on.
func Blocked(cs []Conflict) (Conflict, bool) {
	for _, c := range cs {
		if c.Severity == Blocking {
			return c, true
		}
	}
	return Conflict{}, false
}

func hasAddrIn(addrs []netip.Addr, p netip.Prefix) bool {
	return slices.ContainsFunc(addrs, func(a netip.Addr) bool { return p.Contains(a) })
}

func hostHas(addrs []netip.Addr, ip netip.Addr) bool {
	return slices.Contains(addrs, ip)
}

func pick(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "One " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// holderList names the devices in a conflict, newest-looking name first and
// capped: a list of forty addresses is not something anybody reads.
func holderList(hs []Holder) string {
	slices.SortFunc(hs, func(a, b Holder) int { return a.IP.Compare(b.IP) })
	const max = 6
	parts := make([]string, 0, len(hs))
	for i, h := range hs {
		if i == max {
			parts = append(parts, fmt.Sprintf("and %d more", len(hs)-max))
			break
		}
		if h.Name != "" {
			parts = append(parts, h.IP.String()+" ("+h.Name+")")
		} else {
			parts = append(parts, h.IP.String())
		}
	}
	return strings.Join(parts, ", ")
}
