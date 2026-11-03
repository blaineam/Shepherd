// SPDX-License-Identifier: AGPL-3.0-or-later

package dhcp

import (
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// Pool is the inclusive range of addresses the allocator hands out
// dynamically. Reserved addresses live outside it, which Reservation.Validate
// enforces.
type Pool struct {
	Start netip.Addr `json:"start"`
	End   netip.Addr `json:"end"`
}

// Valid reports whether the pool is a usable IPv4 range.
func (p Pool) Valid() bool {
	return p.Start.IsValid() && p.End.IsValid() && p.Start.Is4() && p.End.Is4() && p.Start.Compare(p.End) <= 0
}

// Contains reports whether ip falls in the range.
func (p Pool) Contains(ip netip.Addr) bool {
	return p.Valid() && ip.Is4() && p.Start.Compare(ip) <= 0 && ip.Compare(p.End) <= 0
}

// Size is how many addresses the pool holds. It is capped because a
// misconfigured pool spanning a /8 would otherwise make every full-pool walk
// take a quarter of a billion steps.
func (p Pool) Size() int {
	if !p.Valid() {
		return 0
	}
	s, e := p.Start.As4(), p.End.As4()
	n := int64(uint32(e[0])<<24|uint32(e[1])<<16|uint32(e[2])<<8|uint32(e[3])) -
		int64(uint32(s[0])<<24|uint32(s[1])<<16|uint32(s[2])<<8|uint32(s[3])) + 1
	if n > maxPool {
		return maxPool
	}
	return int(n)
}

// maxPool bounds a pool walk. A home LAN that needs more than this has
// outgrown the assumption this whole package is built on (one flat segment).
const maxPool = 65536

// ErrPoolExhausted means every address in the pool is taken by an active
// lease. The server answers nothing in that case rather than handing out an
// address it knows is in use; the client retries, and by then a lease may
// have expired.
var ErrPoolExhausted = errors.New("dhcp: address pool exhausted")

// Allocator chooses the address for one request. It owns no state: everything
// it needs is the lease store, the reservations and the moment.
type Allocator struct {
	Pool    Pool
	Subnet  netip.Prefix
	Leases  *Leases
	State   *State
	Now     func() time.Time
	Reserve func(mac string) (Reservation, bool) // nil uses State
	// Taken reports addresses that must never be offered whatever the
	// leases say: Shepherd's own addresses, the gateway's, the network and
	// broadcast addresses. Keeping it a function rather than a slice means
	// the caller can recompute it when an interface changes.
	Taken func(netip.Addr) bool
}

func (a *Allocator) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *Allocator) reservation(mac string) (Reservation, bool) {
	if a.Reserve != nil {
		return a.Reserve(mac)
	}
	if a.State == nil {
		return Reservation{}, false
	}
	return a.State.Reservation(mac)
}

func (a *Allocator) taken(ip netip.Addr) bool {
	if !ip.IsValid() || !ip.Is4() {
		return true
	}
	if a.Subnet.IsValid() {
		if !a.Subnet.Contains(ip) {
			return true
		}
		if ip == a.Subnet.Masked().Addr() || ip == broadcastOf(a.Subnet) {
			return true
		}
	}
	return a.Taken != nil && a.Taken(ip)
}

// broadcastOf returns the all-ones address of a prefix.
func broadcastOf(p netip.Prefix) netip.Addr {
	if !p.IsValid() || !p.Addr().Is4() {
		return netip.Addr{}
	}
	b := p.Masked().Addr().As4()
	host := 32 - p.Bits()
	for i := 0; i < host; i++ {
		b[3-i/8] |= 1 << (i % 8)
	}
	return netip.AddrFrom4(b)
}

// free reports whether ip can be offered to mac: not structurally taken, and
// either unleased, leased to mac already, or holding a lease that has
// expired.
func (a *Allocator) free(ip netip.Addr, mac string, now time.Time) bool {
	if a.taken(ip) {
		return false
	}
	if l, ok := a.Leases.ByIP(ip); ok {
		if l.MAC != mac && l.Active(now) {
			return false
		}
		// An address a client declined is in use by something Shepherd
		// cannot see, so it stays out of the pool whoever asks for it.
		if l.Declines > 0 && l.MAC != mac {
			return false
		}
	}
	// Someone else's reservation is never free, active lease or not: the
	// reservation is the intent and the lease is only a cache of it.
	for _, r := range a.reservations() {
		if r.MAC != mac && r.IP.IsValid() && r.IP == ip {
			return false
		}
	}
	return true
}

func (a *Allocator) reservations() []Reservation {
	if a.State == nil {
		return nil
	}
	return a.State.Reservations()
}

// Allocate chooses an address for mac, honouring, in order: the reservation,
// the address the client asked for, the address it held last time, then the
// next free address in the pool.
//
// That order is deliberate. A reservation is an instruction. A requested
// address is usually a client renewing something it already has, and refusing
// it causes a round trip for no reason. The previous lease keeps a device's
// address stable across a Shepherd restart, which is what makes a short lease
// time safe to use.
func (a *Allocator) Allocate(mac string, requested netip.Addr) (ip netip.Addr, reserved bool, err error) {
	mac = NormalizeMAC(mac)
	if mac == "" {
		return netip.Addr{}, false, fmt.Errorf("dhcp: allocate: no usable MAC address")
	}
	now := a.now()

	if r, ok := a.reservation(mac); ok && r.IP.IsValid() {
		// A reservation is honoured even when something else currently
		// holds the address: the other device loses the lease and gets a
		// different address when it next asks. Refusing the reservation
		// instead would leave a printer wandering for as long as the
		// squatter kept renewing.
		if !a.taken(r.IP) {
			return r.IP, true, nil
		}
		// Structurally impossible addresses (the gateway's, Shepherd's
		// own, the broadcast address) are the one case a reservation
		// cannot have, and silently handing out something else would hide
		// an operator mistake. Fall through to the pool and let the
		// portal's validation be where this is caught.
	}

	if requested.IsValid() && a.free(requested, mac, now) && (a.Pool.Contains(requested) || a.heldBy(requested, mac)) {
		return requested, false, nil
	}

	if l, ok := a.Leases.Get(mac); ok && l.IP.IsValid() && a.free(l.IP, mac, now) {
		return l.IP, false, nil
	}

	if !a.Pool.Valid() {
		return netip.Addr{}, false, fmt.Errorf("dhcp: allocate: no usable address pool")
	}
	// Walk from the address after the last one handed out, so a restart
	// does not immediately re-offer an address a device has just declined.
	ip = a.Pool.Start
	for i := 0; i < a.Pool.Size(); i++ {
		if a.free(ip, mac, now) {
			return ip, false, nil
		}
		ip = ip.Next()
		if !a.Pool.Contains(ip) {
			break
		}
	}
	return netip.Addr{}, false, ErrPoolExhausted
}

// heldBy reports whether mac already holds ip, which is what makes it safe to
// honour a requested address that sits outside the pool — a reserved address,
// or one from before the pool was narrowed.
func (a *Allocator) heldBy(ip netip.Addr, mac string) bool {
	l, ok := a.Leases.Get(mac)
	return ok && l.IP == ip
}
