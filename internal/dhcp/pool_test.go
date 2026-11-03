// SPDX-License-Identifier: AGPL-3.0-or-later

package dhcp

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestPoolBoundsAndSize(t *testing.T) {
	p := Pool{Start: poolStart, End: poolEnd}
	if !p.Valid() {
		t.Fatal("a start below its end is a valid pool")
	}
	if got := p.Size(); got != 11 {
		t.Errorf("Size = %d, want 11 (inclusive)", got)
	}
	if !p.Contains(poolStart) || !p.Contains(poolEnd) || !p.Contains(netip.MustParseAddr("192.0.2.105")) {
		t.Error("Contains is inclusive at both ends")
	}
	if p.Contains(netip.MustParseAddr("192.0.2.99")) || p.Contains(netip.MustParseAddr("192.0.2.111")) {
		t.Error("Contains must not reach outside the range")
	}

	for _, bad := range []Pool{
		{},
		{Start: poolEnd, End: poolStart},
		{Start: netip.MustParseAddr("2001:db8::1"), End: netip.MustParseAddr("2001:db8::2")},
	} {
		if bad.Valid() {
			t.Errorf("%+v should not be a valid pool", bad)
		}
		if bad.Size() != 0 || bad.Contains(poolStart) {
			t.Errorf("%+v should hold nothing", bad)
		}
	}

	// A pool spanning more than the cap is clamped rather than walked a
	// quarter of a billion times.
	huge := Pool{Start: netip.MustParseAddr("192.0.2.0"), End: netip.MustParseAddr("203.0.113.255")}
	if got := huge.Size(); got != maxPool {
		t.Errorf("Size of an absurd pool = %d, want the %d cap", got, maxPool)
	}
}

func TestBroadcastOf(t *testing.T) {
	cases := map[string]string{
		"192.0.2.0/24":  "192.0.2.255",
		"192.0.2.0/25":  "192.0.2.127",
		"192.0.2.64/26": "192.0.2.127",
		"192.0.2.5/32":  "192.0.2.5",
	}
	for in, want := range cases {
		if got := broadcastOf(netip.MustParsePrefix(in)); got.String() != want {
			t.Errorf("broadcastOf(%s) = %s, want %s", in, got, want)
		}
	}
	if broadcastOf(netip.Prefix{}).IsValid() {
		t.Error("an invalid prefix has no broadcast address")
	}
	if broadcastOf(netip.MustParsePrefix("2001:db8::/64")).IsValid() {
		t.Error("this is IPv4 only")
	}
}

func newAllocator(t *testing.T, c *clock, leases *Leases, state *State) *Allocator {
	t.Helper()
	return &Allocator{
		Pool: Pool{Start: poolStart, End: poolEnd}, Subnet: lanPrefix,
		Leases: leases, State: state, Now: c.now,
		Taken: func(ip netip.Addr) bool { return ip == shepherdA || ip == gatewayA },
	}
}

func TestAllocateWalksThePoolAndSkipsWhatIsTaken(t *testing.T) {
	c := newClock()
	leases := NewLeases()
	a := newAllocator(t, c, leases, nil)

	ip, reserved, err := a.Allocate(macA, netip.Addr{})
	if err != nil || reserved {
		t.Fatalf("Allocate = %v, %v, %v", ip, reserved, err)
	}
	if ip != poolStart {
		t.Errorf("the first allocation should be the start of the pool, got %s", ip)
	}
	leases.Put(Lease{MAC: macA, IP: ip, Expires: c.now().Add(time.Hour)})

	// A second device must not be handed the first one's live address.
	ip2, _, err := a.Allocate(macB, netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	if ip2 == ip {
		t.Fatalf("two devices were handed %s", ip)
	}
}

func TestAllocateHonoursTheAddressTheClientAsksForWhenItCan(t *testing.T) {
	c := newClock()
	leases := NewLeases()
	a := newAllocator(t, c, leases, nil)
	want := netip.MustParseAddr("192.0.2.107")
	got, _, err := a.Allocate(macA, want)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("Allocate = %s, want the requested %s: refusing costs a round trip for nothing", got, want)
	}

	// Something outside the pool is refused, unless the device already
	// holds it -- which is how a reserved address, or one from before the
	// pool was narrowed, keeps working.
	outside := netip.MustParseAddr("192.0.2.50")
	got, _, err = a.Allocate(macA, outside)
	if err != nil {
		t.Fatal(err)
	}
	if got == outside {
		t.Error("an address outside the pool should not be granted on request alone")
	}
	leases.Put(Lease{MAC: macB, IP: outside, Expires: c.now().Add(time.Hour)})
	got, _, err = a.Allocate(macB, outside)
	if err != nil {
		t.Fatal(err)
	}
	if got != outside {
		t.Errorf("a device already holding %s should keep it, got %s", outside, got)
	}
}

func TestAllocateKeepsADevicesPreviousAddressAcrossARestart(t *testing.T) {
	c := newClock()
	leases := NewLeases()
	a := newAllocator(t, c, leases, nil)
	held := netip.MustParseAddr("192.0.2.109")
	leases.Put(Lease{MAC: macA, IP: held, Expires: c.now().Add(-time.Minute)}) // expired
	got, _, err := a.Allocate(macA, netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	if got != held {
		t.Errorf("Allocate = %s, want the address it had (%s): that is what makes a short lease time safe", got, held)
	}
}

func TestAllocateHonoursAReservationOverEverything(t *testing.T) {
	c := newClock()
	leases := NewLeases()
	s, _, _ := openState(t)
	pool := Pool{Start: poolStart, End: poolEnd}
	reserved := netip.MustParseAddr("192.0.2.50")
	if err := s.SetReservation(Reservation{MAC: macA, IP: reserved}, lanPrefix, pool); err != nil {
		t.Fatal(err)
	}
	a := newAllocator(t, c, leases, s)

	got, isRes, err := a.Allocate(macA, netip.MustParseAddr("192.0.2.105"))
	if err != nil {
		t.Fatal(err)
	}
	if got != reserved || !isRes {
		t.Fatalf("Allocate = %s, reserved=%v; a reservation is an instruction, not a preference", got, isRes)
	}

	// Another device must never be offered somebody's reserved address,
	// even while nothing holds a lease on it.
	for i := 0; i < pool.Size(); i++ {
		ip, _, err := a.Allocate(macB, netip.Addr{})
		if err != nil {
			t.Fatal(err)
		}
		if ip == reserved {
			t.Fatalf("%s is reserved for %s and was offered to %s", reserved, macA, macB)
		}
		leases.Put(Lease{MAC: macB, IP: ip, Expires: c.now().Add(time.Hour)})
		break
	}
}

// A reservation on the gateway's or Shepherd's own address cannot be
// honoured, and silently handing out something else would hide an operator
// mistake -- so it falls through to the pool and the portal's validation is
// where it is caught.
func TestAllocateFallsThroughWhenAReservedAddressIsStructurallyImpossible(t *testing.T) {
	c := newClock()
	leases := NewLeases()
	a := newAllocator(t, c, leases, nil)
	a.Reserve = func(string) (Reservation, bool) { return Reservation{MAC: macA, IP: gatewayA}, true }
	got, isRes, err := a.Allocate(macA, netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	if isRes || got == gatewayA {
		t.Fatalf("Allocate = %s, reserved=%v; the gateway's address can never be handed out", got, isRes)
	}
}

func TestAllocateReportsAnExhaustedPool(t *testing.T) {
	c := newClock()
	leases := NewLeases()
	a := newAllocator(t, c, leases, nil)
	ip := poolStart
	for i := 0; i < 11; i++ {
		mac := NormalizeMAC("02005e0000" + string("0123456789a"[i]) + "0")
		if mac == "" {
			t.Fatalf("test MAC %d is unusable", i)
		}
		leases.Put(Lease{MAC: mac, IP: ip, Expires: c.now().Add(time.Hour)})
		ip = ip.Next()
	}
	if _, _, err := a.Allocate(macA, netip.Addr{}); !errors.Is(err, ErrPoolExhausted) {
		t.Fatalf("error = %v, want ErrPoolExhausted", err)
	}
}

func TestAllocateRefusesAnUnusableMACOrNoPool(t *testing.T) {
	c := newClock()
	a := newAllocator(t, c, NewLeases(), nil)
	if _, _, err := a.Allocate("nonsense", netip.Addr{}); err == nil {
		t.Error("a request with no usable MAC cannot be allocated")
	}
	a.Pool = Pool{}
	if _, _, err := a.Allocate(macA, netip.Addr{}); err == nil {
		t.Error("with no pool there is nothing to hand out")
	}
}

func TestAllocateWillNotOfferAnAddressAClientDeclined(t *testing.T) {
	c := newClock()
	leases := NewLeases()
	a := newAllocator(t, c, leases, nil)
	leases.Put(Lease{MAC: macB, IP: poolStart, Expires: c.now().Add(time.Hour)})
	leases.Decline(macB, poolStart)
	got, _, err := a.Allocate(macA, poolStart)
	if err != nil {
		t.Fatal(err)
	}
	if got == poolStart {
		t.Errorf("%s was declined, so something on the network holds it and Shepherd cannot see it", poolStart)
	}
}

func TestAllocatorRefusesTheNetworkAndBroadcastAddresses(t *testing.T) {
	c := newClock()
	a := newAllocator(t, c, NewLeases(), nil)
	for _, ip := range []netip.Addr{
		netip.MustParseAddr("192.0.2.0"),
		netip.MustParseAddr("192.0.2.255"),
		netip.MustParseAddr("198.51.100.1"), // outside the LAN
		{},
		netip.MustParseAddr("2001:db8::1"),
	} {
		if !a.taken(ip) {
			t.Errorf("%v must never be handed out", ip)
		}
	}
	if a.taken(poolStart) {
		t.Errorf("%s is an ordinary pool address", poolStart)
	}
}

func TestAllocatorWithoutAClockUsesTheRealOne(t *testing.T) {
	a := &Allocator{Pool: Pool{Start: poolStart, End: poolEnd}, Subnet: lanPrefix, Leases: NewLeases()}
	if a.now().IsZero() {
		t.Error("an allocator with no clock still has a now")
	}
}

func TestFreeRefusesAnAddressSomebodyElseHasReserved(t *testing.T) {
	c := newClock()
	leases := NewLeases()
	s, _, _ := openState(t)
	pool := Pool{Start: poolStart, End: poolEnd}
	outside := netip.MustParseAddr("192.0.2.50")
	if err := s.SetReservation(Reservation{MAC: macB, IP: outside}, lanPrefix, pool); err != nil {
		t.Fatal(err)
	}
	a := newAllocator(t, c, leases, s)
	if a.free(outside, macA, c.now()) {
		t.Error("another device's reservation is never free, lease or no lease")
	}
	if !a.free(outside, macB, c.now()) {
		t.Error("but it is free for the device it belongs to")
	}

	// An expired lease held by somebody else does not block it.
	leases.Put(Lease{MAC: macB, IP: poolStart, Expires: c.now().Add(-time.Minute)})
	if !a.free(poolStart, macA, c.now()) {
		t.Error("an expired lease does not hold an address")
	}
	// But a live one does.
	leases.Put(Lease{MAC: macB, IP: poolStart, Expires: c.now().Add(time.Hour)})
	if a.free(poolStart, macA, c.now()) {
		t.Error("a live lease holds its address")
	}
	// And a declined address is held by something Shepherd cannot see.
	leases.Decline(macB, poolStart)
	if a.free(poolStart, macA, c.now()) {
		t.Error("a declined address stays out of the pool for everyone else")
	}
	if !a.free(poolStart, macB, c.now()) {
		t.Error("the device that declined it may still be offered it again, having said why")
	}
}

func TestHeldByIsFalseForADeviceWithNoLease(t *testing.T) {
	c := newClock()
	a := newAllocator(t, c, NewLeases(), nil)
	if a.heldBy(poolStart, macA) {
		t.Error("a device with no lease holds nothing")
	}
}
