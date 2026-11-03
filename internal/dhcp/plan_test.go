// SPDX-License-Identifier: AGPL-3.0-or-later

package dhcp

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// A chosen range on 192.168.1.0/24 while the interface is on the
// documentation range is the case the whole check exists for: somebody who
// wants their addresses to read differently. A chosen range has to be a
// private one -- Range.Validate refuses anything else, and that is the point
// -- so every example of one here uses the single private range this
// repository's leakcheck allows as generic.
func goodRange() Range { return privRange() }

func TestRangeValidateAcceptsAWholeRangeAndNormalizesIt(t *testing.T) {
	r := goodRange()
	r.Subnet = netip.MustParsePrefix("192.168.1.37/24") // a host address with a prefix
	if err := r.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if r.Subnet.String() != "192.168.1.0/24" {
		t.Errorf("Subnet = %s, want it masked to the network address", r.Subnet)
	}
	if !r.Set() {
		t.Error("a range with a subnet is set")
	}
	if (Range{}).Set() {
		t.Error("and an empty one is not")
	}
}

func TestRangeValidateRefusesEachWayARangeIsWrong(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Range)
		want string
	}{
		{"no subnet", func(r *Range) { r.Subnet = netip.Prefix{} }, "CIDR form"},
		{"IPv6", func(r *Range) { r.Subnet = netip.MustParsePrefix("2001:db8::/64") }, "IPv4"},
		{"too large", func(r *Range) { r.Subnet = netip.MustParsePrefix("192.168.1.0/15") }, "between /16 and /30"},
		{"too small", func(r *Range) { r.Subnet = netip.MustParsePrefix("192.168.1.0/31") }, "between /16 and /30"},
		{"not private", func(r *Range) {
			r.Subnet = netip.MustParsePrefix("192.0.2.0/24")
			r.ServerIP, r.Gateway = netip.MustParseAddr("192.0.2.20"), netip.MustParseAddr("192.0.2.1")
			r.Pool = Pool{Start: netip.MustParseAddr("192.0.2.100"), End: netip.MustParseAddr("192.0.2.200")}
		}, "private range"},
		{"no Shepherd address", func(r *Range) { r.ServerIP = netip.Addr{} }, "Shepherd's own address"},
		{"no router address", func(r *Range) { r.Gateway = netip.Addr{} }, "the router's address"},
		{"Shepherd outside", func(r *Range) { r.ServerIP = netip.MustParseAddr("198.51.100.2") }, "not inside"},
		{"Shepherd on the network address", func(r *Range) { r.ServerIP = netip.MustParseAddr("192.168.1.0") }, "network or broadcast"},
		{"router on the broadcast address", func(r *Range) { r.Gateway = netip.MustParseAddr("192.168.1.255") }, "network or broadcast"},
		{"one address for both", func(r *Range) { r.Gateway = r.ServerIP }, "cannot share"},
		{"no pool", func(r *Range) { r.Pool = Pool{} }, "a pool to hand out from"},
		{"pool outside", func(r *Range) {
			r.Pool = Pool{Start: netip.MustParseAddr("198.51.100.10"), End: netip.MustParseAddr("198.51.100.20")}
		}, "not inside"},
		{"Shepherd in the pool", func(r *Range) { r.ServerIP = netip.MustParseAddr("192.168.1.105") }, "inside the pool"},
		{"router in the pool", func(r *Range) { r.Gateway = netip.MustParseAddr("192.168.1.105") }, "inside the pool"},
	}
	for _, c := range cases {
		r := goodRange()
		c.edit(&r)
		err := r.Validate()
		if err == nil {
			t.Errorf("%s: want an error", c.name)
			continue
		}
		if !errors.Is(err, ErrRange) {
			t.Errorf("%s: error does not wrap ErrRange: %v", c.name, err)
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q should mention %q", c.name, err, c.want)
		}
	}
}

func TestApplyOverlaysTheChosenRangeOnWhatTheInterfaceGave(t *testing.T) {
	base := testSettings()
	got := goodRange().Apply(base)
	if got.Subnet.String() != "192.168.1.0/24" || got.ServerIP.String() != "192.168.1.20" || got.Gateway.String() != "192.168.1.1" {
		t.Fatalf("Apply = %+v", got)
	}
	if got.Pool.Start.String() != "192.168.1.100" {
		t.Errorf("Pool = %+v", got.Pool)
	}
	// Handing out a resolver in a range nobody uses any more is the
	// commonest way this goes wrong, so a lone resolver follows Shepherd.
	if len(got.DNS) != 1 || got.DNS[0].String() != "192.168.1.20" {
		t.Errorf("DNS = %v, want Shepherd's new address", got.DNS)
	}
	// Two configured resolvers are the operator's own choice and are left
	// alone.
	base.DNS = append(base.DNS, netip.MustParseAddr("192.0.2.53"))
	if got := goodRange().Apply(base); len(got.DNS) != 2 {
		t.Errorf("DNS = %v, want both left as configured", got.DNS)
	}
	// An unset range changes nothing at all.
	if got := (Range{}).Apply(base); got.Subnet != base.Subnet || got.ServerIP != base.ServerIP {
		t.Errorf("an unset range should change nothing, got %+v", got)
	}
	// A range with only a subnet keeps the rest.
	partial := Range{Subnet: netip.MustParsePrefix("192.168.1.0/24")}
	if got := partial.Apply(base); got.ServerIP != base.ServerIP || got.Pool.Start != base.Pool.Start {
		t.Errorf("a partial range should keep what it does not set, got %+v", got)
	}
}

// A real LAN has to be a private range -- Range.Validate refuses anything
// else, and that is the point -- so these fixtures use the one private range
// this repository's leakcheck allows as a generic example. The rest of the
// package's tests use the documentation range, which no household would
// actually be on.
var (
	privLAN      = netip.MustParsePrefix("192.168.1.0/24")
	privShepherd = netip.MustParseAddr("192.168.1.20")
	privGateway  = netip.MustParseAddr("192.168.1.1")
	privPool     = Pool{Start: netip.MustParseAddr("192.168.1.100"), End: netip.MustParseAddr("192.168.1.110")}
)

func privRange() Range {
	return Range{Subnet: privLAN, ServerIP: privShepherd, Gateway: privGateway, Pool: privPool}
}

// lanAsItIs is the network before anything is changed. It is on the
// documentation range, which no household would really be on, and that does
// not matter: Observed is what Shepherd sees rather than something it
// validates.
func lanAsItIs() Observed {
	return Observed{
		HostNets:  []netip.Prefix{lanPrefix},
		HostAddrs: []netip.Addr{shepherdA},
		Gateway:   gatewayA,
		Holders: []Holder{
			{IP: netip.MustParseAddr("192.0.2.31"), MAC: macA, Name: "Garage Camera"},
			{IP: netip.MustParseAddr("192.0.2.47"), MAC: macB, Name: "Kitchen Speaker"},
		},
	}
}

// privLANAsItIs is the same network after the router has been moved onto the
// chosen range, which is the state the check has to pass.
func privLANAsItIs() Observed {
	return Observed{
		HostNets:  []netip.Prefix{privLAN},
		HostAddrs: []netip.Addr{privShepherd},
		Gateway:   privGateway,
		Holders: []Holder{
			{IP: netip.MustParseAddr("192.168.1.31"), MAC: macA, Name: "Garage Camera"},
			{IP: netip.MustParseAddr("192.168.1.47"), MAC: macB, Name: "Kitchen Speaker"},
		},
	}
}

// The rule the whole thing rests on: Shepherd serves the leases, the router
// still routes. A range the router does not use cannot be served, and saying
// which address it would have to move to is the useful part.
func TestCheckRefusesARangeTheRouterDoesNotUseYet(t *testing.T) {
	cs := Check(goodRange(), lanAsItIs(), nil)
	if len(cs) == 0 {
		t.Fatal("a range nothing on this network uses must not be served")
	}
	c, blocked := Blocked(cs)
	if !blocked {
		t.Fatalf("want a blocking conflict, got %+v", cs)
	}
	_ = c

	kinds := map[string]string{}
	for _, x := range cs {
		kinds[x.Kind] = x.Detail
	}
	host, ok := kinds[ConflictNoHostAddress]
	if !ok {
		t.Fatalf("want a %s conflict, got %+v", ConflictNoHostAddress, cs)
	}
	if !strings.Contains(host, privShepherd.String()) || !strings.Contains(host, privLAN.String()) {
		t.Errorf("the detail should name the address to add: %q", host)
	}
	router, ok := kinds[ConflictRouterElsewhere]
	if !ok {
		t.Fatalf("want a %s conflict, got %+v", ConflictRouterElsewhere, cs)
	}
	if !strings.Contains(router, gatewayA.String()) || !strings.Contains(router, privGateway.String()) {
		t.Errorf("the detail should name where the router is and where it must go: %q", router)
	}
	// And the devices that would move are a note, not a refusal.
	moving, ok := kinds[ConflictDevicesMoving]
	if !ok {
		t.Fatalf("want a %s note, got %+v", ConflictDevicesMoving, cs)
	}
	if !strings.Contains(moving, "Garage Camera") || !strings.Contains(moving, "by hand") {
		t.Errorf("the note should name the devices and what will not move on its own: %q", moving)
	}
	for _, x := range cs {
		if x.Kind == ConflictDevicesMoving && x.Severity != Warning {
			t.Error("devices moving is a warning: they renew into the new range on their own")
		}
	}
	// Blocking conflicts come first, because that is what gets read.
	if cs[0].Severity != Blocking {
		t.Errorf("conflicts are not sorted: %+v", cs)
	}
}

func TestCheckPassesARangeTheNetworkAlreadyUses(t *testing.T) {
	cs := Check(privRange(), privLANAsItIs(), nil)
	if len(cs) != 0 {
		t.Fatalf("the range already in use should fit: %+v", cs)
	}
	if _, blocked := Blocked(cs); blocked {
		t.Error("and nothing should be blocking")
	}
}

// The collision the maintainer asked for by name: a device holding an
// address inside the pool that Shepherd did not hand out.
func TestCheckRefusesAStaticAddressInsideThePool(t *testing.T) {
	o := privLANAsItIs()
	o.Holders = append(o.Holders, Holder{IP: netip.MustParseAddr("192.168.1.105"), MAC: macA, Name: "Office Printer"})
	r := privRange()

	cs := Check(r, o, nil)
	c, blocked := Blocked(cs)
	if !blocked || c.Kind != ConflictStaticInPool {
		t.Fatalf("want a blocking %s, got %+v", ConflictStaticInPool, cs)
	}
	if !strings.Contains(c.Detail, "192.168.1.105") || !strings.Contains(c.Detail, "Office Printer") {
		t.Errorf("the detail should name the address and the device: %q", c.Detail)
	}
	if !strings.Contains(c.Detail, "Shrink the pool") || !strings.Contains(c.Detail, "reservation") {
		t.Errorf("the detail should say what to do about it: %q", c.Detail)
	}

	// An address Shepherd itself leased is not a collision: it moves on
	// its own at the next renewal.
	o.Holders[len(o.Holders)-1].Leased = true
	if cs := Check(r, o, nil); len(cs) != 0 {
		t.Errorf("a leased address inside the pool is not a conflict: %+v", cs)
	}
}

func TestCheckIgnoresTheAddressesThatAreNotDevices(t *testing.T) {
	o := privLANAsItIs()
	o.Holders = append(o.Holders,
		Holder{IP: privShepherd, Name: "this host"},
		Holder{IP: privGateway, Name: "the router"},
		Holder{IP: netip.Addr{}, Name: "nothing"},
		Holder{IP: netip.MustParseAddr("2001:db8::1"), Name: "IPv6"},
	)
	if cs := Check(privRange(), o, nil); len(cs) != 0 {
		t.Fatalf("Shepherd, the router and non-IPv4 addresses are not collisions: %+v", cs)
	}
}

func TestCheckNotesAReservationOutsideTheNewRange(t *testing.T) {
	res := []Reservation{
		{MAC: macA, IP: netip.MustParseAddr("192.168.1.50")},
		{MAC: macB, IP: netip.MustParseAddr("198.51.100.5")},
		{MAC: "02:00:5e:01:02:09"}, // name only, nothing to check
	}
	cs := Check(privRange(), privLANAsItIs(), res)
	if len(cs) != 1 || cs[0].Kind != ConflictReservation || cs[0].Severity != Warning {
		t.Fatalf("want one reservation warning, got %+v", cs)
	}
	if !strings.Contains(cs[0].Detail, "198.51.100.5") {
		t.Errorf("the detail should name it: %q", cs[0].Detail)
	}
}

func TestCheckReportsAnUnusableRangeAndStopsThere(t *testing.T) {
	cs := Check(Range{Subnet: netip.MustParsePrefix("192.168.1.0/15")}, lanAsItIs(), nil)
	if len(cs) != 1 || cs[0].Kind != ConflictRangeInvalid || cs[0].Severity != Blocking {
		t.Fatalf("want one blocking range-invalid conflict, got %+v", cs)
	}
	if strings.HasPrefix(cs[0].Detail, "dhcp:") {
		t.Errorf("the detail should read as a sentence, not as a wrapped error: %q", cs[0].Detail)
	}
}

func TestCheckSaysWhenTheHostIsInTheRangeButNotOnTheChosenAddress(t *testing.T) {
	o := Observed{HostAddrs: []netip.Addr{netip.MustParseAddr("192.168.1.37")}, Gateway: privGateway}
	cs := Check(goodRange(), o, nil)
	c, blocked := Blocked(cs)
	if !blocked || c.Kind != ConflictNoHostAddress {
		t.Fatalf("want a %s conflict, got %+v", ConflictNoHostAddress, cs)
	}
	if !strings.Contains(c.Detail, "has an address in") || !strings.Contains(c.Detail, "choose the address it already has") {
		t.Errorf("this is a different problem from having no address at all: %q", c.Detail)
	}
}

func TestCheckWithNothingObservedOnlyChecksTheRangeItself(t *testing.T) {
	// A build with no way to look at the network can still say whether the
	// range makes sense, and must not invent conflicts it cannot see.
	cs := Check(goodRange(), Observed{}, nil)
	for _, c := range cs {
		if c.Kind == ConflictRouterElsewhere {
			t.Errorf("with no observed gateway there is nothing to compare: %+v", c)
		}
	}
	if c, blocked := Blocked(cs); !blocked || c.Kind != ConflictNoHostAddress {
		t.Errorf("but a host with no address in the range is still blocking: %+v", cs)
	}
}

func TestHolderListIsCappedSoItCanBeRead(t *testing.T) {
	var hs []Holder
	for i := 1; i <= 10; i++ {
		hs = append(hs, Holder{IP: netip.AddrFrom4([4]byte{192, 0, 2, byte(i)})})
	}
	got := holderList(hs)
	if !strings.Contains(got, "and 4 more") {
		t.Errorf("holderList = %q, want it capped", got)
	}
	if strings.Contains(got, "192.0.2.8") {
		t.Errorf("holderList = %q, should stop before the eighth", got)
	}
	named := holderList([]Holder{{IP: poolStart, Name: "Printer"}})
	if named != poolStart.String()+" (Printer)" {
		t.Errorf("holderList = %q", named)
	}
}
