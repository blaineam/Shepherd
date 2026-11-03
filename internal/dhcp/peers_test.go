// SPDX-License-Identifier: AGPL-3.0-or-later

package dhcp

import (
	"net/netip"
	"testing"
	"time"
)

func TestPeersRemembersWhoAnsweredAndWhen(t *testing.T) {
	c := newClock()
	p := NewPeers()
	other := netip.MustParseAddr("192.0.2.2")

	if len(p.Active(c.now(), DefaultSettle)) != 0 {
		t.Fatal("a fresh record has seen nothing, which is what lets Shepherd serve")
	}

	p.Saw(other, c.now())
	c.advance(time.Second)
	p.Saw(other, c.now())

	active := p.Active(c.now(), DefaultSettle)
	if len(active) != 1 {
		t.Fatalf("Active = %+v, want one server", active)
	}
	if active[0].Count != 2 {
		t.Errorf("Count = %d, want 2", active[0].Count)
	}
	if !active[0].First.Before(active[0].Last) {
		t.Error("First and Last should bracket the sightings")
	}
}

func TestAPeerFallsOutOfTheWindowOnItsOwn(t *testing.T) {
	c := newClock()
	p := NewPeers()
	p.Saw(netip.MustParseAddr("192.0.2.2"), c.now())
	c.advance(DefaultSettle + time.Second)
	if len(p.Active(c.now(), 0)) != 0 {
		t.Error("a server that has not answered for the settle window is no longer present")
	}
	if len(p.All()) != 1 {
		t.Error("but the sighting is still history, which the portal shows")
	}
}

func TestActiveSortsNewestSightingFirst(t *testing.T) {
	c := newClock()
	p := NewPeers()
	first := netip.MustParseAddr("192.0.2.2")
	second := netip.MustParseAddr("192.0.2.3")
	p.Saw(first, c.now())
	c.advance(time.Second)
	p.Saw(second, c.now())
	active := p.Active(c.now(), DefaultSettle)
	if len(active) != 2 || active[0].Server != second {
		t.Fatalf("Active = %+v, want the newest sighting first", active)
	}
	all := p.All()
	if len(all) != 2 || all[0].Server != second {
		t.Fatalf("All = %+v, want the newest sighting first", all)
	}
}

func TestPeersIgnoresAnUnusableAddressAndIsBounded(t *testing.T) {
	c := newClock()
	p := NewPeers()
	p.Saw(netip.Addr{}, c.now())
	p.Saw(netip.MustParseAddr("0.0.0.0"), c.now())
	if len(p.All()) != 0 {
		t.Fatalf("All = %+v, want nothing: those are not servers", p.All())
	}
	// More than a handful of DHCP servers on one segment is a situation to
	// report, not to catalogue.
	for i := 0; i < maxPeers+10; i++ {
		p.Saw(netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)}), c.now())
	}
	if len(p.All()) > maxPeers {
		t.Errorf("the table holds %d entries, want at most %d", len(p.All()), maxPeers)
	}
}

// After the router's DHCP has been turned off, the interlock is right about
// the past and wrong about the present; waiting out the window for a server
// that is gone is pointless.
func TestForgetClearsTheRecord(t *testing.T) {
	c := newClock()
	p := NewPeers()
	p.Saw(netip.MustParseAddr("192.0.2.2"), c.now())
	p.Forget()
	if len(p.All()) != 0 || len(p.Active(c.now(), DefaultSettle)) != 0 {
		t.Error("Forget clears everything")
	}
}
