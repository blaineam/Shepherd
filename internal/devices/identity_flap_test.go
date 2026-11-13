// SPDX-License-Identifier: AGPL-3.0-or-later

package devices

import (
	"net/netip"
	"testing"
	"time"
)

// Two network cards on one host (a NAS) that both answer ARP for the same
// address make the neighbor table claim that address for one MAC, then the
// other. While it is claimed, no device holds it, and the next DNS query from
// that address used to mint a brand-new IP-only device that then landed in
// Quarantine and blocked the host's own queries.
func TestDNSFromAnAddressNobodyHoldsReusesItsLastHolder(t *testing.T) {
	r, clk := newReg(t)
	nasA := r.Observe(Observation{Source: SourceNeighbor, MAC: "00:00:5e:00:00:0a", IP: "192.0.2.10"})
	nasB := r.Observe(Observation{Source: SourceNeighbor, MAC: "00:00:5e:00:00:0b", IP: "192.0.2.102"})
	clk.Advance(time.Second)
	// NIC B starts answering for .10 and keeps its own address as well; the
	// one-v4-per-MAC cap drops the oldest, .102, leaving B on .10. Then A
	// reclaims it and B is left with .102 only, so .10 has no current holder.
	r.Observe(Observation{Source: SourceNeighbor, MAC: "00:00:5e:00:00:0b", IP: "192.0.2.10"})
	clk.Advance(time.Second)
	r.Observe(Observation{Source: SourceNeighbor, MAC: "00:00:5e:00:00:0b", IP: "192.0.2.102"})
	if h := r.byIP[netip.MustParseAddr("192.0.2.10")]; h != nil {
		t.Fatalf("setup: .10 should have no current holder, has %s", h.ID)
	}
	before := len(r.List())
	clk.Advance(time.Second)
	id := r.Observe(Observation{Source: SourceDNS, IP: "192.0.2.10"})
	if id != nasA && id != nasB {
		t.Fatalf("DNS from .10 created %s, want one of the NAS's own devices (%s, %s)", id, nasA, nasB)
	}
	if got := len(r.List()); got != before {
		t.Errorf("device count %d -> %d: a known address must not create a device", before, got)
	}
}

func TestAnUnrelatedStaleAddressStillCreatesANewDevice(t *testing.T) {
	r, clk := newReg(t)
	old := r.Observe(Observation{Source: SourceNeighbor, MAC: "00:00:5e:00:00:0a", IP: "192.0.2.10"})
	clk.Advance(time.Second)
	r.Observe(Observation{Source: SourceNeighbor, MAC: "00:00:5e:00:00:0a", IP: "192.0.2.11"}) // moved on
	clk.Advance(reuseWindow + time.Hour)
	id := r.Observe(Observation{Source: SourceDNS, IP: "192.0.2.10"})
	if id == old {
		t.Error("an address released long ago is a different machine now")
	}
}

// A device that sat in Quarantine only because it had no MAC yet must not
// pull Quarantine into the real device it turns out to be.
func TestMergingAQuarantineOnlyStubKeepsTheRealDevicesGroups(t *testing.T) {
	r, _ := newReg(t)
	r.EnsureQuarantineGroup()
	g, err := r.CreateGroup("Servers", "#fff")
	if err != nil {
		t.Fatal(err)
	}
	real := r.Observe(Observation{Source: SourceNeighbor, MAC: "00:00:5e:00:00:0a", IP: "192.0.2.10"})
	if _, err := r.BulkAssignGroup([]string{real}, g.ID); err != nil {
		t.Fatal(err)
	}
	stub := r.Observe(Observation{Source: SourceDNS, IP: "192.0.2.20"})
	if _, err := r.BulkAssignGroup([]string{stub}, QuarantineGroupID); err != nil {
		t.Fatal(err)
	}
	// The neighbor table now says the stub's address is the real device's.
	r.Observe(Observation{Source: SourceNeighbor, MAC: "00:00:5e:00:00:0a", IP: "192.0.2.20"})
	d := mustDevice(t, r, real)
	eq(t, d.Groups, []string{g.ID})
}

func TestMergingKeepsQuarantineWhenEverySideIsQuarantined(t *testing.T) {
	r, _ := newReg(t)
	r.EnsureQuarantineGroup()
	a := r.Observe(Observation{Source: SourceNeighbor, MAC: "00:00:5e:00:00:0a", IP: "192.0.2.10"})
	b := r.Observe(Observation{Source: SourceDNS, IP: "192.0.2.20"})
	for _, id := range []string{a, b} {
		if _, err := r.BulkAssignGroup([]string{id}, QuarantineGroupID); err != nil {
			t.Fatal(err)
		}
	}
	r.Observe(Observation{Source: SourceNeighbor, MAC: "00:00:5e:00:00:0a", IP: "192.0.2.20"})
	eq(t, mustDevice(t, r, a).Groups, []string{QuarantineGroupID})
}
