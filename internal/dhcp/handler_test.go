// SPDX-License-Identifier: AGPL-3.0-or-later

package dhcp

import (
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"

	"shepherd/internal/devices"
)

type harness struct {
	h      *Handler
	leases *Leases
	state  *State
	peers  *Peers
	sink   *recordingSink
	clock  *clock
	route  bool
	set    Settings
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	c := newClock()
	state, _, _ := openState(t)
	leases := NewLeases()
	peers := NewPeers()
	sink := &recordingSink{}
	hs := &harness{leases: leases, state: state, peers: peers, sink: sink, clock: c, set: testSettings()}
	alloc := &Allocator{
		Pool: hs.set.Pool, Subnet: hs.set.Subnet, Leases: leases, State: state, Now: c.now,
		Taken: func(ip netip.Addr) bool { return ip == shepherdA || ip == gatewayA },
	}
	hs.h = &Handler{
		Settings: func() Settings { return hs.set },
		Policy: func() RoutePolicy {
			return RoutePolicy{Route: hs.route, Own: Own{IPs: []netip.Addr{shepherdA}, Gateway: gatewayA, GatewayMAC: macGateway}}
		},
		Leases: leases, Alloc: alloc, Peers: peers, Sink: sink, Now: c.now,
	}
	return hs
}

func TestSettingsValidNamesWhatIsMissing(t *testing.T) {
	good := testSettings()
	if err := good.Valid(); err != nil {
		t.Fatalf("the test settings should be valid: %v", err)
	}
	if good.leaseTime() != 10*time.Minute {
		t.Error("leaseTime should use the configured value")
	}
	bare := Settings{Subnet: lanPrefix, ServerIP: shepherdA, Gateway: gatewayA, Pool: good.Pool}
	if bare.leaseTime() != DefaultLeaseTime {
		t.Errorf("leaseTime with none set = %v, want %v", bare.leaseTime(), DefaultLeaseTime)
	}

	cases := []struct {
		name string
		set  Settings
		want string
	}{
		{"no subnet", Settings{}, "no IPv4 LAN prefix"},
		{"no server address", Settings{Subnet: lanPrefix}, "no IPv4 address for Shepherd"},
		{"server outside the LAN", Settings{Subnet: lanPrefix, ServerIP: netip.MustParseAddr("198.51.100.1")}, "not inside the LAN"},
		{"no gateway", Settings{Subnet: lanPrefix, ServerIP: shepherdA}, "no IPv4 gateway"},
		{"gateway outside the LAN", Settings{Subnet: lanPrefix, ServerIP: shepherdA, Gateway: netip.MustParseAddr("198.51.100.1")}, "not inside the LAN"},
		{"no pool", Settings{Subnet: lanPrefix, ServerIP: shepherdA, Gateway: gatewayA}, "no usable address pool"},
		{"pool outside the LAN", Settings{Subnet: lanPrefix, ServerIP: shepherdA, Gateway: gatewayA,
			Pool: Pool{Start: netip.MustParseAddr("198.51.100.1"), End: netip.MustParseAddr("198.51.100.9")}}, "not inside the LAN"},
		{"Shepherd inside the pool", Settings{Subnet: lanPrefix, ServerIP: shepherdA, Gateway: gatewayA,
			Pool: Pool{Start: netip.MustParseAddr("192.0.2.10"), End: netip.MustParseAddr("192.0.2.30")}}, "Shepherd's own address"},
		{"the gateway inside the pool", Settings{Subnet: lanPrefix, ServerIP: shepherdA, Gateway: gatewayA,
			Pool: Pool{Start: netip.MustParseAddr("192.0.2.1"), End: netip.MustParseAddr("192.0.2.9")}}, "gateway's address"},
	}
	for _, c := range cases {
		err := c.set.Valid()
		if err == nil {
			t.Errorf("%s: want an error", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q should mention %q", c.name, err, c.want)
		}
	}
}

func TestDiscoverIsAnsweredWithAnOfferAndNothingIsStoredYet(t *testing.T) {
	hs := newHarness(t)
	res := hs.h.Handle(request(t, dhcpv4.MessageTypeDiscover, macA), ModeServe, netip.Addr{})
	if res.Action != ActionOffer || res.Reply == nil {
		t.Fatalf("Handle = %+v, want an offer", res)
	}
	reply := decodeReply(t, res.Reply)
	if reply.MessageType() != dhcpv4.MessageTypeOffer {
		t.Errorf("message type = %s, want an offer", reply.MessageType())
	}
	offered, _ := netip.AddrFromSlice(reply.YourIPAddr.To4())
	if offered != poolStart {
		t.Errorf("offered %s, want %s", offered, poolStart)
	}
	// An offer is not a lease: storing it here would let one device's
	// DISCOVER sweep reserve the whole pool.
	if hs.leases.Len() != 0 {
		t.Errorf("an offer stored %d leases, want 0", hs.leases.Len())
	}
	if res.To != bcastAll {
		t.Errorf("a reply to a client with no address goes to the broadcast address, got %s", res.To)
	}
}

func TestAnOfferCarriesTheOptionsAClientNeeds(t *testing.T) {
	hs := newHarness(t)
	hs.set.Domain = "example.test"
	res := hs.h.Handle(request(t, dhcpv4.MessageTypeDiscover, macA, dhcpv4.WithOption(dhcpv4.OptHostName("printer"))), ModeServe, netip.Addr{})
	reply := decodeReply(t, res.Reply)

	if sid := reply.ServerIdentifier(); sid == nil || !sid.Equal(net.IP(shepherdA.AsSlice())) {
		t.Errorf("server identifier = %v, want %s", sid, shepherdA)
	}
	if mask := reply.SubnetMask(); mask == nil {
		t.Error("the reply must carry a netmask")
	} else if ones, _ := mask.Size(); ones != 24 {
		t.Errorf("netmask = /%d, want /24", ones)
	}
	routers := reply.Router()
	if len(routers) != 1 || !routers[0].Equal(net.IP(gatewayA.AsSlice())) {
		t.Errorf("option 3 = %v, want the gateway %s while routing is off", routers, gatewayA)
	}
	if got := reply.IPAddressLeaseTime(0); got != 10*time.Minute {
		t.Errorf("lease time = %v, want 10m", got)
	}
	if got := reply.IPAddressRenewalTime(0); got != 5*time.Minute {
		t.Errorf("renewal time = %v, want half the lease", got)
	}
	if got := reply.IPAddressRebindingTime(0); got != 8*time.Minute+45*time.Second {
		t.Errorf("rebinding time = %v, want seven eighths of the lease", got)
	}
	dns := reply.DNS()
	if len(dns) != 1 || !dns[0].Equal(net.IP(shepherdA.AsSlice())) {
		t.Errorf("option 6 = %v, want Shepherd %s", dns, shepherdA)
	}
	if reply.DomainName() != "example.test" {
		t.Errorf("option 15 = %q", reply.DomainName())
	}
	if reply.HostName() != "printer" {
		t.Errorf("option 12 = %q, want the client's own name echoed", reply.HostName())
	}
	bcast := reply.BroadcastAddress()
	if bcast == nil || bcast.String() != "192.0.2.255" {
		t.Errorf("option 28 = %v, want 192.0.2.255", bcast)
	}
}

func TestRequestIsAcknowledgedAndStoredWithTheGatewayItWasGiven(t *testing.T) {
	hs := newHarness(t)
	req := request(t, dhcpv4.MessageTypeRequest, macA,
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(poolStart.AsSlice())),
		dhcpv4.WithOption(dhcpv4.OptHostName("printer")),
		dhcpv4.WithOption(dhcpv4.OptClassIdentifier("MSFT 5.0")),
		dhcpv4.WithRequestedOptions(dhcpv4.OptionSubnetMask, dhcpv4.OptionRouter, dhcpv4.OptionDomainNameServer),
	)
	res := hs.h.Handle(req, ModeServe, netip.Addr{})
	if res.Action != ActionAck {
		t.Fatalf("Handle = %+v, want an acknowledgement", res)
	}
	l, ok := hs.leases.Get(macA)
	if !ok {
		t.Fatal("an acknowledgement stores the lease")
	}
	if l.IP != poolStart || l.Router != gatewayA || l.Origin != OriginShepherd {
		t.Errorf("stored lease = %+v", l)
	}
	if l.Hostname != "printer" || l.VendorClass != "MSFT 5.0" {
		t.Errorf("the lease should record what the client said about itself: %+v", l)
	}
	if l.Fingerprint != "1,3,6" {
		t.Errorf("Fingerprint = %q, want the parameter request list", l.Fingerprint)
	}
	if !l.Expires.Equal(hs.clock.now().Add(10 * time.Minute)) {
		t.Errorf("Expires = %v", l.Expires)
	}
}

func TestRoutingOnPutsShepherdsOwnAddressInOptionThree(t *testing.T) {
	hs := newHarness(t)
	hs.route = true
	res := hs.h.Handle(request(t, dhcpv4.MessageTypeRequest, macA,
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(poolStart.AsSlice()))), ModeServe, netip.Addr{})
	if res.Action != ActionAck || !res.Routing.Routed {
		t.Fatalf("Handle = %+v, want a routed acknowledgement", res)
	}
	reply := decodeReply(t, res.Reply)
	routers := reply.Router()
	if len(routers) != 1 || !routers[0].Equal(net.IP(shepherdA.AsSlice())) {
		t.Fatalf("option 3 = %v, want Shepherd %s", routers, shepherdA)
	}
	l, _ := hs.leases.Get(macA)
	if !l.Routed([]netip.Addr{shepherdA}) {
		t.Error("the stored lease should record that this device was routed")
	}
}

func TestRenewalKeepsTheAddressAndTheOriginalAllocationTime(t *testing.T) {
	hs := newHarness(t)
	first := hs.h.Handle(request(t, dhcpv4.MessageTypeRequest, macA,
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(poolStart.AsSlice()))), ModeServe, netip.Addr{})
	if first.Action != ActionAck {
		t.Fatal(first.Why)
	}
	allocated := first.Lease.Allocated

	hs.clock.advance(5 * time.Minute)
	renew := request(t, dhcpv4.MessageTypeRequest, macA)
	renew.ClientIPAddr = poolStart.AsSlice()
	res := hs.h.Handle(renew, ModeServe, netip.Addr{})
	if res.Action != ActionAck {
		t.Fatalf("a renewal should be acknowledged, got %+v", res)
	}
	if res.Lease.IP != poolStart {
		t.Errorf("a renewal must keep the address, got %s", res.Lease.IP)
	}
	if !res.Lease.Allocated.Equal(allocated) {
		t.Error("a renewal keeps the time the address was first allocated")
	}
	if res.To != poolStart {
		t.Errorf("a renewal from a configured client is answered to %s, got %s", poolStart, res.To)
	}
}

func TestARequestForAnUnavailableAddressIsRefusedWithANak(t *testing.T) {
	hs := newHarness(t)
	// Another device holds it.
	hs.leases.Put(Lease{MAC: macB, IP: poolStart, Expires: hs.clock.now().Add(time.Hour)})
	res := hs.h.Handle(request(t, dhcpv4.MessageTypeRequest, macA,
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(poolStart.AsSlice()))), ModeServe, netip.Addr{})
	if res.Action != ActionNak {
		t.Fatalf("Handle = %+v, want a refusal", res)
	}
	if res.To != bcastAll {
		t.Errorf("a refusal is broadcast, because the address being refused is the one the client thinks it has; got %s", res.To)
	}
	reply := decodeReply(t, res.Reply)
	if reply.MessageType() != dhcpv4.MessageTypeNak {
		t.Errorf("message type = %s", reply.MessageType())
	}
	if reply.Message() == "" {
		t.Error("a refusal should say why")
	}
	if _, ok := hs.leases.Get(macA); ok {
		t.Error("a refused request stores no lease")
	}
}

func TestARequestNamingNoAddressIsRefused(t *testing.T) {
	hs := newHarness(t)
	res := hs.h.Handle(request(t, dhcpv4.MessageTypeRequest, macA), ModeServe, netip.Addr{})
	if res.Action != ActionNak || !strings.Contains(res.Why, "names no address") {
		t.Fatalf("Handle = %+v", res)
	}
}

// A REQUEST naming another server's identifier is the client saying it chose
// somebody else. Silence is the right answer, and the sighting is the thing
// the interlock needs.
func TestARequestForAnotherServerIsIgnoredAndRecordsThatServer(t *testing.T) {
	hs := newHarness(t)
	other := netip.MustParseAddr("192.0.2.2")
	res := hs.h.Handle(request(t, dhcpv4.MessageTypeRequest, macA,
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(other.AsSlice())),
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(poolStart.AsSlice()))), ModeServe, netip.Addr{})
	if res.Action != ActionIgnore || res.Reply != nil {
		t.Fatalf("Handle = %+v, want silence", res)
	}
	if !strings.Contains(res.Why, other.String()) {
		t.Errorf("Why = %q, should name the server the client chose", res.Why)
	}
	active := hs.peers.Active(hs.clock.now(), DefaultSettle)
	if len(active) != 1 || active[0].Server != other {
		t.Fatalf("Active = %+v, want the other server recorded", active)
	}
}

func TestDeclineKeepsTheAddressOutOfThePool(t *testing.T) {
	hs := newHarness(t)
	hs.leases.Put(Lease{MAC: macA, IP: poolStart, Expires: hs.clock.now().Add(time.Hour)})
	res := hs.h.Handle(request(t, dhcpv4.MessageTypeDecline, macA,
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(poolStart.AsSlice()))), ModeServe, netip.Addr{})
	if res.Action != ActionObserve || res.Reply != nil {
		t.Fatalf("Handle = %+v; a decline is not answered", res)
	}
	l, _ := hs.leases.Get(macA)
	if l.Declines != 1 {
		t.Errorf("Declines = %d, want 1", l.Declines)
	}

	empty := hs.h.Handle(request(t, dhcpv4.MessageTypeDecline, macB), ModeServe, netip.Addr{})
	if empty.Action != ActionIgnore {
		t.Errorf("a decline naming no address is ignored, got %+v", empty)
	}
}

func TestReleaseDropsTheLease(t *testing.T) {
	hs := newHarness(t)
	hs.leases.Put(Lease{MAC: macA, IP: poolStart, Expires: hs.clock.now().Add(time.Hour)})
	res := hs.h.Handle(request(t, dhcpv4.MessageTypeRelease, macA), ModeServe, netip.Addr{})
	if res.Action != ActionObserve || res.Reply != nil {
		t.Fatalf("Handle = %+v", res)
	}
	if _, ok := hs.leases.Get(macA); ok {
		t.Error("a release drops the lease")
	}
	again := hs.h.Handle(request(t, dhcpv4.MessageTypeRelease, macA), ModeServe, netip.Addr{})
	if again.Action != ActionIgnore {
		t.Errorf("a release for a device with no lease is ignored, got %+v", again)
	}
}

func TestInformIsAnsweredWithConfigurationAndNoLease(t *testing.T) {
	hs := newHarness(t)
	inform := request(t, dhcpv4.MessageTypeInform, macA)
	inform.ClientIPAddr = netip.MustParseAddr("192.0.2.60").AsSlice()
	res := hs.h.Handle(inform, ModeServe, netip.Addr{})
	if res.Action != ActionAck {
		t.Fatalf("Handle = %+v, want an acknowledgement", res)
	}
	if hs.leases.Len() != 0 {
		t.Error("an inform asks for configuration without a lease, so none is stored")
	}
	reply := decodeReply(t, res.Reply)
	if got := reply.IPAddressLeaseTime(0); got != 0 {
		t.Errorf("an inform reply must carry no lease time, got %v", got)
	}
	if reply.IPAddressRenewalTime(0) != 0 || reply.IPAddressRebindingTime(0) != 0 {
		t.Error("and no renewal or rebinding time either")
	}
	if len(reply.Router()) == 0 {
		t.Error("option 3 is the whole point of answering an inform")
	}

	bare := hs.h.Handle(request(t, dhcpv4.MessageTypeInform, macA), ModeServe, netip.Addr{})
	if bare.Action != ActionIgnore {
		t.Errorf("an inform from no address is ignored, got %+v", bare)
	}
}

// Observe mode is the safety claim this whole design rests on, so it is
// checked for every message type rather than for one.
func TestObserveModeNeverProducesAReply(t *testing.T) {
	for _, mt := range []dhcpv4.MessageType{
		dhcpv4.MessageTypeDiscover, dhcpv4.MessageTypeRequest, dhcpv4.MessageTypeDecline,
		dhcpv4.MessageTypeRelease, dhcpv4.MessageTypeInform,
	} {
		hs := newHarness(t)
		res := hs.h.Handle(request(t, mt, macA,
			dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(poolStart.AsSlice()))), ModeObserve, netip.Addr{})
		if res.Reply != nil {
			t.Errorf("%s produced a reply in observe mode", mt)
		}
		if res.Action != ActionObserve {
			t.Errorf("%s = %q, want %q", mt, res.Action, ActionObserve)
		}
		if hs.leases.Len() != 0 {
			t.Errorf("%s changed the lease store in observe mode", mt)
		}
	}
}

// Observe mode's own reason for existing: the registry learns the things only
// DHCP can tell it.
func TestEveryClientPacketFeedsTheRegistry(t *testing.T) {
	hs := newHarness(t)
	req := request(t, dhcpv4.MessageTypeDiscover, macA,
		dhcpv4.WithOption(dhcpv4.OptHostName("printer")),
		dhcpv4.WithOption(dhcpv4.OptClassIdentifier("android-dhcp-14")),
		dhcpv4.WithRequestedOptions(dhcpv4.OptionSubnetMask, dhcpv4.OptionRouter),
	)
	req.ClientIPAddr = poolStart.AsSlice()
	hs.h.Handle(req, ModeObserve, netip.Addr{})

	obs := hs.sink.all()
	if len(obs) != 1 {
		t.Fatalf("got %d observations, want 1", len(obs))
	}
	o := obs[0]
	if o.Source != devices.SourceDHCP {
		t.Errorf("Source = %q, want %q", o.Source, devices.SourceDHCP)
	}
	if o.MAC != macA || o.Hostname != "printer" || o.IP != poolStart.String() {
		t.Errorf("observation = %+v", o)
	}
	joined := strings.Join(o.Hints, "|")
	if !strings.Contains(joined, "android-dhcp-14") {
		t.Errorf("Hints = %v, want the vendor class as a hint rather than a vendor name", o.Hints)
	}
	if !strings.Contains(joined, "dhcp-fingerprint:1,3") {
		t.Errorf("Hints = %v, want the parameter request list", o.Hints)
	}
}

func TestAnotherServersAcknowledgementIsRecordedAsAnObservedLease(t *testing.T) {
	hs := newHarness(t)
	other := netip.MustParseAddr("192.0.2.2")
	ack := serverReply(t, dhcpv4.MessageTypeAck, macB, other, poolEnd,
		dhcpv4.WithOption(dhcpv4.OptRouter(other.AsSlice())),
		dhcpv4.WithOption(dhcpv4.OptHostName("tv")),
		dhcpv4.WithOption(dhcpv4.OptIPAddressLeaseTime(time.Hour)),
	)
	res := hs.h.Handle(ack, ModeObserve, other)
	if res.Action != ActionObserve {
		t.Fatalf("Handle = %+v", res)
	}
	l, ok := hs.leases.Get(macB)
	if !ok {
		t.Fatal("watching before serving is exactly how the lease picture gets built")
	}
	if l.Origin != OriginObserved || l.IP != poolEnd || l.Router != other || l.Hostname != "tv" {
		t.Errorf("observed lease = %+v", l)
	}
	if !l.Expires.Equal(hs.clock.now().Add(time.Hour)) {
		t.Errorf("Expires = %v, want the lease time the other server gave", l.Expires)
	}
	if len(hs.peers.Active(hs.clock.now(), DefaultSettle)) != 1 {
		t.Error("and the server that sent it is recorded")
	}
}

func TestOurOwnReplyAndIrrelevantRepliesAreIgnored(t *testing.T) {
	hs := newHarness(t)
	ours := serverReply(t, dhcpv4.MessageTypeAck, macA, shepherdA, poolStart)
	if res := hs.h.Handle(ours, ModeServe, shepherdA); res.Action != ActionIgnore {
		t.Errorf("our own reply = %+v, want ignored", res)
	}
	if len(hs.peers.All()) != 0 {
		t.Error("Shepherd is not another DHCP server")
	}

	other := netip.MustParseAddr("192.0.2.2")
	notInteresting := serverReply(t, dhcpv4.MessageTypeNak, macA, other, netip.Addr{})
	if res := hs.h.Handle(notInteresting, ModeServe, other); res.Action != ActionIgnore {
		t.Errorf("a refusal from another server = %+v", res)
	}

	// A reply with no server identifier at all falls back to the address it
	// arrived from, which is the only thing there is to go on.
	bare, err := dhcpv4.New(dhcpv4.WithMessageType(dhcpv4.MessageTypeOffer), dhcpv4.WithHwAddr(hw(t, macA)))
	if err != nil {
		t.Fatal(err)
	}
	bare.OpCode = dhcpv4.OpcodeBootReply
	if res := hs.h.Handle(bare, ModeServe, other); res.Action != ActionObserve {
		t.Errorf("an offer from %s = %+v, want it observed", other, res)
	}
	if len(hs.peers.All()) != 1 {
		t.Error("a reply with no server identifier still identifies a server by where it came from")
	}
}

func TestARelayedRequestIsRefusedRatherThanHalfHandled(t *testing.T) {
	hs := newHarness(t)
	req := request(t, dhcpv4.MessageTypeDiscover, macA)
	req.GatewayIPAddr = netip.MustParseAddr("198.51.100.1").AsSlice()
	res := hs.h.Handle(req, ModeServe, netip.Addr{})
	if res.Action != ActionIgnore || !strings.Contains(res.Why, "one flat segment") {
		t.Fatalf("Handle = %+v, want a refusal naming the limit", res)
	}
	// It is still identity evidence.
	if len(hs.sink.all()) != 1 {
		t.Error("a relayed request still says what the device is")
	}
}

func TestMalformedAndUnservedPacketsAreIgnored(t *testing.T) {
	hs := newHarness(t)
	if res := hs.h.Handle(nil, ModeServe, netip.Addr{}); res.Action != ActionIgnore {
		t.Error("a nil packet is ignored")
	}

	noMAC, err := dhcpv4.New(dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover))
	if err != nil {
		t.Fatal(err)
	}
	noMAC.OpCode = dhcpv4.OpcodeBootRequest
	if res := hs.h.Handle(noMAC, ModeServe, netip.Addr{}); res.Action != ActionIgnore {
		t.Error("a request with no usable MAC is ignored")
	}

	odd := request(t, dhcpv4.MessageTypeOffer, macA) // a client sending a server message
	if res := hs.h.Handle(odd, ModeServe, netip.Addr{}); res.Action != ActionIgnore {
		t.Error("a message type that is not served is ignored")
	}

	bad := request(t, dhcpv4.MessageTypeDiscover, macA)
	bad.OpCode = dhcpv4.OpcodeType(9)
	if res := hs.h.Handle(bad, ModeServe, netip.Addr{}); res.Action != ActionIgnore {
		t.Error("something that is neither a request nor a reply is ignored")
	}
}

func TestServingWithUnusableSettingsAnswersNothingAndSaysWhy(t *testing.T) {
	hs := newHarness(t)
	hs.set = Settings{}
	res := hs.h.Handle(request(t, dhcpv4.MessageTypeDiscover, macA), ModeServe, netip.Addr{})
	if res.Action != ActionIgnore || res.Reply != nil {
		t.Fatalf("Handle = %+v", res)
	}
	if !strings.Contains(res.Why, "LAN prefix") {
		t.Errorf("Why = %q, should name what is missing", res.Why)
	}
}

func TestAnExhaustedPoolAnswersNothingRatherThanRefusing(t *testing.T) {
	hs := newHarness(t)
	ip := poolStart
	for i := 0; i < 11; i++ {
		mac := NormalizeMAC("02005e0000" + string("0123456789a"[i]) + "0")
		hs.leases.Put(Lease{MAC: mac, IP: ip, Expires: hs.clock.now().Add(time.Hour)})
		ip = ip.Next()
	}
	res := hs.h.Handle(request(t, dhcpv4.MessageTypeDiscover, macA), ModeServe, netip.Addr{})
	if res.Action != ActionIgnore || res.Reply != nil {
		t.Fatalf("Handle = %+v; silence is right, because the client is already retrying", res)
	}
	if !strings.Contains(res.Why, "exhausted") {
		t.Errorf("Why = %q", res.Why)
	}
	// And a REQUEST in the same state is refused, which makes the client
	// start over.
	req := hs.h.Handle(request(t, dhcpv4.MessageTypeRequest, macA,
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(netip.MustParseAddr("192.0.2.200").AsSlice()))), ModeServe, netip.Addr{})
	if req.Action != ActionNak {
		t.Errorf("Handle = %+v, want a refusal", req)
	}
}

func TestAReservedHostnameOverridesWhatTheClientCallsItself(t *testing.T) {
	hs := newHarness(t)
	if err := hs.state.SetReservation(Reservation{MAC: macA, IP: netip.MustParseAddr("192.0.2.50"), Hostname: "doorbell"},
		lanPrefix, hs.set.Pool); err != nil {
		t.Fatal(err)
	}
	res := hs.h.Handle(request(t, dhcpv4.MessageTypeRequest, macA,
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(netip.MustParseAddr("192.0.2.50").AsSlice())),
		dhcpv4.WithOption(dhcpv4.OptHostName("whatever-it-calls-itself"))), ModeServe, netip.Addr{})
	if res.Action != ActionAck {
		t.Fatalf("Handle = %+v", res)
	}
	if res.Lease.Hostname != "doorbell" {
		t.Errorf("Hostname = %q, want the reserved name", res.Lease.Hostname)
	}
	if !res.Lease.Reserved {
		t.Error("the lease should record that it came from a reservation")
	}
}

func TestClientIdentifierIsRecordedAsHexWithoutBeingInterpreted(t *testing.T) {
	hs := newHarness(t)
	res := hs.h.Handle(request(t, dhcpv4.MessageTypeRequest, macA,
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(poolStart.AsSlice())),
		dhcpv4.WithOption(dhcpv4.OptClientIdentifier([]byte{0x01, 0x02, 0x00, 0x5e, 0x01, 0x02, 0x03}))), ModeServe, netip.Addr{})
	if res.Lease.ClientID != "0102005e010203" {
		t.Errorf("ClientID = %q, want the raw option as hex", res.Lease.ClientID)
	}
	if clientID(request(t, dhcpv4.MessageTypeDiscover, macA)) != "" {
		t.Error("a client that sends no identifier has none")
	}
}

func TestHandlerWithNoSettingsOrPolicyIsSafe(t *testing.T) {
	h := &Handler{Leases: NewLeases()}
	if got := h.settings(); got.Subnet.IsValid() {
		t.Error("a handler with no settings function has empty settings")
	}
	if got := h.policy(); got.Route {
		t.Error("and a policy that routes nothing")
	}
	if h.now().IsZero() {
		t.Error("and a real clock")
	}
	// No sink: observing must not panic.
	h.observeClient(request(t, dhcpv4.MessageTypeDiscover, macA), macA)
}

func TestFirstIPPicksTheFirstIPv4(t *testing.T) {
	if got := firstIP(nil); got != nil {
		t.Errorf("firstIP(nil) = %v", got)
	}
	v6 := net.ParseIP("2001:db8::1")
	v4 := net.ParseIP("192.0.2.1")
	if got := firstIP([]net.IP{v6, v4}); got == nil || net.IP(got).String() != "192.0.2.1" {
		t.Errorf("firstIP = %v, want the IPv4 address", got)
	}
}
