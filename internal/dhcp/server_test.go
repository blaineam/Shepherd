// SPDX-License-Identifier: AGPL-3.0-or-later

package dhcp

import (
	"context"
	"errors"
	"io"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"

	"shepherd/internal/devices"
)

type raisedAlarm struct{ severity, title, detail string }

type serverHarness struct {
	srv   *Server
	conn  *fakeConn
	nft   *fakeNFT
	sc    *fakeSysctl
	state *State
	clock *clock
	sink  *recordingSink

	mu     sync.Mutex
	alarms []raisedAlarm
	mode   Mode
	route  bool
	set    Settings
	logs   safeBuffer
}

// safeBuffer is a log sink a test can read while the server writes: the
// server logs from its own goroutine, so an unsynchronised strings.Builder
// is a data race rather than a convenience.
type safeBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func newServerHarness(t *testing.T, mode Mode) *serverHarness {
	t.Helper()
	c := newClock()
	dir := t.TempDir()
	state, err := OpenState(filepath.Join(dir, "dhcp.json"), c.now)
	if err != nil {
		t.Fatal(err)
	}
	nft := &fakeNFT{}
	sc := newSysctl()
	hs := &serverHarness{conn: newFakeConn(), nft: nft, sc: sc, state: state, clock: c,
		sink: &recordingSink{}, mode: mode, set: testSettings()}
	hs.srv = &Server{
		Mode:          func() Mode { return hs.currentMode() },
		Settings:      func() Settings { return hs.settings() },
		Route:         func() bool { return hs.routing() },
		RouteConsoles: func() bool { return false },
		Own:           func() Own { return Own{IPs: []netip.Addr{shepherdA}, Gateway: gatewayA, GatewayMAC: macGateway} },
		Lookup:        func(string) (devices.Device, bool) { return devices.Device{}, false },
		Store:         NewLeases(),
		State:         state,
		Peers:         NewPeers(),
		Sink:          hs.sink,
		NAT:           &Reconciler{LAN: "eth0", Run: nft.run, Sysctl: sc, NFT: "nft-test"},
		Open:          func(context.Context, string, bool) (Conn, error) { return hs.conn, nil },
		Iface:         "eth0",
		LeasePath:     filepath.Join(dir, "dhcp-leases.json"),
		Interval:      5 * time.Millisecond,
		Now:           c.now,
		Log:           log.New(&hs.logs, "", 0),
		Alarm:         hs.alarm,
	}
	return hs
}

func (h *serverHarness) currentMode() Mode {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.mode
}

func (h *serverHarness) setMode(m Mode) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.mode = m
}

func (h *serverHarness) routing() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.route
}

func (h *serverHarness) setRouting(on bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.route = on
}

func (h *serverHarness) settings() Settings {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.set
}

func (h *serverHarness) setSettings(s Settings) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.set = s
}

func (h *serverHarness) alarm(severity, title, detail string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.alarms = append(h.alarms, raisedAlarm{severity, title, detail})
}

func (h *serverHarness) raised() []raisedAlarm {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]raisedAlarm(nil), h.alarms...)
}

func (h *serverHarness) log() string { return h.logs.String() }

// run starts the server and returns a stop function.
func (h *serverHarness) run(t *testing.T) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.srv.Run(ctx) }()
	return func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Run: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Run did not return after its context was cancelled")
		}
	}
}

func (h *serverHarness) send(t *testing.T, pkt *dhcpv4.DHCPv4) {
	t.Helper()
	select {
	case h.conn.in <- pkt.ToBytes():
	case <-time.After(time.Second):
		t.Fatal("the server is not reading its socket")
	}
}

func TestModeOffOpensNoSocketAndIsNotAnError(t *testing.T) {
	hs := newServerHarness(t, ModeOff)
	opened := false
	hs.srv.Open = func(context.Context, string, bool) (Conn, error) { opened = true; return hs.conn, nil }
	if err := hs.srv.Run(context.Background()); err != nil {
		t.Fatalf("Run in off mode = %v, want nil: there is nothing to run and that is not a failure", err)
	}
	if opened {
		t.Error("off mode must not open a socket")
	}
	st := hs.srv.Status()
	if st.Mode != "off" || st.Listening || st.Serving {
		t.Errorf("Status = %+v", st)
	}
}

func TestServingIsGatedOnTheConfirmationAndSaysSo(t *testing.T) {
	hs := newServerHarness(t, ModeServe)
	stop := hs.run(t)
	defer stop()

	waitFor(t, "the status to settle", func() bool { return hs.srv.Status().Blocked != "" })
	if got := hs.srv.Status().Blocked; !strings.Contains(got, "confirmed in the portal") {
		t.Fatalf("Blocked = %q, want the confirmation named", got)
	}

	// Until it is confirmed, a request is observed rather than answered.
	hs.send(t, request(t, dhcpv4.MessageTypeDiscover, macA))
	waitFor(t, "the request to be observed", func() bool { return len(hs.sink.all()) == 1 })
	if len(hs.conn.replies()) != 0 {
		t.Fatal("nothing may be sent before serving is confirmed")
	}

	if err := hs.srv.Confirm(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "serving to start", func() bool { return hs.srv.Status().Serving })
	hs.send(t, request(t, dhcpv4.MessageTypeDiscover, macA))
	waitFor(t, "an offer", func() bool { return len(hs.conn.replies()) == 1 })
	sent := hs.conn.replies()[0]
	if sent.to.Port() != ClientPort {
		t.Errorf("a reply goes to port %d, got %d", ClientPort, sent.to.Port())
	}
	reply, err := dhcpv4.FromBytes(sent.data)
	if err != nil {
		t.Fatalf("the reply does not decode: %v", err)
	}
	if reply.MessageType() != dhcpv4.MessageTypeOffer {
		t.Errorf("message type = %s", reply.MessageType())
	}
}

// The interlock exists because two servers answering is worse than one, and
// the one that should survive is the one that was there first.
func TestAnotherDHCPServerStopsServingAndRaisesACriticalAlarm(t *testing.T) {
	hs := newServerHarness(t, ModeServe)
	if err := hs.state.SetConfirmed(true); err != nil {
		t.Fatal(err)
	}
	stop := hs.run(t)
	defer stop()
	waitFor(t, "serving to start", func() bool { return hs.srv.Status().Serving })

	other := netip.MustParseAddr("192.0.2.2")
	hs.send(t, serverReply(t, dhcpv4.MessageTypeOffer, macB, other, poolEnd))
	waitFor(t, "serving to stop", func() bool { return !hs.srv.Status().Serving })

	st := hs.srv.Status()
	if !strings.Contains(st.Blocked, other.String()) {
		t.Errorf("Blocked = %q, should name the server that answered", st.Blocked)
	}
	if len(st.Peers) != 1 {
		t.Errorf("Peers = %+v", st.Peers)
	}
	var found bool
	for _, a := range hs.raised() {
		if strings.Contains(a.title, "DHCP server") && a.severity == severityCritical {
			found = true
		}
	}
	if !found {
		t.Errorf("a critical alarm must be raised; got %+v", hs.raised())
	}

	// After the router's DHCP is off, clearing the sighting lets it serve
	// again without waiting out the window.
	hs.srv.ForgetPeers(context.Background())
	waitFor(t, "serving to resume", func() bool { return hs.srv.Status().Serving })
}

// Routing is a separate decision from serving. This is the heart of the
// fail-open behaviour: Shepherd keeps handing out addresses through every
// failure that stops it being a safe path.
func TestRoutingIsASecondSwitchAndLeasingSurvivesItsFailures(t *testing.T) {
	hs := newServerHarness(t, ModeServe)
	if err := hs.state.SetConfirmed(true); err != nil {
		t.Fatal(err)
	}
	hs.setRouting(true)
	stop := hs.run(t)
	defer stop()
	waitFor(t, "routing to start", func() bool { return hs.srv.Status().Routing })

	hs.send(t, request(t, dhcpv4.MessageTypeRequest, macA,
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(poolStart.AsSlice()))))
	waitFor(t, "the lease to be routed", func() bool { return hs.srv.Status().RoutedCount == 1 })
	waitFor(t, "the kernel to be told", func() bool {
		for _, c := range hs.nft.all() {
			if strings.Contains(c.stdin, poolStart.String()) {
				return true
			}
		}
		return false
	})

	// Now make the kernel refuse the rules. Routing must stop by itself,
	// and the lease handed out next must name the gateway instead.
	hs.nft.fail(errors.New("exit status 1"))
	waitFor(t, "routing to stop on its own", func() bool { return !hs.srv.Status().Routing })
	st := hs.srv.Status()
	if st.RoutingBlocked == "" {
		t.Error("the status must say why routing stopped")
	}
	if !st.Serving {
		t.Error("leasing carries on: that is the whole point of failing open")
	}

	before := len(hs.conn.replies())
	hs.send(t, request(t, dhcpv4.MessageTypeRequest, macB,
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(poolEnd.AsSlice()))))
	waitFor(t, "the next lease", func() bool { return len(hs.conn.replies()) > before })
	reply, err := dhcpv4.FromBytes(hs.conn.replies()[len(hs.conn.replies())-1].data)
	if err != nil {
		t.Fatal(err)
	}
	routers := reply.Router()
	if len(routers) != 1 || routers[0].String() != gatewayA.String() {
		t.Fatalf("option 3 = %v, want the gateway %s: an unhealthy Shepherd stops claiming to be it", routers, gatewayA)
	}
	var sawNAT bool
	for _, a := range hs.raised() {
		if strings.Contains(a.title, "NAT") {
			sawNAT = true
		}
	}
	if !sawNAT {
		t.Errorf("a NAT failure must be raised as an alarm; got %+v", hs.raised())
	}
}

func TestTheKillSwitchStopsRoutingAndSurvivesARestart(t *testing.T) {
	hs := newServerHarness(t, ModeServe)
	if err := hs.state.SetConfirmed(true); err != nil {
		t.Fatal(err)
	}
	hs.setRouting(true)
	stop := hs.run(t)
	defer stop()
	waitFor(t, "routing to start", func() bool { return hs.srv.Status().Routing })

	if err := hs.srv.Unroute(context.Background(), "testing"); err != nil {
		t.Fatalf("Unroute: %v", err)
	}
	st := hs.srv.Status()
	if st.Routing {
		t.Fatal("the kill switch stops routing at once")
	}
	if !st.Disarmed || st.DisarmedReason != "testing" {
		t.Errorf("Status = %+v, want the kill switch recorded with its reason", st)
	}
	if !st.Serving {
		t.Error("leasing carries on, so no device loses its address")
	}
	// It stays pulled across a restart, which is what makes pressing it a
	// decision rather than a pause.
	off, reason, _ := hs.state.Disarmed()
	if !off || reason != "testing" {
		t.Errorf("Disarmed = %v, %q", off, reason)
	}

	if err := hs.srv.Rearm(context.Background()); err != nil {
		t.Fatalf("Rearm: %v", err)
	}
	waitFor(t, "routing to resume", func() bool { return hs.srv.Status().Routing })
}

func TestObserveModeIsHandedAConnectionItCannotWriteThrough(t *testing.T) {
	hs := newServerHarness(t, ModeObserve)
	var wantedWrite bool
	hs.srv.Open = func(_ context.Context, _ string, write bool) (Conn, error) {
		wantedWrite = write
		if !write {
			return ReadOnly(hs.conn), nil
		}
		return hs.conn, nil
	}
	if err := hs.state.SetConfirmed(true); err != nil {
		t.Fatal(err)
	}
	stop := hs.run(t)
	defer stop()
	waitFor(t, "the socket to open", func() bool { return hs.srv.Status().Listening })
	if wantedWrite {
		t.Fatal("observe mode must ask for a connection with no send path")
	}

	hs.send(t, request(t, dhcpv4.MessageTypeDiscover, macA))
	waitFor(t, "the request to be observed", func() bool { return len(hs.sink.all()) == 1 })
	if len(hs.conn.replies()) != 0 {
		t.Fatal("observe mode sent something")
	}
	if hs.srv.Status().Serving {
		t.Error("observe mode is not serving")
	}
}

func TestLeasesArePersistedAndReloaded(t *testing.T) {
	hs := newServerHarness(t, ModeServe)
	if err := hs.state.SetConfirmed(true); err != nil {
		t.Fatal(err)
	}
	stop := hs.run(t)
	waitFor(t, "serving to start", func() bool { return hs.srv.Status().Serving })
	hs.send(t, request(t, dhcpv4.MessageTypeRequest, macA,
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(poolStart.AsSlice()))))
	waitFor(t, "the lease to be stored", func() bool { return hs.srv.Status().Leases == 1 })
	waitFor(t, "the lease to be saved", func() bool { return !hs.srv.Store.Dirty() })
	stop()

	back := NewLeases()
	if err := back.Load(hs.srv.LeasePath); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := back.Get(macA); !ok {
		t.Fatal("the lease should be on disk, or an address could be handed out twice after a restart")
	}
}

// A corrupt lease file is recoverable in one renewal interval; refusing to
// start is not recoverable at all. But it is loud, because for that interval
// two devices could be offered the same address.
func TestABadLeaseFileIsSetAsideLoudly(t *testing.T) {
	hs := newServerHarness(t, ModeObserve)
	if err := writeFileAtomic(hs.srv.LeasePath, []byte("{broken")); err != nil {
		t.Fatal(err)
	}
	if err := hs.srv.Prepare(); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if !strings.Contains(hs.log(), "moved to") {
		t.Errorf("the log should say the file was set aside; got %q", hs.log())
	}
	var found bool
	for _, a := range hs.raised() {
		if strings.Contains(a.title, "lease file") {
			found = true
		}
	}
	if !found {
		t.Errorf("an alarm should be raised; got %+v", hs.raised())
	}
	if !hs.srv.Store.Loaded() {
		t.Error("and the server should carry on with an empty store")
	}
}

func TestAnUnusableLeasePathStopsPrepare(t *testing.T) {
	hs := newServerHarness(t, ModeObserve)
	hs.srv.LeasePath = filepath.Join(t.TempDir(), "leases-as-a-directory")
	if err := os.Mkdir(hs.srv.LeasePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := hs.srv.Run(context.Background()); err == nil {
		t.Fatal("a lease path that cannot be read is a startup failure")
	}
	if hs.srv.Status().Error == "" {
		t.Error("and the reason belongs in the status")
	}
}

func TestServeGateNamesEveryReasonItWillNotServe(t *testing.T) {
	hs := newServerHarness(t, ModeOff)
	if err := hs.srv.Prepare(); err != nil {
		t.Fatal(err)
	}
	now := hs.clock.now()

	if ok, why := hs.srv.serveGate(now); ok || !strings.Contains(why, "the mode is off") {
		t.Errorf("off: %v, %q", ok, why)
	}
	hs.setMode(ModeServe)
	if ok, why := hs.srv.serveGate(now); ok || !strings.Contains(why, "confirmed") {
		t.Errorf("unconfirmed: %v, %q", ok, why)
	}
	if err := hs.state.SetConfirmed(true); err != nil {
		t.Fatal(err)
	}
	hs.setSettings(Settings{})
	if ok, why := hs.srv.serveGate(now); ok || !strings.Contains(why, "LAN prefix") {
		t.Errorf("bad settings: %v, %q", ok, why)
	}
	hs.setSettings(testSettings())
	if ok, why := hs.srv.serveGate(now); !ok {
		t.Errorf("with everything in place it should serve: %q", why)
	}

	// An unloaded lease store is the one that would hand an address out
	// twice, so it is checked even though it is nearly impossible to reach.
	hs.srv.Store = NewLeases()
	if ok, why := hs.srv.serveGate(now); ok || !strings.Contains(why, "handed out twice") {
		t.Errorf("unloaded store: %v, %q", ok, why)
	}
}

func TestRouteGateNamesEveryReasonItWillNotRoute(t *testing.T) {
	hs := newServerHarness(t, ModeServe)
	if err := hs.srv.Prepare(); err != nil {
		t.Fatal(err)
	}
	if ok, why := hs.srv.routeGate(); ok || why != "" {
		t.Errorf("routing off is not a problem to explain: %v, %q", ok, why)
	}
	hs.setRouting(true)
	// Nothing has told the status that NAT is available yet.
	if ok, why := hs.srv.routeGate(); ok || why == "" {
		t.Errorf("without a working kernel configuration it cannot route: %v, %q", ok, why)
	}
	hs.srv.setNAT(NATStatus{Available: true})
	if ok, _ := hs.srv.routeGate(); !ok {
		t.Error("with NAT available and the switch on, it routes")
	}
	if err := hs.state.SetDisarmed(true, ""); err != nil {
		t.Fatal(err)
	}
	if ok, why := hs.srv.routeGate(); ok || !strings.Contains(why, "kill switch") {
		t.Errorf("the kill switch: %v, %q", ok, why)
	}
}

func TestRunRefusesWithNoOpenerAndReportsAFailedOpen(t *testing.T) {
	hs := newServerHarness(t, ModeObserve)
	hs.srv.Open = nil
	if err := hs.srv.Run(context.Background()); err == nil {
		t.Fatal("a mode that listens needs a way to open a socket")
	}

	hs2 := newServerHarness(t, ModeObserve)
	hs2.srv.Open = func(context.Context, string, bool) (Conn, error) { return nil, errors.New("permission denied") }
	if err := hs2.srv.Run(context.Background()); err == nil {
		t.Fatal("a failed open must be reported")
	}
	if !strings.Contains(hs2.srv.Status().Error, "permission denied") {
		t.Errorf("Status.Error = %q", hs2.srv.Status().Error)
	}
}

func TestAnUnavailableKernelConfigurationIsReportedRatherThanFatal(t *testing.T) {
	hs := newServerHarness(t, ModeObserve)
	hs.nft.fail(errors.New("executable file not found"))
	stop := hs.run(t)
	defer stop()
	waitFor(t, "the NAT status", func() bool { return hs.srv.Status().NAT.Error != "" })
	if hs.srv.Status().NAT.Available {
		t.Error("NAT is not available")
	}
	if !hs.srv.Status().Listening {
		t.Error("but DHCP mode still runs: leasing does not need nft")
	}
}

func TestUnsendableRepliesAreLoggedRatherThanLost(t *testing.T) {
	hs := newServerHarness(t, ModeServe)
	if err := hs.state.SetConfirmed(true); err != nil {
		t.Fatal(err)
	}
	hs.conn.mu.Lock()
	hs.conn.writeErr = errors.New("network is down")
	hs.conn.mu.Unlock()
	stop := hs.run(t)
	defer stop()
	waitFor(t, "serving to start", func() bool { return hs.srv.Status().Serving })
	hs.send(t, request(t, dhcpv4.MessageTypeDiscover, macA))
	waitFor(t, "the failure to be logged", func() bool { return strings.Contains(hs.log(), "network is down") })
}

func TestTheServersPortalHandleWorksWithTheModeOff(t *testing.T) {
	hs := newServerHarness(t, ModeOff)
	if err := hs.srv.Prepare(); err != nil {
		t.Fatal(err)
	}
	// This is the point of being able to prepare everything before turning
	// it on.
	if err := hs.srv.SetReservation(Reservation{MAC: macA, IP: netip.MustParseAddr("192.0.2.50"), Hostname: "printer"}); err != nil {
		t.Fatalf("SetReservation: %v", err)
	}
	if got := hs.srv.Reservations(); len(got) != 1 || got[0].MAC != macA {
		t.Fatalf("Reservations = %+v", got)
	}
	if err := hs.srv.SetReservation(Reservation{MAC: macB, IP: poolStart}); err != nil {
		t.Errorf("pinning a device to a pool address is the ordinary case: %v", err)
	}
	if err := hs.srv.SetReservation(Reservation{MAC: "02:00:5e:01:02:09", IP: netip.MustParseAddr("198.51.100.5")}); err == nil {
		t.Error("an address outside the LAN must still be refused")
	}
	ok, err := hs.srv.DeleteReservation(macA)
	if err != nil || !ok {
		t.Fatalf("DeleteReservation = %v, %v", ok, err)
	}

	set := hs.srv.SettingsView()
	if set.Subnet != "192.0.2.0/24" || set.ServerIP != shepherdA.String() || set.Gateway != gatewayA.String() {
		t.Errorf("SettingsView = %+v", set)
	}
	if set.PoolStart != poolStart.String() || set.PoolSize != 11 || set.LeaseSeconds != 600 {
		t.Errorf("SettingsView = %+v", set)
	}
	if len(set.DNS) != 1 || set.DNS[0] != shepherdA.String() {
		t.Errorf("SettingsView.DNS = %v", set.DNS)
	}
}

func TestSettingsViewWithNothingConfigured(t *testing.T) {
	s := &Server{Settings: func() Settings { return Settings{} }}
	v := s.SettingsView()
	if v.Subnet != "" || v.ServerIP != "" || v.Gateway != "" || v.PoolStart != "" {
		t.Errorf("SettingsView = %+v, want empty strings rather than invalid addresses", v)
	}
	if v.LeaseSeconds != int(DefaultLeaseTime/time.Second) {
		t.Errorf("LeaseSeconds = %d, want the default", v.LeaseSeconds)
	}
}

func TestLeasesViewExplainsWhyADeviceIsNotRouted(t *testing.T) {
	hs := newServerHarness(t, ModeServe)
	if err := hs.srv.Prepare(); err != nil {
		t.Fatal(err)
	}
	hs.srv.Store.Put(Lease{MAC: macA, IP: poolStart, Router: gatewayA, Origin: OriginShepherd,
		Allocated: hs.clock.now(), Expires: hs.clock.now().Add(time.Hour)})
	hs.srv.Store.Put(Lease{MAC: macB, IP: poolEnd, Router: shepherdA, Origin: OriginShepherd,
		Allocated: hs.clock.now(), Expires: hs.clock.now().Add(-time.Minute)})

	views := hs.srv.Leases()
	if len(views) != 2 {
		t.Fatalf("Leases = %+v", views)
	}
	byMAC := map[string]LeaseView{}
	for _, v := range views {
		byMAC[v.MAC] = v
	}
	if byMAC[macA].Routed {
		t.Error("a lease naming the gateway is not routed")
	}
	if byMAC[macA].Reason == "" {
		t.Error("and the screen should be able to say why")
	}
	if !byMAC[macB].Routed {
		t.Error("a lease naming Shepherd is routed")
	}
	if !byMAC[macB].Expired {
		t.Error("an expired lease is shown as expired rather than hidden")
	}
}

func TestNilStoresMakeThePortalHandleAnswerEmptyRatherThanPanic(t *testing.T) {
	s := &Server{}
	if s.Leases() != nil || s.Reservations() != nil {
		t.Error("with no stores there is nothing to show")
	}
	if err := s.SetReservation(Reservation{MAC: macA}); err == nil {
		t.Error("and nothing to save to")
	}
	if _, err := s.DeleteReservation(macA); err == nil {
		t.Error("or to delete from")
	}
	if err := s.Confirm(context.Background(), true); err == nil {
		t.Error("or to confirm in")
	}
	if err := s.Unroute(context.Background(), "x"); err == nil {
		t.Error("or to disarm in")
	}
	if err := s.Rearm(context.Background()); err == nil {
		t.Error("or to re-arm in")
	}
	s.ForgetPeers(context.Background())
	if s.mode() != ModeOff || s.own().Gateway.IsValid() || s.settings().Subnet.IsValid() {
		t.Error("a zero-valued server is off, owns nothing and has no settings")
	}
	if s.interval() != DefaultInterval {
		t.Errorf("interval = %v, want the default", s.interval())
	}
	if s.now().IsZero() {
		t.Error("and still has a clock")
	}
}

func TestRoutedNoteReadsPlainly(t *testing.T) {
	if got := routedNote(Decision{Routed: true}); !strings.Contains(got, "routed through Shepherd") {
		t.Errorf("routedNote = %q", got)
	}
	if got := routedNote(Decision{Reason: ReasonConsole}); !strings.Contains(got, "not routed") {
		t.Errorf("routedNote = %q", got)
	}
	if got := routedNote(Decision{}); got != "" {
		t.Errorf("routedNote = %q, want nothing to say", got)
	}
}

func TestReadGivesUpOnASocketThatKeepsFailing(t *testing.T) {
	// A socket that fails every read must not spin: the reader counts
	// failures and stops, rather than burning a core logging.
	hs := newServerHarness(t, ModeObserve)
	if err := hs.srv.Prepare(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan packet, 1)
	done := make(chan struct{})
	go func() { hs.srv.read(ctx, failingConn{}, out); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("read should give up rather than spin")
	}
	if !strings.Contains(hs.log(), "giving up") {
		t.Errorf("and say so; got %q", hs.log())
	}
}

func TestUndecodableBytesAreSkippedWithoutStopping(t *testing.T) {
	hs := newServerHarness(t, ModeObserve)
	if err := hs.state.SetConfirmed(true); err != nil {
		t.Fatal(err)
	}
	stop := hs.run(t)
	defer stop()
	waitFor(t, "the socket to open", func() bool { return hs.srv.Status().Listening })
	// A DHCP socket on a household LAN sees malformed and unrelated
	// traffic; treating that as a fault would make the log noise exactly
	// when it needs reading.
	hs.conn.in <- []byte{0x00, 0x01, 0x02}
	hs.send(t, request(t, dhcpv4.MessageTypeDiscover, macA))
	waitFor(t, "the good packet to be handled", func() bool { return len(hs.sink.all()) == 1 })
}

type failingConn struct{}

func (failingConn) ReadFrom([]byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, errors.New("socket error")
}
func (failingConn) WriteTo([]byte, netip.AddrPort) (int, error) { return 0, io.ErrClosedPipe }
func (failingConn) Close() error                                { return nil }

// Every portal action that writes state has to report a write it could not
// make: "routing stopped but the kill switch was not recorded" is a different
// situation from "routing stopped", and the operator has to be able to tell.
func TestThePortalActionsReportAFailedWrite(t *testing.T) {
	hs := newServerHarness(t, ModeServe)
	if err := hs.srv.Prepare(); err != nil {
		t.Fatal(err)
	}
	// Make the state file unwritable by removing the directory under it.
	dir := filepath.Dir(hs.srv.LeasePath)
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := hs.srv.Confirm(ctx, true); err == nil {
		t.Error("Confirm must report a write it could not make")
	}
	if err := hs.srv.Unroute(ctx, "x"); err == nil {
		t.Error("Unroute must report a write it could not make")
	}
	if err := hs.srv.Rearm(ctx); err == nil {
		t.Error("Rearm must report a write it could not make")
	}
	if err := hs.srv.SetReservation(Reservation{MAC: macA}); err == nil {
		t.Error("SetReservation must report a write it could not make")
	}
}

// The kill switch records its decision first and clears the kernel second, so
// a kernel that will not clear is reported without losing the decision.
func TestUnrouteReportsAKernelItCouldNotClear(t *testing.T) {
	hs := newServerHarness(t, ModeServe)
	if err := hs.srv.Prepare(); err != nil {
		t.Fatal(err)
	}
	hs.nft.fail(errors.New("exit status 1"))
	err := hs.srv.Unroute(context.Background(), "testing")
	if err == nil || !strings.Contains(err.Error(), "could not be cleared") {
		t.Fatalf("Unroute = %v, want one saying the rules were not cleared", err)
	}
	if off, _, _ := hs.state.Disarmed(); !off {
		t.Error("but the decision must stick: that is what survives a restart")
	}
}

func TestShutdownSavesAndClearsOnADeliberateStop(t *testing.T) {
	hs := newServerHarness(t, ModeServe)
	if err := hs.state.SetConfirmed(true); err != nil {
		t.Fatal(err)
	}
	stop := hs.run(t)
	waitFor(t, "serving to start", func() bool { return hs.srv.Status().Serving })
	hs.send(t, request(t, dhcpv4.MessageTypeRequest, macA,
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(poolStart.AsSlice()))))
	waitFor(t, "the lease", func() bool { return hs.srv.Status().Leases == 1 })
	stop()

	// A deliberate stop leaves the kernel clean, so the next start does not
	// inherit a rule set nobody is tracking. It is not the safety
	// mechanism -- that is the short lease -- but it is worth doing.
	var cleared bool
	for _, c := range hs.nft.all() {
		if strings.Contains(c.stdin, "delete table ip "+TableName) {
			cleared = true
		}
	}
	if !cleared {
		t.Error("the rule set should be removed on the way out")
	}
}

func TestShutdownComplainsAboutASaveItCouldNotMake(t *testing.T) {
	hs := newServerHarness(t, ModeObserve)
	if err := hs.srv.Prepare(); err != nil {
		t.Fatal(err)
	}
	hs.srv.Store.Put(Lease{MAC: macA, IP: poolStart})
	if err := os.RemoveAll(filepath.Dir(hs.srv.LeasePath)); err != nil {
		t.Fatal(err)
	}
	hs.nft.fail(errors.New("exit status 1"))
	hs.srv.shutdown(newFakeConn())
	for _, want := range []string{"saving leases", "clearing the rule set"} {
		if !strings.Contains(hs.log(), want) {
			t.Errorf("the log should mention %q; got %q", want, hs.log())
		}
	}
}

func TestPrepareWithNoLeasePathUsesAnInMemoryStore(t *testing.T) {
	hs := newServerHarness(t, ModeObserve)
	hs.srv.LeasePath = ""
	hs.srv.Store = nil
	hs.srv.Peers = nil
	if err := hs.srv.Prepare(); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if !hs.srv.Store.Loaded() {
		t.Error("an in-memory store counts as loaded: there is nothing to recover")
	}
	if hs.srv.Peers == nil {
		t.Error("Prepare should build the peer record it was not given")
	}
}

func TestUpdateStatusCarriesAConfigurationProblemWhileTheModeIsOn(t *testing.T) {
	hs := newServerHarness(t, ModeObserve)
	hs.setSettings(Settings{})
	if err := hs.srv.Prepare(); err != nil {
		t.Fatal(err)
	}
	if got := hs.srv.Status().Error; got == "" {
		t.Fatal("a mode that is on with unusable settings must say so")
	}
	// With the mode off there is nothing to complain about: nobody asked.
	hs.setMode(ModeOff)
	hs.srv.updateStatus()
	if got := hs.srv.Status().Error; got != "" {
		t.Errorf("Status.Error = %q, want nothing while the mode is off", got)
	}
}

func TestServeRefusesToSendAReplyOutsideServeMode(t *testing.T) {
	// The belt-and-braces check in serve: a reply in a non-serving mode is
	// a bug, and it must not reach the wire while it is being found.
	hs := newServerHarness(t, ModeServe)
	if err := hs.srv.Prepare(); err != nil {
		t.Fatal(err)
	}
	pkt := request(t, dhcpv4.MessageTypeDiscover, macA)
	hs.setMode(ModeObserve)
	hs.srv.serve(context.Background(), hs.conn, packet{pkt: pkt})
	if len(hs.conn.replies()) != 0 {
		t.Fatal("observe mode sent something")
	}
}

// Choosing a range the network does not use yet is allowed and is the point:
// the operator writes down where they are going and is told what has to
// change on the router. Serving stops until it fits.
func TestAChosenRangeThatDoesNotFitStopsServingAndSaysWhatToChange(t *testing.T) {
	hs := newServerHarness(t, ModeServe)
	hs.srv.Observe = func() Observed {
		return Observed{HostAddrs: []netip.Addr{shepherdA}, Gateway: gatewayA}
	}
	if err := hs.state.SetConfirmed(true); err != nil {
		t.Fatal(err)
	}
	if err := hs.srv.Prepare(); err != nil {
		t.Fatal(err)
	}
	if ok, _ := hs.srv.serveGate(hs.clock.now()); !ok {
		t.Fatal("it should serve before a range is chosen")
	}

	want := Range{
		Subnet:   netip.MustParsePrefix("192.168.1.0/24"),
		ServerIP: netip.MustParseAddr("192.168.1.20"),
		Gateway:  netip.MustParseAddr("192.168.1.1"),
		Pool:     Pool{Start: netip.MustParseAddr("192.168.1.100"), End: netip.MustParseAddr("192.168.1.200")},
	}
	if err := hs.srv.SetRange(context.Background(), want); err != nil {
		t.Fatalf("SetRange: %v; a range that does not fit yet is still worth storing", err)
	}
	ok, why := hs.srv.serveGate(hs.clock.now())
	if ok {
		t.Fatal("a range the router does not use must stop serving")
	}
	if !strings.Contains(why, "192.168.1") {
		t.Errorf("the reason should say what to change: %q", why)
	}
	if len(hs.srv.Conflicts()) == 0 {
		t.Error("and the conflicts should be readable on their own")
	}

	// The chosen range is in force for the addressing even while it is
	// blocked, so the screen shows what it would hand out.
	if got := hs.srv.SettingsView().Subnet; got != "192.168.1.0/24" {
		t.Errorf("SettingsView.Subnet = %q, want the chosen range", got)
	}
	rv := hs.srv.RangeView()
	if !rv.Chosen || rv.Subnet != "192.168.1.0/24" || rv.Gateway != "192.168.1.1" {
		t.Errorf("RangeView = %+v", rv)
	}
	if rv.Current.Subnet != "192.0.2.0/24" {
		t.Errorf("RangeView.Current = %+v, want what it would fall back to", rv.Current)
	}

	// Once the network matches, it serves.
	hs.srv.Observe = func() Observed {
		return Observed{HostAddrs: []netip.Addr{want.ServerIP}, Gateway: want.Gateway}
	}
	if ok, why := hs.srv.serveGate(hs.clock.now()); !ok {
		t.Errorf("with the router moved it should serve: %q", why)
	}

	// Clearing it goes back to the interface's own range.
	if err := hs.srv.SetRange(context.Background(), Range{}); err != nil {
		t.Fatalf("clearing: %v", err)
	}
	if hs.srv.RangeView().Chosen || hs.srv.SettingsView().Subnet != "192.0.2.0/24" {
		t.Error("clearing the range puts the configuration file back in charge")
	}
	if hs.srv.Conflicts() != nil {
		t.Error("and there is nothing left to compare")
	}
}

func TestAnAddressShepherdLeasedIsNotCountedAsACollision(t *testing.T) {
	hs := newServerHarness(t, ModeServe)
	if err := hs.srv.Prepare(); err != nil {
		t.Fatal(err)
	}
	inPool := netip.MustParseAddr("192.168.1.105")
	rng := Range{
		Subnet:   netip.MustParsePrefix("192.168.1.0/24"),
		ServerIP: netip.MustParseAddr("192.168.1.20"),
		Gateway:  netip.MustParseAddr("192.168.1.1"),
		Pool:     Pool{Start: netip.MustParseAddr("192.168.1.100"), End: netip.MustParseAddr("192.168.1.200")},
	}
	hs.srv.Observe = func() Observed {
		return Observed{HostAddrs: []netip.Addr{rng.ServerIP}, Gateway: rng.Gateway,
			Holders: []Holder{{IP: inPool, MAC: macA, Name: "Kids Tablet"}}}
	}
	if err := hs.srv.SetRange(context.Background(), rng); err != nil {
		t.Fatal(err)
	}
	if _, blocked := Blocked(hs.srv.Conflicts()); !blocked {
		t.Fatal("an address in the pool that Shepherd did not hand out is a collision")
	}

	// Once it is one of Shepherd's own leases it moves on its own.
	hs.srv.Store.Put(Lease{MAC: macA, IP: inPool, Origin: OriginShepherd, Expires: hs.clock.now().Add(time.Hour)})
	if c, blocked := Blocked(hs.srv.Conflicts()); blocked {
		t.Errorf("a leased address is not a collision: %+v", c)
	}
}

func TestSetRangeRefusesARangeThatIsWrongOnItsOwnTerms(t *testing.T) {
	hs := newServerHarness(t, ModeOff)
	if err := hs.srv.Prepare(); err != nil {
		t.Fatal(err)
	}
	err := hs.srv.SetRange(context.Background(), Range{Subnet: netip.MustParsePrefix("192.168.1.0/24")})
	if err == nil || !errors.Is(err, ErrRange) {
		t.Fatalf("SetRange = %v, want an ErrRange", err)
	}
	var none *Server
	_ = none
	if err := (&Server{}).SetRange(context.Background(), Range{}); err == nil {
		t.Error("a server with no state store cannot save a range")
	}
	if (&Server{}).Conflicts() != nil {
		t.Error("and has nothing to compare")
	}
	if (&Server{}).RangeView().Chosen {
		t.Error("or to report")
	}
	if _, ok := (&Server{}).Reservation(macA); ok {
		t.Error("or to look a reservation up in")
	}
}
