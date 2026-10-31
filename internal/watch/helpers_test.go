// SPDX-License-Identifier: AGPL-3.0-or-later

package watch

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"shepherd/internal/arp"
	"shepherd/internal/devices"
	"shepherd/internal/intercept"
)

var (
	gwIP = netip.MustParseAddr("192.0.2.1")
	// The gateway's and the phone's link-local addresses (…::1 and …::10),
	// built from byte arrays to keep link-local literals out of the source,
	// the same convention internal/ndp's own tests use.
	gwLinkLocal = linkLocal(0x01)
	phoneV6     = linkLocal(0x10)
	shepherdV6  = netip.MustParseAddr("2001:db8::2")
	gwMAC       = mustMAC("02:00:5e:00:00:01")
	shepherdMAC = mustMAC("02:00:5e:00:00:02")
	shepherdIP  = netip.MustParseAddr("192.0.2.2")
	phoneMAC    = mustMAC("02:00:5e:00:00:10")
	phoneIP     = netip.MustParseAddr("192.0.2.10")
	t0          = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
)

// linkLocal builds a link-local address ending in last, without writing
// the prefix out as text.
func linkLocal(last byte) netip.Addr {
	var b [16]byte
	b[0], b[1] = 0xfe, 0x80
	b[15] = last
	return netip.AddrFrom16(b)
}

// uniqueLocal builds a unique-local address ending in last: the range a
// network has when it has no globally routable IPv6, which is what IPv6
// steering idles on.
func uniqueLocal(last byte) netip.Addr {
	var b [16]byte
	b[0] = 0xfc
	b[15] = last
	return netip.AddrFrom16(b)
}

func mustMAC(s string) arp.MAC {
	m, err := arp.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return m
}

// fakePlatform is a Platform with no kernel behind it. Every knob a test
// wants to turn is a field; the relays block until their context ends
// unless told to fail.
type fakePlatform struct {
	// driver/carrier stand in for sysfs: the NIC's driver name and the
	// kernel's link-transition counter.
	driver string
	// xdpRequested is the mode the engine last asked for, so a test can
	// assert that it chose generic rather than letting auto find native.
	xdpRequested intercept.XDPMode
	driverErr    error
	carrier      uint64
	carrierErr   error
	// extraMACs/extraIPs are further interfaces this host has, for the
	// multi-homed case; localAddrsErr makes the enumeration fail.
	extraMACs     []arp.MAC
	extraIPs      []netip.Addr
	localAddrsErr error
	mu            sync.Mutex
	iface         string
	gateway       netip.Addr
	gwMAC         arp.MAC
	link          Link
	neighbors     []Neighbor
	sender        *intercept.FakeSender

	route6    Route6
	route6Err error

	routeErr, linkErr, gwErr, senderErr error
	xdpErr                              error // AttachXDP fails at once with this
	xdpMode                             intercept.XDPMode
	relayErr                            error // ParallelRelay fails at once with this
	gro                                 bool
	groErr, setGROErr                   error
	unsupported                         bool

	xdpAttached, relayStarted int
	groSets                   []bool
	xdpDie                    chan error // when set, AttachXDP returns what it receives
}

func newFakePlatform() *fakePlatform {
	return &fakePlatform{
		iface: "eth0", gateway: gwIP, gwMAC: gwMAC,
		link:      Link{Name: "eth0", Index: 2, MAC: shepherdMAC, IPv4s: []netip.Addr{shepherdIP}, IPv6s: []netip.Addr{shepherdV6}},
		route6:    Route6{Iface: "eth0", NextHop: gwLinkLocal},
		neighbors: []Neighbor{{IP: gwIP, MAC: gwMAC}},
		sender:    intercept.NewFakeSender(),
		xdpMode:   intercept.XDPNative,
		xdpDie:    make(chan error, 1),
		gro:       true,
	}
}

func (p *fakePlatform) DefaultRoute() (string, netip.Addr, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.unsupported {
		return "", netip.Addr{}, ErrUnsupported
	}
	return p.iface, p.gateway, p.routeErr
}

func (p *fakePlatform) DefaultRoute6() (Route6, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.unsupported {
		return Route6{}, ErrUnsupported
	}
	return p.route6, p.route6Err
}

func (p *fakePlatform) Link(name string) (Link, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.linkErr != nil {
		return Link{}, p.linkErr
	}
	l := p.link
	l.Name = name
	return l, nil
}

// LocalAddrs is the host's own addresses. The fake answers with the links
// it knows about, so a test can add a second interface on the same subnet
// and check that Watch mode refuses to steer it.
func (p *fakePlatform) LocalAddrs() ([]arp.MAC, []netip.Addr, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.localAddrsErr != nil {
		return nil, nil, p.localAddrsErr
	}
	macs := []arp.MAC{shepherdMAC}
	ips := []netip.Addr{shepherdIP}
	macs = append(macs, p.extraMACs...)
	ips = append(ips, p.extraIPs...)
	return macs, ips, nil
}

// Driver and CarrierChanges let a test stand in for a NIC whose driver
// drops the link when a native XDP attach rebuilds its rings.
func (p *fakePlatform) Driver(string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.driver, p.driverErr
}

func (p *fakePlatform) CarrierChanges(string) (uint64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.carrierErr != nil {
		return 0, p.carrierErr
	}
	return p.carrier, nil
}

// flapOnNativeAttach makes the next native attach look like it took the
// link down and up, the way the atlantic driver really does.
func (p *fakePlatform) flapOnNativeAttach() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.carrier++
}

func (p *fakePlatform) GatewayMAC(ctx context.Context, iface string, gw netip.Addr) (arp.MAC, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.gwErr != nil {
		return arp.MAC{}, p.gwErr
	}
	return p.gwMAC, nil
}

func (p *fakePlatform) Neighbors(string) ([]Neighbor, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]Neighbor(nil), p.neighbors...), nil
}

func (p *fakePlatform) OpenSender(string) (intercept.Sender, func() error, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.senderErr != nil {
		return nil, nil, p.senderErr
	}
	return p.sender, func() error { return nil }, nil
}

func (p *fakePlatform) AttachXDP(ctx context.Context, c *intercept.Controller, iface string, opts intercept.XDPOptions) error {
	p.mu.Lock()
	if p.xdpErr != nil {
		err := p.xdpErr
		p.mu.Unlock()
		return err
	}
	p.xdpAttached++
	p.xdpRequested = opts.Mode
	mode, die := p.xdpMode, p.xdpDie
	// Asking for generic gets generic; asking for auto or native gets
	// whatever this fake NIC is set up to support.
	if opts.Mode == intercept.XDPGeneric {
		mode = intercept.XDPGeneric
	}
	p.mu.Unlock()
	if opts.OnAttached != nil {
		opts.OnAttached(mode)
	}
	select {
	case <-ctx.Done():
		return nil
	case err := <-die:
		return err
	}
}

func (p *fakePlatform) ParallelRelay(ctx context.Context, c *intercept.Controller, iface string, workers int) error {
	p.mu.Lock()
	if p.relayErr != nil {
		err := p.relayErr
		p.mu.Unlock()
		return err
	}
	p.relayStarted++
	p.mu.Unlock()
	<-ctx.Done()
	return nil
}

func (p *fakePlatform) GRO(string) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.gro, p.groErr
}

func (p *fakePlatform) SetGRO(_ string, on bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.setGROErr != nil {
		return p.setGROErr
	}
	p.gro = on
	p.groSets = append(p.groSets, on)
	return nil
}

func (p *fakePlatform) setGatewayMAC(m arp.MAC) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.gwMAC = m
	p.neighbors = []Neighbor{{IP: gwIP, MAC: m}}
}

func (p *fakePlatform) counts() (xdp, relay int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.xdpAttached, p.relayStarted
}

// testEngine wires an Engine over a fake platform, a FakeClock and a fresh
// registry whose clock is the same FakeClock.
type testEngine struct {
	*Engine
	plat  *fakePlatform
	clock *intercept.FakeClock
	reg   *devices.Registry
	logs  *logSink
	done  chan error
	stop  context.CancelFunc
}

type logSink struct {
	mu    sync.Mutex
	lines []string
}

func (l *logSink) printf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, sprintf(format, args...))
}

func (l *logSink) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.lines...)
}

func newTestEngine(t *testing.T, plat *fakePlatform, mutate func(*Config)) *testEngine {
	t.Helper()
	clock := intercept.NewFakeClock(t0)
	reg := devices.New(devices.Options{Now: clock.Now})
	logs := &logSink{}
	cfg := Config{Enabled: true, Registry: reg, Platform: plat, Clock: clock, Logf: logs.printf,
		StatePath: t.TempDir() + "/watch.json"}
	if mutate != nil {
		mutate(&cfg)
	}
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.attachTimeout = 2 * time.Second
	e.relayGrace = 5 * time.Millisecond
	return &testEngine{Engine: e, plat: plat, clock: clock, reg: reg, logs: logs}
}

// start runs the engine in the background.
func (te *testEngine) start(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	te.stop = cancel
	te.done = make(chan error) // closed when Run returns
	go func() { _ = te.Run(ctx); close(te.done) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-te.done:
		case <-time.After(5 * time.Second):
			t.Error("engine did not stop")
		}
	})
}

// waitFor polls cond (real time, since the engine's own startup waits are
// real) until it holds or the test's patience runs out.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func (te *testEngine) waitRunning(t *testing.T) {
	t.Helper()
	waitFor(t, "engine running", func() bool { return te.Snapshot().Phase == PhaseRunning })
}

// addPhone puts an ordinary, recently seen phone in the registry.
func (te *testEngine) addPhone(t *testing.T) string {
	t.Helper()
	id := te.reg.Observe(devices.Observation{Source: devices.SourceNeighbor, MAC: phoneMAC.String(), IP: phoneIP.String(), Hostname: "phone"})
	if id == "" {
		t.Fatal("observe returned no id")
	}
	return id
}

// addPhoneV6 gives the phone an IPv6 address too, so it is steerable for
// both families.
func (te *testEngine) addPhoneV6(t *testing.T) string {
	t.Helper()
	id := te.addPhone(t)
	te.reg.Observe(devices.Observation{Source: devices.SourceNeighbor, MAC: phoneMAC.String(), IP: phoneV6.String()})
	return id
}

// families returns the families the Controller is steering for mac.
func (te *testEngine) families(mac arp.MAC) intercept.Family {
	te.mu.Lock()
	c := te.ctrl
	te.mu.Unlock()
	if c == nil {
		return 0
	}
	for _, d := range c.Status() {
		if d.MAC == mac {
			return d.Family
		}
	}
	return 0
}

func (te *testEngine) steeredMACs() []arp.MAC {
	te.mu.Lock()
	c := te.ctrl
	te.mu.Unlock()
	if c == nil {
		return nil
	}
	var out []arp.MAC
	for _, d := range c.Status() {
		out = append(out, d.MAC)
	}
	return out
}

func (te *testEngine) isSteered(mac arp.MAC) bool {
	for _, m := range te.steeredMACs() {
		if m == mac {
			return true
		}
	}
	return false
}

func (te *testEngine) waitSteered(t *testing.T, mac arp.MAC, want bool) {
	t.Helper()
	// The engine reconciles on registry events and on its one-second tick;
	// poke it directly so the test does not depend on either.
	waitFor(t, "steered="+sprintf("%v", want)+" for "+mac.String(), func() bool {
		te.poke(te.kick)
		return te.isSteered(mac) == want
	})
}

// waitFailures waits until the device's health-failure count reaches n:
// the Controller removes a device from Status before OnUnsteer records
// the failure, so a test that saw it unsteered may be a hair early.
func (te *testEngine) waitFailures(t *testing.T, id string, n int) {
	t.Helper()
	waitFor(t, sprintf("%d failures", n), func() bool { return te.status(t, id).Failures == n })
}

func (te *testEngine) status(t *testing.T, id string) DeviceStatus {
	t.Helper()
	for _, d := range te.Snapshot().Devices {
		if d.DeviceID == id {
			return d
		}
	}
	t.Fatalf("device %s missing from the snapshot", id)
	return DeviceStatus{}
}

var errBoom = errors.New("boom")

// requestedXDP is the XDP mode the engine last asked AttachXDP for.
func (p *fakePlatform) requestedXDP() intercept.XDPMode {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.xdpRequested
}
