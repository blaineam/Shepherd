// SPDX-License-Identifier: AGPL-3.0-or-later

package dhcp

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"

	"shepherd/internal/devices"
)

// Documentation addresses throughout (RFC 5737, RFC 7042): the repository's
// leakcheck refuses anything that could be a real network.
var (
	lanPrefix = netip.MustParsePrefix("192.0.2.0/24")
	shepherdA = netip.MustParseAddr("192.0.2.20")
	gatewayA  = netip.MustParseAddr("192.0.2.1")
	poolStart = netip.MustParseAddr("192.0.2.100")
	poolEnd   = netip.MustParseAddr("192.0.2.110")
	bcastAll  = netip.MustParseAddr("255.255.255.255")
)

const (
	macA       = "02:00:5e:01:02:03"
	macB       = "02:00:5e:01:02:04"
	macGateway = "02:00:5e:00:00:01"
)

func testSettings() Settings {
	return Settings{
		Subnet: lanPrefix, ServerIP: shepherdA, Gateway: gatewayA,
		Pool: Pool{Start: poolStart, End: poolEnd},
		DNS:  []netip.Addr{shepherdA}, LeaseTime: 10 * time.Minute,
	}
}

// clock is a controllable time source, so every lease expiry in these tests
// is exact rather than racy.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)} }

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func hw(t *testing.T, mac string) net.HardwareAddr {
	t.Helper()
	h, err := net.ParseMAC(mac)
	if err != nil {
		t.Fatalf("parsing %q: %v", mac, err)
	}
	return h
}

// request builds a client packet of one message type, the way a real client
// would: the message-type option, the client's MAC, and whatever extra
// options the caller adds.
func request(t *testing.T, mt dhcpv4.MessageType, mac string, mods ...dhcpv4.Modifier) *dhcpv4.DHCPv4 {
	t.Helper()
	all := append([]dhcpv4.Modifier{
		dhcpv4.WithMessageType(mt),
		dhcpv4.WithHwAddr(hw(t, mac)),
	}, mods...)
	p, err := dhcpv4.New(all...)
	if err != nil {
		t.Fatalf("building a %s: %v", mt, err)
	}
	p.OpCode = dhcpv4.OpcodeBootRequest
	return p
}

// serverReply builds what another DHCP server's reply looks like on the wire,
// which is what the rogue-server interlock has to recognise.
func serverReply(t *testing.T, mt dhcpv4.MessageType, mac string, server, offered netip.Addr, mods ...dhcpv4.Modifier) *dhcpv4.DHCPv4 {
	t.Helper()
	all := append([]dhcpv4.Modifier{
		dhcpv4.WithMessageType(mt),
		dhcpv4.WithHwAddr(hw(t, mac)),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(server.AsSlice())),
	}, mods...)
	p, err := dhcpv4.New(all...)
	if err != nil {
		t.Fatalf("building a %s: %v", mt, err)
	}
	p.OpCode = dhcpv4.OpcodeBootReply
	if offered.IsValid() {
		p.YourIPAddr = offered.AsSlice()
	}
	return p
}

// recordingSink collects the registry observations a handler makes, so the
// "observe mode is useful on its own" claim can be checked.
type recordingSink struct {
	mu sync.Mutex
	in []devices.Observation
}

func (r *recordingSink) Observe(o devices.Observation) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.in = append(r.in, o)
	return "dev-" + o.MAC
}

func (r *recordingSink) all() []devices.Observation {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]devices.Observation(nil), r.in...)
}

// fakeConn is a Conn over two channels, so the serve loop runs with no
// socket and no privilege.
type fakeConn struct {
	in     chan []byte
	from   netip.AddrPort
	mu     sync.Mutex
	sent   []sentPacket
	closed bool
	// writeErr, when set, is what WriteTo returns.
	writeErr error
}

type sentPacket struct {
	data []byte
	to   netip.AddrPort
}

func newFakeConn() *fakeConn {
	return &fakeConn{in: make(chan []byte, 16), from: netip.AddrPortFrom(netip.MustParseAddr("192.0.2.101"), ClientPort)}
}

func (f *fakeConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	b, ok := <-f.in
	if !ok {
		return 0, netip.AddrPort{}, net.ErrClosed
	}
	return copy(p, b), f.from, nil
}

func (f *fakeConn) WriteTo(p []byte, to netip.AddrPort) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	f.sent = append(f.sent, sentPacket{data: append([]byte(nil), p...), to: to})
	return len(p), nil
}

func (f *fakeConn) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.closed {
		f.closed = true
		close(f.in)
	}
	return nil
}

func (f *fakeConn) replies() []sentPacket {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]sentPacket(nil), f.sent...)
}

// fakeNFT records what would have been handed to nft, and can be made to
// fail, which is the path that has to make routing stop on its own.
type fakeNFT struct {
	mu    sync.Mutex
	calls []nftCall
	err   error
}

type nftCall struct {
	name  string
	args  []string
	stdin string
}

func (f *fakeNFT) run(_ context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, nftCall{name: name, args: args, stdin: string(stdin)})
	if f.err != nil {
		return []byte("nft: refused"), f.err
	}
	return nil, nil
}

func (f *fakeNFT) all() []nftCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]nftCall(nil), f.calls...)
}

func (f *fakeNFT) fail(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

// fakeSysctl is a map standing in for /proc/sys, with a record of writes so a
// test can tell "already correct" from "set by Shepherd".
type fakeSysctl struct {
	mu      sync.Mutex
	values  map[string]string
	writes  []string
	readErr map[string]error
	setErr  map[string]error
}

func newSysctl() *fakeSysctl {
	return &fakeSysctl{values: map[string]string{}, readErr: map[string]error{}, setErr: map[string]error{}}
}

func (f *fakeSysctl) Get(key string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.readErr[key]; err != nil {
		return "", err
	}
	v, ok := f.values[key]
	if !ok {
		return "", net.ErrClosed // stands in for "no such file"
	}
	return v, nil
}

func (f *fakeSysctl) Set(key, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.setErr[key]; err != nil {
		return err
	}
	f.values[key] = value
	f.writes = append(f.writes, key+"="+value)
	return nil
}

func (f *fakeSysctl) wrote() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.writes...)
}

// decodeReply parses a reply the handler produced, so assertions are about
// the bytes a client would see rather than about the struct.
func decodeReply(t *testing.T, p *dhcpv4.DHCPv4) *dhcpv4.DHCPv4 {
	t.Helper()
	out, err := dhcpv4.FromBytes(p.ToBytes())
	if err != nil {
		t.Fatalf("the reply does not decode: %v", err)
	}
	return out
}

// waitFor polls cond until it holds or the deadline passes. The serve loop is
// a goroutine, so a test that asserts on its effect has to wait for it; this
// is deliberately a poll rather than a sleep so a fast machine is fast.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
