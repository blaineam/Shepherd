// SPDX-License-Identifier: AGPL-3.0-or-later

package dhcp

import (
	"context"
	"errors"
	"log"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// The guarantee that makes observe mode safe to run on a live network is
// enforced in the connection as well as in the server, because a bug in the
// handler must not be able to put a frame on the wire.
func TestReadOnlyRefusesEveryWrite(t *testing.T) {
	f := newFakeConn()
	defer f.Close()
	c := ReadOnly(f)
	if _, err := c.WriteTo([]byte{1}, netip.AddrPortFrom(bcastAll, ClientPort)); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("WriteTo = %v, want ErrReadOnly", err)
	}
	if len(f.replies()) != 0 {
		t.Fatal("nothing may reach the underlying socket")
	}
	// Reading still works: that is the whole point of the mode.
	f.in <- []byte("hello")
	buf := make([]byte, 16)
	n, _, err := c.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "hello" {
		t.Fatalf("ReadFrom = %d, %v", n, err)
	}
}

func TestMultiConnReadsFromEverySocketAndWritesThroughOne(t *testing.T) {
	a, b := newFakeConn(), newFakeConn()
	out := newFakeConn()
	m := newMultiConn(out, a, b)
	defer m.Close()

	a.in <- []byte("from-67")
	b.in <- []byte("from-68")
	buf := make([]byte, 32)
	seen := map[string]bool{}
	for i := 0; i < 2; i++ {
		n, _, err := m.ReadFrom(buf)
		if err != nil {
			t.Fatalf("ReadFrom: %v", err)
		}
		seen[string(buf[:n])] = true
	}
	if !seen["from-67"] || !seen["from-68"] {
		t.Fatalf("both sockets should be read, got %v", seen)
	}

	if _, err := m.WriteTo([]byte("reply"), netip.AddrPortFrom(bcastAll, ClientPort)); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if got := out.replies(); len(got) != 1 || string(got[0].data) != "reply" {
		t.Fatalf("the reply must go out through the port-67 socket, got %+v", got)
	}
	// Closing is idempotent, because both the server and a test may do it.
	if err := m.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if err := m.Close(); err != nil {
		t.Errorf("a second Close: %v", err)
	}
	if _, _, err := m.ReadFrom(buf); err == nil {
		t.Error("reading a closed connection is an error")
	}
}

func TestMultiConnWithNoOutputSocketCannotWrite(t *testing.T) {
	a := newFakeConn()
	m := newMultiConn(nil, a)
	defer m.Close()
	if _, err := m.WriteTo([]byte("x"), netip.AddrPortFrom(bcastAll, ClientPort)); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("WriteTo = %v, want ErrReadOnly", err)
	}
}

func TestMultiConnSurfacesAReadError(t *testing.T) {
	a := newFakeConn()
	m := newMultiConn(a, a)
	a.Close() // closing the channel makes ReadFrom report net.ErrClosed
	buf := make([]byte, 8)
	if _, _, err := m.ReadFrom(buf); err == nil {
		t.Fatal("a socket error must reach the reader")
	}
	m.Close()
}

type fakeListener struct {
	ports     []int
	broadcast map[int]bool
	fail      map[int]error
	conns     []*fakeConn
}

func (f *fakeListener) listen(_ context.Context, _ string, port int, broadcast bool) (Conn, error) {
	if f.broadcast == nil {
		f.broadcast = map[int]bool{}
	}
	if err := f.fail[port]; err != nil {
		return nil, err
	}
	f.ports = append(f.ports, port)
	f.broadcast[port] = broadcast
	c := newFakeConn()
	f.conns = append(f.conns, c)
	return c, nil
}

func TestUDPOpenerBindsBothPortsAndAsksForBroadcastOnlyWhenServing(t *testing.T) {
	f := &fakeListener{}
	o := UDPOpener{Listen: f.listen}
	c, err := o.Open(context.Background(), "eth0", true)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer c.Close()
	if len(f.ports) != 2 || f.ports[0] != ServerPort || f.ports[1] != ClientPort {
		t.Fatalf("ports = %v, want 67 then 68", f.ports)
	}
	// A server that cannot broadcast cannot answer a client that has no
	// address yet, which is every client the first time.
	if !f.broadcast[ServerPort] {
		t.Error("the serving socket must ask for broadcast")
	}
	if f.broadcast[ClientPort] {
		t.Error("the watching socket never sends, so it needs no broadcast")
	}
	if _, err := c.WriteTo([]byte("x"), netip.AddrPortFrom(bcastAll, ClientPort)); err != nil {
		t.Errorf("a serving connection can write: %v", err)
	}
}

func TestUDPOpenerInObserveModeReturnsAConnectionThatCannotWrite(t *testing.T) {
	f := &fakeListener{}
	c, err := UDPOpener{Listen: f.listen}.Open(context.Background(), "eth0", false)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer c.Close()
	if f.broadcast[ServerPort] {
		t.Error("observe mode asks for nothing that would let it send")
	}
	if _, err := c.WriteTo([]byte("x"), netip.AddrPortFrom(bcastAll, ClientPort)); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("WriteTo = %v, want ErrReadOnly", err)
	}
}

// Something else on the host being a DHCP client is normal, and the interlock
// then falls back to clients' own requests rather than refusing to start.
func TestUDPOpenerCarriesOnWhenPortSixtyEightIsTaken(t *testing.T) {
	var logged strings.Builder
	f := &fakeListener{fail: map[int]error{ClientPort: errors.New("address already in use")}}
	o := UDPOpener{Listen: f.listen, Log: log.New(&logged, "", 0)}
	c, err := o.Open(context.Background(), "eth0", true)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer c.Close()
	if len(f.ports) != 1 || f.ports[0] != ServerPort {
		t.Fatalf("ports = %v, want just 67", f.ports)
	}
	if !strings.Contains(logged.String(), "clients' own requests") {
		t.Errorf("the reduced sensitivity must be logged, not discovered later; got %q", logged.String())
	}
}

func TestUDPOpenerFailsWhenPortSixtySevenCannotBeBound(t *testing.T) {
	f := &fakeListener{fail: map[int]error{ServerPort: errors.New("permission denied")}}
	if _, err := (UDPOpener{Listen: f.listen}).Open(context.Background(), "eth0", true); err == nil {
		t.Fatal("without port 67 there is no DHCP server")
	}
}

// udpConn is the one piece of the socket layer that can be exercised without
// privilege: a pair of loopback sockets on high ports behaves exactly like
// the real thing minus the port numbers and the socket options.
func TestUDPConnRoundTripsOverLoopback(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("loopback UDP is unavailable here: %v", err)
	}
	sc := udpConn{c: server}
	defer func() {
		if err := sc.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()

	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("second socket: %v", err)
	}
	defer client.Close()

	to := netip.MustParseAddrPort(client.LocalAddr().String())
	if _, err := sc.WriteTo([]byte("offer"), to); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	buf := make([]byte, 32)
	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, from, err := client.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("the client did not receive it: %v", err)
	}
	if string(buf[:n]) != "offer" || from == nil {
		t.Fatalf("received %q from %v", buf[:n], from)
	}

	// And the other direction, which is what ReadFrom is for.
	back := netip.MustParseAddrPort(server.LocalAddr().String())
	if _, err := client.WriteToUDPAddrPort([]byte("request"), back); err != nil {
		t.Fatal(err)
	}
	if err := server.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, fromAP, err := sc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if string(buf[:n]) != "request" || !fromAP.IsValid() {
		t.Fatalf("ReadFrom = %q from %v", buf[:n], fromAP)
	}
}

type closeErrConn struct {
	Conn
	err error
}

func (c closeErrConn) Close() error { _ = c.Conn.Close(); return c.err }

func TestMultiConnReportsTheFirstCloseFailure(t *testing.T) {
	bad := closeErrConn{Conn: newFakeConn(), err: errors.New("close failed")}
	good := newFakeConn()
	m := newMultiConn(good, bad, good)
	if err := m.Close(); err == nil {
		t.Fatal("a socket that will not close must be reported")
	}
}
