// SPDX-License-Identifier: AGPL-3.0-or-later

package decoy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// fakeAddr is a connection source the test chooses.
type fakeAddr string

func (a fakeAddr) Network() string { return "tcp" }
func (a fakeAddr) String() string  { return string(a) }

type fakeConn struct {
	net.Conn
	from fakeAddr
}

func (c fakeConn) RemoteAddr() net.Addr { return c.from }
func (c fakeConn) Close() error         { return nil }

// fakeListener hands out the connections a test pushes into it.
type fakeListener struct {
	conns  chan net.Conn
	errs   chan error
	closed chan struct{}
	once   sync.Once
}

func newFakeListener() *fakeListener {
	return &fakeListener{conns: make(chan net.Conn), errs: make(chan error, 1), closed: make(chan struct{})}
}

func (l *fakeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case err := <-l.errs:
		return nil, err
	case <-l.closed:
		return nil, net.ErrClosed
	}
}
func (l *fakeListener) Close() error   { l.once.Do(func() { close(l.closed) }); return nil }
func (l *fakeListener) Addr() net.Addr { return fakeAddr("0.0.0.0:0") }

func TestTouchesAreReportedOncePerQuietPeriod(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	lns := map[string]*fakeListener{}
	touches := make(chan Touch, 16)
	d := New(Options{
		Ports: []int{2323, 23, 23, 445},
		Listen: func(network, addr string) (net.Listener, error) {
			if addr == ":445" {
				return nil, errors.New("address already in use")
			}
			l := newFakeListener()
			lns[addr] = l
			return l, nil
		},
		Ignore:  func(a netip.Addr) bool { return a == netip.MustParseAddr("192.0.2.20") },
		OnTouch: func(t Touch) { touches <- t },
		Now:     func() time.Time { return now },
	})
	if len(d.Status()) != 0 || len(d.Recent()) != 0 || len(d.Listening()) != 0 {
		t.Error("a decoy that has not started should report nothing")
	}
	ctx, cancel := context.WithCancel(context.Background())
	st := d.Start(ctx)
	if len(st) != 3 || !st[0].Listening || st[0].Port != 23 || st[1].Listening || st[1].Error == "" || st[1].Port != 445 || !st[2].Listening {
		t.Fatalf("status = %+v", st)
	}
	if got := d.Listening(); len(got) != 2 || got[0] != 23 || got[1] != 2323 {
		t.Errorf("listening = %v", got)
	}
	send := func(port, from string) { lns[port].conns <- fakeConn{from: fakeAddr(from)} }

	send(":23", "192.0.2.77:51000")
	if got := <-touches; got.Source != "192.0.2.77" || got.Port != 23 || got.Count != 1 || !got.Time.Equal(now) {
		t.Errorf("touch = %+v", got)
	}
	// Our own address, loopback, an unparsable source and a repeat inside
	// the quiet period are all silent; an accept error does not stop the
	// listener.
	send(":23", "192.0.2.20:40000")
	send(":23", "127.0.0.1:40000")
	send(":23", "[::ffff:127.0.0.1]:40000")
	send(":23", "not-an-address")
	lns[":23"].errs <- errors.New("too many open files")
	send(":23", "192.0.2.77:51001")
	send(":23", "127.0.0.1:40001") // accepted only once the repeat has been handled
	// Another port from the same source is its own report.
	send(":2323", "[::ffff:192.0.2.77]:51002")
	if got := <-touches; got.Port != 2323 || got.Source != "192.0.2.77" || got.Count != 1 {
		t.Errorf("touch = %+v", got)
	}
	now = now.Add(2 * time.Hour)
	send(":23", "192.0.2.77:51003")
	if got := <-touches; got.Port != 23 || got.Count != 3 {
		t.Errorf("touch after the quiet period = %+v", got)
	}
	if got := d.Recent(); len(got) != 3 || got[0].Count != 3 {
		t.Errorf("recent = %+v", got)
	}
	cancel()
	d.Wait()
}

func TestRealListenerAcceptsAndCloses(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback listener:", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	d := New(Options{Ports: []int{port}, Host: "127.0.0.1"})
	ctx, cancel := context.WithCancel(context.Background())
	if st := d.Start(ctx); !st[0].Listening {
		t.Skip("port was taken:", st[0].Error)
	}
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := c.Read(make([]byte, 1)); err == nil || n != 0 {
		t.Errorf("a decoy should close without sending anything: n=%d err=%v", n, err)
	}
	c.Close()
	cancel()
	d.Wait()
	if len(d.Recent()) != 0 {
		t.Error("loopback is never reported")
	}
}

func TestBoundsAndNames(t *testing.T) {
	d := New(Options{})
	if len(d.opt.Ports) != len(DefaultPorts()) || d.opt.Quiet != DefaultQuiet {
		t.Errorf("defaults = %+v", d.opt)
	}
	for i := 0; i < recentMax+50; i++ {
		d.touched(fakeAddr(netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)}), 1).String()), 23)
	}
	if len(d.Recent()) != recentMax {
		t.Errorf("recent = %d", len(d.Recent()))
	}
	for i := 0; i < 4200; i++ {
		d.touched(fakeAddr(netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 19, byte(i >> 8), byte(i)}), 1).String()), 23)
	}
	if len(d.hits) > 4096 {
		t.Errorf("hits = %d", len(d.hits))
	}
	for port, want := range map[int]string{23: "Telnet", 2323: "Telnet", 3389: "remote desktop", 5900: "screen sharing (VNC)", 445: "Windows file sharing", 22: "SSH", 8081: "port 8081"} {
		if got := PortName(port); got != want {
			t.Errorf("PortName(%d) = %q", port, got)
		}
	}
}
