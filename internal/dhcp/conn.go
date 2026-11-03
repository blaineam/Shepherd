// SPDX-License-Identifier: AGPL-3.0-or-later

package dhcp

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
)

// ErrReadOnly is what an observe-mode connection returns from WriteTo. The
// guarantee that observe mode cannot transmit is enforced here, in the
// connection itself, as well as in Server: a bug in the handler should not be
// able to put a frame on a live network.
var ErrReadOnly = errors.New("dhcp: this connection is read-only (observe mode)")

// readOnly wraps a Conn and refuses every write.
type readOnly struct{ Conn }

func (readOnly) WriteTo([]byte, netip.AddrPort) (int, error) { return 0, ErrReadOnly }

// ReadOnly returns c with its send path removed.
func ReadOnly(c Conn) Conn { return readOnly{c} }

// udpConn is one UDP socket, as a Conn.
type udpConn struct{ c *net.UDPConn }

func (u udpConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	n, ap, err := u.c.ReadFromUDPAddrPort(p)
	return n, ap, err
}

func (u udpConn) WriteTo(p []byte, to netip.AddrPort) (int, error) {
	return u.c.WriteToUDPAddrPort(p, to)
}

func (u udpConn) Close() error { return u.c.Close() }

// multiConn reads from several sockets at once and writes through the first.
//
// It exists because a DHCP server and a DHCP watcher need different sockets.
// Requests arrive on port 67, which is the one Shepherd must have. Other
// servers' replies go to port 68, and listening there is the only way a UDP
// socket can see the router still answering — which is what the rogue-server
// interlock is for.
//
// The honest limit: a reply another server unicasts to a client that already
// has an address is addressed to that client, not to this host, so it is not
// seen. A *broadcast* reply is, and a client that is asking for an address
// for the first time normally sets the broadcast flag, so in practice the
// router's DHCP coming back is caught. Catching every case needs a raw frame
// socket. Handler.request covers the remaining common path: a client that
// names a different server identifier in its REQUEST tells Shepherd about
// that server directly.
type multiConn struct {
	conns []Conn
	// out is the socket replies go through: port 67, so that a client sees
	// a reply from the port it expects a server on.
	out Conn

	once   sync.Once
	closed atomic.Bool
	ch     chan readResult
	stop   chan struct{}
	wg     sync.WaitGroup
}

type readResult struct {
	data []byte
	from netip.AddrPort
	err  error
}

func newMultiConn(out Conn, conns ...Conn) *multiConn {
	return &multiConn{conns: conns, out: out, ch: make(chan readResult, 8), stop: make(chan struct{})}
}

func (m *multiConn) start() {
	for _, c := range m.conns {
		c := c
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			buf := make([]byte, 1500)
			for {
				n, from, err := c.ReadFrom(buf)
				var r readResult
				if err != nil {
					if m.closed.Load() {
						return
					}
					r = readResult{err: err}
				} else {
					r = readResult{data: append([]byte(nil), buf[:n]...), from: from}
				}
				select {
				case m.ch <- r:
				case <-m.stop:
					return
				}
			}
		}()
	}
}

func (m *multiConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	m.once.Do(m.start)
	select {
	case r, ok := <-m.ch:
		if !ok {
			return 0, netip.AddrPort{}, net.ErrClosed
		}
		if r.err != nil {
			return 0, netip.AddrPort{}, r.err
		}
		return copy(p, r.data), r.from, nil
	case <-m.stop:
		return 0, netip.AddrPort{}, net.ErrClosed
	}
}

func (m *multiConn) WriteTo(p []byte, to netip.AddrPort) (int, error) {
	if m.out == nil {
		return 0, ErrReadOnly
	}
	return m.out.WriteTo(p, to)
}

func (m *multiConn) Close() error {
	if m.closed.Swap(true) {
		return nil
	}
	close(m.stop)
	var first error
	for _, c := range m.conns {
		if err := c.Close(); err != nil && first == nil {
			first = err
		}
	}
	m.wg.Wait()
	return first
}

// UDPOpener opens the real sockets. It is an Opener.
//
// It binds port 67 unconditionally, because that is where requests arrive,
// and tries port 68 as well so other servers' broadcast replies are seen. A
// failure to bind 68 is not fatal: something else on the host is a DHCP
// client, which is normal, and the interlock then relies on clients' own
// REQUESTs to spot another server.
type UDPOpener struct {
	// Log, when set, records what was and was not bound, because "the
	// interlock is working at reduced sensitivity" is not something to
	// discover later.
	Log *log.Logger
	// Listen is a seam for the tests: it returns a Conn for one port.
	// Nil uses the real UDP sockets.
	Listen func(ctx context.Context, iface string, port int, broadcast bool) (Conn, error)
}

// Open implements Opener.
func (o UDPOpener) Open(ctx context.Context, iface string, write bool) (Conn, error) {
	listen := o.Listen
	if listen == nil {
		listen = listenUDP
	}
	server, err := listen(ctx, iface, ServerPort, write)
	if err != nil {
		return nil, fmt.Errorf("dhcp: binding UDP port %d: %w", ServerPort, err)
	}
	conns := []Conn{server}
	if client, err := listen(ctx, iface, ClientPort, false); err != nil {
		if o.Log != nil {
			o.Log.Printf("dhcp: could not also listen on UDP port %d (%v); another DHCP server will be spotted from clients' own requests rather than from its replies", ClientPort, err)
		}
	} else {
		conns = append(conns, client)
	}
	out := Conn(server)
	if !write {
		out = nil
	}
	m := newMultiConn(out, conns...)
	if !write {
		return ReadOnly(m), nil
	}
	return m, nil
}
