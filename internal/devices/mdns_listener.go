// SPDX-License-Identifier: AGPL-3.0-or-later

package devices

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// PacketConn is the part of a UDP socket the listener needs.
type PacketConn interface {
	ReadFrom(b []byte) (int, net.Addr, error)
	Close() error
}

// MDNSListener passively listens for multicast DNS responses and feeds what
// they reveal to a Sink. It never transmits: no queries, no announcements
// (docs/IPV6.md rule 2).
type MDNSListener struct {
	Sink    Sink
	Agg     *MDNSAggregator
	Now     func() time.Time
	OnError func(error) // parse errors and socket warnings; may be nil
}

// NewMDNSListener builds a listener for sink.
func NewMDNSListener(sink Sink) *MDNSListener {
	return &MDNSListener{Sink: sink, Agg: NewMDNSAggregator(), Now: time.Now}
}

func (l *MDNSListener) report(err error) {
	if l.OnError != nil {
		l.OnError(err)
	}
}

// Serve reads packets from conn until ctx is cancelled or the socket fails,
// closing conn on return. Malformed packets are reported and skipped.
func (l *MDNSListener) Serve(ctx context.Context, conn PacketConn) error {
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-stop:
		}
	}()
	defer conn.Close()
	buf := make([]byte, 9000)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		obs, err := l.Agg.Ingest(buf[:n], l.Now())
		if err != nil {
			l.report(fmt.Errorf("mdns: bad packet: %w", err))
			continue
		}
		for _, o := range obs {
			l.Sink.Observe(o)
		}
	}
}

// listenShared opens a UDP socket that coexists with other mDNS listeners
// on the machine (SO_REUSEADDR and SO_REUSEPORT), so port 5353 needs no
// special privileges and does not displace the system responder.
func listenShared(ctx context.Context, network, addr string) (net.PacketConn, error) {
	lc := net.ListenConfig{Control: reuseControl}
	return lc.ListenPacket(ctx, network, addr)
}

// joinAll calls join for every interface and reports how many succeeded.
func joinAll(ifaces []net.Interface, join func(*net.Interface) error) (int, error) {
	joined := 0
	var first error
	for i := range ifaces {
		if err := join(&ifaces[i]); err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		joined++
	}
	return joined, first
}

// mdnsInterfaces lists interfaces that can carry multicast.
func mdnsInterfaces() []net.Interface {
	all, _ := net.Interfaces()
	var out []net.Interface
	for _, ifc := range all {
		if ifc.Flags&net.FlagUp != 0 && ifc.Flags&net.FlagMulticast != 0 && ifc.Flags&net.FlagLoopback == 0 {
			out = append(out, ifc)
		}
	}
	return out
}

// Run joins the mDNS multicast groups (the IPv4 and IPv6 link-local groups) on every
// multicast-capable interface and serves until ctx is cancelled. It
// succeeds if either address family could be opened.
func (l *MDNSListener) Run(ctx context.Context) error {
	ifaces := mdnsInterfaces()
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errs []error
	opened := 0
	start := func(network, addr string, join func(net.PacketConn, *net.Interface) error) {
		c, err := listenShared(ctx, network, addr)
		if err == nil {
			var n int
			if n, err = joinAll(ifaces, func(i *net.Interface) error { return join(c, i) }); n == 0 {
				c.Close()
				if err == nil {
					err = errors.New("no multicast interface")
				}
			} else {
				err = nil
			}
		}
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			errs = append(errs, fmt.Errorf("mdns %s: %w", network, err))
			return
		}
		opened++
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := l.Serve(ctx, c); err != nil {
				l.report(err)
			}
		}()
	}
	start("udp4", "0.0.0.0:5353", func(c net.PacketConn, i *net.Interface) error {
		return ipv4.NewPacketConn(c).JoinGroup(i, &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251)})
	})
	start("udp6", "[::]:5353", func(c net.PacketConn, i *net.Interface) error {
		return ipv6.NewPacketConn(c).JoinGroup(i, &net.UDPAddr{IP: net.ParseIP("ff02::fb")})
	})
	if opened == 0 {
		return errors.Join(errs...)
	}
	for _, e := range errs {
		l.report(e)
	}
	wg.Wait()
	return nil
}

var _ Discoverer = (*MDNSListener)(nil)
