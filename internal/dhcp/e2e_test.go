// SPDX-License-Identifier: AGPL-3.0-or-later

package dhcp

import (
	"context"
	"log"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"

	"shepherd/internal/devices"
)

// A whole lease, over real UDP sockets, with the real encoder on both sides.
//
// The unit tests drive the handler by calling a method, which proves the
// decisions and nothing about the wire. This proves the wire: the bytes a
// client puts on a socket, Shepherd's own decode, its reply encoded and sent,
// and the client's decode of that. What it cannot prove is the two things
// that need a real segment and a privileged socket -- port 67 itself, and
// broadcasting to a client that has no address yet -- which is why
// docs/DHCP.md puts observe mode on the live LAN and a parallel segment ahead
// of anything else.
func TestAWholeLeaseOverRealSockets(t *testing.T) {
	serverSock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("loopback UDP is unavailable here: %v", err)
	}
	clientSock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("client socket: %v", err)
	}
	defer clientSock.Close()
	clientAddr := netip.MustParseAddrPort(clientSock.LocalAddr().String())

	c := newClock()
	dir := t.TempDir()
	state, err := OpenState(filepath.Join(dir, "dhcp.json"), c.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.SetConfirmed(true); err != nil {
		t.Fatal(err)
	}
	sink := &recordingSink{}
	var logs safeBuffer
	srv := &Server{
		Mode: func() Mode { return ModeServe }, Settings: testSettings,
		Route: func() bool { return false }, RouteConsoles: func() bool { return false },
		Own: func() Own {
			return Own{IPs: []netip.Addr{shepherdA}, Gateway: gatewayA, GatewayMAC: macGateway}
		},
		Lookup: func(string) (devices.Device, bool) { return devices.Device{}, false },
		Store:  NewLeases(), State: state, Peers: NewPeers(), Sink: sink,
		// Replies go to the client's own port rather than to 68, because
		// nothing here is privileged enough to bind 68 either.
		Open: func(context.Context, string, bool) (Conn, error) {
			return redirectedConn{Conn: udpConn{c: serverSock}, to: clientAddr}, nil
		},
		LeasePath: filepath.Join(dir, "dhcp-leases.json"),
		Interval:  10 * time.Millisecond,
		Now:       c.now,
		Log:       log.New(&logs, "", 0),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Run: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Run did not stop")
		}
	})
	waitFor(t, "serving to start", func() bool { return srv.Status().Serving })

	serverAddr := netip.MustParseAddrPort(serverSock.LocalAddr().String())
	exchange := func(pkt *dhcpv4.DHCPv4) *dhcpv4.DHCPv4 {
		t.Helper()
		if _, err := clientSock.WriteToUDPAddrPort(pkt.ToBytes(), serverAddr); err != nil {
			t.Fatalf("sending: %v", err)
		}
		if err := clientSock.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 1500)
		n, _, err := clientSock.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("no reply: %v (log: %s)", err, logs.String())
		}
		reply, err := dhcpv4.FromBytes(buf[:n])
		if err != nil {
			t.Fatalf("the reply does not decode: %v", err)
		}
		return reply
	}

	discover := request(t, dhcpv4.MessageTypeDiscover, macA,
		dhcpv4.WithOption(dhcpv4.OptHostName("printer")),
		dhcpv4.WithOption(dhcpv4.OptClassIdentifier("MSFT 5.0")),
		dhcpv4.WithRequestedOptions(dhcpv4.OptionSubnetMask, dhcpv4.OptionRouter, dhcpv4.OptionDomainNameServer),
	)
	offer := exchange(discover)
	if offer.MessageType() != dhcpv4.MessageTypeOffer {
		t.Fatalf("message type = %s, want an offer", offer.MessageType())
	}
	offered, ok := netip.AddrFromSlice(offer.YourIPAddr.To4())
	if !ok || offered != poolStart {
		t.Fatalf("offered %v, want %s", offer.YourIPAddr, poolStart)
	}
	if offer.TransactionID != discover.TransactionID {
		t.Error("the reply must carry the client's own transaction ID, or the client ignores it")
	}

	// The client accepts the offer the way a real one does: a REQUEST
	// naming the server and the address.
	accept := request(t, dhcpv4.MessageTypeRequest, macA,
		dhcpv4.WithTransactionID(discover.TransactionID),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(offer.ServerIdentifier())),
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(offered.AsSlice())),
		dhcpv4.WithOption(dhcpv4.OptHostName("printer")),
		dhcpv4.WithOption(dhcpv4.OptClassIdentifier("MSFT 5.0")),
		dhcpv4.WithRequestedOptions(dhcpv4.OptionSubnetMask, dhcpv4.OptionRouter, dhcpv4.OptionDomainNameServer),
	)
	ack := exchange(accept)
	if ack.MessageType() != dhcpv4.MessageTypeAck {
		t.Fatalf("message type = %s, want an acknowledgement", ack.MessageType())
	}
	if got, _ := netip.AddrFromSlice(ack.YourIPAddr.To4()); got != offered {
		t.Errorf("acknowledged %s, want the offered %s", got, offered)
	}
	routers := ack.Router()
	if len(routers) != 1 || !routers[0].Equal(net.IP(gatewayA.AsSlice())) {
		t.Errorf("option 3 = %v, want the gateway %s while routing is off", routers, gatewayA)
	}
	if got := ack.IPAddressLeaseTime(0); got != 10*time.Minute {
		t.Errorf("lease time = %v", got)
	}

	// The lease is stored, and the registry learned what only DHCP could
	// tell it.
	waitFor(t, "the lease to be stored", func() bool { return srv.Status().Leases == 1 })
	l, ok := srv.Store.Get(macA)
	if !ok {
		t.Fatal("the lease should be in the store")
	}
	// The lease records what the REQUEST said, not what the DISCOVER said:
	// the acknowledged packet is the one that becomes the lease.
	if l.IP != offered || l.Hostname != "printer" || l.VendorClass != "MSFT 5.0" || l.Fingerprint != "1,3,6" {
		t.Errorf("stored lease = %+v", l)
	}
	var sawDHCP bool
	for _, o := range sink.all() {
		if o.Source == devices.SourceDHCP && o.Hostname == "printer" {
			sawDHCP = true
		}
	}
	if !sawDHCP {
		t.Errorf("the registry should have a DHCP-sourced name; got %+v", sink.all())
	}

	// A renewal keeps the address.
	renew := request(t, dhcpv4.MessageTypeRequest, macA, dhcpv4.WithClientIP(offered.AsSlice()))
	renew.ClientIPAddr = offered.AsSlice()
	if got := exchange(renew); got.MessageType() != dhcpv4.MessageTypeAck {
		t.Errorf("a renewal was answered with %s", got.MessageType())
	}

	// And a request for an address that is not available is refused rather
	// than quietly answered with a different one.
	other := request(t, dhcpv4.MessageTypeRequest, macB,
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(offered.AsSlice())))
	if got := exchange(other); got.MessageType() != dhcpv4.MessageTypeNak {
		t.Errorf("a request for somebody else's address was answered with %s, want a refusal", got.MessageType())
	}

	// And a release gives it back.
	release := request(t, dhcpv4.MessageTypeRelease, macA, dhcpv4.WithClientIP(offered.AsSlice()))
	if _, err := clientSock.WriteToUDPAddrPort(release.ToBytes(), serverAddr); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the lease to be released", func() bool {
		_, ok := srv.Store.Get(macA)
		return !ok
	})
	if strings.Contains(logs.String(), "refusing to send") {
		t.Errorf("the server logged a refusal to send: %s", logs.String())
	}
}

// redirectedConn sends every reply to one address instead of to the client
// port, because nothing in an unprivileged test can bind port 68. Everything
// else -- the socket, the encoding, the decoding -- is the real thing.
type redirectedConn struct {
	Conn
	to netip.AddrPort
}

func (r redirectedConn) WriteTo(p []byte, _ netip.AddrPort) (int, error) {
	return r.Conn.WriteTo(p, r.to)
}
