// SPDX-License-Identifier: AGPL-3.0-or-later

package devices

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func rr(t testing.TB, s string) dns.RR {
	t.Helper()
	r, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("NewRR(%q): %v", s, err)
	}
	return r
}

func packet(t testing.TB, response bool, answers, extra []string) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.Response = response
	m.Authoritative = response
	for _, s := range answers {
		m.Answer = append(m.Answer, rr(t, s))
	}
	for _, s := range extra {
		m.Extra = append(m.Extra, rr(t, s))
	}
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A crafted "living room TV" announcement.
func tvPacket(t testing.TB) []byte {
	return packet(t, true,
		[]string{
			`_services._dns-sd._udp.local. 4500 IN PTR _googlecast._tcp.local.`,
			`_googlecast._tcp.local. 4500 IN PTR Den\032Display._googlecast._tcp.local.`,
			`Den\032Display._googlecast._tcp.local. 120 IN SRV 0 0 8009 den-tv.local.`,
			`Den\032Display._googlecast._tcp.local. 4500 IN TXT "md=Chromecast Ultra" "fn=Den Display" "ve=05"`,
			`den-tv.local. 120 IN A 192.0.2.44`,
		},
		[]string{
			`den-tv.local. 120 IN AAAA 2001:db8::44`,
			`_airplay._tcp.local. 4500 IN PTR Den\032Display._airplay._tcp.local.`,
			`Den\032Display._airplay._tcp.local. 120 IN SRV 0 0 7000 den-tv.local.`,
			`Den\032Display._airplay._tcp.local. 4500 IN TXT "model=AppleTV6,2" "manufacturer=ExampleCo"`,
		})
}

func TestParseMDNS(t *testing.T) {
	hosts, err := ParseMDNS(tvPacket(t))
	if err != nil {
		t.Fatal(err)
	}
	h := hosts["den-tv.local"]
	if h == nil || len(hosts) != 1 {
		t.Fatalf("hosts: %+v", hosts)
	}
	eq(t, h.Name, "den-tv")
	eq(t, len(h.IPs), 2)
	eq(t, h.IPs[0].String(), "192.0.2.44")
	eq(t, h.Services, []string{"_airplay._tcp", "_googlecast._tcp"})
	foundModel, foundName := false, false
	for _, x := range h.Hints {
		if x == "Chromecast Ultra" {
			foundModel = true
		}
		if x == "Den Display" {
			foundName = true
		}
	}
	if !foundModel || !foundName {
		t.Fatalf("hints: %v", h.Hints)
	}
	eq(t, h.Vendor, "ExampleCo") // explicit manufacturer overrides the Apple model guess

	// Queries carry no identity.
	q := packet(t, false, []string{`den-tv.local. 120 IN A 192.0.2.44`}, nil)
	hosts, err = ParseMDNS(q)
	if err != nil || len(hosts) != 0 {
		t.Fatalf("query parsed as %v, %v", hosts, err)
	}
	// Garbage fails cleanly.
	if _, err := ParseMDNS([]byte{1, 2, 3}); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestParseMDNSAppleVendorAndOddRecords(t *testing.T) {
	b := packet(t, true, []string{
		`Studio._companion-link._tcp.local. 120 IN SRV 0 0 49153 studio-mac.local.`,
		`Studio._companion-link._tcp.local. 4500 IN TXT "rpMd=MacBookPro18,3" "novalue" "usb_MFG=Acme"`,
		`orphan._ipp._tcp.local. 120 IN SRV 0 0 631 .`,
		`orphan2._ipp._tcp.local. 120 IN TXT "ty=Orphan"`,
		`studio-mac.local. 120 IN A 198.51.100.7`,
		`weird. 120 IN A 198.51.100.8`,
		`plain._notservice.local. 120 IN SRV 0 0 1 studio-mac.local.`,
	}, nil)
	hosts, err := ParseMDNS(b)
	if err != nil {
		t.Fatal(err)
	}
	h := hosts["studio-mac.local"]
	if h == nil {
		t.Fatalf("hosts %v", hosts)
	}
	eq(t, h.Vendor, "Acme") // usb_MFG sorts into vendor keys
	eq(t, h.Services, []string{"_companion-link._tcp"})
	// A pure Apple model without manufacturer maps to Apple.
	b = packet(t, true, []string{
		`Mac._companion-link._tcp.local. 120 IN SRV 0 0 1 mac-two.local.`,
		`Mac._companion-link._tcp.local. 120 IN TXT "rpMd=iPhone14,2"`,
		`mac-two.local. 120 IN A 198.51.100.9`,
	}, nil)
	hosts, _ = ParseMDNS(b)
	eq(t, hosts["mac-two.local"].Vendor, "Apple")
	if hasApplePrefix("Toaster1,1") {
		t.Fatal("false Apple")
	}
}

func TestUnescapeAndSplit(t *testing.T) {
	eq(t, unescapeDNS(`Den\032Display`), "Den Display")
	eq(t, unescapeDNS(`a\.b\\c`), `a.b\c`)
	eq(t, unescapeDNS(`trail\`), `trail\`)
	eq(t, unescapeDNS(`plain`), "plain")
	name, svc := splitInstance(`My\032TV._googlecast._tcp.local.`)
	eq(t, name, "My TV")
	eq(t, svc, "_googlecast._tcp")
	name, svc = splitInstance("host.local.")
	eq(t, name+svc, "")
}

func TestMDNSAggregator(t *testing.T) {
	agg := NewMDNSAggregator()
	t0 := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

	// Services first, addresses later: nothing to emit until an IP is known.
	svcOnly := packet(t, true, []string{
		`Cam._rtsp._tcp.local. 120 IN SRV 0 0 554 porch-cam.local.`,
	}, nil)
	obs, err := agg.Ingest(svcOnly, t0)
	if err != nil || len(obs) != 0 {
		t.Fatalf("%v %v", obs, err)
	}
	addr := packet(t, true, []string{`porch-cam.local. 120 IN A 192.0.2.60`, `porch-cam.local. 120 IN AAAA 2001:db8::60`}, nil)
	obs, err = agg.Ingest(addr, t0.Add(time.Second))
	if err != nil || len(obs) != 2 {
		t.Fatalf("%v %v", obs, err)
	}
	o := obs[0]
	if o.Source != SourceMDNS || o.Hostname != "porch-cam" || len(o.Services) != 1 || o.Services[0] != "_rtsp._tcp" {
		t.Fatalf("%+v", o)
	}
	// Repeats are suppressed until something changes or the re-emit window passes.
	obs, _ = agg.Ingest(addr, t0.Add(2*time.Second))
	if len(obs) != 0 {
		t.Fatal("repeat not suppressed")
	}
	obs, _ = agg.Ingest(packet(t, true, []string{`porch-cam.local. 120 IN A 192.0.2.61`}, nil), t0.Add(3*time.Second))
	if len(obs) != 3 {
		t.Fatalf("new address not emitted: %d", len(obs))
	}
	obs, _ = agg.Ingest(addr, t0.Add(10*time.Minute))
	if len(obs) != 3 {
		t.Fatal("periodic re-emit missing")
	}
	// Vendor hint updates flow through.
	obs, _ = agg.Ingest(packet(t, true, []string{
		`Cam._rtsp._tcp.local. 120 IN SRV 0 0 554 porch-cam.local.`,
		`Cam._rtsp._tcp.local. 120 IN TXT "manufacturer=ExampleCo"`,
	}, nil), t0.Add(11*time.Minute))
	if len(obs) != 3 || obs[0].VendorHint != "ExampleCo" {
		t.Fatalf("%+v", obs)
	}
	if _, err := agg.Ingest([]byte{9}, t0); err == nil {
		t.Fatal("garbage accepted")
	}
	// Expiry of stale hosts once the cache is large.
	for i := 0; i < mdnsMaxKeep+5; i++ {
		agg.hosts["h"+itoa(i)] = &aggHost{seen: t0.Add(-3 * time.Hour)}
	}
	agg.Ingest(addr, t0.Add(20*time.Minute))
	if len(agg.hosts) > 10 {
		t.Fatalf("stale hosts kept: %d", len(agg.hosts))
	}
}

func TestMDNSEndToEndIntoRegistry(t *testing.T) {
	r, clk := newReg(t)
	agg := NewMDNSAggregator()
	// The neighbor table knows the MAC; mDNS then names the device and types it.
	id := r.Observe(Observation{Source: SourceNeighbor, MAC: macA, IP: "192.0.2.44"})
	obs, _ := agg.Ingest(tvPacket(t), clk.Now())
	for _, o := range obs {
		r.Observe(o)
	}
	d := mustDevice(t, r, id)
	if r.Len() != 1 {
		t.Fatalf("mDNS made duplicates: %d", r.Len())
	}
	eq(t, d.MDNSName, "den-tv")
	eq(t, d.Type, TypeTV)
	eq(t, d.IPs, []string{"192.0.2.44", "2001:db8::44"})
	eq(t, d.DisplayName(), "den-tv")
}

// ---- listener ----

type fakeConn struct {
	mu      sync.Mutex
	packets [][]byte
	err     error
	closed  bool
	block   chan struct{}
}

func (f *fakeConn) ReadFrom(b []byte) (int, net.Addr, error) {
	f.mu.Lock()
	if len(f.packets) > 0 {
		p := f.packets[0]
		f.packets = f.packets[1:]
		f.mu.Unlock()
		return copy(b, p), &net.UDPAddr{IP: net.ParseIP("192.0.2.44"), Port: 5353}, nil
	}
	closed, err := f.closed, f.err
	f.mu.Unlock()
	if err != nil {
		return 0, nil, err
	}
	if f.block != nil && !closed {
		<-f.block
	}
	return 0, nil, net.ErrClosed
}

func (f *fakeConn) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.closed {
		f.closed = true
		if f.block != nil {
			close(f.block)
		}
	}
	return nil
}

func TestMDNSListenerServe(t *testing.T) {
	r, _ := newReg(t)
	var mu sync.Mutex
	var errs []error
	l := NewMDNSListener(r)
	l.OnError = func(e error) { mu.Lock(); errs = append(errs, e); mu.Unlock() }
	conn := &fakeConn{packets: [][]byte{{1, 2, 3}, tvPacket(t)}, err: errors.New("socket died")}
	err := l.Serve(context.Background(), conn)
	if err == nil || err.Error() != "socket died" {
		t.Fatalf("err = %v", err)
	}
	if len(errs) != 1 || r.Len() != 1 {
		t.Fatalf("errs %v, devices %d", errs, r.Len())
	}
	if !conn.closed {
		t.Fatal("conn not closed")
	}
	// A nil OnError is fine.
	l2 := NewMDNSListener(r)
	l2.Serve(context.Background(), &fakeConn{packets: [][]byte{{7}}})

	// Cancellation unblocks a waiting reader and returns nil.
	ctx, cancel := context.WithCancel(context.Background())
	bc := &fakeConn{block: make(chan struct{})}
	done := make(chan error)
	go func() { done <- l.Serve(ctx, bc) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not stop")
	}
}

func TestListenSharedAndJoinAll(t *testing.T) {
	// Two sockets may share one loopback port: that is what lets us coexist
	// with the system mDNS responder. This uses only the loopback interface.
	c1, err := listenShared(context.Background(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	c2, err := listenShared(context.Background(), "udp4", c1.LocalAddr().String())
	if err != nil {
		t.Fatalf("port not shareable: %v", err)
	}
	c2.Close()

	ifs := []net.Interface{{Name: "a"}, {Name: "b"}, {Name: "c"}}
	n, err := joinAll(ifs, func(i *net.Interface) error {
		if i.Name == "b" {
			return errors.New("no multicast on b")
		}
		return nil
	})
	if n != 2 || err == nil {
		t.Fatalf("n=%d err=%v", n, err)
	}
	n, err = joinAll(nil, nil)
	if n != 0 || err != nil {
		t.Fatal("empty join")
	}
	_ = mdnsInterfaces() // must not panic; contents depend on the machine
}
