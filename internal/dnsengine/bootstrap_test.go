// SPDX-License-Identifier: AGPL-3.0-or-later

package dnsengine

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock { return &fakeClock{t: time.Unix(1_800_000_000, 0)} }
func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *fakeClock) advance(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func testBoot(t *testing.T, fb *fakeBoot) (*bootstrap, *fakeClock) {
	t.Helper()
	b := newBootstrap()
	if err := b.setServers([]string{fb.addr}); err != nil {
		t.Fatal(err)
	}
	clk := newClock()
	b.now = clk.now
	return b, clk
}

func addrStrings(a []netip.Addr) string {
	var s []string
	for _, x := range a {
		s = append(s, x.String())
	}
	return strings.Join(s, ",")
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestBootstrapResolvesAAndAAAAAndCaches(t *testing.T) {
	fb := newFakeBoot(t, "dns.example.com", "192.0.2.10", "2001:db8::10")
	b, _ := testBoot(t, fb)
	got, err := b.lookup(context.Background(), "dns.example.com")
	if err != nil || len(got) != 2 {
		t.Fatalf("got %v, %v", got, err)
	}
	if _, err := b.lookup(context.Background(), "dns.example.com"); err != nil {
		t.Fatal(err)
	}
	if fb.aCalls.Load() != 1 {
		t.Errorf("resolved %d times, cache not used", fb.aCalls.Load())
	}
}

func TestBootstrapLiteralsSkipTheNetwork(t *testing.T) {
	fb := newFakeBoot(t, "")
	b, _ := testBoot(t, fb)
	got, err := b.lookup(context.Background(), "2001:db8::1")
	if err != nil || addrStrings(got) != "2001:db8::1" {
		t.Fatalf("got %v, %v", got, err)
	}
	if fb.allCall.Load() != 0 {
		t.Error("literals must not hit the network")
	}
}

func TestBootstrapMinimumTTLAndRefreshBeforeExpiry(t *testing.T) {
	fb := newFakeBoot(t, "dns.example.com", "192.0.2.10")
	fb.setTTL(1) // far below the 60 s floor
	b, clk := testBoot(t, fb)
	if _, err := b.lookup(context.Background(), "dns.example.com"); err != nil {
		t.Fatal(err)
	}
	clk.advance(40 * time.Second) // inside the 60 s floor, before the refresh point
	if _, err := b.lookup(context.Background(), "dns.example.com"); err != nil {
		t.Fatal(err)
	}
	if fb.aCalls.Load() != 1 {
		t.Fatalf("TTL floor violated: %d resolutions after 40 s", fb.aCalls.Load())
	}

	// Past three quarters of the lifetime but before expiry: the cached
	// answer is returned at once and a refresh runs in the background.
	fb.set("dns.example.com", "192.0.2.11")
	clk.advance(10 * time.Second)
	got, err := b.lookup(context.Background(), "dns.example.com")
	if err != nil || addrStrings(got) != "192.0.2.10" {
		t.Fatalf("expected the cached answer first, got %v, %v", got, err)
	}
	waitFor(t, "background refresh", func() bool { return fb.aCalls.Load() == 2 })
	waitFor(t, "refreshed answer", func() bool {
		got, _ := b.lookup(context.Background(), "dns.example.com")
		return addrStrings(got) == "192.0.2.11"
	})
}

func TestBootstrapExpiredEntryResolvesSynchronously(t *testing.T) {
	fb := newFakeBoot(t, "dns.example.com", "192.0.2.10")
	b, clk := testBoot(t, fb)
	b.lookup(context.Background(), "dns.example.com")
	fb.set("dns.example.com", "192.0.2.20")
	clk.advance(2 * time.Hour)
	got, err := b.lookup(context.Background(), "dns.example.com")
	if err != nil || addrStrings(got) != "192.0.2.20" {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestBootstrapTTLIsCapped(t *testing.T) {
	fb := newFakeBoot(t, "dns.example.com", "192.0.2.10")
	fb.setTTL(86400)
	b, clk := testBoot(t, fb)
	b.lookup(context.Background(), "dns.example.com")
	clk.advance(2 * time.Hour)
	b.lookup(context.Background(), "dns.example.com")
	if fb.aCalls.Load() != 2 {
		t.Errorf("a one-day TTL must be capped to an hour, resolutions = %d", fb.aCalls.Load())
	}
}

func TestBootstrapFailureIsCleanWithoutCache(t *testing.T) {
	fb := newFakeBoot(t, "")
	b, _ := testBoot(t, fb)
	_, err := b.lookup(context.Background(), "missing.example.com")
	if err == nil || !strings.Contains(err.Error(), "no such host") || !strings.Contains(err.Error(), "bootstrap") {
		t.Fatalf("err = %v", err)
	}
	// A name with neither A nor AAAA records.
	fb.set("empty.example.com")
	if _, err := b.lookup(context.Background(), "empty.example.com"); err == nil || !strings.Contains(err.Error(), "no A or AAAA") {
		t.Fatalf("err = %v", err)
	}
	// No reachable resolver at all.
	b2 := newBootstrap()
	if err := b2.setServers([]string{"127.0.0.1:1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := b2.lookup(context.Background(), "x.example.com"); err == nil || !strings.Contains(err.Error(), "bootstrap") {
		t.Fatalf("err = %v", err)
	}
	// No servers configured at the engine level.
	b3 := newBootstrap()
	if _, err := b3.lookup(context.Background(), "x.example.com"); err == nil {
		t.Fatal("expected an error with no resolvers")
	}
}

func TestBootstrapFallsBackToNextResolver(t *testing.T) {
	good := newFakeBoot(t, "dns.example.com", "192.0.2.10")
	b := newBootstrap()
	if err := b.setServers([]string{"127.0.0.1:1", good.addr}); err != nil {
		t.Fatal(err)
	}
	got, err := b.lookup(context.Background(), "dns.example.com")
	if err != nil || addrStrings(got) != "192.0.2.10" {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestBootstrapServesStaleWhenRefreshFails(t *testing.T) {
	fb := newFakeBoot(t, "dns.example.com", "192.0.2.10")
	b, clk := testBoot(t, fb)
	b.lookup(context.Background(), "dns.example.com")
	fb.setDown(false)
	fb.mu.Lock()
	delete(fb.recs, "dns.example.com.")
	fb.mu.Unlock()
	clk.advance(2 * time.Hour)
	got, err := b.lookup(context.Background(), "dns.example.com")
	if err != nil || addrStrings(got) != "192.0.2.10" {
		t.Fatalf("a failed refresh must not break a working upstream: %v, %v", got, err)
	}
}

func TestBootstrapSingleflightAndContext(t *testing.T) {
	fb := newFakeBoot(t, "dns.example.com", "192.0.2.10")
	b, _ := testBoot(t, fb)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := b.lookup(context.Background(), "dns.example.com"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if fb.aCalls.Load() != 1 {
		t.Errorf("concurrent lookups caused %d resolutions, want 1", fb.aCalls.Load())
	}

	// A caller whose context ends stops waiting; the resolution carries on.
	slow := newFakeBoot(t, "slow.example.com", "192.0.2.30")
	slow.setDown(true)
	b2, _ := testBoot(t, slow)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := b2.lookup(ctx, "slow.example.com"); err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
}

func TestBootstrapQueryRetriesTCPOnTruncation(t *testing.T) {
	port := freeUDPAndTCPPort(t)
	addr := net.JoinHostPort("127.0.0.1", itoa(port))
	h := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if _, isTCP := w.RemoteAddr().(*net.TCPAddr); !isTCP {
			m.Truncated = true
		} else if r.Question[0].Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120}, A: net.ParseIP("192.0.2.44")})
		}
		_ = w.WriteMsg(m)
	})
	udp, _ := net.ListenPacket("udp", addr)
	tcp, _ := net.Listen("tcp", addr)
	us, ts := &dns.Server{PacketConn: udp, Handler: h}, &dns.Server{Listener: tcp, Handler: h}
	go us.ActivateAndServe()
	go ts.ActivateAndServe()
	defer us.Shutdown()
	defer ts.Shutdown()
	b := newBootstrap()
	if err := b.setServers([]string{addr}); err != nil {
		t.Fatal(err)
	}
	got, err := b.lookup(context.Background(), "big.example.com")
	if err != nil || addrStrings(got) != "192.0.2.44" {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestSetBootstrapValidation(t *testing.T) {
	p, err := NewPool([]string{"192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]string{nil, {"dns.example.com"}, {"tls://192.0.2.1"}, {"https://192.0.2.1/dns-query"}, {"192.0.2.1:99999"}} {
		if err := p.SetBootstrap(bad); err == nil {
			t.Errorf("SetBootstrap(%v) should fail", bad)
		}
	}
	if err := p.SetBootstrap([]string{"192.0.2.1", "[2001:db8::1]:5353", "udp://192.0.2.2"}); err != nil {
		t.Error(err)
	}
	if _, err := NewPool([]string{"192.0.2.1"}, WithBootstrap("not-an-ip")); err == nil {
		t.Error("NewPool must surface a bad bootstrap option")
	}
	if got := strings.Join(DefaultBootstrapServers(), ","); got != DefaultBootstrap {
		t.Errorf("DefaultBootstrap %q != servers %q", DefaultBootstrap, got)
	}
}

func TestExtractAddrsIgnoresOtherRecords(t *testing.T) {
	m := new(dns.Msg)
	m.Answer = []dns.RR{
		&dns.CNAME{Hdr: dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 5}, Target: "b.example.com."},
		&dns.A{Hdr: dns.RR_Header{Name: "b.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 90}, A: net.ParseIP("192.0.2.5")},
		&dns.A{Hdr: dns.RR_Header{Name: "b.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.IP{1}}, // invalid length
	}
	addrs, ttl := extractAddrs(m)
	if len(addrs) != 1 || ttl != 90*time.Second {
		t.Errorf("addrs=%v ttl=%v", addrs, ttl)
	}
}

// ---- DoT ----

func startDoT(t *testing.T, ln net.Listener, cert tls.Certificate) {
	t.Helper()
	tl := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	srv := &dns.Server{Listener: tl, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.77")})
		_ = w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { _ = srv.Shutdown() })
}

func TestDoTViaBootstrapAndIPLiteral(t *testing.T) {
	certSrc := newDoHTest(t, func(http.ResponseWriter, *http.Request, *dns.Msg) {})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	startDoT(t, ln, certSrc.cert())
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	fb := newFakeBoot(t, "example.com", "127.0.0.1")

	p := testPool(t, fb, certSrc.roots, "tls://example.com:"+port, "tls://127.0.0.1:"+port)
	for i := 0; i < 2; i++ {
		resp, up, _, err := p.Exchange(context.Background(), aQuery("dot.example.org."))
		if err != nil || len(resp.Answer) != 1 {
			t.Fatalf("via %v: %v", up, err)
		}
	}
	for _, st := range p.Status() {
		if st.Queries == 0 && st.Errors != 0 {
			t.Errorf("status %+v", st)
		}
	}
	// Untrusted certificate (no hook) fails.
	p2 := testPool(t, fb, nil, "tls://example.com:"+port)
	if _, _, _, err := p2.Exchange(context.Background(), aQuery("dot.example.org.")); err == nil {
		t.Fatal("untrusted DoT certificate must fail")
	}
}

func TestDoTSecondAddressAndBootstrapFailure(t *testing.T) {
	certSrc := newDoHTest(t, func(http.ResponseWriter, *http.Request, *dns.Msg) {})
	ln := ipv6Loopback(t)
	startDoT(t, ln, certSrc.cert())
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	fb := newFakeBoot(t, "example.com", "127.0.0.1", "::1")
	p := testPool(t, fb, certSrc.roots, "tls://example.com:"+port)
	if _, _, _, err := p.Exchange(context.Background(), aQuery("dot.example.org.")); err != nil {
		t.Fatal(err)
	}

	pf, err := NewPool([]string{"tls://dns.example.net"}, WithBootstrap("127.0.0.1:1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := pf.Exchange(context.Background(), aQuery("a.example.org.")); err == nil || !strings.Contains(err.Error(), "bootstrap") {
		t.Fatalf("err = %v", err)
	}

	// Only dead addresses: the last dial error is returned.
	fb2 := newFakeBoot(t, "example.com", "127.0.0.1")
	pd := testPool(t, fb2, certSrc.roots, "tls://example.com:1")
	if _, _, _, err := pd.Exchange(context.Background(), aQuery("a.example.org.")); err == nil {
		t.Fatal("expected a dial error")
	}
	// A cancelled context before any dial returns the context error.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := pd.snapshot()[0].exchangeDoT(ctx, aQuery("a.example.org."), time.Second); err == nil {
		t.Fatal("expected a context error")
	}
}
