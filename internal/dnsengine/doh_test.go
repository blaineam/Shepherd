// SPDX-License-Identifier: AGPL-3.0-or-later

package dnsengine

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestDoHPostRoundTripOverHTTP2WithBootstrap(t *testing.T) {
	var seen struct {
		method, ctype, accept, ua string
		id                        uint16
	}
	d := newDoHTest(t, func(w http.ResponseWriter, r *http.Request, q *dns.Msg) {
		seen.method, seen.ctype, seen.accept, seen.ua = r.Method, r.Header.Get("Content-Type"), r.Header.Get("Accept"), r.Header.Get("User-Agent")
		seen.id = q.Id
		answerA(w, q, nil)
	})
	fb := newFakeBoot(t, "example.com", "127.0.0.1")
	p := testPool(t, fb, d.roots, d.url("example.com"))
	q := aQuery("host.example.org.")
	q.Id = 0x1234
	resp, up, _, err := p.Exchange(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if seen.method != "POST" || seen.ctype != "application/dns-message" || seen.accept != "application/dns-message" || !strings.Contains(seen.ua, "shepherd") {
		t.Errorf("request headers: %+v", seen)
	}
	if seen.id != 0 {
		t.Errorf("wire ID = %d, RFC 8484 recommends 0", seen.id)
	}
	if q.Id != 0x1234 {
		t.Error("the caller's message must not be mutated")
	}
	if resp.Id != 0x1234 || len(resp.Answer) != 1 || up.Addr != d.url("example.com") {
		t.Errorf("resp id=%#x answers=%d via %s", resp.Id, len(resp.Answer), up.Addr)
	}
	if d.proto.Load() != 2 {
		t.Errorf("HTTP major version = %d, want 2", d.proto.Load())
	}
	if fb.aCalls.Load() != 1 {
		t.Errorf("bootstrap resolved %d times, want 1", fb.aCalls.Load())
	}
}

func TestDoHKeepAliveReusesOneConnection(t *testing.T) {
	d := newDoHTest(t, func(w http.ResponseWriter, r *http.Request, q *dns.Msg) { answerA(w, q, nil) })
	fb := newFakeBoot(t, "example.com", "127.0.0.1")
	p := testPool(t, fb, d.roots, d.url("example.com"))
	for i := 0; i < 5; i++ {
		if _, _, _, err := p.Exchange(context.Background(), aQuery("k.example.org.")); err != nil {
			t.Fatal(err)
		}
	}
	if d.conns.Load() != 1 || d.reqs.Load() != 5 {
		t.Errorf("connections=%d requests=%d, want 1 and 5", d.conns.Load(), d.reqs.Load())
	}
	if fb.aCalls.Load() != 1 {
		t.Errorf("bootstrap queried %d times, cache should absorb the rest", fb.aCalls.Load())
	}
}

func TestDoHRejectsBadResponses(t *testing.T) {
	big := strings.Repeat("x", maxDoHResponse+10)
	cases := map[string]struct {
		h    dohHandler
		want string
	}{
		"wrong content type": {func(w http.ResponseWriter, r *http.Request, q *dns.Msg) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html>"))
		}, "Content-Type"},
		"missing content type": {func(w http.ResponseWriter, r *http.Request, q *dns.Msg) {
			w.Header()["Content-Type"] = nil
			_, _ = w.Write([]byte{1, 2})
		}, "Content-Type"},
		"oversized": {func(w http.ResponseWriter, r *http.Request, q *dns.Msg) {
			w.Header().Set("Content-Type", "application/dns-message")
			_, _ = w.Write([]byte(big))
		}, "larger than"},
		"http error": {func(w http.ResponseWriter, r *http.Request, q *dns.Msg) {
			http.Error(w, "nope", http.StatusServiceUnavailable)
		}, "503"},
		"garbled": {func(w http.ResponseWriter, r *http.Request, q *dns.Msg) {
			w.Header().Set("Content-Type", "application/dns-message")
			_, _ = w.Write([]byte{0xde, 0xad, 0xbe, 0xef, 1, 2, 3})
		}, "malformed"},
		"truncated message": {func(w http.ResponseWriter, r *http.Request, q *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(q)
			for i := 0; i < 5; i++ {
				m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}, A: net.ParseIP("192.0.2.9")})
			}
			wire, _ := m.Pack()
			w.Header().Set("Content-Type", "application/dns-message")
			_, _ = w.Write(wire[:len(wire)-6])
		}, "malformed"},
		"not a response": {func(w http.ResponseWriter, r *http.Request, q *dns.Msg) {
			w.Header().Set("Content-Type", "application/dns-message")
			wire, _ := q.Pack() // echoes the query: QR bit unset
			_, _ = w.Write(wire)
		}, "not a DNS response"},
		"question mismatch": {func(w http.ResponseWriter, r *http.Request, q *dns.Msg) {
			o := aQuery("other.example.net.")
			answerA(w, o, nil)
		}, "does not match"},
		"redirect": {func(w http.ResponseWriter, r *http.Request, q *dns.Msg) {
			http.Redirect(w, r, "https://example.net/", http.StatusFound)
		}, "redirects are not followed"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			d := newDoHTest(t, c.h)
			p := testPool(t, nil, d.roots, d.url("127.0.0.1"))
			_, _, _, err := p.Exchange(context.Background(), aQuery("a.example.org."))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want containing %q", err, c.want)
			}
			if st := p.Status()[0]; st.Errors != 1 || st.LastError == "" {
				t.Errorf("failure not recorded: %+v", st)
			}
		})
	}
}

func TestDoHTruncatedFlagIsPassedThrough(t *testing.T) {
	d := newDoHTest(t, func(w http.ResponseWriter, r *http.Request, q *dns.Msg) {
		answerA(w, q, func(m *dns.Msg) { m.Truncated = true })
	})
	p := testPool(t, nil, d.roots, d.url("127.0.0.1"))
	resp, _, _, err := p.Exchange(context.Background(), aQuery("t.example.org."))
	if err != nil || !resp.Truncated {
		t.Fatalf("resp=%v err=%v", resp, err)
	}
}

func TestDoHIPLiteralUsesIPSANs(t *testing.T) {
	d := newDoHTest(t, func(w http.ResponseWriter, r *http.Request, q *dns.Msg) { answerA(w, q, nil) })
	p := testPool(t, nil, d.roots, d.url("127.0.0.1")) // no bootstrap needed for a literal
	if _, _, _, err := p.Exchange(context.Background(), aQuery("ip.example.org.")); err != nil {
		t.Fatal(err)
	}
}

func TestDoHIPv6LiteralURL(t *testing.T) {
	ln := ipv6Loopback(t)
	d := newDoHTestOn(t, ln, func(w http.ResponseWriter, r *http.Request, q *dns.Msg) { answerA(w, q, nil) })
	p := testPool(t, nil, d.roots, d.url("::1"))
	if want := "https://[::1]:" + d.port + "/dns-query"; p.List()[0].Config != want {
		t.Errorf("config = %s, want %s", p.List()[0].Config, want)
	}
	if _, _, _, err := p.Exchange(context.Background(), aQuery("v6.example.org.")); err != nil {
		t.Fatal(err)
	}
}

func TestDoHFallsThroughDeadAddressToWorkingOne(t *testing.T) {
	ln := ipv6Loopback(t)
	d := newDoHTestOn(t, ln, func(w http.ResponseWriter, r *http.Request, q *dns.Msg) { answerA(w, q, nil) })
	// IPv4 is tried first and refused; the IPv6 address then answers.
	fb := newFakeBoot(t, "example.com", "127.0.0.1", "::1")
	p := testPool(t, fb, d.roots, d.url("example.com"))
	if _, _, _, err := p.Exchange(context.Background(), aQuery("f.example.org.")); err != nil {
		t.Fatal(err)
	}
}

func TestDoHCertificateVerificationIsNotWeakened(t *testing.T) {
	d := newDoHTest(t, func(w http.ResponseWriter, r *http.Request, q *dns.Msg) { answerA(w, q, nil) })
	// Untrusted CA (no test hook): must fail.
	p := testPool(t, nil, nil, d.url("127.0.0.1"))
	_, _, _, err := p.Exchange(context.Background(), aQuery("a.example.org."))
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("want a certificate error, got %v", err)
	}
	// Trusted CA but the hostname does not match the certificate.
	fb := newFakeBoot(t, "wrong.example.net", "127.0.0.1")
	p2 := testPool(t, fb, d.roots, d.url("wrong.example.net"))
	_, _, _, err = p2.Exchange(context.Background(), aQuery("a.example.org."))
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("want a hostname mismatch error, got %v", err)
	}
}

func TestDoHBlackholeTimesOutAndFailsOverToPlain(t *testing.T) {
	d := newDoHTest(t, func(w http.ResponseWriter, r *http.Request, q *dns.Msg) {
		<-r.Context().Done() // connects, then never answers
	})
	var hits atomicInt
	live := fakeUpstreamCounting(t, &hits)
	p := testPool(t, nil, d.roots, d.url("127.0.0.1"), live)
	p.timeout = 200 * time.Millisecond
	start := time.Now()
	resp, up, _, err := p.Exchange(context.Background(), aQuery("b.example.org."))
	if err != nil || up.Addr != live || resp == nil {
		t.Fatalf("expected failover to the plain upstream, got up=%v err=%v", up, err)
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("failover took %v", time.Since(start))
	}
	// The prober marks the silent DoH upstream unhealthy after a second failure.
	p.snapshot()[0].probe(context.Background(), p.timeout)
	st := p.Status()
	if st[0].Healthy || !st[1].Healthy || st[0].Fails != 2 {
		t.Errorf("status = %+v", st)
	}
	if p.order()[0].Addr != live {
		t.Error("the plain upstream should now be tried first")
	}
}

func TestDoHConnectionResetIsAnError(t *testing.T) {
	d := newDoHTest(t, func(w http.ResponseWriter, r *http.Request, q *dns.Msg) {
		panic(http.ErrAbortHandler) // reset in transit after the connection was made
	})
	p := testPool(t, nil, d.roots, d.url("127.0.0.1"))
	if _, _, _, err := p.Exchange(context.Background(), aQuery("r.example.org.")); err == nil {
		t.Fatal("expected an error")
	}
}

func TestDoHShortBodyIsReadError(t *testing.T) {
	d := newDoHTest(t, func(w http.ResponseWriter, r *http.Request, q *dns.Msg) {
		w.Header().Set("Content-Type", "application/dns-message")
		w.Header().Set("Content-Length", "500")
		_, _ = w.Write([]byte{1, 2, 3})
	})
	p := testPool(t, nil, d.roots, d.url("127.0.0.1"))
	if _, _, _, err := p.Exchange(context.Background(), aQuery("s.example.org.")); err == nil {
		t.Fatal("expected a read error")
	}
}

func TestDoHBootstrapFailureNeverUsesSystemResolver(t *testing.T) {
	// The name is never resolved by anything but the bootstrap list.
	p, err := NewPool([]string{"https://dns.example.net/dns-query"}, WithBootstrap("127.0.0.1:1"))
	if err != nil {
		t.Fatal(err)
	}
	p.timeout = 2 * time.Second
	_, _, _, err = p.Exchange(context.Background(), aQuery("a.example.org."))
	if err == nil || !strings.Contains(err.Error(), "bootstrap") {
		t.Fatalf("err = %v", err)
	}

	// A bootstrap resolver that never answers: the query still ends at its deadline.
	dead := newFakeBoot(t, "")
	dead.setDown(true)
	p2 := testPool(t, dead, nil, "https://dns.example.net/dns-query")
	p2.timeout = 300 * time.Millisecond
	if _, _, _, err := p2.Exchange(context.Background(), aQuery("a.example.org.")); err == nil {
		t.Fatal("expected an error")
	}
	if dead.allCall.Load() == 0 {
		t.Error("bootstrap resolver was never asked")
	}
}

func TestDoHUnreachableServerIsAnError(t *testing.T) {
	d := newDoHTest(t, func(w http.ResponseWriter, r *http.Request, q *dns.Msg) { answerA(w, q, nil) })
	d.srv.Close()
	p := testPool(t, nil, d.roots, d.url("127.0.0.1"))
	if _, _, _, err := p.Exchange(context.Background(), aQuery("a.example.org.")); err == nil {
		t.Fatal("expected a dial error")
	}
}

func TestDoHPackErrorAndBadURLRequest(t *testing.T) {
	p := testPool(t, nil, nil, "https://127.0.0.1/dns-query")
	u := p.snapshot()[0]
	bad := new(dns.Msg)
	bad.Question = []dns.Question{{Name: strings.Repeat("a", 300) + ".", Qtype: dns.TypeA, Qclass: dns.ClassINET}}
	if _, _, err := u.exchangeDoH(context.Background(), bad, time.Second); err == nil || !strings.Contains(err.Error(), "pack") {
		t.Errorf("pack error expected, got %v", err)
	}
	u.dohURL = "https://127.0.0.1/\x7f" // cannot form a request
	if _, _, err := u.exchangeDoH(context.Background(), aQuery("a.example.org."), time.Second); err == nil {
		t.Error("request construction error expected")
	}
}

func TestDoHDialContextEdgeCases(t *testing.T) {
	p := testPool(t, nil, nil, "https://127.0.0.1/dns-query")
	u := p.snapshot()[0]
	if _, err := u.dialContext(context.Background(), "tcp", "no-port"); err == nil {
		t.Error("an address without a port must fail")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := u.dialContext(ctx, "tcp", "127.0.0.1:9"); err == nil {
		t.Error("a cancelled context must fail the dial")
	}
}

func TestUnwrapURLError(t *testing.T) {
	plain := net.UnknownNetworkError("x")
	if unwrapURLError(plain) != error(plain) {
		t.Error("non-URL errors pass through")
	}
}
