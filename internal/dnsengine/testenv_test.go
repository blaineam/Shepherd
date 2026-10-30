// SPDX-License-Identifier: AGPL-3.0-or-later

package dnsengine

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// withRoots is the test-only hook that trusts a test CA. Production code has
// no such switch: certificate verification is never weakened.
func withRoots(cp *x509.CertPool) PoolOption {
	return func(p *Pool) error { p.env.roots = cp; return nil }
}

// fakeBoot is a plain DNS server on loopback that plays the bootstrap
// resolver: it knows a fixed set of synthetic names.
type fakeBoot struct {
	addr    string
	aCalls  atomic.Int32 // A queries seen: one per resolution
	allCall atomic.Int32
	mu      sync.Mutex
	recs    map[string][]string
	ttl     uint32
	down    bool // answer nothing (drop)
}

func newFakeBoot(t *testing.T, host string, ips ...string) *fakeBoot {
	t.Helper()
	fb := &fakeBoot{recs: map[string][]string{}, ttl: 300}
	if host != "" {
		fb.set(host, ips...)
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(fb.serve)}
	go srv.ActivateAndServe()
	t.Cleanup(func() { _ = srv.Shutdown() })
	fb.addr = pc.LocalAddr().String()
	return fb
}

func (fb *fakeBoot) set(host string, ips ...string) {
	fb.mu.Lock()
	fb.recs[dns.Fqdn(strings.ToLower(host))] = ips
	fb.mu.Unlock()
}

func (fb *fakeBoot) setTTL(ttl uint32) { fb.mu.Lock(); fb.ttl = ttl; fb.mu.Unlock() }
func (fb *fakeBoot) setDown(d bool)    { fb.mu.Lock(); fb.down = d; fb.mu.Unlock() }

func (fb *fakeBoot) serve(w dns.ResponseWriter, r *dns.Msg) {
	fb.allCall.Add(1)
	q := r.Question[0]
	if q.Qtype == dns.TypeA {
		fb.aCalls.Add(1)
	}
	fb.mu.Lock()
	ips, ok := fb.recs[strings.ToLower(q.Name)]
	ttl, down := fb.ttl, fb.down
	fb.mu.Unlock()
	if down {
		return
	}
	m := new(dns.Msg)
	if !ok {
		m.SetRcode(r, dns.RcodeNameError)
		_ = w.WriteMsg(m)
		return
	}
	m.SetReply(r)
	for _, s := range ips {
		ip := net.ParseIP(s)
		hdr := dns.RR_Header{Name: q.Name, Class: dns.ClassINET, Ttl: ttl}
		if ip.To4() != nil && q.Qtype == dns.TypeA {
			hdr.Rrtype = dns.TypeA
			m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: ip})
		} else if ip.To4() == nil && q.Qtype == dns.TypeAAAA {
			hdr.Rrtype = dns.TypeAAAA
			m.Answer = append(m.Answer, &dns.AAAA{Hdr: hdr, AAAA: ip})
		}
	}
	_ = w.WriteMsg(m)
}

// dohHandler receives the unpacked query; it writes the HTTP response itself.
type dohHandler func(w http.ResponseWriter, r *http.Request, q *dns.Msg)

type dohTest struct {
	srv   *httptest.Server
	port  string
	roots *x509.CertPool
	conns atomic.Int32
	reqs  atomic.Int32
	proto atomic.Int32 // last request's HTTP major version
}

// answerA writes a normal DoH answer for q: 192.0.2.1.
func answerA(w http.ResponseWriter, q *dns.Msg, mut func(*dns.Msg)) {
	m := new(dns.Msg)
	m.SetReply(q)
	m.Answer = append(m.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.ParseIP("192.0.2.1"),
	})
	if mut != nil {
		mut(m)
	}
	wire, _ := m.Pack()
	w.Header().Set("Content-Type", "application/dns-message")
	_, _ = w.Write(wire)
}

func newDoHTest(t *testing.T, h dohHandler) *dohTest {
	t.Helper()
	return newDoHTestOn(t, nil, h)
}

func newDoHTestOn(t *testing.T, ln net.Listener, h dohHandler) *dohTest {
	t.Helper()
	d := &dohTest{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.reqs.Add(1)
		d.proto.Store(int32(r.ProtoMajor))
		body := make([]byte, 0, 512)
		buf := make([]byte, 512)
		for {
			n, err := r.Body.Read(buf)
			body = append(body, buf[:n]...)
			if err != nil {
				break
			}
		}
		q := new(dns.Msg)
		if err := q.Unpack(body); err != nil {
			q = nil
		}
		h(w, r, q)
	}))
	if ln != nil {
		srv.Listener.Close()
		srv.Listener = ln
	}
	srv.EnableHTTP2 = true
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			d.conns.Add(1)
		}
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	d.srv = srv
	_, d.port, _ = net.SplitHostPort(srv.Listener.Addr().String())
	d.roots = x509.NewCertPool()
	d.roots.AddCert(srv.Certificate())
	return d
}

// url returns the DoH URL using the given host (the test certificate is valid
// for example.com, 127.0.0.1 and ::1).
func (d *dohTest) url(host string) string {
	return "https://" + net.JoinHostPort(host, d.port) + "/dns-query"
}

func (d *dohTest) cert() tls.Certificate { return d.srv.TLS.Certificates[0] }

func testPool(t *testing.T, fb *fakeBoot, roots *x509.CertPool, addrs ...string) *Pool {
	t.Helper()
	opts := []PoolOption{}
	if fb != nil {
		opts = append(opts, WithBootstrap(fb.addr))
	}
	if roots != nil {
		opts = append(opts, withRoots(roots))
	}
	p, err := NewPool(addrs, opts...)
	if err != nil {
		t.Fatal(err)
	}
	p.timeout = 2 * time.Second
	t.Cleanup(func() {
		for _, u := range p.snapshot() {
			u.closeIdle()
		}
	})
	return p
}

func aQuery(name string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)
	return m
}

func ipv6Loopback(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 loopback unavailable")
	}
	return ln
}

// startServfail runs a plain upstream that always answers SERVFAIL.
func startServfail(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}
