// SPDX-License-Identifier: AGPL-3.0-or-later

package dnsengine

// The DNS QA harness (docs/DNS-QA.md): a real Engine, served on real UDP and
// TCP sockets, in front of fake upstream resolvers whose behaviour a test
// dials in (answer, SERVFAIL, stall, drop, truncate, NXDOMAIN, a TTL). Every
// TestQA_ test drives it the way a device would, over the wire, and asserts
// what the device sees plus what the upstreams saw. scripts/dns-qa runs them.

import (
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Fake resolver behaviours.
const (
	qaAnswer   int32 = iota // a normal answer
	qaServfail              // SERVFAIL
	qaDrop                  // read the query, never answer (a blackhole)
	qaTruncate              // UDP: TC=1 and no answer; TCP: the full answer
	qaNXDomain              // NXDOMAIN
)

// Addresses the fake hands out.
const (
	qaA    = "192.0.2.10"
	qaAAAA = "2001:db8::10" // leakcheck:allow documentation prefix
)

// qaResolver is a fake upstream listening on one loopback port over UDP and
// TCP.
type qaResolver struct {
	Addr string // host:port, usable as a plain upstream

	mode  atomic.Int32
	delay atomic.Int64 // ns before answering
	ttl   atomic.Uint32
	many  atomic.Int32 // A records per answer (0 means one)

	udp, tcp atomic.Int32 // queries seen per transport

	mu    sync.Mutex
	names map[string]int
}

func newQAResolver(t *testing.T) *qaResolver {
	t.Helper()
	r := &qaResolver{names: map[string]int{}}
	r.ttl.Store(300)
	port := itoa(freeUDPAndTCPPort(t))
	r.Addr = "127.0.0.1:" + port
	pc, err := net.ListenPacket("udp", r.Addr)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", r.Addr)
	if err != nil {
		t.Fatal(err)
	}
	us := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) { r.serve(w, q, &r.udp, true) })}
	ts := &dns.Server{Listener: ln, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) { r.serve(w, q, &r.tcp, false) })}
	go us.ActivateAndServe()
	go ts.ActivateAndServe()
	t.Cleanup(func() { _ = us.Shutdown(); _ = ts.Shutdown() })
	return r
}

func (r *qaResolver) set(mode int32)           { r.mode.Store(mode) }
func (r *qaResolver) setDelay(d time.Duration) { r.delay.Store(int64(d)) }
func (r *qaResolver) total() int               { return int(r.udp.Load() + r.tcp.Load()) }

// seen counts the queries for name (any type, any transport).
func (r *qaResolver) seen(name string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.names[strings.ToLower(dns.Fqdn(name))]
}

func (r *qaResolver) serve(w dns.ResponseWriter, q *dns.Msg, count *atomic.Int32, isUDP bool) {
	count.Add(1)
	qn := q.Question[0]
	r.mu.Lock()
	r.names[strings.ToLower(qn.Name)]++
	r.mu.Unlock()
	mode := r.mode.Load()
	if mode == qaDrop {
		return
	}
	if d := time.Duration(r.delay.Load()); d > 0 {
		time.Sleep(d)
	}
	m := new(dns.Msg)
	m.SetReply(q)
	switch {
	case mode == qaServfail:
		m.Rcode = dns.RcodeServerFailure
	case mode == qaNXDomain:
		m.Rcode = dns.RcodeNameError
	case mode == qaTruncate && isUDP:
		m.Truncated = true
	default:
		hdr := dns.RR_Header{Name: qn.Name, Class: dns.ClassINET, Ttl: r.ttl.Load()}
		switch qn.Qtype {
		case dns.TypeA:
			hdr.Rrtype = dns.TypeA
			n := int(r.many.Load())
			if n == 0 {
				n = 1
			}
			for i := 0; i < n; i++ {
				ip := net.ParseIP(qaA).To4()
				ip[3] = byte(10 + i)
				m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: ip})
			}
		case dns.TypeAAAA:
			hdr.Rrtype = dns.TypeAAAA
			m.Answer = append(m.Answer, &dns.AAAA{Hdr: hdr, AAAA: net.ParseIP(qaAAAA)})
		case dns.TypeHTTPS:
			hdr.Rrtype = dns.TypeHTTPS
			m.Answer = append(m.Answer, &dns.HTTPS{SVCB: dns.SVCB{Hdr: hdr, Priority: 1, Target: ".", Value: []dns.SVCBKeyValue{
				&dns.SVCBAlpn{Alpn: []string{"h2"}},
				&dns.SVCBIPv4Hint{Hint: []net.IP{net.ParseIP(qaA).To4()}},
				&dns.SVCBIPv6Hint{Hint: []net.IP{net.ParseIP(qaAAAA)}},
			}}})
		}
	}
	if isUDP {
		m.Truncate(dns.MinMsgSize) // a real resolver cuts a plain UDP answer at 512 bytes
	}
	_ = w.WriteMsg(m)
}

// qaWaitServing waits until addr answers over UDP and TCP without touching
// the engine's pool, filter or log: it sends an opcode the engine refuses
// with FORMERR before doing anything else, so the first real query of a test
// meets pristine upstream health and an empty cache.
func qaWaitServing(t *testing.T, addr string) {
	t.Helper()
	for _, proto := range []string{"udp", "tcp"} {
		deadline := time.Now().Add(5 * time.Second)
		for {
			q := new(dns.Msg)
			q.SetQuestion("ready.invalid.", dns.TypeA)
			q.Opcode = dns.OpcodeStatus
			if _, _, err := (&dns.Client{Net: proto, Timeout: time.Second}).Exchange(q, addr); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s %s never started serving", proto, addr)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// qaEngine serves a real Engine over UDP and TCP on one loopback port, in
// front of pool, and returns it with its address. mut adjusts the engine
// before it starts serving.
func qaEngine(t *testing.T, pool *Pool, mut func(*Engine)) (*Engine, string) {
	t.Helper()
	e := &Engine{Filter: NewFilter(), Pool: pool, Cache: NewCache(1000), Log: NewQueryLog(500), Stats: NewStats()}
	if mut != nil {
		mut(e)
	}
	addr := "127.0.0.1:" + itoa(freeUDPAndTCPPort(t))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = Serve(ctx, []string{addr}, e); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	qaWaitServing(t, addr)
	return e, addr
}

// qaPool builds a pool of plain upstreams with a short timeout.
func qaPool(t *testing.T, timeout time.Duration, addrs ...string) *Pool {
	t.Helper()
	p, err := NewPool(addrs)
	if err != nil {
		t.Fatal(err)
	}
	p.timeout = timeout
	return p
}

// qaQuery asks addr over proto ("udp" or "tcp") and returns the response
// and how long it took.
func qaQuery(t *testing.T, proto, addr, name string, qtype uint16) (*dns.Msg, time.Duration) {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), qtype)
	q.RecursionDesired = true
	c := &dns.Client{Net: proto, Timeout: 5 * time.Second}
	resp, rtt, err := c.Exchange(q, addr)
	if err != nil {
		t.Fatalf("%s query %s %s: %v", proto, name, dns.TypeToString[qtype], err)
	}
	return resp, rtt
}

// qaIPs lists the A and AAAA addresses in resp.
func qaIPs(resp *dns.Msg) []string {
	var out []string
	for _, ip := range answerIPs(resp) {
		out = append(out, ip.String())
	}
	return out
}

// qaLastEntry returns the newest query-log entry for name.
func qaLastEntry(t *testing.T, e *Engine, name string) Entry {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		all := e.Log.All()
		for i := len(all) - 1; i >= 0; i-- {
			if all[i].Name == name {
				return all[i]
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no log entry for %s", name)
	return Entry{}
}
