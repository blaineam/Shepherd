// SPDX-License-Identifier: AGPL-3.0-or-later

package dnsengine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// fakeWriter captures replies without a network, and lets tests choose the
// transport (UDP vs TCP) the engine believes it is serving.
type fakeWriter struct {
	remote net.Addr
	msgs   []*dns.Msg
}

func (f *fakeWriter) LocalAddr() net.Addr  { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53} }
func (f *fakeWriter) RemoteAddr() net.Addr { return f.remote }
func (f *fakeWriter) WriteMsg(m *dns.Msg) error {
	f.msgs = append(f.msgs, m.Copy())
	return nil
}
func (f *fakeWriter) Write(b []byte) (int, error) { return len(b), nil }
func (f *fakeWriter) Close() error                { return nil }
func (f *fakeWriter) TsigStatus() error           { return nil }
func (f *fakeWriter) TsigTimersOnly(bool)         {}
func (f *fakeWriter) Hijack()                     {}

func udpWriter() *fakeWriter {
	return &fakeWriter{remote: &net.UDPAddr{IP: net.ParseIP("192.0.2.50"), Port: 4000}}
}
func tcpWriter() *fakeWriter {
	return &fakeWriter{remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.50"), Port: 4000}}
}

func query(name string, qtype uint16) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(name, qtype)
	return q
}

func deadEngine(t *testing.T) *Engine {
	t.Helper()
	pool, err := NewPool([]string{"127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	pool.timeout = 200 * time.Millisecond
	return &Engine{Filter: NewFilter(), Pool: pool, Cache: NewCache(10), Log: NewQueryLog(10), Stats: NewStats()}
}

func TestServeDNSIgnoresResponsesAndRejectsMalformedQueries(t *testing.T) {
	e := deadEngine(t)
	w := udpWriter()
	resp := query("a.example.", dns.TypeA)
	resp.Response = true
	e.ServeDNS(w, resp)
	if len(w.msgs) != 0 {
		t.Error("a message that is already a response must be dropped")
	}

	noQuestion := new(dns.Msg)
	e.ServeDNS(w, noQuestion)
	notify := query("a.example.", dns.TypeA)
	notify.Opcode = dns.OpcodeNotify
	e.ServeDNS(w, notify)
	if len(w.msgs) != 2 || w.msgs[0].Rcode != dns.RcodeFormatError || w.msgs[1].Rcode != dns.RcodeFormatError {
		t.Errorf("malformed queries must get FORMERR, got %v", w.msgs)
	}
}

func TestServeDNSUpstreamFailureIsServfailAndLogged(t *testing.T) {
	e := deadEngine(t)
	w := udpWriter()
	e.ServeDNS(w, query("fail.example.", dns.TypeA))
	if len(w.msgs) != 1 || w.msgs[0].Rcode != dns.RcodeServerFailure {
		t.Fatalf("want SERVFAIL, got %v", w.msgs)
	}
	entries, _ := e.Log.After(0, 10)
	if len(entries) != 1 || entries[0].Action != "error" || entries[0].Reason == "" || entries[0].Client != "192.0.2.50" {
		t.Errorf("log = %+v", entries)
	}
	if s := e.Stats.Snapshot(); s.Errors != 1 {
		t.Errorf("stats = %+v", s)
	}
}

func TestBlockModesAndRecordTypes(t *testing.T) {
	e := deadEngine(t)
	e.Filter.SetList("ads", set("ads.example"))

	w := udpWriter()
	e.ServeDNS(w, query("ads.example.", dns.TypeMX)) // not A/AAAA: NOERROR, no answer
	if r := w.msgs[0]; r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0 {
		t.Errorf("MX sinkhole = rcode %d answers %d, want NODATA", r.Rcode, len(r.Answer))
	}

	e.BlockNXDOMAIN = true
	e.ServeDNS(w, query("ads.example.", dns.TypeA))
	if w.msgs[1].Rcode != dns.RcodeNameError {
		t.Errorf("nxdomain mode rcode = %d", w.msgs[1].Rcode)
	}
}

func TestUnknownQueryTypeIsNamedInLog(t *testing.T) {
	e := deadEngine(t)
	e.ServeDNS(udpWriter(), query("odd.example.", 65280))
	entries, _ := e.Log.After(0, 1)
	if len(entries) != 1 || entries[0].Type != "TYPE65280" {
		t.Errorf("log = %+v", entries)
	}
}

func TestClientIPFromAnyAddress(t *testing.T) {
	if got := clientIP(&net.UDPAddr{IP: net.ParseIP("2001:db8::7"), Port: 1}); got != "2001:db8::7" {
		t.Errorf("udp v6 = %q", got)
	}
	if got := clientIP(&net.TCPAddr{IP: net.ParseIP("192.0.2.9"), Port: 1}); got != "192.0.2.9" {
		t.Errorf("tcp = %q", got)
	}
	if got := clientIP(strAddr("198.51.100.4:99")); got != "198.51.100.4" {
		t.Errorf("custom host:port = %q", got)
	}
	if got := clientIP(strAddr("weird")); got != "weird" {
		t.Errorf("custom opaque = %q", got)
	}
}

type strAddr string

func (s strAddr) Network() string { return "test" }
func (s strAddr) String() string  { return string(s) }

func TestMaxSizeByTransportAndEDNS(t *testing.T) {
	plain := query("a.example.", dns.TypeA)
	edns := query("a.example.", dns.TypeA)
	edns.SetEdns0(4096, false)
	tiny := query("a.example.", dns.TypeA)
	tiny.SetEdns0(100, false)
	if got := maxSize(udpWriter(), plain); got != dns.MinMsgSize {
		t.Errorf("udp plain = %d", got)
	}
	if got := maxSize(udpWriter(), edns); got != 4096 {
		t.Errorf("udp edns = %d", got)
	}
	if got := maxSize(udpWriter(), tiny); got != dns.MinMsgSize {
		t.Errorf("udp tiny edns = %d, want the 512 floor", got)
	}
	if got := maxSize(tcpWriter(), plain); got != dns.MaxMsgSize {
		t.Errorf("tcp = %d", got)
	}
}

// bigUpstream answers TXT with a payload far larger than 512 bytes, over UDP
// and TCP on one port. The UDP side may truncate, like a real resolver would.
func bigUpstream(t *testing.T, truncateUDP bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	pc, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	full := func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		for i := 0; i < 40; i++ {
			m.Answer = append(m.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
				Txt: []string{strings.Repeat("x", 120)},
			})
		}
		_ = w.WriteMsg(m)
	}
	udpHandler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		if truncateUDP {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Truncated = true
			_ = w.WriteMsg(m)
			return
		}
		full(w, r)
	})
	us := &dns.Server{PacketConn: pc, Handler: udpHandler}
	ts := &dns.Server{Listener: ln, Handler: dns.HandlerFunc(full)}
	go us.ActivateAndServe()
	go ts.ActivateAndServe()
	t.Cleanup(func() { _ = us.Shutdown(); _ = ts.Shutdown() })
	return fmt.Sprintf("127.0.0.1:%d", port)
}

func TestLargeAnswersAreTruncatedOverUDPButNotTCP(t *testing.T) {
	addr := bigUpstream(t, false)
	pool, _ := NewPool([]string{"tcp://" + addr})
	e := &Engine{Filter: NewFilter(), Pool: pool, Cache: NewCache(0), Log: NewQueryLog(10), Stats: NewStats()}

	u := udpWriter()
	e.ServeDNS(u, query("big.example.", dns.TypeTXT))
	if !u.msgs[0].Truncated || len(u.msgs[0].Answer) >= 40 {
		t.Errorf("udp reply should be truncated: truncated=%v answers=%d", u.msgs[0].Truncated, len(u.msgs[0].Answer))
	}
	tc := tcpWriter()
	e.ServeDNS(tc, query("big.example.", dns.TypeTXT))
	if tc.msgs[0].Truncated || len(tc.msgs[0].Answer) != 40 {
		t.Errorf("tcp reply should be complete: truncated=%v answers=%d", tc.msgs[0].Truncated, len(tc.msgs[0].Answer))
	}
}

func TestUpstreamRetriesOverTCPWhenUDPIsTruncated(t *testing.T) {
	addr := bigUpstream(t, true)
	pool, _ := NewPool([]string{addr})
	resp, _, _, err := pool.Exchange(context.Background(), query("big.example.", dns.TypeTXT))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Truncated || len(resp.Answer) != 40 {
		t.Errorf("TCP retry failed: truncated=%v answers=%d", resp.Truncated, len(resp.Answer))
	}
}

func TestTLSUpstreamFailureIsRecordedNotFatal(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() { // accept and hang up: a TLS handshake can never succeed
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	pool, err := NewPool([]string{fmt.Sprintf("tls://%s", ln.Addr())})
	if err != nil {
		t.Fatal(err)
	}
	pool.timeout = 500 * time.Millisecond
	if _, _, _, err := pool.Exchange(context.Background(), query("a.example.", dns.TypeA)); err == nil {
		t.Error("expected an error from a broken TLS upstream")
	}
	if st := pool.Status()[0]; st.Errors != 1 || st.LastError == "" {
		t.Errorf("status = %+v", st)
	}
}

func TestPoolReturnsServfailWhenThatIsAllItGets(t *testing.T) {
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	defer srv.Shutdown()
	pool, _ := NewPool([]string{pc.LocalAddr().String()})
	resp, up, _, err := pool.Exchange(context.Background(), query("a.example.", dns.TypeA))
	if err != nil || resp.Rcode != dns.RcodeServerFailure || up == nil {
		t.Fatalf("resp=%v up=%v err=%v", resp, up, err)
	}
	if st := pool.Status()[0]; st.LastError != "SERVFAIL" || st.Fails != 1 {
		t.Errorf("status = %+v", st)
	}
}

func TestPoolErrorsAndLimits(t *testing.T) {
	if _, err := NewPool(nil); err == nil {
		t.Error("an empty pool must be rejected")
	}
	if _, err := NewPool([]string{"ftp://x"}); err == nil {
		t.Error("an unsupported scheme must be rejected")
	}
	if _, err := parseUpstream("udp://"); err == nil {
		t.Error("an empty host must be rejected")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	pool, _ := NewPool([]string{"127.0.0.1:1"})
	if _, _, _, err := pool.Exchange(ctx, query("a.example.", dns.TypeA)); err == nil || !strings.Contains(err.Error(), "no upstream answered") {
		t.Errorf("a cancelled context should give a clear error, got %v", err)
	}

	// Only three upstreams are tried per query.
	var addrs []string
	for i := 0; i < 5; i++ {
		addrs = append(addrs, "127.0.0.1:1")
	}
	p5, _ := NewPool(addrs)
	p5.timeout = 100 * time.Millisecond
	p5.Exchange(context.Background(), query("a.example.", dns.TypeA))
	var tried uint64
	for _, st := range p5.Status() {
		tried += st.Queries
	}
	if tried != 3 {
		t.Errorf("tried %d upstreams, want 3", tried)
	}
	_ = errors.New
}

func TestProbeMarksHealthAndStops(t *testing.T) {
	var hits atomicInt
	live := fakeUpstreamCounting(t, &hits)
	pool, _ := NewPool([]string{live, "127.0.0.1:1"})
	pool.timeout = 200 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { pool.Probe(ctx, 20*time.Millisecond); close(done) }()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		st := pool.Status()
		if st[0].Queries >= 2 && !st[1].Healthy {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	st := pool.Status()
	if !st[0].Healthy || st[1].Healthy || st[0].Queries < 2 {
		t.Errorf("probe status = %+v", st)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Probe did not stop")
	}
}

func TestServeAnswersAndStopsAndReportsBusyAddresses(t *testing.T) {
	port := freeUDPAndTCPPort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	h := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, []string{addr}, h) }()
	for _, network := range []string{"udp", "tcp"} {
		var err error
		for i := 0; i < 50; i++ {
			_, _, err = (&dns.Client{Net: network, Timeout: 200 * time.Millisecond}).Exchange(query("a.example.", dns.TypeA), addr)
			if err == nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if err != nil {
			t.Fatalf("%s query: %v", network, err)
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("clean stop returned %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not stop")
	}

	// UDP port busy.
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer pc.Close()
	busyUDP := pc.LocalAddr().String()
	if err := Serve(context.Background(), []string{busyUDP}, h); err == nil || !strings.Contains(err.Error(), "udp") {
		t.Errorf("busy udp: %v", err)
	}
	// TCP port busy while UDP is free: the UDP socket opened first must be released.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	if err := Serve(context.Background(), []string{ln.Addr().String()}, h); err == nil || !strings.Contains(err.Error(), "tcp") {
		t.Errorf("busy tcp: %v", err)
	}
}

func TestCacheBoundsTTLsAndEviction(t *testing.T) {
	q := query("c.example.", dns.TypeA)
	rr := func(ttl uint32) []dns.RR {
		return []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "c.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: net.ParseIP("192.0.2.1")}}
	}

	// Disabled cache never stores.
	off := NewCache(0)
	ok := new(dns.Msg)
	ok.SetReply(q)
	ok.Answer = rr(60)
	off.Put(q, ok)
	if _, hit := off.Get(q); hit {
		t.Error("a zero-size cache must not store")
	}

	c := NewCache(2)
	// TTL 0 is not cached; a huge TTL is capped at an hour.
	zero := ok.Copy()
	zero.Answer = rr(0)
	c.Put(q, zero)
	if _, hit := c.Get(q); hit {
		t.Error("ttl 0 must not be cached")
	}
	huge := ok.Copy()
	huge.Answer = rr(999999)
	c.Put(q, huge)
	if it := c.m[cacheKey(q)]; it.ttl != time.Hour {
		t.Errorf("ttl cap = %v, want 1h", it.ttl)
	}

	// NXDOMAIN with no records still caches for a short default.
	nx := new(dns.Msg)
	nx.SetReply(q)
	nx.Rcode = dns.RcodeNameError
	q2 := query("nx.example.", dns.TypeA)
	c.Put(q2, nx)
	if it := c.m[cacheKey(q2)]; it.ttl != 30*time.Second {
		t.Errorf("negative ttl = %v, want 30s", it.ttl)
	}

	// A third distinct entry evicts one; the map never exceeds its max.
	c.Put(query("third.example.", dns.TypeA), ok)
	if len(c.m) > 2 {
		t.Errorf("cache grew to %d entries, max 2", len(c.m))
	}

	// Truncated answers are never cached.
	tr := ok.Copy()
	tr.Truncated = true
	c2 := NewCache(5)
	c2.Put(q, tr)
	if _, hit := c2.Get(q); hit {
		t.Error("truncated answers must not be cached")
	}
}

func TestCacheDecrementsTTLsAndKeepsOPT(t *testing.T) {
	q := query("ttl.example.", dns.TypeA)
	c := NewCache(5)
	msg := new(dns.Msg)
	msg.SetReply(q)
	msg.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "ttl.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 100}, A: net.ParseIP("192.0.2.1")},
		&dns.A{Hdr: dns.RR_Header{Name: "ttl.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}, A: net.ParseIP("192.0.2.2")},
	}
	msg.SetEdns0(4096, false)
	c.m[cacheKey(q)] = cacheItem{msg: msg, stored: time.Now().Add(-3 * time.Second), ttl: 200 * time.Second}

	got, hit := c.Get(q)
	if !hit {
		t.Fatal("expected a hit")
	}
	if ttl := got.Answer[0].Header().Ttl; ttl > 97 || ttl < 95 {
		t.Errorf("ttl after 3s = %d, want about 97", ttl)
	}
	if ttl := got.Answer[1].Header().Ttl; ttl != 1 {
		t.Errorf("a ttl that ran out must floor at 1, got %d", ttl)
	}
	if got.IsEdns0() == nil {
		t.Error("the OPT record must survive caching")
	}
	if got.Id != q.Id {
		t.Error("cached answer must carry the asker's ID")
	}
}

func TestStatsBoundsMemory(t *testing.T) {
	s := NewStats()
	for i := 0; i <= statsCap; i++ {
		s.Record(Entry{Client: fmt.Sprintf("c%d", i), Action: "allowed"})
	}
	s.Record(Entry{Client: "c1", Action: "blocked", Name: "ads.example", Reason: "ads"})
	snap := s.Snapshot()
	if snap.Total != statsCap+2 || snap.Blocked != 1 {
		t.Errorf("totals = %+v", snap)
	}
	if len(s.clients) > statsCap {
		t.Errorf("client map grew to %d", len(s.clients))
	}
	if len(snap.TopBlocked) != 1 || snap.TopBlocked[0].Key != "ads.example" || len(snap.Reasons) != 1 {
		t.Errorf("blocked tops = %+v", snap)
	}
	// Ties sort by key for stable output.
	s2 := NewStats()
	s2.Record(Entry{Client: "b", Action: "allowed"})
	s2.Record(Entry{Client: "a", Action: "allowed"})
	if tc := s2.Snapshot().TopClients; tc[0].Key != "a" {
		t.Errorf("tie order = %+v", tc)
	}
	for _, a := range []string{"cached", "error"} {
		s2.Record(Entry{Client: "z", Action: a})
	}
	if sn := s2.Snapshot(); sn.Cached != 1 || sn.Errors != 1 {
		t.Errorf("cached/errors = %+v", sn)
	}
}

func TestQueryLogEdges(t *testing.T) {
	l := NewQueryLog(0) // falls back to a sane default size
	for i := 0; i < 5; i++ {
		l.Add(Entry{Name: fmt.Sprintf("n%d", i)})
	}
	if got, last := l.After(0, 2); len(got) != 2 || got[0].Name != "n3" || last != 5 {
		t.Errorf("limit on first read = %v last=%d", got, last)
	}
	if got, last := l.After(1, 2); len(got) != 2 || got[0].Name != "n1" || last != 3 {
		t.Errorf("limit after id = %v last=%d", got, last)
	}
	if got, last := NewQueryLog(5).After(0, 5); got != nil || last != 0 {
		t.Errorf("empty log = %v last=%d", got, last)
	}
	if got, _ := l.After(0, 50); len(got) != 5 {
		t.Errorf("fewer entries than the limit = %d", len(got))
	}
}

func TestRulesErrorsAndRemoval(t *testing.T) {
	dir := t.TempDir()
	f := NewFilter()
	r, err := LoadRules(filepath.Join(dir, "rules.json"), f, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Add("nope", "a.example"); err == nil {
		t.Error("a bad kind must be rejected")
	}
	if err := r.Remove("nope", "a.example"); err == nil {
		t.Error("a bad kind must be rejected on remove")
	}
	r.Add("block", "a.example")
	r.Add("block", "a.example") // duplicate: still one entry
	if _, block, _ := r.Snapshot(); len(block) != 1 {
		t.Errorf("duplicate add -> %v", block)
	}
	if err := r.Remove("block", "a.example"); err != nil {
		t.Fatal(err)
	}
	if f.Check("a.example").Blocked {
		t.Error("removed rule still blocks")
	}
	if got := KnownPolicies(); len(got) != 1 || got[0] != PolicyPrivateRelay {
		t.Errorf("KnownPolicies = %v", got)
	}

	if _, err := LoadRules(filepath.Join(dir, "sub"), f, nil); err != nil && !strings.Contains(err.Error(), "directory") {
		t.Logf("directory path: %v", err)
	}
	os.MkdirAll(filepath.Join(dir, "isdir"), 0o750)
	if _, err := LoadRules(filepath.Join(dir, "isdir"), f, nil); err == nil {
		t.Error("a directory where rules.json should be must error")
	}
	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte("{nope"), 0o600)
	if _, err := LoadRules(bad, f, nil); err == nil {
		t.Error("corrupt JSON must error")
	}

	// Saving into a vanished directory reports the failure.
	gone := filepath.Join(dir, "gone")
	os.MkdirAll(gone, 0o750)
	r2, _ := LoadRules(filepath.Join(gone, "rules.json"), f, nil)
	os.RemoveAll(gone)
	if err := r2.Add("block", "b.example"); err == nil {
		t.Error("a save failure must surface")
	}
}

func TestFilterCountsAndListRemoval(t *testing.T) {
	f := NewFilter()
	f.SetList("a", set("x.example", "y.example"))
	f.SetList("b", set("y.example", "z.example")) // y is in both lists
	f.SetRules([]string{"ok.example"}, []string{"no.example"})
	if listed, allow, block := f.Counts(); listed != 3 || allow != 1 || block != 1 {
		t.Errorf("counts = %d %d %d", listed, allow, block)
	}
	f.SetList("a", nil)
	if f.Check("x.example").Blocked || !f.Check("y.example").Blocked {
		t.Error("removing list a must unblock only its exclusive entries")
	}
	if d := f.Check("y.example"); d.Reason != "b" {
		t.Errorf("reason after removal = %q", d.Reason)
	}
	f.SetPolicy("p", []string{"pol.example"})
	f.SetPolicy("p", nil)
	if f.Check("pol.example").Blocked {
		t.Error("a disabled policy must not block")
	}
}
