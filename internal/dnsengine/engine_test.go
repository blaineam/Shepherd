// SPDX-License-Identifier: AGPL-3.0-or-later

package dnsengine

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Test data uses reserved names (example.*, RFC 5737 addresses) only.

func set(domains ...string) map[string]struct{} {
	m := map[string]struct{}{}
	for _, d := range domains {
		m[d] = struct{}{}
	}
	return m
}

func TestFilterMatchesParentsOnly(t *testing.T) {
	f := NewFilter()
	f.SetList("ads", set("tracker.example"))
	cases := map[string]bool{
		"tracker.example":       true,
		"a.b.tracker.example.":  true,
		"TRACKER.example":       true,
		"notracker.example":     false,
		"tracker.example.other": false,
	}
	for name, want := range cases {
		if got := f.Check(name).Blocked; got != want {
			t.Errorf("Check(%q).Blocked = %v, want %v", name, got, want)
		}
	}
	if d := f.Check("x.tracker.example"); d.Reason != "ads" {
		t.Errorf("reason = %q, want the list name", d.Reason)
	}
}

func TestAllowRuleBeatsEverything(t *testing.T) {
	f := NewFilter()
	f.SetList("ads", set("tracker.example"))
	f.SetPolicy(PolicyPrivateRelay, []string{"mask.example"})
	f.SetRules([]string{"ok.tracker.example", "mask.example"}, []string{"blocked.example"})
	if f.Check("ok.tracker.example").Blocked {
		t.Error("allow rule should override the list")
	}
	if f.Check("deep.ok.tracker.example").Blocked {
		t.Error("allow rule should cover subdomains")
	}
	if f.Check("mask.example").Blocked {
		t.Error("allow rule should override a policy")
	}
	if d := f.Check("sub.blocked.example"); !d.Blocked || d.Reason != "custom rule" {
		t.Errorf("custom block = %+v", d)
	}
}

func TestParseListFormats(t *testing.T) {
	in := `# comment
! adblock comment
0.0.0.0 hosts.example
127.0.0.1 localhost
plain.example
||adblock.example^
||withopts.example^$third-party
||wild*.example^
##.cosmetic-rule
not a domain line here
192.0.2.1
UPPER.Example
`
	got, err := ParseList(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := set("hosts.example", "plain.example", "adblock.example", "upper.example")
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for d := range want {
		if _, ok := got[d]; !ok {
			t.Errorf("missing %s", d)
		}
	}
}

func TestGuard(t *testing.T) {
	prev := map[string]struct{}{}
	for i := 0; i < 2000; i++ {
		prev[strings.Repeat("a", i%20+1)+string(rune('a'+i%26))+".example"+string(rune('a'+i/26%26))] = struct{}{}
	}
	big := map[string]struct{}{}
	for i := 0; i < 7000; i++ {
		big[string(rune('a'+i%26))+strings.Repeat("b", i/26)+".example"] = struct{}{}
	}
	tests := []struct {
		name       string
		prev, next map[string]struct{}
		wantErr    string
	}{
		{"empty", nil, set(), "empty"},
		{"protected", nil, set("fine.example", "google.com"), "protected"},
		{"first load ok", nil, set("fine.example"), ""},
		{"shrank", prev, set("x.example"), "shrank"},
		{"grew", prev, big, "grew"},
		{"similar ok", prev, prev, ""},
	}
	for _, tc := range tests {
		err := Guard(tc.prev, tc.next, DefaultProtected)
		switch {
		case tc.wantErr == "" && err != nil:
			t.Errorf("%s: unexpected error %v", tc.name, err)
		case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
			t.Errorf("%s: error %v, want containing %q", tc.name, err, tc.wantErr)
		}
	}
}

// fakeUpstream answers every A query with answer and counts hits.
func fakeUpstream(t *testing.T, answer string, hits *atomic.Int32) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		hits.Add(1)
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Question[0].Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP(answer),
			})
		}
		_ = w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func TestPoolFailsOverFromDeadUpstream(t *testing.T) {
	var hits atomic.Int32
	live := fakeUpstream(t, "192.0.2.7", &hits)
	pool, err := NewPool([]string{"127.0.0.1:1", live}) // port 1: nothing listens
	if err != nil {
		t.Fatal(err)
	}
	pool.timeout = 500 * time.Millisecond
	q := new(dns.Msg)
	q.SetQuestion("host.example.", dns.TypeA)
	resp, up, _, err := pool.Exchange(context.Background(), q)
	if err != nil {
		t.Fatalf("expected failover, got %v", err)
	}
	if up.Addr != live || len(resp.Answer) != 1 {
		t.Fatalf("answered by %s with %d answers", up.Addr, len(resp.Answer))
	}
	// The live upstream now has a measured RTT, so it is tried first and the
	// dead one is no longer retried by queries. The prober records its second
	// failure, which marks it unhealthy.
	if got := pool.order()[0].Addr; got != live {
		t.Errorf("fastest known upstream should be tried first, got %s", got)
	}
	pool.ups[0].probe(context.Background(), pool.timeout)
	st := pool.Status()
	if st[0].Healthy || !st[1].Healthy {
		t.Errorf("health = %+v", st)
	}
	if st[0].Fails != 2 {
		t.Errorf("dead upstream failures = %d, want 2", st[0].Fails)
	}
}

func TestParseUpstream(t *testing.T) {
	good := map[string]string{
		"9.9.9.10":             "udp 9.9.9.10:53",
		"tcp://1.1.1.1":        "tcp 1.1.1.1:53",
		"tls://dns.example":    "tcp-tls dns.example:853",
		"2001:db8::1":          "udp [2001:db8::1]:53",
		"[2001:db8::1]:5353":   "udp [2001:db8::1]:5353",
		"tls://192.0.2.1:8853": "tcp-tls 192.0.2.1:8853",
	}
	for in, want := range good {
		u, err := parseUpstream(in)
		if err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		if got := u.network + " " + u.hostport; got != want {
			t.Errorf("%s -> %s, want %s", in, got, want)
		}
	}
	u, err := parseUpstream("https://dns.example/dns-query")
	if err != nil || u.network != "https" || u.hostport != "dns.example:443" {
		t.Errorf("https upstream: %+v, %v", u, err)
	}
}

func startEngine(t *testing.T, upstream string) (*Engine, string) {
	t.Helper()
	pool, err := NewPool([]string{upstream})
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{Filter: NewFilter(), Pool: pool, Cache: NewCache(100), Log: NewQueryLog(50), Stats: NewStats()}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: e}
	go srv.ActivateAndServe()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return e, pc.LocalAddr().String()
}

func ask(t *testing.T, addr, name string, qtype uint16) *dns.Msg {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion(name, qtype)
	c := &dns.Client{Timeout: 3 * time.Second}
	resp, _, err := c.Exchange(q, addr)
	if err != nil {
		t.Fatalf("query %s: %v", name, err)
	}
	return resp
}

func TestEngineEndToEnd(t *testing.T) {
	var hits atomic.Int32
	e, addr := startEngine(t, fakeUpstream(t, "192.0.2.9", &hits))
	e.Filter.SetList("ads", set("ads.example"))
	e.Filter.SetPolicy(PolicyPrivateRelay, policyDomains[PolicyPrivateRelay])

	// Allowed: forwarded, then served from cache.
	for i := 0; i < 2; i++ {
		r := ask(t, addr, "site.example.", dns.TypeA)
		if len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "192.0.2.9" {
			t.Fatalf("allowed answer wrong: %v", r.Answer)
		}
	}
	if hits.Load() != 1 {
		t.Errorf("upstream hit %d times, want 1 (second answer cached)", hits.Load())
	}

	// Blocked: sinkholed without touching the upstream.
	before := hits.Load()
	r := ask(t, addr, "x.ads.example.", dns.TypeA)
	if len(r.Answer) != 1 || !r.Answer[0].(*dns.A).A.Equal(net.IPv4zero) {
		t.Errorf("blocked A answer = %v, want 0.0.0.0", r.Answer)
	}
	r = ask(t, addr, "x.ads.example.", dns.TypeAAAA)
	if len(r.Answer) != 1 || !r.Answer[0].(*dns.AAAA).AAAA.Equal(net.IPv6zero) {
		t.Errorf("blocked AAAA answer = %v, want ::", r.Answer)
	}
	if hits.Load() != before {
		t.Error("blocked queries must not reach the upstream")
	}

	// Private Relay hostnames get NXDOMAIN, as Apple documents for networks.
	for _, host := range []string{"mask.icloud.com.", "mask-h2.icloud.com.", "mask-api.icloud.com."} {
		if r := ask(t, addr, host, dns.TypeA); r.Rcode != dns.RcodeNameError {
			t.Errorf("%s rcode = %s, want NXDOMAIN", host, dns.RcodeToString[r.Rcode])
		}
	}
	// icloud.com itself is untouched.
	if r := ask(t, addr, "www.icloud.com.", dns.TypeA); r.Rcode != dns.RcodeSuccess {
		t.Errorf("www.icloud.com rcode = %s", dns.RcodeToString[r.Rcode])
	}

	// Log and stats saw it all. Wait for every query's entry to land (see
	// waitForLogEntries) before reading Stats, which Engine.done updates
	// right alongside the log, in the same call.
	waitForLogEntries(t, e.Log, 8)
	entries, _ := e.Log.After(0, 100)
	var relay int
	for _, en := range entries {
		if en.Reason == PolicyPrivateRelay {
			relay++
		}
	}
	if relay != 3 {
		t.Errorf("log recorded %d private relay blocks, want 3", relay)
	}
	if s := e.Stats.Snapshot(); s.Blocked != 5 || s.Cached != 1 {
		t.Errorf("stats = %+v", s)
	}
}

func TestQueryLogAfter(t *testing.T) {
	l := NewQueryLog(3)
	for i := 0; i < 5; i++ {
		l.Add(Entry{Name: string(rune('a' + i))})
	}
	got, last := l.After(0, 10)
	if len(got) != 3 || got[0].Name != "c" || got[2].Name != "e" || last != 5 {
		t.Errorf("ring kept %v last=%d, want c,d,e last=5", got, last)
	}
	got, last = l.After(4, 10)
	if len(got) != 1 || got[0].Name != "e" || last != 5 {
		t.Errorf("after 4 = %v last=%d", got, last)
	}
	if got, last = l.After(5, 10); got != nil || last != 5 {
		t.Errorf("after latest = %v last=%d", got, last)
	}
}

func TestRulesPersistAndPolicyDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	f := NewFilter()
	r, err := LoadRules(path, f, map[string]bool{PolicyPrivateRelay: true})
	if err != nil {
		t.Fatal(err)
	}
	if !f.Check("mask.icloud.com").Blocked {
		t.Fatal("default-on policy should be active")
	}
	if err := r.Add("block", "evil.example"); err != nil {
		t.Fatal(err)
	}
	if err := r.Add("allow", "evil.example"); err != nil { // moves it to allow
		t.Fatal(err)
	}
	if err := r.SetPolicy(PolicyPrivateRelay, false); err != nil {
		t.Fatal(err)
	}
	if err := r.Add("block", "not a domain"); err == nil {
		t.Error("invalid domain accepted")
	}
	if err := r.SetPolicy("nope", true); err == nil {
		t.Error("unknown policy accepted")
	}

	// A fresh load sees the saved state and the saved policy choice wins over the default.
	f2 := NewFilter()
	r2, err := LoadRules(path, f2, map[string]bool{PolicyPrivateRelay: true})
	if err != nil {
		t.Fatal(err)
	}
	allow, block, pol := r2.Snapshot()
	if len(allow) != 1 || len(block) != 0 || pol[PolicyPrivateRelay] {
		t.Errorf("reloaded allow=%v block=%v policies=%v", allow, block, pol)
	}
	if f2.Check("mask.icloud.com").Blocked {
		t.Error("saved 'off' must beat the config default")
	}
}

func TestCacheExpiresAndSkipsErrors(t *testing.T) {
	c := NewCache(10)
	q := new(dns.Msg)
	q.SetQuestion("c.example.", dns.TypeA)

	servfail := new(dns.Msg)
	servfail.SetReply(q)
	servfail.Rcode = dns.RcodeServerFailure
	c.Put(q, servfail)
	if _, ok := c.Get(q); ok {
		t.Error("SERVFAIL must not be cached")
	}

	ok := new(dns.Msg)
	ok.SetReply(q)
	ok.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "c.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}, A: net.ParseIP("192.0.2.1")}}
	c.Put(q, ok)
	if _, hit := c.Get(q); !hit {
		t.Fatal("expected a hit")
	}
	time.Sleep(1100 * time.Millisecond)
	if _, hit := c.Get(q); hit {
		t.Error("entry should have expired")
	}
}
