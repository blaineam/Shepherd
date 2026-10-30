// SPDX-License-Identifier: AGPL-3.0-or-later

package dnsengine

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestParseUpstreamForms(t *testing.T) {
	good := []struct{ in, network, hostport, kind string }{
		{"192.0.2.1", "udp", "192.0.2.1:53", "udp"},
		{" 192.0.2.1:5353 ", "udp", "192.0.2.1:5353", "udp"},
		{"udp://192.0.2.1", "udp", "192.0.2.1:53", "udp"},
		{"UDP://192.0.2.1", "udp", "192.0.2.1:53", "udp"},
		{"tcp://192.0.2.1", "tcp", "192.0.2.1:53", "tcp"},
		{"tcp://[2001:db8::1]:5353", "tcp", "[2001:db8::1]:5353", "tcp"},
		{"2001:db8::1", "udp", "[2001:db8::1]:53", "udp"},
		{"[2001:db8::1]", "udp", "[2001:db8::1]:53", "udp"},
		{"tls://dns.example.com", "tcp-tls", "dns.example.com:853", "dot"},
		{"tls://dns.example.com:8853", "tcp-tls", "dns.example.com:8853", "dot"},
		{"tls://192.0.2.1", "tcp-tls", "192.0.2.1:853", "dot"},
		{"tls://[2001:db8::1]", "tcp-tls", "[2001:db8::1]:853", "dot"},
		{"tls://2001:db8::1", "tcp-tls", "[2001:db8::1]:853", "dot"},
		{"https://dns.example.com/dns-query", "https", "dns.example.com:443", "doh"},
		{"HTTPS://dns.example.com/q?x=1", "https", "dns.example.com:443", "doh"},
		{"https://dns.example.com", "https", "dns.example.com:443", "doh"},
		{"https://dns.example.com:8443/dns-query", "https", "dns.example.com:8443", "doh"},
		{"https://192.0.2.1/dns-query", "https", "192.0.2.1:443", "doh"},
		{"https://[2001:db8::1]/dns-query", "https", "[2001:db8::1]:443", "doh"},
		{"https://[2001:db8::1]:8443/dns-query", "https", "[2001:db8::1]:8443", "doh"},
	}
	for _, c := range good {
		u, err := parseUpstream(c.in)
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if u.network != c.network || u.hostport != c.hostport || u.kind != c.kind {
			t.Errorf("%q -> %s %s %s, want %s %s %s", c.in, u.network, u.hostport, u.kind, c.network, c.hostport, c.kind)
		}
		if err := ValidateUpstream(c.in); err != nil {
			t.Errorf("ValidateUpstream(%q): %v", c.in, err)
		}
	}
	if u, _ := parseUpstream("https://dns.example.com"); u.dohURL != "https://dns.example.com:443/dns-query" {
		t.Errorf("default path: %s", u.dohURL)
	}
	if u, _ := parseUpstream("tls://192.0.2.1"); u.serverName != "" {
		t.Error("an IP literal must not become an SNI name")
	}
}

func TestParseUpstreamRejects(t *testing.T) {
	bad := map[string]string{
		"":                                 "empty",
		"   ":                              "empty",
		"ftp://192.0.2.1":                  "unsupported scheme",
		"quic://dns.example.com":           "unsupported scheme",
		"http://dns.example.com/dns-query": "https://",
		"udp://":                           "missing host",
		"tls://":                           "missing host",
		"https://":                         "missing host",
		"https:///dns-query":               "missing host",
		"dns.example.com":                  "IP address",
		"udp://dns.example.com":            "IP address",
		"tcp://dns.example.com:53":         "IP address",
		"192.0.2.1:0":                      "invalid port",
		"192.0.2.1:65536":                  "invalid port",
		"192.0.2.1:abc":                    "invalid port",
		"tls://dns.example.com:0":          "invalid port",
		"https://dns.example.com:99999/x":  "port",
		"[2001:db8::1":                     "malformed",
		"192.0.2.1:53:53x":                 "",
		"0.0.0.0":                          "not a usable",
		"224.0.0.1":                        "not a usable",
		"2001:db8::1%en0":                  "zones",
		"192.0.2.1/dns-query":              "unexpected",
		"192.0.2.1 evil":                   "unexpected",
		"tls://dns.example.com/path":       "unexpected",
		"tls://-bad.example.com":           "invalid hostname",
		"tls://bad_name.example.com":       "invalid hostname",
		"tls://a..b":                       "invalid hostname",
		"tls://999.1.1.1":                  "invalid hostname or malformed IP",
		"tls://1.2.3":                      "invalid hostname or malformed IP",
		"tls://0.0.0.0":                    "not a usable",
		"tls://" + strings.Repeat("a", 64) + ".example.com": "invalid hostname",
		"tls://" + strings.Repeat("a.", 130) + "com":        "invalid hostname",
		"https://user:pw@dns.example.com/dns-query":         "credentials", // leakcheck:allow synthetic URL userinfo
		"https://dns.example.com/dns-query#frag":            "fragment",
		"https://dns.example.com/dns-query#":                "fragment",
		"https://dns.exa mple.com/":                         "malformed",
		"https://bad_host.example.com/":                     "invalid hostname",
		"https://[2001:db8::1%25en0]/dns-query":             "zones",
		"https://0.0.0.0/dns-query":                         "not a usable",
		"https://dns.example.com:/dns-query":                "",
	}
	for in, want := range bad {
		if in == "https://dns.example.com:/dns-query" || in == "192.0.2.1:53:53x" {
			continue // ambiguous spellings: only assert they never panic
		}
		err := ValidateUpstream(in)
		if err == nil {
			t.Errorf("%q should be rejected", in)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%q: error %q lacks %q", in, err, want)
		}
	}
	ValidateUpstream("https://dns.example.com:/dns-query")
	ValidateUpstream("192.0.2.1:53:53x")
}

func TestPoolSetValidatesAllFirstAndKeepsStats(t *testing.T) {
	var hits atomicInt
	live := fakeUpstreamCounting(t, &hits)
	p, err := NewPool([]string{live, "198.51.100.7"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := p.Exchange(context.Background(), aQuery("a.example.org.")); err != nil {
		t.Fatal(err)
	}
	before := p.List()
	if before[0].Queries != 1 {
		t.Fatalf("setup: %+v", before)
	}

	// One bad entry: nothing changes.
	if err := p.Set([]string{live, "ftp://x"}); err == nil {
		t.Fatal("expected a validation error")
	}
	if got := p.List(); len(got) != 2 || got[0].Queries != 1 {
		t.Fatalf("a failed Set must not change the pool: %+v", got)
	}

	if err := p.Set([]string{"203.0.113.9", live, "https://dns.example.com/dns-query"}); err != nil {
		t.Fatal(err)
	}
	got := p.List()
	if len(got) != 3 || got[0].Config != "203.0.113.9" || got[1].Config != live || got[1].Queries != 1 || got[2].Kind != KindDoH {
		t.Fatalf("after Set: %+v", got)
	}
	if got[0].Queries != 0 {
		t.Error("a new entry starts with fresh stats")
	}

	for name, bad := range map[string][]string{
		"empty":     nil,
		"duplicate": {live, live},
		"respelled": {"192.0.2.1", "192.0.2.1:53"},
	} {
		if err := p.Set(bad); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if len(p.List()) != 3 {
		t.Error("failed Sets must leave the pool alone")
	}
}

func TestPoolAddRemoveList(t *testing.T) {
	p, err := NewPool([]string{"192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Add("tls://dns.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := p.Add("192.0.2.1:53"); err == nil || !strings.Contains(err.Error(), "already configured") {
		t.Errorf("duplicate Add: %v", err)
	}
	if err := p.Add("ftp://nope"); err == nil {
		t.Error("invalid Add must fail")
	}
	l := p.List()
	if len(l) != 2 || l[1].Config != "tls://dns.example.com" || l[1].Kind != KindDoT || !l[1].Healthy {
		t.Fatalf("list = %+v", l)
	}
	if err := p.Remove("203.0.113.1"); err == nil {
		t.Error("removing an unknown upstream must fail")
	}
	if err := p.Remove(" 192.0.2.1 "); err != nil {
		t.Fatal(err)
	}
	if err := p.Remove("tls://dns.example.com"); err == nil || !strings.Contains(err.Error(), "last") {
		t.Errorf("removing the last upstream must fail, got %v", err)
	}
	if got := p.Status(); len(got) != 1 || got[0].Addr != "tls://dns.example.com" {
		t.Errorf("status = %+v", got)
	}
}

func TestPoolTestResults(t *testing.T) {
	var hits atomicInt
	live := fakeUpstreamCounting(t, &hits)
	d := newDoHTest(t, func(w http.ResponseWriter, r *http.Request, q *dns.Msg) { answerA(w, q, nil) })
	p := testPool(t, nil, d.roots, live)
	p.timeout = 300 * time.Millisecond
	ctx := context.Background()

	r := p.Test(ctx, live)
	if !r.OK || r.Rcode != "NXDOMAIN" || r.Err != "" || r.RTT <= 0 {
		t.Errorf("plain: %+v", r)
	}
	r = p.Test(ctx, d.url("127.0.0.1"))
	if !r.OK || r.Rcode != "NOERROR" {
		t.Errorf("doh not in the pool: %+v", r)
	}
	if got := p.List(); len(got) != 1 || got[0].Queries != 0 {
		t.Errorf("Test must not touch the pool: %+v", got)
	}
	r = p.Test(ctx, "127.0.0.1:1")
	if r.OK || r.Err == "" {
		t.Errorf("dead: %+v", r)
	}
	r = p.Test(ctx, "ftp://x")
	if r.OK || !strings.Contains(r.Err, "unsupported scheme") {
		t.Errorf("invalid: %+v", r)
	}
	d2 := newDoHTest(t, func(w http.ResponseWriter, r *http.Request, q *dns.Msg) { http.Error(w, "x", 500) })
	p2 := testPool(t, nil, d2.roots, live)
	if r := p2.Test(ctx, d2.url("127.0.0.1")); r.OK || !strings.Contains(r.Err, "500") {
		t.Errorf("http error: %+v", r)
	}

	servfail := startServfail(t)
	if r := p.Test(ctx, servfail); r.OK || r.Rcode != "SERVFAIL" || !strings.Contains(r.Err, "SERVFAIL") {
		t.Errorf("servfail: %+v", r)
	}
}

func TestProbeKickedBySet(t *testing.T) {
	var hits atomicInt
	live := fakeUpstreamCounting(t, &hits)
	p, _ := NewPool([]string{live})
	p.timeout = 200 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Probe(ctx, time.Hour); close(done) }()
	waitFor(t, "first probe", func() bool { return hits.Load() >= 1 })
	other := fakeUpstreamCounting(t, &hits)
	if err := p.Set([]string{live, other}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "probe of the new upstream", func() bool { return p.Status()[1].Queries >= 1 })
	cancel()
	<-done
}

func TestPoolConcurrentExchangeWhileSetRuns(t *testing.T) {
	var hits atomicInt
	a := fakeUpstreamCounting(t, &hits)
	b := fakeUpstreamCounting(t, &hits)
	d := newDoHTest(t, func(w http.ResponseWriter, r *http.Request, q *dns.Msg) { answerA(w, q, nil) })
	p := testPool(t, nil, d.roots, a)
	p.timeout = time.Second
	configs := [][]string{{a}, {b, a}, {a, d.url("127.0.0.1")}, {d.url("127.0.0.1"), b}}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	var failures int
	var fmu sync.Mutex
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; ctx.Err() == nil; j++ {
				_, _, _, err := p.Exchange(ctx, aQuery(fmt.Sprintf("n%d.example.org.", j)))
				if err != nil && ctx.Err() == nil {
					fmu.Lock()
					failures++
					fmu.Unlock()
				}
				_ = p.List()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 60; i++ {
			if err := p.Set(configs[i%len(configs)]); err != nil {
				t.Error(err)
			}
			if i%7 == 0 {
				_ = p.Add("203.0.113.5")
				_ = p.Remove("203.0.113.5")
			}
		}
		cancel()
	}()
	wg.Wait()
	if failures != 0 {
		t.Errorf("%d queries failed during Set", failures)
	}
}
